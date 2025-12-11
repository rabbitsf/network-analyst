# pcap_tools.py

from scapy.all import rdpcap, IP, TCP, UDP, DNS, ARP, ICMP, Raw, Ether
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional
import math
import subprocess
import json
import tempfile
import os
from pathlib import Path

# Optional imports for application-layer parsing
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False

try:
    from scapy.layers.dhcp import DHCP
    HAS_DHCP = True
except ImportError:
    HAS_DHCP = False


# ---------- Basic loader ----------

def load_pcap(path: str):
    """
    Load a PCAP file and return the packet list.
    """
    return rdpcap(path)


# ---------- Flow stats ----------

def get_flow_stats(packets, min_packets: int = 5, top_n: int = 20) -> List[Dict[str, Any]]:
    """
    Compute basic flow stats:
    - key: (src, dst, sport, dport, proto)
    - metrics: packet_count, byte_count, duration, pps, bps

    Useful for:
    - Top talkers
    - Heavy flows causing congestion
    - Potential DDoS / flood patterns
    """
    flows = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "first_ts": None,
        "last_ts": None,
    })

    for p in packets:
        if IP not in p:
            continue

        ip = p[IP]
        proto = "OTHER"
        sport = dport = None

        if TCP in p:
            proto = "TCP"
            sport = p[TCP].sport
            dport = p[TCP].dport
        elif UDP in p:
            proto = "UDP"
            sport = p[UDP].sport
            dport = p[UDP].dport

        key = (ip.src, ip.dst, sport, dport, proto)

        fl = flows[key]
        fl["packet_count"] += 1
        fl["byte_count"] += len(p)
        ts = float(p.time)
        if fl["first_ts"] is None or ts < fl["first_ts"]:
            fl["first_ts"] = ts
        if fl["last_ts"] is None or ts > fl["last_ts"]:
            fl["last_ts"] = ts

    results: List[Dict[str, Any]] = []
    for (src, dst, sport, dport, proto), data in flows.items():
        if data["packet_count"] < min_packets:
            continue

        duration = (data["last_ts"] - data["first_ts"]) if data["last_ts"] and data["first_ts"] else 0.0
        duration = max(duration, 0.000001)  # avoid division by zero

        pps = data["packet_count"] / duration
        bps = data["byte_count"] * 8 / duration

        results.append({
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "packet_count": data["packet_count"],
            "byte_count": data["byte_count"],
            "duration_sec": round(duration, 6),
            "pps": round(pps, 2),
            "bps": round(bps, 2),
        })

    # Sort by byte_count descending, keep top N
    results.sort(key=lambda x: x["byte_count"], reverse=True)
    return results[:top_n]


# ---------- TCP handshake stats ----------

def get_tcp_handshake_stats(packets) -> Dict[str, Any]:
    """
    Look at TCP flag patterns to infer:
    - How many SYNs, SYN-ACKs, ACKs, RSTs
    - Possible connectivity issues (many SYNs without SYN-ACKs)
    - Possible scanning (many SYNs to different ports)
    """
    syn_count = 0
    syn_ack_count = 0
    ack_count = 0
    rst_count = 0

    syn_per_target = Counter()
    syn_no_synack = Counter()
    saw_syn_ack_for = set()

    for p in packets:
        if TCP not in p or IP not in p:
            continue
        ip = p[IP]
        tcp = p[TCP]
        flags = tcp.flags

        key = (ip.src, ip.dst, tcp.dport)

        # SYN (no ACK)
        if flags & 0x02 and not (flags & 0x10):  # SYN and not ACK
            syn_count += 1
            syn_per_target[key] += 1

        # SYN-ACK
        if (flags & 0x12) == 0x12:  # SYN + ACK
            syn_ack_count += 1
            saw_syn_ack_for.add((ip.dst, ip.src, tcp.sport))  # reverse direction

        # ACK (without SYN)
        if flags & 0x10 and not (flags & 0x02):
            ack_count += 1

        # RST
        if flags & 0x04:
            rst_count += 1

    # Count targets that got SYN but no SYN-ACK
    for key, cnt in syn_per_target.items():
        reverse_key = (key[1], key[0], key[2])  # (dst, src, dport) as in SYN-ACK
        if reverse_key not in saw_syn_ack_for:
            syn_no_synack[key] = cnt

    top_syn_targets = syn_per_target.most_common(10)
    top_failed_syn_targets = syn_no_synack.most_common(10)

    return {
        "syn_count": syn_count,
        "syn_ack_count": syn_ack_count,
        "ack_count": ack_count,
        "rst_count": rst_count,
        "top_syn_targets": top_syn_targets,
        "top_failed_syn_targets": top_failed_syn_targets,
    }


# ---------- DNS stats (with robust qname handling) ----------

def _safe_extract_qname(dns) -> Optional[str]:
    """
    Safely extract qname from a DNS layer.

    Returns a string (without trailing dot) or None if not available.
    """
    try:
        qd = dns.qd
    except Exception:
        return None

    if not qd:
        return None

    try:
        raw_qname = getattr(qd, "qname", None)
    except Exception:
        raw_qname = None

    if raw_qname is None:
        return None

    try:
        if isinstance(raw_qname, bytes):
            name = raw_qname.decode(errors="ignore")
        else:
            name = str(raw_qname)
        return name.rstrip(".")
    except Exception:
        return None


def get_dns_health(packets) -> Dict[str, Any]:
    """
    Look at DNS behavior:
    - Total queries, responses
    - NXDOMAIN / error responses
    - Top queried domains
    - Top failed domains
    """
    total_queries = 0
    total_responses = 0
    nxdomain_count = 0
    error_count = 0

    qname_counter = Counter()
    failed_qnames = Counter()

    for p in packets:
        if not p.haslayer(DNS):
            continue

        dns = p[DNS]

        # Queries
        if dns.qr == 0:
            total_queries += 1
            qname = _safe_extract_qname(dns)
            if qname:
                qname_counter[qname] += 1

        # Responses
        if dns.qr == 1:
            total_responses += 1
            rcode = dns.rcode  # 0=NoError, 3=NXDOMAIN, others=error
            qname = _safe_extract_qname(dns)

            if rcode == 3:  # NXDOMAIN
                nxdomain_count += 1
                if qname:
                    failed_qnames[qname] += 1
            elif rcode != 0:
                error_count += 1
                if qname:
                    failed_qnames[qname] += 1

    return {
        "total_queries": total_queries,
        "total_responses": total_responses,
        "nxdomain_count": nxdomain_count,
        "other_error_count": error_count,
        "top_qnames": qname_counter.most_common(10),
        "top_failed_qnames": failed_qnames.most_common(10),
    }


# ---------- Time-series traffic spikes ----------

def get_traffic_timeseries(packets, bin_size_sec: float = 1.0) -> Dict[str, Any]:
    """
    Analyze traffic over time to detect spikes and anomalies.
    
    Returns:
    - Time bins with packet counts and bytes
    - Peak traffic periods
    - Average and max packets/sec
    - Spikes (periods with >2x average rate)
    """
    if not packets:
        return {
            "time_bins": [],
            "avg_pps": 0.0,
            "max_pps": 0.0,
            "spikes": [],
        }
    
    # Get time range
    times = [float(p.time) for p in packets]
    start_time = min(times)
    end_time = max(times)
    duration = end_time - start_time
    
    if duration == 0:
        duration = 0.000001
    
    # Bin packets by time
    bins = defaultdict(lambda: {"packets": 0, "bytes": 0})
    
    for p in packets:
        ts = float(p.time)
        bin_idx = int((ts - start_time) / bin_size_sec)
        bins[bin_idx]["packets"] += 1
        bins[bin_idx]["bytes"] += len(p)
    
    # Convert to list with timestamps
    time_bins = []
    for bin_idx in sorted(bins.keys()):
        bin_start = start_time + (bin_idx * bin_size_sec)
        pps = bins[bin_idx]["packets"] / bin_size_sec
        bps = bins[bin_idx]["bytes"] * 8 / bin_size_sec
        time_bins.append({
            "time_start": round(bin_start, 2),
            "packets": bins[bin_idx]["packets"],
            "bytes": bins[bin_idx]["bytes"],
            "pps": round(pps, 2),
            "bps": round(bps, 2),
        })
    
    # Calculate statistics
    all_pps = [b["pps"] for b in time_bins]
    avg_pps = sum(all_pps) / len(all_pps) if all_pps else 0.0
    max_pps = max(all_pps) if all_pps else 0.0
    
    # Detect spikes (bins with >2x average)
    spike_threshold = avg_pps * 2.0
    spikes = [
        {
            "time_start": b["time_start"],
            "pps": b["pps"],
            "multiplier": round(b["pps"] / avg_pps, 2) if avg_pps > 0 else 0.0,
        }
        for b in time_bins
        if b["pps"] > spike_threshold and avg_pps > 0
    ]
    
    return {
        "duration_sec": round(duration, 2),
        "bin_size_sec": bin_size_sec,
        "total_bins": len(time_bins),
        "time_bins": time_bins[:50],  # Limit to first 50 bins for readability
        "avg_pps": round(avg_pps, 2),
        "max_pps": round(max_pps, 2),
        "spikes": spikes[:20],  # Top 20 spikes
    }


# ---------- ARP analysis ----------

def get_arp_analysis(packets) -> Dict[str, Any]:
    """
    Analyze ARP traffic:
    - Request/response counts
    - Duplicate IP addresses (possible ARP spoofing)
    - Gratuitous ARP
    - Top requested IPs
    - Suspicious patterns
    """
    arp_requests = 0
    arp_responses = 0
    gratuitous_arp = 0
    
    ip_to_mac = defaultdict(set)  # Track which MACs claim which IPs
    requested_ips = Counter()
    mac_to_ips = defaultdict(set)  # Track which IPs a MAC claims
    
    for p in packets:
        if not p.haslayer(ARP):
            continue
        
        arp = p[ARP]
        op = arp.op  # 1 = request, 2 = response
        
        psrc = arp.psrc  # Protocol source (IP)
        pdst = arp.pdst  # Protocol destination (IP)
        hwsrc = arp.hwsrc  # Hardware source (MAC)
        hwdst = arp.hwdst  # Hardware destination (MAC)
        
        if op == 1:  # Request
            arp_requests += 1
            requested_ips[pdst] += 1
        elif op == 2:  # Response
            arp_responses += 1
            ip_to_mac[psrc].add(hwsrc)
            mac_to_ips[hwsrc].add(psrc)
        
        # Gratuitous ARP: source and destination IP are the same
        if psrc == pdst:
            gratuitous_arp += 1
    
    # Find duplicate IPs (multiple MACs claiming same IP)
    duplicate_ips = {
        ip: list(macs) for ip, macs in ip_to_mac.items()
        if len(macs) > 1
    }
    
    # Find MACs claiming multiple IPs (possible proxy/VM)
    multi_ip_macs = {
        mac: list(ips) for mac, ips in mac_to_ips.items()
        if len(ips) > 1
    }
    
    return {
        "arp_requests": arp_requests,
        "arp_responses": arp_responses,
        "gratuitous_arp": gratuitous_arp,
        "top_requested_ips": requested_ips.most_common(10),
        "duplicate_ip_claims": {ip: macs for ip, macs in list(duplicate_ips.items())[:10]},
        "macs_with_multiple_ips": {mac: ips for mac, ips in list(multi_ip_macs.items())[:10]},
        "suspicious_patterns": {
            "possible_arp_spoofing": len(duplicate_ips) > 0,
            "possible_proxy_arp": len(multi_ip_macs) > 0,
        },
    }


# ---------- ICMP analysis ----------

def get_icmp_analysis(packets) -> Dict[str, Any]:
    """
    Analyze ICMP traffic:
    - Type/code breakdown
    - Unreachable messages (network/host/port unreachable)
    - Echo request/response (ping)
    - Time exceeded (TTL expired)
    - Redirect messages
    - Potential ping floods
    """
    icmp_types = Counter()
    icmp_codes = Counter()
    
    echo_requests = 0
    echo_responses = 0
    unreachable = Counter()  # By code
    time_exceeded = 0
    redirects = 0
    
    # Track ping patterns (potential floods)
    ping_sources = Counter()
    ping_targets = Counter()
    
    for p in packets:
        if not p.haslayer(ICMP):
            continue
        
        icmp = p[ICMP]
        icmp_type = icmp.type
        icmp_code = icmp.code
        
        icmp_types[icmp_type] += 1
        icmp_codes[(icmp_type, icmp_code)] += 1
        
        if IP in p:
            ip = p[IP]
            
            # Echo Request (ping)
            if icmp_type == 8:
                echo_requests += 1
                ping_sources[ip.src] += 1
                ping_targets[ip.dst] += 1
            
            # Echo Reply
            elif icmp_type == 0:
                echo_responses += 1
            
            # Destination Unreachable
            elif icmp_type == 3:
                unreachable[icmp_code] += 1
            
            # Time Exceeded (TTL expired)
            elif icmp_type == 11:
                time_exceeded += 1
            
            # Redirect
            elif icmp_type == 5:
                redirects += 1
    
    # ICMP type names (common ones)
    type_names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
    }
    
    # Detect potential ping floods
    ping_flood_threshold = 100  # More than 100 pings from one source
    potential_floods = [
        (src, count) for src, count in ping_sources.most_common(10)
        if count > ping_flood_threshold
    ]
    
    return {
        "total_icmp_packets": sum(icmp_types.values()),
        "type_breakdown": [(t, type_names.get(t, f"Type {t}"), count) 
                          for t, count in icmp_types.most_common(10)],
        "code_breakdown": [(f"Type {t} Code {c}", count) 
                          for (t, c), count in icmp_codes.most_common(10)],
        "echo_requests": echo_requests,
        "echo_responses": echo_responses,
        "unreachable_by_code": dict(unreachable.most_common(10)),
        "time_exceeded": time_exceeded,
        "redirects": redirects,
        "top_ping_sources": ping_sources.most_common(10),
        "top_ping_targets": ping_targets.most_common(10),
        "potential_ping_floods": potential_floods,
    }


# ---------- TLS handshake statistics ----------

def get_tls_handshake_stats(packets) -> Dict[str, Any]:
    """
    Analyze TLS/SSL handshakes:
    - Client Hello count
    - Server Hello count
    - Handshake completion estimation
    - SNI (Server Name Indication) extraction
    - Failed handshakes (Client Hello without Server Hello)
    """
    client_hellos = 0
    server_hellos = 0
    sni_names = Counter()
    
    # Track handshake pairs (by connection)
    client_hello_connections = set()
    server_hello_connections = set()
    
    for p in packets:
        if not p.haslayer(TCP):
            continue
        
        tcp = p[TCP]
        
        # Try to find TLS Client Hello in raw payload
        if Raw in p:
            raw = p[Raw].load
            
            # Client Hello: Look for TLS handshake type 0x01 (Client Hello)
            # TLS record: 0x16 (handshake) 0x03 0x01-0x03 (version) ... 0x01 (Client Hello)
            try:
                if len(raw) > 5 and raw[0] == 0x16:  # TLS handshake record
                    if len(raw) > 5 and raw[5] == 0x01:  # Client Hello
                        client_hellos += 1
                        if IP in p:
                            ip = p[IP]
                            conn_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
                            client_hello_connections.add(conn_key)
                        
                        # Try to extract SNI
                        sni = _extract_sni_from_raw(raw)
                        if sni:
                            sni_names[sni] += 1
                    
                    elif len(raw) > 5 and raw[5] == 0x02:  # Server Hello
                        server_hellos += 1
                        if IP in p:
                            ip = p[IP]
                            conn_key = (ip.dst, ip.src, tcp.dport, tcp.sport)  # Reverse
                            server_hello_connections.add(conn_key)
            except (IndexError, AttributeError):
                pass
    
    # Estimate failed handshakes (Client Hello without corresponding Server Hello)
    failed_handshakes = 0
    for conn_key in client_hello_connections:
        reverse_key = (conn_key[1], conn_key[0], conn_key[3], conn_key[2])
        if reverse_key not in server_hello_connections:
            failed_handshakes += 1
    
    return {
        "client_hellos": client_hellos,
        "server_hellos": server_hellos,
        "estimated_completed_handshakes": min(client_hellos, server_hellos),
        "estimated_failed_handshakes": failed_handshakes,
        "top_sni_names": sni_names.most_common(20),
    }


def _extract_sni_from_raw(raw: bytes) -> Optional[str]:
    """
    Extract Server Name Indication (SNI) from TLS Client Hello raw bytes.
    Follows TLS 1.2/1.3 handshake structure.
    """
    try:
        if len(raw) < 5:
            return None
        
        # TLS Record Header: ContentType (1 byte) + Version (2 bytes) + Length (2 bytes)
        if raw[0] != 0x16:  # Handshake content type
            return None
        
        # Skip TLS record header (5 bytes) to get to handshake message
        offset = 5
        
        if offset >= len(raw):
            return None
        
        # Handshake message type should be 0x01 (Client Hello)
        if raw[offset] != 0x01:
            return None
        
        # Skip handshake message header: Type (1) + Length (3) + Version (2) + Random (32) + SessionID length (1)
        offset += 1 + 3 + 2 + 32 + 1
        
        # Skip SessionID if present
        if offset < len(raw):
            session_id_len = raw[offset]
            offset += 1 + session_id_len
        
        # Skip Cipher Suites length (2 bytes) and cipher suites
        if offset + 2 > len(raw):
            return None
        cipher_suites_len = (raw[offset] << 8) | raw[offset + 1]
        offset += 2 + cipher_suites_len
        
        # Skip Compression Methods length (1 byte) and compression methods
        if offset >= len(raw):
            return None
        compression_len = raw[offset]
        offset += 1 + compression_len
        
        # Now we're at Extensions length (2 bytes)
        if offset + 2 > len(raw):
            return None
        extensions_len = (raw[offset] << 8) | raw[offset + 1]
        offset += 2
        
        extensions_end = offset + extensions_len
        
        # Parse extensions to find SNI (extension type 0x0000)
        while offset + 4 < extensions_end and offset < len(raw):
            ext_type = (raw[offset] << 8) | raw[offset + 1]
            ext_len = (raw[offset + 2] << 8) | raw[offset + 3]
            offset += 4
            
            if ext_type == 0x0000:  # server_name extension
                # Skip ServerNameList length (2 bytes)
                if offset + 2 > len(raw):
                    break
                name_list_len = (raw[offset] << 8) | raw[offset + 1]
                offset += 2
                
                # Parse ServerName entry: NameType (1) + Name length (2) + Name
                if offset + 3 <= len(raw):
                    name_type = raw[offset]
                    name_len = (raw[offset + 1] << 8) | raw[offset + 2]
                    offset += 3
                    
                    if name_type == 0x00 and name_len > 0 and offset + name_len <= len(raw):  # host_name
                        sni_bytes = raw[offset:offset + name_len]
                        try:
                            sni = sni_bytes.decode('utf-8', errors='strict')
                            if len(sni) > 0:
                                return sni
                        except:
                            pass
                    offset += name_len
                break
            
            offset += ext_len
        
    except (IndexError, ValueError, AttributeError):
        pass
    
    return None


# ---------- Application-layer parsing ----------

def get_application_layer_stats(packets) -> Dict[str, Any]:
    """
    Parse application-layer protocols:
    - HTTP: methods, status codes, hosts, user agents
    - DHCP: message types, requested IPs
    - TLS SNI (already in TLS stats, but also here for completeness)
    """
    http_stats = {
        "requests": 0,
        "responses": 0,
        "methods": Counter(),
        "status_codes": Counter(),
        "hosts": Counter(),
        "user_agents": Counter(),
        "paths": Counter(),
    }
    
    dhcp_stats = {
        "total_messages": 0,
        "message_types": Counter(),
        "requested_ips": Counter(),
        "client_macs": Counter(),
    }
    
    for p in packets:
        # HTTP Request
        if HAS_HTTP and p.haslayer(HTTPRequest):
            try:
                http = p[HTTPRequest]
                http_stats["requests"] += 1
                if hasattr(http, 'Method'):
                    method = http.Method.decode('utf-8', errors='ignore') if isinstance(http.Method, bytes) else str(http.Method)
                    http_stats["methods"][method] += 1
                
                if hasattr(http, 'Host') and http.Host:
                    host = http.Host.decode('utf-8', errors='ignore') if isinstance(http.Host, bytes) else str(http.Host)
                    http_stats["hosts"][host] += 1
                
                if hasattr(http, 'Path') and http.Path:
                    path = http.Path.decode('utf-8', errors='ignore') if isinstance(http.Path, bytes) else str(http.Path)
                    http_stats["paths"][path] += 1
                
                if hasattr(http, 'User_Agent') and http.User_Agent:
                    ua = http.User_Agent.decode('utf-8', errors='ignore') if isinstance(http.User_Agent, bytes) else str(http.User_Agent)
                    http_stats["user_agents"][ua] += 1
            except Exception:
                pass
        
        # HTTP Response
        if HAS_HTTP and p.haslayer(HTTPResponse):
            try:
                http = p[HTTPResponse]
                http_stats["responses"] += 1
                if hasattr(http, 'Status_Code') and http.Status_Code:
                    http_stats["status_codes"][http.Status_Code] += 1
            except Exception:
                pass
        
        # DHCP
        if HAS_DHCP and p.haslayer(DHCP):
            try:
                dhcp = p[DHCP]
                dhcp_stats["total_messages"] += 1
                
                # DHCP message type
                if hasattr(dhcp, 'options'):
                    for opt in dhcp.options:
                        if isinstance(opt, tuple) and len(opt) >= 2:
                            if opt[0] == 'message-type':
                                msg_type = opt[1]
                                type_names = {
                                    1: "DHCPDISCOVER",
                                    2: "DHCPOFFER",
                                    3: "DHCPREQUEST",
                                    4: "DHCPDECLINE",
                                    5: "DHCPACK",
                                    6: "DHCPNAK",
                                    7: "DHCPRELEASE",
                                    8: "DHCPINFORM",
                                }
                                type_name = type_names.get(msg_type, f"Type {msg_type}")
                                dhcp_stats["message_types"][type_name] += 1
                            
                            elif opt[0] == 'requested_addr':
                                dhcp_stats["requested_ips"][opt[1]] += 1
                
                # Client MAC
                if p.haslayer(ARP):
                    dhcp_stats["client_macs"][p[ARP].hwsrc] += 1
                elif p.haslayer(Ether):
                    dhcp_stats["client_macs"][p[Ether].src] += 1
            except Exception:
                pass
    
    return {
        "http": {
            "requests": http_stats["requests"],
            "responses": http_stats["responses"],
            "top_methods": http_stats["methods"].most_common(10),
            "top_status_codes": http_stats["status_codes"].most_common(10),
            "top_hosts": http_stats["hosts"].most_common(10),
            "top_paths": http_stats["paths"].most_common(10),
            "top_user_agents": http_stats["user_agents"].most_common(5),
        },
        "dhcp": {
            "total_messages": dhcp_stats["total_messages"],
            "message_type_breakdown": dhcp_stats["message_types"].most_common(10),
            "top_requested_ips": dhcp_stats["requested_ips"].most_common(10),
            "top_client_macs": dhcp_stats["client_macs"].most_common(10),
        },
    }


# ---------- DNS Anomaly Detection (Tunneling, Remoteshell, etc.) ----------

def _is_suspicious_dns_query(qname: str) -> bool:
    """
    Check if a DNS query name looks suspicious (potential tunneling/remoteshell).
    Indicators:
    - Very long domain names (>100 chars)
    - Base64-like patterns (alphanumeric with = padding)
    - Random-looking strings (high entropy)
    - Unusual subdomain patterns
    - Contains suspicious characters
    """
    if not qname or len(qname) < 3:
        return False
    
    # Very long domain names are suspicious (DNS tunneling often uses long subdomains)
    if len(qname) > 100:
        return True
    
    # Check for base64-like patterns (common in DNS tunneling)
    # Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    if len(qname) > 20 and all(c in base64_chars or c == '.' for c in qname):
        # Check if it has base64-like structure (ends with = or has high ratio of base64 chars)
        if qname.endswith('=') or (sum(1 for c in qname if c in base64_chars) / len(qname)) > 0.9:
            return True
    
    # Check for random-looking strings (high entropy)
    # Count unique characters relative to length
    if len(qname) > 30:
        unique_chars = len(set(qname.lower()))
        if unique_chars / len(qname) > 0.7:  # High character diversity
            return True
    
    # Check for unusual patterns: many subdomains or very long subdomains
    parts = qname.split('.')
    if len(parts) > 5:  # Unusually many subdomains
        return True
    
    for part in parts:
        if len(part) > 50:  # Very long subdomain
            return True
    
    return False


def get_dns_anomaly_signals(packets) -> Dict[str, Any]:
    """
    Detect DNS-based malware/tunneling/remoteshell activity:
    - Unusually large DNS payloads (tunneling often uses large TXT records)
    - Suspicious DNS query patterns (base64-like, random strings, unusual lengths)
    - DNS TXT record queries (commonly used for tunneling)
    - High DNS traffic volume
    - DNS queries that look like encoded data rather than domain names
    
    Returns signals that indicate potential DNS-based attacks or tunneling.
    """
    suspicious_queries = []
    large_payload_responses = []
    txt_queries = []
    total_dns_packets = 0
    total_dns_bytes = 0
    
    for p in packets:
        if not p.haslayer(DNS):
            continue
        
        dns = p[DNS]
        total_dns_packets += 1
        total_dns_bytes += len(p)
        
        # Check queries
        if dns.qr == 0:  # Query
            qname = _safe_extract_qname(dns)
            if qname:
                # Check for suspicious query patterns
                if _is_suspicious_dns_query(qname):
                    src_ip = p[IP].src if IP in p else "unknown"
                    dst_ip = p[IP].dst if IP in p else "unknown"
                    timestamp = float(p.time) if hasattr(p, 'time') else 0.0
                    
                    suspicious_queries.append({
                        "qname": qname,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "qname_length": len(qname),
                        "timestamp": round(timestamp, 6),
                    })
                
                # Check for TXT record queries (commonly used for tunneling)
                try:
                    qtype = dns.qd.qtype if hasattr(dns, 'qd') and dns.qd else None
                    if qtype == 16:  # TXT record
                        src_ip = p[IP].src if IP in p else "unknown"
                        dst_ip = p[IP].dst if IP in p else "unknown"
                        timestamp = float(p.time) if hasattr(p, 'time') else 0.0
                        
                        txt_queries.append({
                            "qname": qname,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "timestamp": round(timestamp, 6),
                        })
                except (AttributeError, TypeError):
                    pass
        
        # Check responses for large payloads
        if dns.qr == 1:  # Response
            # Calculate response payload size
            payload_size = 0
            if IP in p:
                ip = p[IP]
                total_size = len(p)
                ip_header_size = (ip.ihl * 4) if hasattr(ip, 'ihl') else 20
                udp_header_size = 8
                payload_size = total_size - ip_header_size - udp_header_size
            
            # DNS responses larger than 512 bytes are suspicious (standard DNS is 512 bytes max, but tunneling uses larger)
            # Also check for TXT records with large data
            if payload_size > 512:
                qname = _safe_extract_qname(dns)
                src_ip = p[IP].src if IP in p else "unknown"
                dst_ip = p[IP].dst if IP in p else "unknown"
                timestamp = float(p.time) if hasattr(p, 'time') else 0.0
                
                large_payload_responses.append({
                    "qname": qname or "unknown",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "payload_size": payload_size,
                    "timestamp": round(timestamp, 6),
                })
    
    # Calculate DNS traffic ratio
    total_packets = len(packets)
    total_bytes = sum(len(p) for p in packets)
    dns_packet_ratio = (total_dns_packets / total_packets * 100) if total_packets > 0 else 0
    dns_byte_ratio = (total_dns_bytes / total_bytes * 100) if total_bytes > 0 else 0
    
    return {
        "suspicious_queries": suspicious_queries[:50],  # Limit to top 50
        "large_payload_responses": large_payload_responses[:50],
        "txt_record_queries": txt_queries[:50],
        "total_dns_packets": total_dns_packets,
        "total_dns_bytes": total_dns_bytes,
        "dns_packet_ratio_percent": round(dns_packet_ratio, 2),
        "dns_byte_ratio_percent": round(dns_byte_ratio, 2),
        "possible_dns_tunneling": len(suspicious_queries) > 0 or len(large_payload_responses) > 0 or len(txt_queries) > 0,
    }


# ---------- IP Fragmentation Anomaly Detection (Teardrop, overlapping fragments, etc.) ----------

def get_ip_fragmentation_anomalies(packets) -> Dict[str, Any]:
    """
    Detect IP fragmentation-based attacks:
    - Teardrop attack: overlapping IP fragments that cannot be reassembled
    - Malformed fragment offsets
    - Fragments with impossible reassembly patterns
    - Unusual fragmentation behavior
    
    Returns signals that indicate potential fragmentation-based DoS attacks.
    """
    fragmented_packets = []
    fragment_groups = defaultdict(list)  # Group by (src, dst, id)
    overlapping_fragments = []
    malformed_fragments = []
    
    for p in packets:
        if not p.haslayer(IP):
            continue
        
        ip = p[IP]
        
        # Check if packet is fragmented
        if ip.flags & 0x1 or ip.frag != 0:  # More fragments flag or fragment offset > 0
            src_ip = ip.src
            dst_ip = ip.dst
            ip_id = ip.id
            frag_offset = ip.frag  # Fragment offset in 8-byte units
            more_frags = bool(ip.flags & 0x1)  # More fragments flag
            payload_size = len(ip.payload) if ip.payload else 0
            
            # Calculate actual byte offset
            byte_offset = frag_offset * 8
            
            fragmented_packets.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ip_id": ip_id,
                "frag_offset": frag_offset,
                "byte_offset": byte_offset,
                "more_frags": more_frags,
                "payload_size": payload_size,
                "total_length": ip.len,
            })
            
            # Group fragments by (src, dst, id) to check for overlaps
            key = (src_ip, dst_ip, ip_id)
            fragment_groups[key].append({
                "frag_offset": frag_offset,
                "byte_offset": byte_offset,
                "more_frags": more_frags,
                "payload_size": payload_size,
                "total_length": ip.len,
            })
    
    # Analyze fragment groups for overlapping fragments (Teardrop attack)
    for key, fragments in fragment_groups.items():
        if len(fragments) < 2:
            continue  # Need at least 2 fragments to have overlaps
        
        # Sort by fragment offset
        sorted_frags = sorted(fragments, key=lambda x: x["frag_offset"])
        
        # Check for overlapping fragments
        for i in range(len(sorted_frags) - 1):
            frag1 = sorted_frags[i]
            frag2 = sorted_frags[i + 1]
            
            # Calculate end position of first fragment
            frag1_start = frag1["byte_offset"]
            frag1_end = frag1_start + frag1["payload_size"]
            frag2_start = frag2["byte_offset"]
            
            # Check for overlap: frag2 starts before frag1 ends
            if frag2_start < frag1_end:
                # This is a Teardrop-style overlapping fragment attack
                src_ip, dst_ip, ip_id = key
                overlapping_fragments.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ip_id": ip_id,
                    "frag1_offset": frag1["frag_offset"],
                    "frag1_byte_offset": frag1_start,
                    "frag1_end": frag1_end,
                    "frag2_offset": frag2["frag_offset"],
                    "frag2_byte_offset": frag2_start,
                    "overlap_size": frag1_end - frag2_start,
                    "attack_type": "Teardrop-like overlapping fragments",
                })
        
        # Check for malformed fragments
        for frag in sorted_frags:
            # Fragment offset beyond reasonable limits (max IP packet size is 65535)
            if frag["byte_offset"] > 65535:
                src_ip, dst_ip, ip_id = key
                malformed_fragments.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ip_id": ip_id,
                    "frag_offset": frag["frag_offset"],
                    "byte_offset": frag["byte_offset"],
                    "issue": "Fragment offset exceeds maximum IP packet size",
                })
            
            # Fragment with more_frags=0 but offset suggests more should follow
            if not frag["more_frags"] and frag["frag_offset"] > 0:
                # Check if there are other fragments with higher offsets
                higher_frags = [f for f in sorted_frags if f["frag_offset"] > frag["frag_offset"]]
                if higher_frags:
                    src_ip, dst_ip, ip_id = key
                    malformed_fragments.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ip_id": ip_id,
                        "frag_offset": frag["frag_offset"],
                        "issue": "Last fragment flag set but higher offset fragments exist",
                    })
    
    # Calculate fragmentation statistics
    total_ip_packets = sum(1 for p in packets if p.haslayer(IP))
    frag_ratio = (len(fragmented_packets) / total_ip_packets * 100) if total_ip_packets > 0 else 0
    
    return {
        "total_fragmented_packets": len(fragmented_packets),
        "fragmentation_ratio_percent": round(frag_ratio, 2),
        "fragment_groups": len(fragment_groups),
        "overlapping_fragments": overlapping_fragments[:50],  # Limit to top 50
        "malformed_fragments": malformed_fragments[:50],
        "possible_teardrop_attack": len(overlapping_fragments) > 0,
        "possible_fragmentation_attack": len(overlapping_fragments) > 0 or len(malformed_fragments) > 0,
    }


# ---------- DNS Exploit Detection (Malformed DNS, buffer overflow attempts, etc.) ----------

def get_dns_exploit_signals(packets) -> Dict[str, Any]:
    """
    Detect DNS-based exploits and attacks:
    - Malformed DNS packets (UDP port 53 that don't parse as valid DNS)
    - DNS packets with unusual structures (potential buffer overflow attempts)
    - DNS packets with suspiciously large fields
    - DNS packets that might be exploit attempts
    
    Returns signals that indicate potential DNS exploits or attacks.
    """
    malformed_dns_packets = []
    suspicious_dns_packets = []
    port_53_udp_count = 0
    valid_dns_count = 0
    
    for p in packets:
        if not p.haslayer(UDP):
            continue
        
        udp = p[UDP]
        
        # Check for UDP packets on port 53 (DNS port)
        if udp.dport == 53 or udp.sport == 53:
            port_53_udp_count += 1
            
            # Check if it has a DNS layer (valid DNS packet)
            has_dns_layer = p.haslayer(DNS)
            
            if has_dns_layer:
                valid_dns_count += 1
                dns = p[DNS]
                
                # Check for suspicious DNS structures
                suspicious = False
                issues = []
                
                try:
                    # Check for unusually large DNS packet
                    if IP in p:
                        ip = p[IP]
                        if ip.len > 512:  # Standard DNS is max 512 bytes (UDP), larger might be suspicious
                            suspicious = True
                            issues.append(f"Large DNS packet ({ip.len} bytes, standard max is 512)")
                    
                    # Check for malformed DNS structure
                    if hasattr(dns, 'qd') and dns.qd:
                        try:
                            qname = _safe_extract_qname(dns)
                            if qname and len(qname) > 255:  # DNS name max is 255 chars
                                suspicious = True
                                issues.append(f"Excessively long DNS name ({len(qname)} chars)")
                        except Exception:
                            suspicious = True
                            issues.append("Error extracting DNS query name")
                    
                    # Check for unusual DNS flags or opcodes
                    if hasattr(dns, 'opcode') and dns.opcode not in [0, 1, 2]:  # Standard opcodes: 0=query, 1=inverse, 2=status
                        suspicious = True
                        issues.append(f"Unusual DNS opcode ({dns.opcode})")
                    
                    # Check for unusually high record counts (potential buffer overflow)
                    if hasattr(dns, 'qdcount') and dns.qdcount > 1:
                        suspicious = True
                        issues.append(f"Multiple questions in DNS packet ({dns.qdcount})")
                    if hasattr(dns, 'ancount') and dns.ancount > 100:
                        suspicious = True
                        issues.append(f"Unusually high answer count ({dns.ancount})")
                    if hasattr(dns, 'nscount') and dns.nscount > 100:
                        suspicious = True
                        issues.append(f"Unusually high authority count ({dns.nscount})")
                    if hasattr(dns, 'arcount') and dns.arcount > 100:
                        suspicious = True
                        issues.append(f"Unusually high additional count ({dns.arcount})")
                    
                except (AttributeError, TypeError, Exception) as e:
                    suspicious = True
                    issues.append(f"Error parsing DNS structure: {str(e)}")
                
                if suspicious:
                    src_ip = p[IP].src if IP in p else "unknown"
                    dst_ip = p[IP].dst if IP in p else "unknown"
                    timestamp = float(p.time) if hasattr(p, 'time') else 0.0
                    
                    suspicious_dns_packets.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "sport": udp.sport,
                        "dport": udp.dport,
                        "issues": issues,
                        "timestamp": round(timestamp, 6),
                    })
            
            else:
                # UDP packet on port 53 but no DNS layer - this is suspicious!
                # Could be a malformed DNS packet or exploit attempt
                src_ip = p[IP].src if IP in p else "unknown"
                dst_ip = p[IP].dst if IP in p else "unknown"
                timestamp = float(p.time) if hasattr(p, 'time') else 0.0
                
                # Get payload size
                payload_size = 0
                if Raw in p:
                    payload_size = len(p[Raw].load)
                elif IP in p:
                    ip = p[IP]
                    total_size = len(p)
                    ip_header_size = (ip.ihl * 4) if hasattr(ip, 'ihl') else 20
                    udp_header_size = 8
                    payload_size = total_size - ip_header_size - udp_header_size
                
                malformed_dns_packets.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sport": udp.sport,
                    "dport": udp.dport,
                    "payload_size": payload_size,
                    "timestamp": round(timestamp, 6),
                    "issue": "UDP packet on port 53 (DNS) but does not parse as valid DNS",
                })
    
    # Calculate ratio of malformed to valid DNS
    malformed_ratio = (len(malformed_dns_packets) / port_53_udp_count * 100) if port_53_udp_count > 0 else 0
    
    return {
        "port_53_udp_packets": port_53_udp_count,
        "valid_dns_packets": valid_dns_count,
        "malformed_dns_packets": malformed_dns_packets[:50],  # Limit to top 50
        "suspicious_dns_packets": suspicious_dns_packets[:50],
        "malformed_ratio_percent": round(malformed_ratio, 2),
        "possible_dns_exploit": len(malformed_dns_packets) > 0 or len(suspicious_dns_packets) > 0,
    }


# ---------- Transport Port Profiling ----------

def get_port_profiling(packets) -> Dict[str, Any]:
    """
    Profile transport ports to identify:
    - What services are active
    - Unusual port usage
    - High-risk ports (e.g., 445 SMB, 1900 SSDP amplification, etc.)
    - Port distribution patterns
    """
    tcp_ports = Counter()
    udp_ports = Counter()
    port_protocols = defaultdict(set)
    
    # Well-known port mappings
    well_known_ports = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 88: "Kerberos", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1434: "MSSQL-Resolution", 1900: "SSDP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
    }
    
    # High-risk ports for security analysis
    high_risk_ports = {445, 1433, 1434, 135, 139, 3389, 1900, 5353}  # SMB, SQL, RDP, SSDP, mDNS
    
    for p in packets:
        if not p.haslayer(IP):
            continue
        
        if TCP in p:
            tcp = p[TCP]
            sport = tcp.sport
            dport = tcp.dport
            tcp_ports[sport] += 1
            tcp_ports[dport] += 1
            port_protocols[sport].add("TCP")
            port_protocols[dport].add("TCP")
        elif UDP in p:
            udp = p[UDP]
            sport = udp.sport
            dport = udp.dport
            udp_ports[sport] += 1
            udp_ports[dport] += 1
            port_protocols[sport].add("UDP")
            port_protocols[dport].add("UDP")
    
    # Identify active services
    active_services = []
    for port, count in (tcp_ports + udp_ports).most_common(20):
        service = well_known_ports.get(port, f"Port-{port}")
        is_high_risk = port in high_risk_ports
        protocols = list(port_protocols.get(port, set()))
        active_services.append({
            "port": port,
            "service": service,
            "packet_count": count,
            "protocols": protocols,
            "is_high_risk": is_high_risk,
        })
    
    # Count high-risk port usage
    high_risk_usage = sum(count for port, count in (tcp_ports + udp_ports).items() if port in high_risk_ports)
    
    return {
        "top_tcp_ports": tcp_ports.most_common(20),
        "top_udp_ports": udp_ports.most_common(20),
        "active_services": active_services,
        "high_risk_port_count": high_risk_usage,
        "total_unique_ports": len(set(tcp_ports.keys()) | set(udp_ports.keys())),
    }


# ---------- Packet Size Distribution ----------

def get_packet_size_distribution(packets) -> Dict[str, Any]:
    """
    Analyze packet size distribution to detect:
    - Fragmentation patterns
    - Jumbo frames
    - Tiny-packet floods
    - Exfiltration patterns (many small packets vs few big packets)
    """
    packet_sizes = []
    ip_packet_sizes = []
    
    size_buckets = {
        "tiny": 0,      # < 64 bytes
        "small": 0,      # 64-128 bytes
        "medium": 0,    # 128-512 bytes
        "large": 0,     # 512-1500 bytes
        "jumbo": 0,     # > 1500 bytes
    }
    
    for p in packets:
        size = len(p)
        packet_sizes.append(size)
        
        if IP in p:
            ip_size = p[IP].len if hasattr(p[IP], 'len') else size
            ip_packet_sizes.append(ip_size)
        
        # Categorize
        if size < 64:
            size_buckets["tiny"] += 1
        elif size < 128:
            size_buckets["small"] += 1
        elif size < 512:
            size_buckets["medium"] += 1
        elif size < 1500:
            size_buckets["large"] += 1
        else:
            size_buckets["jumbo"] += 1
    
    if not packet_sizes:
        return {
            "total_packets": 0,
            "size_buckets": size_buckets,
            "avg_size": 0,
            "min_size": 0,
            "max_size": 0,
            "median_size": 0,
        }
    
    packet_sizes.sort()
    avg_size = sum(packet_sizes) / len(packet_sizes)
    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    median_size = packet_sizes[len(packet_sizes) // 2]
    
    # Check for suspicious patterns
    tiny_packet_ratio = size_buckets["tiny"] / len(packet_sizes) * 100 if packet_sizes else 0
    jumbo_frame_count = size_buckets["jumbo"]
    
    return {
        "total_packets": len(packet_sizes),
        "size_buckets": size_buckets,
        "avg_size": round(avg_size, 2),
        "min_size": min_size,
        "max_size": max_size,
        "median_size": median_size,
        "tiny_packet_ratio_percent": round(tiny_packet_ratio, 2),
        "jumbo_frame_count": jumbo_frame_count,
        "possible_tiny_packet_flood": tiny_packet_ratio > 50,  # More than 50% tiny packets
        "possible_exfiltration_pattern": tiny_packet_ratio > 30 and len(packet_sizes) > 1000,
    }


# ---------- Conversation Matrix (IP → IP matrix) ----------

def get_conversation_matrix(packets) -> Dict[str, Any]:
    """
    Build IP-to-IP conversation matrix to detect:
    - Fan-out patterns (worm/spread)
    - Fan-in patterns (DDoS target)
    - Unusual communication pairs
    - Communication asymmetry
    """
    conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
    src_fanout = Counter()  # How many destinations per source
    dst_fanin = Counter()   # How many sources per destination
    
    for p in packets:
        if not p.haslayer(IP):
            continue
        
        ip = p[IP]
        src = ip.src
        dst = ip.dst
        
        # Normalize pair (always use smaller IP first for consistency)
        pair = tuple(sorted([src, dst]))
        conversations[pair]["packets"] += 1
        conversations[pair]["bytes"] += len(p)
        
        # Track fan-out and fan-in
        src_fanout[src] += 1
        dst_fanin[dst] += 1
    
    # Find top conversations
    top_conversations = sorted(
        [(pair, data) for pair, data in conversations.items()],
        key=lambda x: x[1]["packets"],
        reverse=True
    )[:20]
    
    # Detect suspicious patterns
    high_fanout_sources = [(src, count) for src, count in src_fanout.most_common(20) if count > 10]
    high_fanin_targets = [(dst, count) for dst, count in dst_fanin.most_common(20) if count > 10]
    
    return {
        "total_conversations": len(conversations),
        "top_conversations": [
            {
                "src": pair[0],
                "dst": pair[1],
                "packets": data["packets"],
                "bytes": data["bytes"],
            }
            for pair, data in top_conversations
        ],
        "high_fanout_sources": high_fanout_sources,  # Potential worm/spread
        "high_fanin_targets": high_fanin_targets,    # Potential DDoS targets
        "possible_worm_activity": len([s for s, c in high_fanout_sources if c > 50]) > 0,
        "possible_ddos_target": len([d for d, c in high_fanin_targets if c > 50]) > 0,
    }


# ---------- Round Trip Time (TCP-based) ----------

def get_tcp_rtt_stats(packets) -> Dict[str, Any]:
    """
    Calculate TCP Round Trip Time (RTT) to detect:
    - Slow servers
    - Network congestion
    - Asymmetry
    - Latency issues
    """
    # Track SYN-SYNACK pairs for RTT estimation
    syn_times = {}  # (src, dst, sport, dport) -> timestamp
    rtt_samples = []
    
    for p in packets:
        if not p.haslayer(TCP) or not p.haslayer(IP):
            continue
        
        ip = p[IP]
        tcp = p[TCP]
        flags = tcp.flags
        timestamp = float(p.time)
        
        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        reverse_key = (ip.dst, ip.src, tcp.dport, tcp.sport)
        
        # SYN (no ACK)
        if flags & 0x02 and not (flags & 0x10):
            syn_times[key] = timestamp
        
        # SYN-ACK
        if (flags & 0x12) == 0x12:  # SYN + ACK
            if reverse_key in syn_times:
                syn_time = syn_times[reverse_key]
                rtt = timestamp - syn_time
                if rtt > 0 and rtt < 10:  # Sanity check: RTT should be positive and < 10 seconds
                    rtt_samples.append({
                        "src": ip.dst,
                        "dst": ip.src,
                        "sport": tcp.dport,
                        "dport": tcp.sport,
                        "rtt_ms": round(rtt * 1000, 2),
                    })
                del syn_times[reverse_key]
    
    if not rtt_samples:
        return {
            "rtt_samples": [],
            "avg_rtt_ms": 0,
            "min_rtt_ms": 0,
            "max_rtt_ms": 0,
            "median_rtt_ms": 0,
            "high_latency_count": 0,
        }
    
    rtt_values = [s["rtt_ms"] for s in rtt_samples]
    rtt_values.sort()
    
    avg_rtt = sum(rtt_values) / len(rtt_values)
    min_rtt = min(rtt_values)
    max_rtt = max(rtt_values)
    median_rtt = rtt_values[len(rtt_values) // 2]
    
    # Flag high latency (RTT > 100ms is often considered high for LAN)
    high_latency_count = sum(1 for rtt in rtt_values if rtt > 100)
    
    return {
        "rtt_samples": rtt_samples[:50],  # Limit to top 50
        "total_samples": len(rtt_samples),
        "avg_rtt_ms": round(avg_rtt, 2),
        "min_rtt_ms": round(min_rtt, 2),
        "max_rtt_ms": round(max_rtt, 2),
        "median_rtt_ms": round(median_rtt, 2),
        "high_latency_count": high_latency_count,
        "possible_congestion": avg_rtt > 100 or high_latency_count > len(rtt_samples) * 0.1,
    }


# ---------- Entropy / Unusual Payload Heuristics ----------

def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data or len(data) == 0:
        return 0.0
    
    # Count byte frequencies
    byte_counts = Counter(data)
    data_len = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def get_payload_entropy_stats(packets) -> Dict[str, Any]:
    """
    Analyze payload entropy to detect:
    - Encrypted vs plaintext
    - Compressed data
    - Suspicious binary blobs
    - Malware-like payload structures
    """
    entropy_samples = []
    high_entropy_packets = []
    low_entropy_packets = []
    
    for p in packets:
        if not p.haslayer(Raw):
            continue
        
        raw = p[Raw]
        payload = raw.load
        
        if len(payload) < 16:  # Skip very small payloads
            continue
        
        entropy = _calculate_entropy(payload)
        
        src_ip = p[IP].src if IP in p else "unknown"
        dst_ip = p[IP].dst if IP in p else "unknown"
        sport = dport = None
        
        if TCP in p:
            sport = p[TCP].sport
            dport = p[TCP].dport
        elif UDP in p:
            sport = p[UDP].sport
            dport = p[UDP].dport
        
        sample = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "sport": sport,
            "dport": dport,
            "payload_size": len(payload),
            "entropy": round(entropy, 2),
        }
        
        entropy_samples.append(sample)
        
        # Categorize
        # High entropy (>7.5) suggests encryption/compression/random data
        # Low entropy (<4.0) suggests plaintext/structured data
        if entropy > 7.5:
            high_entropy_packets.append(sample)
        elif entropy < 4.0:
            low_entropy_packets.append(sample)
    
    if not entropy_samples:
        return {
            "total_samples": 0,
            "avg_entropy": 0,
            "high_entropy_count": 0,
            "low_entropy_count": 0,
            "possible_encrypted_traffic": False,
        }
    
    avg_entropy = sum(s["entropy"] for s in entropy_samples) / len(entropy_samples)
    
    # High entropy ratio suggests encrypted/compressed traffic
    high_entropy_ratio = len(high_entropy_packets) / len(entropy_samples) * 100
    
    return {
        "total_samples": len(entropy_samples),
        "avg_entropy": round(avg_entropy, 2),
        "high_entropy_count": len(high_entropy_packets),
        "low_entropy_count": len(low_entropy_packets),
        "high_entropy_ratio_percent": round(high_entropy_ratio, 2),
        "high_entropy_samples": high_entropy_packets[:20],  # Top 20
        "low_entropy_samples": low_entropy_packets[:20],
        "possible_encrypted_traffic": high_entropy_ratio > 50,  # More than 50% high entropy
        "possible_plaintext_traffic": len(low_entropy_packets) > len(high_entropy_packets),
    }


# ---------- Threat Heuristics (20-25 Lightweight Mini-Signatures) ----------

def get_threat_heuristics(packets) -> Dict[str, Any]:
    """
    Detect common threat patterns using lightweight heuristics:
    - Worms (Code Red, Nimda, Conficker)
    - Scanning patterns (Nmap, UDP scan, ICMP ping sweep)
    - DDoS patterns (UDP flood, DNS/SSDP amplification)
    - C2 patterns (periodic beacons, high entropy)
    - Misconfiguration (ARP storms, DHCP starvation, broadcast storms, looping)
    - Lateral movement (SMB/RDP/MySQL brute force)
    - Data exfiltration patterns
    - IoT anomalies
    """
    results = {
        "worms": {},
        "scanning": {},
        "ddos": {},
        "c2_patterns": {},
        "misconfiguration": {},
        "lateral_movement": {},
        "exfiltration": {},
        "iot_anomalies": {},
    }
    
    # Track various patterns
    http_requests = []
    tcp_445_syns = []
    tcp_3389_syns = []
    tcp_3306_syns = []
    udp_ports_scanned = defaultdict(set)
    icmp_echo_targets = Counter()
    dns_responses = []
    ssdp_responses = []
    periodic_beacons = defaultdict(list)
    dhcp_discovers = []
    arp_requests = Counter()
    packet_signatures = defaultdict(list)  # For loop detection
    slammer_candidates = []  # SQL Slammer detection
    
    # Track flows for exfiltration detection
    outbound_flows = []
    
    for p in packets:
        if not p.haslayer(IP):
            continue
        
        ip = p[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = float(p.time) if hasattr(p, 'time') else 0.0
        
        # (0) SQL Slammer: UDP port 1434 with ~376 byte payloads
        if UDP in p:
            udp = p[UDP]
            if udp.dport == 1434 or udp.sport == 1434:
                # Get payload size
                payload_size = 0
                if Raw in p:
                    payload_size = len(p[Raw].load)
                elif IP in p:
                    total_size = len(p)
                    ip_header_size = (ip.ihl * 4) if hasattr(ip, 'ihl') else 20
                    udp_header_size = 8
                    payload_size = total_size - ip_header_size - udp_header_size
                
                if payload_size > 0:
                    # Flag if payload is around 376 bytes (Slammer) or suspicious size
                    if 350 <= payload_size <= 400:
                        slammer_candidates.append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "sport": udp.sport,
                            "dport": udp.dport,
                            "payload_size": payload_size,
                            "timestamp": round(timestamp, 6),
                            "confidence": "high" if payload_size == 376 else "medium",
                        })
                    elif payload_size > 0:
                        slammer_candidates.append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "sport": udp.sport,
                            "dport": udp.dport,
                            "payload_size": payload_size,
                            "timestamp": round(timestamp, 6),
                            "confidence": "low",
                        })
        
        # (1) Code Red: HTTP GET /default.ida? with long "N" pattern
        if HAS_HTTP and p.haslayer(HTTPRequest):
            try:
                http = p[HTTPRequest]
                if hasattr(http, 'Path') and http.Path:
                    path = http.Path.decode('utf-8', errors='ignore') if isinstance(http.Path, bytes) else str(http.Path)
                    if '/default.ida?' in path.lower() or '/default.ida' in path.lower():
                        results["worms"]["code_red_detected"] = True
                        results["worms"]["code_red_requests"] = results["worms"].get("code_red_requests", [])
                        results["worms"]["code_red_requests"].append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "path": path[:200],  # Limit length
                            "timestamp": round(timestamp, 6),
                        })
            except:
                pass
        
        # (2) Nimda: HTTP patterns with cmd.exe, .printer, long URLs
        if HAS_HTTP and p.haslayer(HTTPRequest):
            try:
                http = p[HTTPRequest]
                path = ""
                if hasattr(http, 'Path') and http.Path:
                    path = http.Path.decode('utf-8', errors='ignore') if isinstance(http.Path, bytes) else str(http.Path)
                
                if any(pattern in path.lower() for pattern in ['cmd.exe', '.printer', 'root.exe']) or len(path) > 200:
                    results["worms"]["nimda_detected"] = True
                    results["worms"]["nimda_requests"] = results["worms"].get("nimda_requests", [])
                    results["worms"]["nimda_requests"].append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "path": path[:200],
                        "timestamp": round(timestamp, 6),
                    })
            except:
                pass
        
        # (3) Conficker: TCP 445 scan pattern (many SYNs to port 445)
        if TCP in p:
            tcp = p[TCP]
            flags = tcp.flags
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                if tcp.dport == 445:  # SMB
                    tcp_445_syns.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": round(timestamp, 6),
                    })
                elif tcp.dport == 3389:  # RDP
                    tcp_3389_syns.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": round(timestamp, 6),
                    })
                elif tcp.dport == 3306:  # MySQL
                    tcp_3306_syns.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": round(timestamp, 6),
                    })
        
        # (4) Nmap SYN scan: Many distinct ports, 1 SYN each, no follow-up
        # Tracked via TCP handshake stats (already have this)
        
        # (5) UDP scan: 1 UDP packet per port, short payloads
        if UDP in p:
            udp = p[UDP]
            if udp.dport > 1024:  # Ephemeral ports
                udp_ports_scanned[src_ip].add(udp.dport)
        
        # (6) ICMP ping sweep: ICMP Echo Requests to sequential hosts
        if ICMP in p:
            icmp = p[ICMP]
            if icmp.type == 8:  # Echo Request
                icmp_echo_targets[dst_ip] += 1
        
        # (7) DNS amplification: Large DNS response packets (already in dns_anomaly_signals)
        if p.haslayer(DNS):
            dns = p[DNS]
            if dns.qr == 1:  # Response
                if IP in p:
                    response_size = p[IP].len
                    if response_size > 512:
                        dns_responses.append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "size": response_size,
                            "timestamp": round(timestamp, 6),
                        })
        
        # (8) SSDP amplification: Many responses from port 1900
        if UDP in p:
            udp = p[UDP]
            if udp.sport == 1900 or udp.dport == 1900:
                ssdp_responses.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "timestamp": round(timestamp, 6),
                })
        
        # (9) Periodic beacons: Repeated small periodic beacons (same size, same IP, regular intervals)
        if IP in p and (TCP in p or UDP in p):
            key = (src_ip, dst_ip)
            size = len(p)
            periodic_beacons[key].append({
                "timestamp": timestamp,
                "size": size,
            })
        
        # (10) DHCP starvation: Many DHCP DISCOVER from random MACs
        if HAS_DHCP and p.haslayer(DHCP):
            try:
                dhcp = p[DHCP]
                for opt in dhcp.options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type' and opt[1] == 1:  # DISCOVER
                        dhcp_discovers.append({
                            "src_ip": src_ip,
                            "timestamp": round(timestamp, 6),
                        })
            except:
                pass
        
        # (11) ARP storms: Many ARP who-has for same IP
        if ARP in p:
            arp = p[ARP]
            if arp.op == 1:  # Request
                arp_requests[arp.pdst] += 1
        
        # (12) Looping traffic: Same packets repeating over time
        # Create signature from packet characteristics
        if IP in p:
            sig = f"{src_ip}:{dst_ip}:{len(p)}"
            packet_signatures[sig].append(timestamp)
        
        # (13) Large outbound flows to unknown IPs (for exfiltration)
        if IP in p:
            # This will be analyzed after collecting all packets
            pass
    
    # Analyze patterns
    
    # SQL Slammer: UDP 1434 with characteristic payload size
    if len(slammer_candidates) > 0:
        results["worms"]["slammer_detected"] = True
        results["worms"]["slammer_candidates"] = slammer_candidates[:50]  # Limit to 50
        results["worms"]["slammer_count"] = len([c for c in slammer_candidates if c["confidence"] in ["high", "medium"]])
        results["worms"]["udp_1434_total"] = len(slammer_candidates)
    
    # Conficker: Many SYNs to 445
    if len(tcp_445_syns) > 10:
        results["worms"]["conficker_detected"] = True
        results["worms"]["conficker_syn_count"] = len(tcp_445_syns)
        results["worms"]["conficker_sources"] = Counter(s["src_ip"] for s in tcp_445_syns).most_common(10)
    
    # UDP scan: Many distinct ports from same source
    for src, ports in udp_ports_scanned.items():
        if len(ports) > 20:  # Scanned more than 20 ports
            results["scanning"]["udp_scan_detected"] = True
            results["scanning"]["udp_scan_sources"] = results["scanning"].get("udp_scan_sources", [])
            results["scanning"]["udp_scan_sources"].append({
                "src_ip": src,
                "ports_scanned": len(ports),
            })
    
    # ICMP ping sweep: Many echo requests to different targets
    if len(icmp_echo_targets) > 10:
        results["scanning"]["icmp_ping_sweep_detected"] = True
        results["scanning"]["icmp_targets_count"] = len(icmp_echo_targets)
    
    # DNS amplification: Many large responses
    if len(dns_responses) > 10:
        large_dns_count = sum(1 for r in dns_responses if r["size"] > 512)
        if large_dns_count > 5:
            results["ddos"]["dns_amplification_detected"] = True
            results["ddos"]["dns_amplification_count"] = large_dns_count
    
    # SSDP amplification: Many SSDP responses
    if len(ssdp_responses) > 50:
        results["ddos"]["ssdp_amplification_detected"] = True
        results["ddos"]["ssdp_response_count"] = len(ssdp_responses)
    
    # Periodic beacons: Check for regular intervals
    for key, beacons in periodic_beacons.items():
        if len(beacons) >= 5:  # At least 5 beacons
            beacons.sort(key=lambda x: x["timestamp"])
            sizes = [b["size"] for b in beacons]
            # Check if sizes are consistent (within 10% variance)
            if sizes and (max(sizes) - min(sizes)) / max(sizes) < 0.1:
                # Check intervals
                intervals = [beacons[i+1]["timestamp"] - beacons[i]["timestamp"] for i in range(len(beacons)-1)]
                if intervals and (max(intervals) - min(intervals)) / max(intervals) < 0.2:  # Regular intervals
                    results["c2_patterns"]["periodic_beacons_detected"] = True
                    results["c2_patterns"]["beacon_flows"] = results["c2_patterns"].get("beacon_flows", [])
                    results["c2_patterns"]["beacon_flows"].append({
                        "src_ip": key[0],
                        "dst_ip": key[1],
                        "beacon_count": len(beacons),
                        "interval_sec": round(sum(intervals) / len(intervals), 2),
                        "packet_size": sizes[0],
                    })
    
    # DHCP starvation: Many DISCOVERs
    if len(dhcp_discovers) > 20:
        unique_sources = len(set(d["src_ip"] for d in dhcp_discovers))
        if unique_sources > 10:
            results["misconfiguration"]["dhcp_starvation_detected"] = True
            results["misconfiguration"]["dhcp_discovers"] = len(dhcp_discovers)
    
    # ARP storms: Many requests for same IP
    for ip, count in arp_requests.most_common(10):
        if count > 50:
            results["misconfiguration"]["arp_storm_detected"] = True
            results["misconfiguration"]["arp_storm_targets"] = results["misconfiguration"].get("arp_storm_targets", [])
            results["misconfiguration"]["arp_storm_targets"].append({
                "target_ip": ip,
                "request_count": count,
            })
    
    # Looping traffic: Same signature repeating
    for sig, timestamps in packet_signatures.items():
        if len(timestamps) > 10:
            timestamps.sort()
            # Check if timestamps are very close (within 1 second)
            if all(timestamps[i+1] - timestamps[i] < 1.0 for i in range(len(timestamps)-1)):
                results["misconfiguration"]["looping_traffic_detected"] = True
                results["misconfiguration"]["looping_signatures"] = results["misconfiguration"].get("looping_signatures", [])
                results["misconfiguration"]["looping_signatures"].append({
                    "signature": sig,
                    "repeat_count": len(timestamps),
                })
    
    # SMB probing: Failed connections to 445
    if len(tcp_445_syns) > 10:
        results["lateral_movement"]["smb_probing_detected"] = True
        results["lateral_movement"]["smb_syn_count"] = len(tcp_445_syns)
        results["lateral_movement"]["smb_targets"] = Counter(s["dst_ip"] for s in tcp_445_syns).most_common(10)
    
    # RDP brute force: Many failed connections to 3389
    if len(tcp_3389_syns) > 10:
        results["lateral_movement"]["rdp_brute_force_detected"] = True
        results["lateral_movement"]["rdp_syn_count"] = len(tcp_3389_syns)
        results["lateral_movement"]["rdp_targets"] = Counter(s["dst_ip"] for s in tcp_3389_syns).most_common(10)
    
    # MySQL brute force: Many failed connections to 3306
    if len(tcp_3306_syns) > 10:
        results["lateral_movement"]["mysql_brute_force_detected"] = True
        results["lateral_movement"]["mysql_syn_count"] = len(tcp_3306_syns)
        results["lateral_movement"]["mysql_targets"] = Counter(s["dst_ip"] for s in tcp_3306_syns).most_common(10)
    
    # MQTT over unusual ports (not 1883, 8883) - check during main loop
    mqtt_ports = {1883, 8883}
    mqtt_unusual_ports = set()
    
    # Re-iterate for MQTT detection (could be optimized but keeping simple)
    for p in packets:
        if TCP in p and Raw in p:
            tcp = p[TCP]
            if tcp.dport not in mqtt_ports:
                try:
                    payload = p[Raw].load[:10]
                    if len(payload) > 0 and (b'MQTT' in payload or (len(payload) > 0 and payload[0] == 0x10)):
                        mqtt_unusual_ports.add(tcp.dport)
                except:
                    pass
    
    if mqtt_unusual_ports:
        results["iot_anomalies"]["mqtt_unusual_port_detected"] = True
        results["iot_anomalies"]["mqtt_ports"] = list(mqtt_unusual_ports)
    
    # Limit lists to prevent huge outputs and convert sets to lists
    for category in results:
        for key in list(results[category].keys()):
            value = results[category][key]
            if isinstance(value, list) and len(value) > 20:
                results[category][key] = value[:20]
            elif isinstance(value, set):
                results[category][key] = list(value)
            elif isinstance(value, tuple):
                results[category][key] = list(value)
    
    return results


# ---------- Suricata Integration ----------

def get_suricata_alerts(pcap_path: str) -> Dict[str, Any]:
    """
    Run Suricata on a PCAP file and parse the alerts.
    Returns structured alert information for LLM analysis.
    
    Suricata command: suricata -r <pcap_file> -l <log_dir>
    Alerts are in: <log_dir>/eve.json
    """
    results = {
        "suricata_available": False,
        "alerts": [],
        "alert_count": 0,
        "alert_categories": {},
        "alert_severities": {},
        "top_alert_signatures": [],
        "error": None,
    }
    
    # Check if Suricata is available (Suricata doesn't support --version, use -V instead)
    try:
        subprocess.run(["suricata", "-V"], 
                      capture_output=True, 
                      timeout=5,
                      check=True)
        results["suricata_available"] = True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        results["error"] = "Suricata not found or not accessible. Install Suricata to enable IDS analysis."
        return results
    
    # Create temporary directory for Suricata logs
    try:
        with tempfile.TemporaryDirectory() as log_dir:
            # Run Suricata on the PCAP file
            try:
                cmd = [
                    "suricata",
                    "-r", pcap_path,
                    "-l", log_dir,
                    "--set", "logging.outputs.0.eve-log.enabled=yes",
                    "--set", "logging.outputs.0.eve-log.filetype=json",
                    "--set", "logging.outputs.0.eve-log.filename=eve.json",
                ]
                
                # Run Suricata (non-blocking, capture output)
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=300,  # 5 minute timeout
                    text=True,
                )
                
                # Check for eve.json file
                eve_json_path = Path(log_dir) / "eve.json"
                
                if not eve_json_path.exists():
                    results["error"] = "Suricata ran but no alerts file generated (eve.json not found)."
                    return results
                
                # Parse eve.json (it's JSONL format - one JSON object per line)
                alerts = []
                try:
                    with open(eve_json_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                event = json.loads(line)
                                # Only process alert events
                                if event.get("event_type") == "alert":
                                    alerts.append(event)
                            except json.JSONDecodeError:
                                continue
                except IOError as e:
                    results["error"] = f"Failed to read Suricata alerts file: {str(e)}"
                    return results
                
                # Process alerts
                alert_categories = Counter()
                alert_severities = Counter()
                alert_signatures = Counter()
                
                for alert in alerts:
                    # Extract alert information
                    alert_info = alert.get("alert", {})
                    signature = alert_info.get("signature", "Unknown")
                    category = alert_info.get("category", "Unknown")
                    severity = alert_info.get("severity", 0)
                    
                    # Extract flow information
                    flow_info = {}
                    if "src_ip" in alert:
                        flow_info["src_ip"] = alert["src_ip"]
                    if "dest_ip" in alert:
                        flow_info["dest_ip"] = alert["dest_ip"]
                    if "src_port" in alert:
                        flow_info["src_port"] = alert["src_port"]
                    if "dest_port" in alert:
                        flow_info["dest_port"] = alert["dest_port"]
                    
                    # Extract protocol
                    protocol = alert.get("proto", "Unknown")
                    
                    alert_categories[category] += 1
                    alert_severities[severity] += 1
                    alert_signatures[signature] += 1
                    
                    results["alerts"].append({
                        "signature": signature,
                        "category": category,
                        "severity": severity,
                        "protocol": protocol,
                        "timestamp": alert.get("timestamp", ""),
                        **flow_info,
                    })
                
                # Limit alerts to prevent huge output
                if len(results["alerts"]) > 100:
                    results["alerts"] = results["alerts"][:100]
                
                results["alert_count"] = len(alerts)
                results["alert_categories"] = dict(alert_categories.most_common(10))
                results["alert_severities"] = dict(alert_severities)
                results["top_alert_signatures"] = alert_signatures.most_common(20)
                
            except subprocess.TimeoutExpired:
                results["error"] = "Suricata analysis timed out (exceeded 5 minutes)."
            except subprocess.CalledProcessError as e:
                results["error"] = f"Suricata execution failed: {e.stderr if e.stderr else str(e)}"
            except Exception as e:
                results["error"] = f"Unexpected error running Suricata: {str(e)}"
    
    except Exception as e:
        results["error"] = f"Failed to set up Suricata analysis: {str(e)}"
    
    return results


# ---------- Snort Integration ----------

def get_snort_alerts(pcap_path: str) -> Dict[str, Any]:
    """
    Run Snort on a PCAP file and parse the alerts.
    Returns structured alert information for LLM analysis.
    
    Snort command: snort -r <pcap_file> -A fast -l <log_dir>
    Alerts are in: <log_dir>/alert
    """
    results = {
        "snort_available": False,
        "alerts": [],
        "alert_count": 0,
        "alert_priorities": {},
        "top_alert_signatures": [],
        "error": None,
    }
    
    # Check if Snort is available
    try:
        subprocess.run(["snort", "--version"], 
                      capture_output=True, 
                      timeout=5,
                      check=True)
        results["snort_available"] = True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        results["error"] = "Snort not found or not accessible. Install Snort to enable IDS analysis."
        return results
    
    # Create temporary directory for Snort logs
    try:
        with tempfile.TemporaryDirectory() as log_dir:
            # Run Snort on the PCAP file
            try:
                cmd = [
                    "snort",
                    "-r", pcap_path,
                    "-A", "fast",  # Fast alert mode
                    "-l", log_dir,
                ]
                
                # Try to use config file if available, but don't fail if not
                config_paths = ["/etc/snort/snort.conf", "/usr/local/etc/snort/snort.conf"]
                config_found = False
                for config_path in config_paths:
                    if os.path.exists(config_path):
                        cmd.extend(["-c", config_path])
                        config_found = True
                        break
                
                # Run Snort (non-blocking, capture output)
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=300,  # 5 minute timeout
                    text=True,
                )
                
                # Check for alert file
                alert_file_path = Path(log_dir) / "alert"
                
                if not alert_file_path.exists():
                    # Try alternative location
                    alert_file_path = Path(log_dir) / "snort.alert.fast"
                    if not alert_file_path.exists():
                        results["error"] = "Snort ran but no alerts file generated."
                        return results
                
                # Parse Snort alert file (fast format)
                alerts = []
                try:
                    with open(alert_file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            
                            # Snort fast alert format:
                            # [**] [1:10000001:1] Rule Name [**] [Priority: 0] [Classification: ...] [Timestamp] src_ip:src_port -> dst_ip:dst_port
                            if "[**]" in line:
                                try:
                                    # Extract signature name
                                    parts = line.split("[**]")
                                    if len(parts) >= 3:
                                        rule_part = parts[1].strip()
                                        # Extract rule ID and name
                                        if "[" in rule_part and "]" in rule_part:
                                            rule_content = rule_part.split("]")[0].replace("[", "")
                                            rule_parts = rule_content.split(":")
                                            if len(rule_parts) >= 3:
                                                signature = rule_parts[2].strip()
                                            else:
                                                signature = "Unknown"
                                        else:
                                            signature = "Unknown"
                                        
                                        # Extract priority
                                        priority = 0
                                        if "[Priority:" in line:
                                            try:
                                                priority_str = line.split("[Priority:")[1].split("]")[0].strip()
                                                priority = int(priority_str)
                                            except:
                                                pass
                                        
                                        # Extract IPs and ports
                                        src_ip = dst_ip = src_port = dst_port = "Unknown"
                                        if "->" in line:
                                            flow_part = line.split("->")[-1].strip()
                                            # Extract destination IP:port
                                            if ":" in flow_part:
                                                dst_part = flow_part.split()[0] if flow_part.split() else flow_part
                                                if ":" in dst_part:
                                                    dst_ip, dst_port = dst_part.rsplit(":", 1)
                                            
                                            # Extract source IP:port (before ->)
                                            src_part = line.split("->")[0].strip()
                                            if ":" in src_part:
                                                src_ip_port = src_part.split()[-1] if src_part.split() else src_part
                                                if ":" in src_ip_port:
                                                    src_ip, src_port = src_ip_port.rsplit(":", 1)
                                        
                                        alerts.append({
                                            "signature": signature,
                                            "priority": priority,
                                            "src_ip": src_ip,
                                            "dst_ip": dst_ip,
                                            "src_port": src_port,
                                            "dst_port": dst_port,
                                            "raw_line": line[:200],  # Limit length
                                        })
                                except Exception:
                                    # Skip malformed lines
                                    continue
                
                except IOError as e:
                    results["error"] = f"Failed to read Snort alerts file: {str(e)}"
                    return results
                
                # Process alerts
                alert_priorities = Counter()
                alert_signatures = Counter()
                
                for alert in alerts:
                    alert_priorities[alert["priority"]] += 1
                    alert_signatures[alert["signature"]] += 1
                
                # Limit alerts to prevent huge output
                if len(alerts) > 100:
                    alerts = alerts[:100]
                
                results["alerts"] = alerts
                results["alert_count"] = len(alerts)
                results["alert_priorities"] = dict(alert_priorities)
                results["top_alert_signatures"] = alert_signatures.most_common(20)
                
            except subprocess.TimeoutExpired:
                results["error"] = "Snort analysis timed out (exceeded 5 minutes)."
            except subprocess.CalledProcessError as e:
                results["error"] = f"Snort execution failed: {e.stderr if e.stderr else str(e)}"
            except Exception as e:
                results["error"] = f"Unexpected error running Snort: {str(e)}"
    
    except Exception as e:
        results["error"] = f"Failed to set up Snort analysis: {str(e)}"
    
    return results


# ---------- Zeek (Bro) Integration ----------

def get_zeek_logs(pcap_path: str) -> Dict[str, Any]:
    """
    Run Zeek on a PCAP file and parse the logs.
    Returns structured log information for LLM analysis.
    
    Zeek command: zeek -r <pcap_file> -C
    Logs are in current directory: conn.log, http.log, dns.log, etc.
    """
    results = {
        "zeek_available": False,
        "logs": {},
        "log_summary": {},
        "error": None,
    }
    
    # Check if Zeek is available
    try:
        subprocess.run(["zeek", "--version"], 
                      capture_output=True, 
                      timeout=5,
                      check=True)
        results["zeek_available"] = True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        results["error"] = "Zeek not found or not accessible. Install Zeek to enable network analysis."
        return results
    
    # Create temporary directory for Zeek logs
    try:
        with tempfile.TemporaryDirectory() as log_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(log_dir)
                
                # Run Zeek on the PCAP file
                try:
                    cmd = [
                        "zeek",
                        "-r", pcap_path,
                        "-C",  # Don't load scripts, use default
                    ]
                    
                    # Run Zeek (non-blocking, capture output)
                    process = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=300,  # 5 minute timeout
                        text=True,
                    )
                    
                    # Parse Zeek log files (TSV format with headers)
                    zeek_logs = {}
                    
                    # Common Zeek log files to check
                    log_files = [
                        "conn.log",      # Connection logs
                        "http.log",      # HTTP requests
                        "dns.log",       # DNS queries
                        "ssl.log",       # SSL/TLS
                        "files.log",     # File analysis
                        "weird.log",     # Weird/abnormal events
                        "notice.log",    # Security notices
                    ]
                    
                    for log_file in log_files:
                        log_path = Path(log_dir) / log_file
                        if log_path.exists():
                            try:
                                # Read Zeek TSV log file
                                with open(log_path, 'r') as f:
                                    lines = f.readlines()
                                    
                                    if not lines:
                                        continue
                                    
                                    # First line is header (starts with #fields)
                                    # Data starts after #types or #separator
                                    data_lines = []
                                    fields = []
                                    for line in lines:
                                        line = line.strip()
                                        if line.startswith('#fields'):
                                            fields = line.replace('#fields', '').strip().split('\t')
                                        elif line and not line.startswith('#'):
                                            data_lines.append(line)
                                    
                                    # Parse TSV data
                                    if data_lines and fields:
                                        parsed_rows = []
                                        for data_line in data_lines[:50]:  # Limit to 50 rows per log
                                            values = data_line.split('\t')
                                            row = {}
                                            for i, field in enumerate(fields):
                                                if i < len(values):
                                                    row[field] = values[i]
                                            parsed_rows.append(row)
                                        
                                        zeek_logs[log_file.replace('.log', '')] = {
                                            "row_count": len(data_lines),
                                            "sample_rows": parsed_rows[:20],  # Top 20
                                        }
                            except Exception:
                                # Skip logs that can't be parsed
                                continue
                    
                    results["logs"] = zeek_logs
                    
                    # Create summary
                    summary = {}
                    for log_name, log_data in zeek_logs.items():
                        summary[log_name] = {
                            "total_entries": log_data["row_count"],
                            "sample_count": len(log_data["sample_rows"]),
                        }
                    results["log_summary"] = summary
                    
                except subprocess.TimeoutExpired:
                    results["error"] = "Zeek analysis timed out (exceeded 5 minutes)."
                except subprocess.CalledProcessError as e:
                    results["error"] = f"Zeek execution failed: {e.stderr if e.stderr else str(e)}"
                except Exception as e:
                    results["error"] = f"Unexpected error running Zeek: {str(e)}"
                finally:
                    os.chdir(original_dir)
            
            except Exception as e:
                results["error"] = f"Failed to set up Zeek analysis: {str(e)}"
    
    except Exception as e:
        results["error"] = f"Failed to set up Zeek analysis: {str(e)}"
    
    return results

