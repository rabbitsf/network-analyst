# pcap_tools.py

from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional


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

