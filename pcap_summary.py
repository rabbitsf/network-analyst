from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR
from collections import Counter, defaultdict
import sys
import os

def summarize_pcap(path: str) -> dict:
    packets = rdpcap(path)
    total_packets = len(packets)
    total_bytes = sum(len(p) for p in packets)

    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    ports = Counter()

    dns_queries = Counter()
    dns_failures = 0

    for p in packets:
        if IP in p:
            ip = p[IP]
            src_ips[ip.src] += 1
            dst_ips[ip.dst] += 1

        # Protocols
        if TCP in p:
            protocols["TCP"] += 1
            tcp = p[TCP]
            ports[tcp.sport] += 1
            ports[tcp.dport] += 1
        elif UDP in p:
            protocols["UDP"] += 1
            udp = p[UDP]
            ports[udp.sport] += 1
            ports[udp.dport] += 1
        else:
            protocols["other"] += 1

        # Simple DNS stats
        if p.haslayer(DNS):
            dns = p[DNS]
            # Query
            if dns.qr == 0 and dns.qd is not None and isinstance(dns.qd, DNSQR):
                dns_queries[dns.qd.qname.decode(errors="ignore")] += 1
            # Response
            if dns.qr == 1:
                # crude “failure” detection (no answers)
                if dns.ancount == 0 and dns.rcode != 0:
                    dns_failures += 1

    summary = {
        "file_name": os.path.basename(path),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_breakdown": protocols.most_common(),
        "top_source_ips": src_ips.most_common(10),
        "top_destination_ips": dst_ips.most_common(10),
        "top_ports": ports.most_common(10),
        "dns_top_queries": dns_queries.most_common(10),
        "dns_failures": dns_failures,
    }

    return summary

def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_summary.py <file.pcap>")
        sys.exit(1)

    path = sys.argv[1]
    summary = summarize_pcap(path)

    from pprint import pprint
    pprint(summary)

if __name__ == "__main__":
    main()

