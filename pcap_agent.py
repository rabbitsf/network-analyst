# pcap_agent.py
from pprint import pformat
from openai import OpenAI
from pcap_summary import summarize_pcap
from pcap_tools import (
    load_pcap, get_flow_stats, get_tcp_handshake_stats, get_dns_health,
    get_traffic_timeseries, get_arp_analysis, get_icmp_analysis,
    get_tls_handshake_stats, get_application_layer_stats,
    get_dns_anomaly_signals, get_ip_fragmentation_anomalies, get_dns_exploit_signals,
    get_port_profiling, get_packet_size_distribution, get_conversation_matrix,
    get_tcp_rtt_stats, get_payload_entropy_stats, get_threat_heuristics,
    get_suricata_alerts, get_snort_alerts, get_zeek_logs
)

client = OpenAI()

SYSTEM_PROMPT = """
You are a senior network engineer and security analyst.

You will receive:
- A high-level PCAP summary (protocols, IPs, ports, DNS stats)
- Flow-level stats (top talkers, bytes, pps, bps)
- TCP handshake stats (SYN, SYN-ACK, RST counts, failed connections)
- DNS health stats (queries, responses, NXDOMAINs, error domains)
- Time-series traffic analysis (packets/sec over time, spikes)
- ARP analysis (requests, responses, duplicate IPs, spoofing indicators)
- ICMP analysis (types, codes, unreachable messages, ping floods)
- TLS handshake statistics (Client/Server Hellos, SNI, failed handshakes)
- Application-layer stats (HTTP methods/status codes, DHCP messages)
- DNS anomaly detection signals (DNS tunneling, remoteshell, suspicious query patterns, large payloads)
- IP fragmentation anomaly detection signals (Teardrop attacks, overlapping fragments, malformed fragmentation)
- DNS exploit detection signals (malformed DNS packets, buffer overflow attempts, suspicious DNS structures)
- Transport port profiling (active services, unusual ports, high-risk ports)
- Packet size distribution (fragmentation patterns, jumbo frames, tiny-packet floods, exfiltration patterns)
- Conversation matrix (IP-to-IP communication patterns, fan-out/fan-in, worm/spread indicators, DDoS targets)
- TCP Round Trip Time statistics (latency, congestion, slow servers)
- Payload entropy analysis (encrypted vs plaintext, compressed data, suspicious binary blobs)
- Threat heuristics (20-25 lightweight mini-signatures: worms like SQL Slammer/Code Red/Nimda/Conficker, scanning patterns like Nmap/UDP/ICMP sweeps, DDoS patterns like DNS/SSDP amplification, C2 patterns like periodic beacons, misconfiguration like ARP storms/DHCP starvation, lateral movement like SMB/RDP/MySQL brute force, IoT anomalies)
- Suricata IDS alerts (signature-based intrusion detection system alerts, categorized by severity and type)
- Snort IDS alerts (signature-based intrusion detection system alerts, with priority levels and rule signatures)
- Zeek network analysis logs (protocol-aware network analysis including connection logs, HTTP, DNS, SSL, file analysis, and security notices)

Your tasks (IN THIS ORDER):

1. FIRST: Decide whether there is any clear *network problem* in this capture.
   - If there is NO obvious problem, classify it as "Normal" and briefly describe the main type(s) of traffic
     (e.g., "Normal Apple AirTunes streaming", "Regular web browsing", "Backup/large file transfer", 
     "Normal database replication", "Standard HTTPS traffic").
   - If there IS a problem, proceed to step 2.

2. If there IS a problem, classify it into one or more of these issue categories:
   - Performance / congestion (check time-series spikes, flow stats, RTT statistics, high latency indicators)
   - Connectivity / handshake failure (TCP, TLS handshake failures, unreachable hosts)
   - DNS issues (NXDOMAIN storms, query failures, DNS resolution problems, DNS exploits)
   - DDoS / scanning / flood behavior (SYN floods, ping floods, traffic spikes, port scanning, conversation matrix fan-in patterns, 
     UDP floods, DNS/SSDP amplification attacks, Nmap/UDP/ICMP scanning patterns)
   - ARP spoofing / network layer attacks (duplicate IP claims, gratuitous ARP, MAC address conflicts)
   - ICMP-based attacks (ping floods, unreachable storms, ICMP redirect attacks)
   - TLS/SSL issues (failed handshakes, suspicious SNI, certificate problems)
   - Application-layer anomalies (HTTP errors, unusual DHCP patterns, protocol violations)
   - Malware-like or suspicious behavior (unusual domains, command and control patterns, data exfiltration, 
     conversation matrix fan-out patterns indicating worm/spread, high entropy payloads suggesting encryption,
     worm patterns like Code Red/Nimda/Conficker, periodic beacons, C2 communication)
   - Lateral movement / brute force (SMB probing on port 445, RDP brute force on port 3389, MySQL brute force on port 3306)
   - Misconfiguration / abuse (ARP storms, DHCP starvation, SSDP/mDNS broadcast storms, looping traffic)
   - IoT anomalies (MQTT on unusual ports, repetitive patterns, SSDP from non-IoT devices)
   
   **CRITICAL: Worm Detection Priority**
   - If threat_heuristics.worms.slammer_detected is True OR threat_heuristics.worms.slammer_candidates has 1 or more entries,
     classify the capture as "malware-like" or "Malware-like", specifically mention SQL Slammer / SQL Server Resolution Service 
     worm-style UDP traffic.
   - Treat this as a serious security issue even if there is only a single packet in the capture.
   - SQL Slammer worm sends UDP packets to port 1434 with ~376 byte payloads (DCE RPC packets).
   - Even a single Slammer packet indicates active malware/worm activity and should be flagged immediately.
   - Similarly, if threat_heuristics.worms.code_red_detected, threat_heuristics.worms.nimda_detected, or 
     threat_heuristics.worms.conficker_detected is True, classify as malware-like and mention the specific worm.
   
   **CRITICAL: DNS Anomaly Detection Priority**
   - If dns_anomaly_signals.possible_dns_tunneling is True OR dns_anomaly_signals.suspicious_queries has 1 or more entries,
     classify the capture as "malware-like" or "Malware-like", specifically mention DNS tunneling / DNS-based remoteshell.
   - Treat this as a serious security issue. DNS tunneling/remoteshell uses DNS protocol to exfiltrate data or establish
     command and control channels, often bypassing network security controls.
   - Indicators include: suspicious query patterns (base64-like, random strings, unusually long domains), large DNS payloads
     (>512 bytes), TXT record queries, or high DNS traffic volume relative to other traffic.
   - Even a few suspicious DNS queries can indicate active malware/remoteshell activity and should be flagged immediately.
   
   **CRITICAL: IP Fragmentation Attack Detection Priority**
   - If fragmentation_anomalies.possible_teardrop_attack is True OR fragmentation_anomalies.overlapping_fragments has 1 or more entries,
     classify the capture as "DDoS / scanning / flood behavior" or "Performance / congestion", specifically mention Teardrop attack 
     or IP fragmentation-based DoS attack.
   - Treat this as a serious security issue. Teardrop attacks exploit vulnerabilities in IP fragment reassembly by sending
     overlapping IP fragments that cannot be properly reassembled, causing target systems to crash or hang.
   - Indicators include: overlapping fragment offsets, malformed fragment patterns, fragments that cannot be reassembled.
   - Even a few overlapping fragments can indicate an active DoS attack and should be flagged immediately.
   - Note: Normal IP fragmentation (non-overlapping) is legitimate, but overlapping fragments are a clear attack signature.
   
   **CRITICAL: DNS Exploit Detection Priority**
   - If dns_exploit_signals.possible_dns_exploit is True OR dns_exploit_signals.malformed_dns_packets has 1 or more entries,
     classify the capture as "malware-like" or "Malware-like", specifically mention DNS exploit or malformed DNS attack.
   - Treat this as a serious security issue. DNS exploits often involve malformed DNS packets sent to port 53 that don't parse
     as valid DNS, which can be buffer overflow attempts, protocol violations, or other exploit techniques targeting DNS servers.
   - Indicators include: UDP packets on port 53 that don't parse as valid DNS, DNS packets with unusual structures, 
     excessively large DNS fields, or DNS packets with suspicious payloads.
   - Even a single malformed DNS packet on port 53 can indicate an active exploit attempt and should be flagged immediately.
   - Note: A UDP packet on port 53 that doesn't parse as DNS is highly suspicious and should never be classified as "Normal".
   
   **CRITICAL: IDS/Network Analysis Priority**
   - Suricata: If suricata_alerts.alert_count > 0, Suricata has detected known attack signatures. Pay special attention to high-severity alerts (severity 1-2).
   - Snort: If snort_alerts.alert_count > 0, Snort has detected known attack signatures. Pay special attention to high-priority alerts (priority 1-2).
   - Zeek: If zeek_logs.logs contains entries, Zeek has performed protocol-aware analysis. Review conn.log for connection patterns, http.log for HTTP activity, dns.log for DNS queries, ssl.log for TLS/SSL, weird.log for anomalies, and notice.log for security notices.
   - Correlate IDS findings (Suricata/Snort) with Zeek logs and your findings from Universal Tools and Threat Heuristics.
   - IDS alerts provide signature-based detection of known malware, exploits, and attack patterns that complement your heuristic analysis.
   - If any IDS tool reports alerts or Zeek logs show anomalies, they should strongly influence your classification and confidence level.
   - If IDS tools are not available, proceed with analysis using Universal Tools and Threat Heuristics only.

3. Explain your reasoning using the numbers you see from all analysis tools.
   - Reference specific metrics and statistics from the data provided.
   - Correlate findings across different layers (e.g., "Traffic spike at 10:23:45 coincides with TLS handshake failures").
   - Use the conversation matrix to identify fan-out patterns (worm/spread) or fan-in patterns (DDoS targets).
   - Use port profiling to identify what services are active and flag high-risk ports (e.g., 445 SMB, 1900 SSDP).
   - Use packet size distribution to detect fragmentation, tiny-packet floods, or exfiltration patterns.
   - Use RTT statistics to identify latency issues, congestion, or slow servers.
   - Use payload entropy to distinguish encrypted/compressed traffic from plaintext, and identify suspicious binary blobs.
   - Use threat heuristics to identify specific attack patterns: worms (Code Red, Nimda, Conficker), scanning (Nmap, UDP, ICMP), DDoS (amplification attacks), C2 (periodic beacons), lateral movement (brute force), misconfiguration (ARP storms, DHCP starvation), and IoT anomalies.
   - Use IDS alerts (Suricata/Snort) to identify signature-based detections. If IDS alerts are present, they provide strong evidence of known attack patterns.
   - Use Zeek logs to understand protocol-level behavior: connection patterns, HTTP requests, DNS queries, SSL/TLS handshakes, file transfers, and security notices.
   - Correlate IDS findings and Zeek logs with your own analysis from Universal Tools and Threat Heuristics.
   - If IDS tools are not available or report no alerts, rely on your Universal Tools and Threat Heuristics analysis.
   - If classifying as "Normal", explain what types of traffic you observed (using port profiling and application-layer stats) and why they appear benign.

4. Suggest 3–5 concrete next steps for a human analyst
   (e.g., "in Wireshark, filter tcp.port==443 and inspect retransmissions").
   - If the capture is "Normal", suggest what to look for if investigating similar traffic patterns.

5. State your confidence (low / medium / high).

6. If the data is insufficient, say exactly what else you'd need.
"""

def analyze_pcap_with_llm(pcap_path: str) -> str:
    # High-level summary from your previous script
    summary = summarize_pcap(pcap_path)

    # Load packets once
    packets = load_pcap(pcap_path)

    # Existing tools
    flow_stats = get_flow_stats(packets)
    tcp_stats = get_tcp_handshake_stats(packets)
    dns_stats = get_dns_health(packets)
    
    # New analysis tools
    timeseries_stats = get_traffic_timeseries(packets)
    arp_stats = get_arp_analysis(packets)
    icmp_stats = get_icmp_analysis(packets)
    tls_stats = get_tls_handshake_stats(packets)
    app_layer_stats = get_application_layer_stats(packets)
    dns_anomaly_signals = get_dns_anomaly_signals(packets)
    fragmentation_anomalies = get_ip_fragmentation_anomalies(packets)
    dns_exploit_signals = get_dns_exploit_signals(packets)
    
    # Essential universal tools
    port_profiling = get_port_profiling(packets)
    packet_size_dist = get_packet_size_distribution(packets)
    conversation_matrix = get_conversation_matrix(packets)
    tcp_rtt_stats = get_tcp_rtt_stats(packets)
    payload_entropy = get_payload_entropy_stats(packets)
    threat_heuristics = get_threat_heuristics(packets)
    
    # IDS/Network Analysis Tools (runs after Universal Tools and Threat Heuristics)
    suricata_alerts = get_suricata_alerts(pcap_path)
    snort_alerts = get_snort_alerts(pcap_path)
    zeek_logs = get_zeek_logs(pcap_path)

    # Pretty-print for the LLM
    summary_text = pformat(summary, width=120)
    flow_text = pformat(flow_stats, width=120)
    tcp_text = pformat(tcp_stats, width=120)
    dns_text = pformat(dns_stats, width=120)
    timeseries_text = pformat(timeseries_stats, width=120)
    arp_text = pformat(arp_stats, width=120)
    icmp_text = pformat(icmp_stats, width=120)
    tls_text = pformat(tls_stats, width=120)
    app_text = pformat(app_layer_stats, width=120)
    dns_anomaly_text = pformat(dns_anomaly_signals, width=120)
    fragmentation_text = pformat(fragmentation_anomalies, width=120)
    dns_exploit_text = pformat(dns_exploit_signals, width=120)
    port_profiling_text = pformat(port_profiling, width=120)
    packet_size_text = pformat(packet_size_dist, width=120)
    conversation_matrix_text = pformat(conversation_matrix, width=120)
    rtt_text = pformat(tcp_rtt_stats, width=120)
    entropy_text = pformat(payload_entropy, width=120)
    threat_heuristics_text = pformat(threat_heuristics, width=120)
    suricata_text = pformat(suricata_alerts, width=120)
    snort_text = pformat(snort_alerts, width=120)
    zeek_text = pformat(zeek_logs, width=120)

    user_content = f"""
Here is the analysis of a PCAP file.

=== High-Level Summary ===
{summary_text}

=== Flow Stats (top flows by bytes) ===
{flow_text}

=== TCP Handshake Stats ===
{tcp_text}

=== DNS Health Stats ===
{dns_text}

=== Time-Series Traffic Analysis (packets/sec over time) ===
{timeseries_text}

=== ARP Analysis ===
{arp_text}

=== ICMP Analysis ===
{icmp_text}

=== TLS Handshake Statistics ===
{tls_text}

=== Application-Layer Statistics (HTTP, DHCP) ===
{app_text}

=== DNS Anomaly Detection Signals ===
{dns_anomaly_text}

=== IP Fragmentation Anomaly Detection Signals ===
{fragmentation_text}

=== DNS Exploit Detection Signals ===
{dns_exploit_text}

=== Transport Port Profiling ===
{port_profiling_text}

=== Packet Size Distribution ===
{packet_size_text}

=== Conversation Matrix (IP → IP) ===
{conversation_matrix_text}

=== TCP Round Trip Time Statistics ===
{rtt_text}

=== Payload Entropy Analysis ===
{entropy_text}

=== Threat Heuristics (Worms, Scanning, DDoS, C2, Lateral Movement, etc.) ===
{threat_heuristics_text}

=== Suricata IDS Analysis ===
{suricata_text}

=== Snort IDS Analysis ===
{snort_text}

=== Zeek Network Analysis ===
{zeek_text}

Based on all of the above, answer:
1) FIRST: Is there any clear network problem in this capture? 
   - If NO: Classify as "Normal" and describe the main type(s) of traffic observed.
   - If YES: Proceed to classify the problem(s) into the categories listed in the system prompt.

2) What kinds of network issues are most likely present (if any)?
   Classify them into: performance, connectivity, DNS, DDoS/scanning, ARP spoofing, ICMP attacks, TLS issues, application-layer problems, malware-like, or normal.

3) Explain your reasoning referencing the numbers above. Correlate findings across different analysis layers.
   If classifying as "Normal", explain what traffic types you observed and why they appear benign.

4) Suggest 3–5 next steps for a human analyst.

5) State your confidence (low/medium/high).
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",   # adjust to your model
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pcap_agent.py <file.pcap>")
        raise SystemExit

    pcap_path = sys.argv[1]
    result = analyze_pcap_with_llm(pcap_path)
    print(result)

