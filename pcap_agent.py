# pcap_agent.py
from pprint import pformat
from openai import OpenAI
from pcap_summary import summarize_pcap
from pcap_tools import load_pcap, get_flow_stats, get_tcp_handshake_stats, get_dns_health

client = OpenAI()

SYSTEM_PROMPT = """
You are a senior network engineer and security analyst.

You will receive:
- A high-level PCAP summary (protocols, IPs, ports, DNS stats)
- Flow-level stats (top talkers, bytes, pps, bps)
- TCP handshake stats (SYN, SYN-ACK, RST counts, failed connections)
- DNS health stats (queries, responses, NXDOMAINs, error domains)

Your tasks:
1. Identify likely categories of issues:
   - Performance / congestion
   - Connectivity / handshake failure
   - DNS issues
   - DDoS / scanning / flood behavior
   - Malware-like or suspicious behavior
   - Or "no obvious problem at this level"

2. Explain your reasoning using the numbers you see.
3. Suggest 3–5 concrete next steps (e.g., "in Wireshark, filter tcp.port==443 and inspect retransmissions").
4. State your confidence (low / medium / high).
5. If the data is insufficient, say exactly what else you'd need.
"""

def analyze_pcap_with_llm(pcap_path: str) -> str:
    # High-level summary from your previous script
    summary = summarize_pcap(pcap_path)

    # Load packets once
    packets = load_pcap(pcap_path)

    # New tools
    flow_stats = get_flow_stats(packets)
    tcp_stats = get_tcp_handshake_stats(packets)
    dns_stats = get_dns_health(packets)

    # Pretty-print for the LLM
    summary_text = pformat(summary, width=120)
    flow_text = pformat(flow_stats, width=120)
    tcp_text = pformat(tcp_stats, width=120)
    dns_text = pformat(dns_stats, width=120)

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

Based on all of the above, answer:
1) What kinds of network issues are most likely present, if any?
2) Classify them into performance, connectivity, DNS, DDoS/scanning, malware-like, or normal.
3) Explain your reasoning referencing the numbers above.
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

