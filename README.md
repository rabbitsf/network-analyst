# PCAP Agent - AI-Powered Network Forensic Assistant

An intelligent network forensic analysis tool that processes Wireshark PCAP/PCAPNG files and generates professional-grade diagnostic reports using Large Language Models (LLMs). Automate first-pass network troubleshooting without manually digging through packets.

## 🚀 Features

### Core Capabilities
- **Web Interface**: Simple Flask-based UI for uploading PCAP files and receiving detailed analysis
- **Automated Packet Analysis**: Comprehensive packet parsing using Scapy
- **AI-Generated Reports**: LLM-powered analysis that reads like a senior network engineer's report
- **Automatic History Logging**: Each analysis saved as timestamped JSON for auditing

### Detection Capabilities

The agent can identify:
- ✅ DNS outages and NXDOMAIN storms
- ✅ Failed TCP connections / unreachable hosts
- ✅ SYN floods and port scanning
- ✅ Large data transfers and throughput anomalies
- ✅ Suspicious domain queries
- ✅ **SQL Slammer worm** (UDP 1434 with 376-byte payloads)
- ✅ **DNS tunneling/remoteshell** (suspicious DNS query patterns)
- ✅ **Teardrop attacks** (overlapping IP fragments)
- ✅ **DNS exploits** (malformed DNS packets)
- ✅ **Code Red, Nimda, Conficker worms**
- ✅ **Nmap/UDP/ICMP scanning patterns**
- ✅ **DDoS patterns** (DNS/SSDP amplification)
- ✅ **C2 patterns** (periodic beacons)
- ✅ **Lateral movement** (SMB/RDP/MySQL brute force)
- ✅ **Misconfiguration** (ARP storms, DHCP starvation)
- ✅ **IoT anomalies**

## 📋 Requirements

### Python Dependencies
- Python 3.8+
- Flask
- Scapy
- OpenAI (or compatible LLM API)
- httpx

### Optional IDS/Network Analysis Tools
- **Suricata** (recommended) - Signature-based IDS
- **Snort** (optional) - Signature-based IDS
- **Zeek** (optional) - Protocol-aware network analysis

### Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd pcap-agent
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python dependencies:**
   ```bash
   pip install flask scapy openai httpx
   ```

4. **Install IDS tools (optional but recommended):**
   
   **On macOS (using Homebrew):**
   ```bash
   brew install suricata snort zeek
   ```
   
   **On Ubuntu/Debian:**
   ```bash
   sudo apt-get install suricata snort zeek
   ```
   
   **On other systems:**
   - Follow official installation guides for [Suricata](https://suricata.io/), [Snort](https://www.snort.org/), and [Zeek](https://zeek.org/)

5. **Set up OpenAI API key:**
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```
   
   Or create a `.env` file:
   ```
   OPENAI_API_KEY=your-api-key-here
   ```

## 🛠️ Usage

### Web Interface

1. **Start the web server:**
   ```bash
   python web_app.py
   ```

2. **Open your browser:**
   Navigate to `http://localhost:5050`

3. **Upload a PCAP file:**
   - Select a `.pcap` or `.pcapng` file
   - Click "Upload"
   - Wait for analysis (typically 10-30 seconds)
   - View the detailed report

### Command Line Interface

```bash
python pcap_agent.py <path-to-pcap-file>
```

## 📊 Analysis Tools

The agent uses a comprehensive set of analysis tools organized into three layers:

### 1. Universal Tools (12 Essential Tools)
- **High-Level Summary**: Total packets, bytes, protocols, top IPs/ports
- **Flow Statistics**: Top talkers, heavy flows, asymmetric traffic
- **TCP Handshake Health**: SYN/SYN-ACK/RST counts, failed connections
- **DNS Health**: Queries, responses, NXDOMAIN counts, error domains
- **Time-Series Traffic**: Packets/sec over time, traffic spikes
- **ARP/ICMP Analysis**: ARP storms, ping sweeps, network discovery
- **Transport Port Profiling**: Active services, high-risk ports
- **Packet Size Distribution**: Fragmentation, jumbo frames, tiny-packet floods
- **Application-Layer Identifiers**: HTTP, TLS SNI, DHCP, mDNS
- **Conversation Matrix**: IP-to-IP patterns, fan-out/fan-in detection
- **Round Trip Time**: TCP latency, congestion detection
- **Payload Entropy**: Encrypted vs plaintext detection

### 2. Threat Heuristics (20-25 Mini-Signatures)
- **Worms**: SQL Slammer, Code Red, Nimda, Conficker
- **Scanning**: Nmap SYN scans, UDP scans, ICMP ping sweeps
- **DDoS**: UDP floods, DNS/SSDP amplification
- **C2 Patterns**: Periodic beacons, high-entropy payloads
- **Lateral Movement**: SMB/RDP/MySQL brute force
- **Misconfiguration**: ARP storms, DHCP starvation, broadcast storms
- **IoT Anomalies**: MQTT on unusual ports, repetitive patterns

### 3. IDS/Network Analysis Tools
- **Suricata**: Signature-based intrusion detection
- **Snort**: Signature-based intrusion detection
- **Zeek**: Protocol-aware network analysis (conn.log, http.log, dns.log, ssl.log, etc.)

## 📁 Project Structure

```
pcap-agent/
├── pcap_agent.py          # Main LLM integration and orchestration
├── pcap_tools.py          # All analysis tools (Universal, Threat Heuristics, IDS)
├── pcap_summary.py        # High-level PCAP summary
├── web_app.py             # Flask web interface
├── labels.json            # File labels/metadata (issue_category, traffic_type, notes)
├── templates/
│   ├── upload.html        # Upload page
│   └── result.html        # Results display page
├── analyses/              # Saved analysis results (timestamped JSON)
└── README.md              # This file
```

## 🔧 Configuration

### Labels File

The `labels.json` file allows you to add metadata for known PCAP files:

```json
{
    "filename.pcap": {
        "issue_category": "Normal",
        "traffic_type": "Description of traffic type",
        "notes": "Additional notes about the capture"
    }
}
```

Labels are automatically included in the analysis JSON when a matching file is uploaded.

### OpenAI Model

Default model is `gpt-4.1-mini`. To change it, edit `pcap_agent.py`:

```python
response = client.chat.completions.create(
    model="gpt-4",  # Change this
    ...
)
```

## 📝 Analysis Output

Each analysis generates a JSON file in the `analyses/` directory with:
- Timestamp
- Original filename
- AI-generated analysis text
- Labels (if available in `labels.json`)

Example:
```json
{
  "timestamp_utc": "2025-12-11T19:45:28.123456Z",
  "original_filename": "slammer.pcap",
  "analysis": "Detailed AI-generated analysis...",
  "labels": {
    "issue_category": "Malware-like",
    "traffic_type": "SQL Slammer worm",
    "notes": "Sample of Slammer worm sending DCE RPC packet"
  }
}
```

## 🎯 Use Cases

- **Network Troubleshooting**: Quickly identify connectivity, DNS, and performance issues
- **Security Analysis**: Detect malware, worms, scanning, and attack patterns
- **Forensic Investigation**: Automated first-pass analysis of network captures
- **Traffic Classification**: Understand what types of traffic are present
- **Anomaly Detection**: Identify unusual patterns and suspicious behavior

## 🔍 Example Detections

The agent can detect:
- **SQL Slammer**: UDP port 1434 with ~376 byte payloads
- **DNS Tunneling**: Base64-like query patterns, large DNS payloads
- **Teardrop Attack**: Overlapping IP fragments
- **DNS Exploits**: Malformed DNS packets on port 53
- **Code Red**: HTTP GET /default.ida patterns
- **Nimda**: HTTP patterns with cmd.exe, .printer
- **Conficker**: TCP 445 scan patterns
- **Nmap Scans**: Many distinct ports, 1 SYN each
- **DDoS**: DNS/SSDP amplification, UDP floods
- **C2 Beacons**: Periodic small packets with regular intervals

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

[Add your license here]

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet analysis
- Uses [OpenAI API](https://platform.openai.com/) for LLM analysis
- Integrates with [Suricata](https://suricata.io/), [Snort](https://www.snort.org/), and [Zeek](https://zeek.org/) for IDS/network analysis

## 📧 Support

For issues, questions, or contributions, please open an issue on GitHub.

