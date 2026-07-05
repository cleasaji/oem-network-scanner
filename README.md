# Automated OEM Network Scanner

A network reconnaissance and vulnerability detection tool that automatically discovers OEM devices (routers, switches, IP cameras, printers, IoT devices) on a network, fingerprints them, and maps open ports to known CVEs.

## What it does

- Scans a network range and discovers all active devices
- Identifies device type, manufacturer, and model via banner grabbing and MAC OUI lookup
- Maps open ports to known CVE entries using the NVD database
- Detects default credentials on common OEM devices
- Generates a full vulnerability report in JSON and HTML format

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core scripting |
| Nmap (python-nmap) | Port scanning and service detection |
| Scapy | Packet crafting and ARP discovery |
| Shodan API | Enrichment with external threat data |
| Requests | CVE lookup via NVD REST API |
| Jinja2 | HTML report generation |

## Project Structure

```
oem-network-scanner/
├── scanner.py           # Main scan orchestrator
├── fingerprint.py       # Device fingerprinting logic
├── cve_lookup.py        # NVD API integration
├── shodan_enrich.py     # Shodan API enrichment
├── report.py            # JSON + HTML report generator
├── templates/
│   └── report.html      # Report template
├── config.py            # API keys and scan settings
├── requirements.txt
└── README.md
```

## How to Run

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/oem-network-scanner.git
cd oem-network-scanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your Shodan API key in config.py (optional)
# SHODAN_API_KEY = "your_key_here"

# 4. Run a scan (replace with your network range)
python scanner.py --target 192.168.1.0/24

# 5. View the report
# Opens report.html in your browser
```

## Example Output

```
[*] Scanning 192.168.1.0/24 ...
[+] Found 12 devices

192.168.1.1   - TP-Link TL-WR841N (Router)
  Open ports: 80, 443, 22
  CVEs found: CVE-2021-44228 (Critical), CVE-2020-9054 (High)
  Default credentials: admin/admin [VULNERABLE]

192.168.1.105 - Hikvision DS-2CD2143G2 (IP Camera)  
  Open ports: 80, 554, 8000
  CVEs found: CVE-2021-36260 (Critical - RCE)
  Default credentials: admin/12345 [VULNERABLE]

[*] Report saved: report_2026-07-01.html
```

## Sample Report Sections

- **Executive Summary** — total devices, critical findings count
- **Device Inventory** — full list with MAC, IP, manufacturer, model
- **Vulnerability Table** — CVE ID, severity, CVSS score, affected device
- **Recommendations** — patch links and mitigation steps

## Disclaimer

This tool is intended for use only on networks you own or have explicit written permission to scan. Unauthorised scanning is illegal.

## Requirements

```
python-nmap
scapy
shodan
requests
jinja2
```
