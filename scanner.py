import socket
import struct
import argparse
import ipaddress
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [21, 22, 23, 80, 443, 554, 8080, 8443, 8888]

OEM_SIGNATURES = {
    "TP-Link":    ["tp-link", "tplink", "TL-"],
    "Hikvision":  ["hikvision", "dvr", "nvr", "DS-"],
    "D-Link":     ["d-link", "dlink", "DIR-"],
    "Netgear":    ["netgear", "NETGEAR"],
    "MikroTik":   ["mikrotik", "RouterOS"],
    "Cisco":      ["cisco", "Cisco IOS"],
    "Dahua":      ["dahua", "IPC-"],
}

SAMPLE_CVES = {
    80:  [{"id": "CVE-2021-44228", "severity": "Critical", "desc": "Log4Shell RCE via HTTP"}],
    22:  [{"id": "CVE-2023-38408", "severity": "High",     "desc": "OpenSSH agent forwarding RCE"}],
    23:  [{"id": "CVE-2020-10188", "severity": "Critical", "desc": "Telnet unauth RCE"}],
    554: [{"id": "CVE-2021-36260", "severity": "Critical", "desc": "Hikvision RTSP RCE"}],
    443: [{"id": "CVE-2022-0778",  "severity": "High",     "desc": "OpenSSL infinite loop DoS"}],
}


def scan_port(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except Exception:
        return None


def grab_banner(ip, port, timeout=2.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(1024).decode(errors="ignore")
    except Exception:
        return ""


def fingerprint_device(banner):
    banner_lower = banner.lower()
    for vendor, keywords in OEM_SIGNATURES.items():
        for kw in keywords:
            if kw.lower() in banner_lower:
                return vendor
    return "Unknown"


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def scan_host(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in COMMON_PORTS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    if not open_ports:
        return None

    banner = grab_banner(ip, open_ports[0]) if open_ports else ""
    vendor = fingerprint_device(banner)
    hostname = get_hostname(ip)

    cves = []
    for port in open_ports:
        cves.extend(SAMPLE_CVES.get(port, []))

    return {
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor,
        "open_ports": open_ports,
        "cves": cves,
        "banner_snippet": banner[:200].strip()
    }


def scan_network(target, max_workers=50):
    print(f"\n[*] Scanning {target} ...\n")
    try:
        hosts = [str(h) for h in ipaddress.ip_network(target, strict=False).hosts()]
    except ValueError:
        hosts = [target]

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_host, ip): ip for ip in hosts}
        for f in as_completed(futures):
            result = f.result()
            if result:
                results.append(result)
                print(f"[+] {result['ip']} ({result['hostname']}) — {result['vendor']}")
                print(f"    Ports: {result['open_ports']}")
                if result["cves"]:
                    for cve in result["cves"]:
                        print(f"    CVE: {cve['id']} [{cve['severity']}] — {cve['desc']}")
                print()

    return results


def save_report(results, output="report.json"):
    report = {
        "scan_time": datetime.utcnow().isoformat(),
        "total_devices": len(results),
        "results": results
    }
    with open(output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report saved to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OEM Network Scanner")
    parser.add_argument("--target", required=True, help="Target IP or CIDR e.g. 192.168.1.0/24")
    parser.add_argument("--output", default="report.json", help="Output report file")
    args = parser.parse_args()

    results = scan_network(args.target)
    save_report(results, args.output)
    print(f"\n[*] Scan complete. {len(results)} devices found.")
