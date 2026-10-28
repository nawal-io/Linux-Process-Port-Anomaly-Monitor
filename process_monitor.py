import subprocess
import re
import json
from datetime import datetime

SUSPICIOUS_PROCESS_NAMES = [
    "nc", "ncat", "netcat", "xmrig", "bash -i", 
    "python -c import socket", "perl -e", "ruby -e"
]

HIGH_RISK_PORTS = [4444, 1337, 6667, 31337]

def get_running_processes():
    """Fetches active system processes using native Linux 'ps' utility."""
    try:
        output = subprocess.check_output(["ps", "-eo", "pid,user,comm,args"], text=True)
        processes = []
        for line in output.splitlines()[1:]:
            parts = line.split(maxsplit=3)
            if len(parts) >= 4:
                processes.append({
                    "pid": parts[0],
                    "user": parts[1],
                    "command": parts[2],
                    "args": parts[3]
                })
        return processes
    except Exception as error:
        print(f"[-] Error executing process discovery: {error}")
        return []

def scan_anomalies():
    """Audits running processes against threat indicators and high-risk port patterns."""
    print("=" * 60)
    print("   LINUX CLI PROCESS & PORT ANOMALY MONITOR")
    print("=" * 60)
    print(f"Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    processes = get_running_processes()
    detected_anomalies = []

    print(f"[+] Scanning {len(processes)} active system processes...")

    for proc in processes:
        full_cmd = proc["args"].lower()
        
        for threat in SUSPICIOUS_PROCESS_NAMES:
            if threat in full_cmd:
                detected_anomalies.append({
                    "type": "SUSPICIOUS_PROCESS",
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "details": f"Matches threat signature: '{threat}'",
                    "command": proc["args"]
                })

        for port in HIGH_RISK_PORTS:
            if f":{port}" in full_cmd or f" {port}" in full_cmd:
                detected_anomalies.append({
                    "type": "HIGH_RISK_PORT_ACTIVITY",
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "details": f"Associated with high-risk port {port}",
                    "command": proc["args"]
                })

    print("\n" + "=" * 60)
    print("                 DETECTION SUMMARY")
    print("=" * 60)
    print(f"Total Anomalies Detected: {len(detected_anomalies)}\n")

    if detected_anomalies:
        for idx, alert in enumerate(detected_anomalies, 1):
            print(f"[{idx}] ALERT TYPE: {alert['type']}")
            print(f"    PID     : {alert['pid']} | User: {alert['user']}")
            print(f"    Details : {alert['details']}")
            print(f"    Command : {alert['command']}\n")
    else:
        print("[OK] No suspicious processes or anomalous connections detected.")

if __name__ == "__main__":
    scan_anomalies()
