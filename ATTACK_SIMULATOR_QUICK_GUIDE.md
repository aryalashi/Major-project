# Attack Simulator - Quick Start Guide

## Overview
`simulate_attacks.py` is a **cross-platform** attack simulator with support for:
- 30+ network-based attacks (TCP/UDP/ICMP flooding, port scanning, brute force)
- 5 payload-based attacks (SQL Injection, XSS, Shellcode, Path Traversal, RCE)
- Automatic timestamp logging to JSON files
- Works on Windows, Linux, and macOS

---

## Installation

### Prerequisites
```bash
pip install scapy npcap
```

**Windows:** Download and install [Npcap](https://npcap.com) for packet capture

### Run as Administrator (Required)
- **Windows:** Run Command Prompt/PowerShell as Administrator
- **Linux:** Use `sudo` prefix
- **macOS:** Use `sudo` prefix

---

## Quick Start

### List All Available Attacks
```bash
py simulate_attacks.py --list
```

### Run Specific Attack
```bash
# SQL Injection
py simulate_attacks.py --attack sqli

# XSS Attack
py simulate_attacks.py --attack xss

# Shellcode Injection
py simulate_attacks.py --attack shellcode

# Path Traversal
py simulate_attacks.py --attack path_trav

# Remote Code Execution
py simulate_attacks.py --attack rce
```

### Run Multiple Attacks
```bash
py simulate_attacks.py --attack sqli,xss,shellcode
```

### Run All Attacks (30+ network + 5 payload)
```bash
py simulate_attacks.py --attack all
```

---

## Available Attack Categories

### Network-Based Attacks (Volume Floods)
```
syn, udp, icmp, ack, rst, synack, fin_flood, psh_ack
```

### Port Scanning
```
scan, fin_scan, null, xmas, udpscan
```

### Brute Force Attacks
```
heartbleed, ftp, ssh, telnet, rdp, mysql, mssql, postgres, winrm, ldap
```

### Application Layer
```
http, https, smtp, dns, smb, netbios, elastic
```

### Payload Attacks (NEW - Cross-Platform HTTP)
```
sqli, xss, shellcode, path_trav, rce
```

### DDoS
```
ddos
```

### Benign Traffic (False Positive Testing)
```
normal
```

---

## Command-Line Options

```bash
py simulate_attacks.py [OPTIONS]

Options:
  --target <IP>      Target IP address (auto-detects local IP if not specified)
  --attack <ATTACK>  Attack to run (see list above)
  --duration <SEC>   Attack duration in seconds (default: 15)
  --rate <PPS>       Packets per second (default: uses per-attack default)
  --log <PATH>       Path to nids.log (default: logs/nids.log)
  --cooldown <SEC>   Seconds between attacks (default: 8)
  --list             List all available attacks
```

---

## Examples

### Test SQL Injection with Custom Duration
```bash
py simulate_attacks.py --attack sqli --duration 30 --rate 20
```

### Test Payload Attacks on Specific Target
```bash
py simulate_attacks.py --attack sqli,xss,rce --target 192.168.1.105
```

### Run Comprehensive Test Suite
```bash
py simulate_attacks.py --attack all --duration 20 --cooldown 5
```

### Test with Custom NIDS Log Path
```bash
py simulate_attacks.py --attack sqli --log /path/to/custom/nids.log
```

---

## Output & Logging

### Console Output
```
[Attack Status]
──────────────────────────────────────────────────
ATTACK: SQL Injection Attack
Method : HTTP GET/POST with SQL injection payload
Target : 192.168.1.100  Rate: 10 pkt/s  Duration: 15s
Watching nids.log for: SQL INJECTION, SQLI...

[Elapsed Seconds]
✅  DETECTED  in 2.3s
Log: [ALERT] Payload Attack - SQL Injection detected from 192.168.1.100
```

### Log File
**Location:** `logs/attack_simulation_log_<TIMESTAMP>.json`

**Content:** (JSON format)
```json
{
  "sim_arg": "sqli",
  "rule_name": "SQL Injection Attack",
  "detected": true,
  "det_time": 2.3,
  "packets": 15,
  "attack_started_at": "2026-03-28T20:53:37.620025",
  "elapsed_time": 15.4,
  "logged_at": "2026-03-28T20:53:37.620025"
}
```

---

## Cross-Platform Notes

### Windows
- ✅ Uses `ping.exe` with `-n` flag
- ✅ Supports Npcap for packet capture
- ✅ Path separators handled automatically

### Linux
- ✅ Uses `ping` with `-c` flag
- ✅ Requires `libpcap` for Scapy
- ✅ May need `sudo` for packet access

### macOS
- ✅ Uses `ping` with `-c` flag
- ✅ Requires `libpcap` (usually pre-installed)
- ✅ May need `sudo` for packet access

---

## Troubleshooting

### "MISSED (waited 25s after attack)"
1. Ensure NIDS is running: `py main.py`
2. Check NIDS is capturing on the correct interface
3. Verify target IP matches NIDS capture network
4. Check logs for rule definition

### "Scapy not available"
```bash
pip install scapy npcap
```

### "No such file or directory: logs/nids.log"
- Start NIDS first to generate the log file
- Or specify custom log path: `--log /path/to/nids.log`

### Loopback IP Warning
- Don't use `127.0.0.1` as target
- Use your actual LAN IP address from: `ipconfig` (Windows) or `ifconfig` (Linux)
- Script auto-detects and auto-switches for you

---

## Performance Metrics

### Detection Accuracy Reporting
The simulator automatically generates:
- ✅ True Positives (attacks correctly detected)
- ❌ False Negatives (attacks missed)
- ⚠️ False Positives (benign traffic triggering alerts)
- Sensitivity/Recall percentage
- Confusion Matrix (TP/FN/FP/TN)

### Timestamp Analysis
All attacks logged with ISO 8601 timestamps enabling:
- Detection latency measurement
- Attack-to-detection time correlation
- Performance trend analysis
- Accuracy tracking over time

---

## Example Test Workflow

```bash
# Step 1: Start NIDS
py main.py &

# Step 2: Wait 5 seconds for NIDS to initialize
sleep 5

# Step 3: Run payload attack tests
py simulate_attacks.py --attack sqli --duration 15
py simulate_attacks.py --attack xss --duration 15
py simulate_attacks.py --attack rce --duration 15

# Step 4: View Results
cat logs/attack_simulation_log_*.json
```

---

## Log Analysis

### List All Generated Logs
```bash
ls -lah logs/attack_simulation_log_*.json
```

### View Latest Log
```bash
cat logs/attack_simulation_log_$(ls -t logs/attack_simulation_log_*.json | head -1 | xargs basename)
```

### Parse Logs with Python
```python
import json
with open('logs/attack_simulation_log_*.json') as f:
    data = json.load(f)
    for attack in data:
        print(f"{attack['rule_name']}: {attack['detected']} in {attack.get('det_time')}s")
```

---

## Support

For issues:
1. Check that NIDS is running
2. Verify correct target IP (not loopback)
3. Ensure packet capture interface is correct
4. Review NIDS logs for errors
5. Run as Administrator/root

---

**Last Updated:** 2026-03-28
**Version:** 2.0 (Cross-Platform + Payload Attacks)
