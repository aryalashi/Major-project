# Attack Simulator Updates - Cross-Platform & Payload Attacks

## Summary of Changes

The `simulate_attacks.py` has been completely updated to support cross-platform execution, payload attack simulation, and comprehensive logging with timestamps.

---

## 1. **Cross-Platform Support**

### ICMP Ping Command Optimization
- **Before:** Windows-only ping command
- **After:** Detects OS and uses appropriate ping syntax:
  - **Windows:** `ping -n <count> -l <size> -w <timeout> <target>`
  - **Linux/macOS:** `ping -c <count> -s <size> -W <timeout> <target>`

```python
if platform.system() == "Windows":
    ping_cmd = ["ping", "-n", str(duration * 200), "-l", "1400", "-w", "1", target]
else:  # Linux, macOS
    ping_cmd = ["ping", "-c", str(duration * 200), "-s", "1400", "-W", "1", target]
```

### Cross-Platform Path Handling
- Uses `pathlib.Path` for automatic path separator resolution
- Works on Windows (`\`), Linux (`/`), and macOS

---

## 2. **New Payload Attack Functions**

Five new HTTP-based payload attack functions added that work cross-platform:

### a) **SQL Injection Attack** (`sqli`)
- Sends HTTP GET/POST requests with SQL injection payloads
- Payload variations:
  - `user=admin' OR '1'='1`
  - `id=1 UNION SELECT NULL,NULL--`
  - `search=' OR DROP TABLE users--`
  - `username=admin'; DROP TABLE credentials;--`

### b) **XSS Attack** (`xss`)
- Cross-Site Scripting attack in HTTP requests
- Payload variations:
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `<svg onload=alert('XSS')>`
  - `<iframe src="javascript:alert('XSS')">`

### c) **Shellcode Injection** (`shellcode`)
- NOP sled + shellcode pattern simulation
- Sends x86 prologue bytes to detect shellcode injection
- Pattern: `\x90` × 20 + `\x55\x8b\xec\x51\x52`

### d) **Path Traversal Attack** (`path_trav`)
- Directory traversal payload testing
- Payload variations:
  - `../../../etc/passwd` (Unix)
  - `..\..\..\\windows\system32\config\sam` (Windows)
  - `....//....//....//etc/shadow`
  - `../../../../etc/hosts`

### e) **Remote Code Execution** (`rce`)
- Command injection attack simulation
- Payload variations:
  - `; cat /etc/passwd`
  - `| whoami`
  - `; powershell -enc <base64>`
  - Backtick command execution

### HTTP Payload Delivery Method
All payload attacks use the new `send_http_payload()` function:
```python
def send_http_payload(target, port, payload, method="GET", path="/", stop_evt=None):
    """Send HTTP request with malicious payload (cross-platform)."""
    # Uses urllib for maximum compatibility across platforms
```

---

## 3. **Timestamp Logging System**

### Automatic Log File Creation
- **Location:** `logs/attack_simulation_log_<TIMESTAMP>.json`
- **Timestamp Format:** `YYYYMMDD_HHMMSS`
- **Example:** `attack_simulation_log_20260328_205337.json`

### Log Data Structure
Each attack is recorded with:
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

### Logging Functions
- `init_attack_log(base_dir="logs")` - Initialize new timestamped log file
- `log_attack(attack_data)` - Log individual attack with ISO timestamp
- Automatic JSON file updates after each attack

---

## 4. **Updated RULES Dictionary**

New payload attack entries:
```python
"sqli":       ("SQL Injection Attack",  [...], 10, "HTTP GET/POST with SQL injection payload")
"xss":        ("XSS Attack",            [...], 10, "HTTP GET/POST with XSS payload")
"shellcode":  ("Shellcode Injection",   [...], 10, "HTTP POST with NOP sled + shellcode")
"path_trav":  ("Path Traversal Attack", [...], 10, "HTTP GET with path traversal payload")
"rce":        ("Remote Code Execution", [...], 10, "HTTP POST with command injection")
```

---

## 5. **Updated Attack Dispatch Table**

The `ATTACK_FUNCTIONS` dictionary now includes:
```python
"sqli":       attack_sqli,
"xss":        attack_xss,
"shellcode":  attack_shellcode,
"path_trav":  attack_path_trav,
"rce":        attack_rce,
```

---

## 6. **Enhanced Interactive Menu**

New menu category added:
```
── Payload Attacks ──
  sqli
  xss
  shellcode
  path_trav
  rce
```

---

## 7. **Command-Line Usage**

### List All Attacks
```bash
py simulate_attacks.py --list
```

### Run Single Payload Attack
```bash
py simulate_attacks.py --attack sqli
```

### Run Multiple Attacks
```bash
py simulate_attacks.py --attack sqli,xss,rce
```

### Run All Attacks
```bash
py simulate_attacks.py --attack all
```

### Custom Settings
```bash
py simulate_attacks.py --attack sqli --duration 20 --rate 15 --target 192.168.1.5
```

---

## 8. **Features Summary**

| Feature | Support |
|---------|---------|
| **Windows** | ✅ Full support |
| **Linux** | ✅ Full support |
| **macOS** | ✅ Full support |
| **Payload Attacks** | ✅ 5 new types |
| **HTTP Payload Delivery** | ✅ urllib-based |
| **Timestamp Logging** | ✅ ISO 8601 format |
| **JSON Logs** | ✅ Auto-generated |
| **Network Attacks** | ✅ 30+ existing types |
| **Detection Accuracy** | ✅ With timestamps |

---

## 9. **Log File Example**

```json
[
  {
    "sim_arg": "sqli",
    "rule_name": "SQL Injection Attack",
    "detected": true,
    "det_time": 2.3,
    "packets": 15,
    "attack_started_at": "2026-03-28T20:53:37.620025",
    "elapsed_time": 15.4,
    "logged_at": "2026-03-28T20:53:37.620025"
  },
  {
    "sim_arg": "xss",
    "rule_name": "XSS Attack",
    "detected": true,
    "det_time": 1.8,
    "packets": 12,
    "attack_started_at": "2026-03-28T20:53:39.621000",
    "elapsed_time": 15.2,
    "logged_at": "2026-03-28T20:53:39.621000"
  }
]
```

---

## 10. **Backward Compatibility**

✅ All existing network-based attacks remain fully functional
✅ 30+ network DoS/scanning attacks still supported
✅ Brute force attacks unchanged
✅ DDoS multi-source simulation intact

---

## Testing

All payload attacks are readily available for accuracy testing:

```bash
# Test SQL Injection detection
py simulate_attacks.py --attack sqli

# Test XSS detection  
py simulate_attacks.py --attack xss

# Test all payload attacks
py simulate_attacks.py --attack sqli,xss,shellcode,path_trav,rce

# Get complete report with timestamps
py simulate_attacks.py --attack all
```

Each test execution creates a timestamped log file in `logs/` for performance analysis and accuracy tracking.
