"""
simulate_attacks.py
-------------------
Attack simulator for NIDS testing — all 30 detection rules.
Runs attacks from the SAME PC as the NIDS (loopback / local IP).
After each attack, reads nids.log and reports whether the rule fired.

Usage:
    py simulate_attacks.py                          (interactive menu)
    py simulate_attacks.py --attack syn             (single attack)
    py simulate_attacks.py --attack all             (all 30 attacks)
    py simulate_attacks.py --attack syn,udp,icmp    (comma-separated list)
    py simulate_attacks.py --target 192.168.1.X     (different local IP)
    py simulate_attacks.py --duration 15 --rate 120
    py simulate_attacks.py --log logs/nids.log      (custom log path)
    py simulate_attacks.py --list                   (show all attack names)

Requirements:
    pip install scapy
    Run as Administrator (required for raw socket / Scapy)
    Npcap installed on Windows (https://npcap.com)

How same-PC testing works:
    The NIDS sniffer captures packets on the network interface.
    Attacks sent to 127.0.0.1 (loopback) stay inside the OS and are NOT
    captured by Scapy on the real NIC. Instead, use your local LAN IP
    (e.g. 192.168.1.X) as the target so packets travel through the NIC
    and the sniffer sees them. The script auto-detects your local IP.
"""

import socket
import threading
import time
import random
import argparse
import sys
import os
import subprocess
import re
import json
import platform
from datetime import datetime
from itertools import cycle
from pathlib import Path
import urllib.request
import urllib.error

# ------------------------------------------------------------------ #
#  SCAPY IMPORT                                                        #
# ------------------------------------------------------------------ #
try:
    from scapy.all import IP, TCP, UDP, ICMP, send, RandShort
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    IP = TCP = UDP = ICMP = send = RandShort = None

# ------------------------------------------------------------------ #
#  DEFAULTS                                                            #
# ------------------------------------------------------------------ #
DEFAULT_PORT     = 80
DEFAULT_DURATION = 15
DEFAULT_RATE     = 120
DEFAULT_LOG      = "logs/nids.log"
DDOS_SOURCES     = 30
DDOS_RATE        = 20

# ------------------------------------------------------------------ #
#  COLORS (Windows 10+ supports ANSI via os.system('') trick)         #
# ------------------------------------------------------------------ #
if sys.platform == "win32":
    os.system("")   # enable ANSI in Windows terminal

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


# ================================================================== #
#  RULE TABLE  — maps sim_arg → detection keywords + rule name        #
#  Keywords match against lines in nids.log (case-insensitive)        #
# ================================================================== #

RULES = {
    # sim_arg : (rule_name, [keywords_in_log], default_rate, description)
    "syn":        ("TCP SYN Flood",         ["TCP_SYN Flood", "TCP SYN Flood", "SYN Flood"],               120,  "TCP SYN flood to port 80"),
    "udp":        ("UDP Flood",             ["UDP Flood"],                                 120,  "UDP flood to random ports"),
    "icmp":       ("ICMP Flood",            ["ICMP Ping Flood", "ICMP Flood"],                        200,  "ICMP echo flood"),
    "ack":        ("TCP ACK Flood",         ["TCP ACK Flood"],                120,  "TCP ACK flood"),
    "rst":        ("TCP RST Flood",         ["TCP RST Flood"],                120,  "TCP RST flood"),
    "scan":       ("Port Scan Detection",   ["TCP SYN Port Scan", "Port Scan"], 10, "TCP SYN port scan (variety)"),
    "fin_scan":   ("TCP FIN Scan",          ["TCP FIN Scan"],                  10,   "TCP FIN port scan (variety)"),
    "null":       ("TCP NULL Scan",         ["TCP NULL Scan"],                10,   "TCP NULL scan (flags=0)"),
    "xmas":       ("TCP XMAS Scan",         ["TCP XMAS Scan"],               10,   "TCP XMAS scan (FIN+PSH+URG)"),
    "udpscan":    ("UDP Port Scan",         ["UDP Port Scan"],                 10,   "UDP port scan (variety)"),
    "heartbleed": ("Heartbleed Attack",     ["Heartbleed"],                                20,   "Heartbleed (SYN to port 443)"),
    "ftp":        ("FTP Brute Force",       ["FTP Brute Force"],       20,   "FTP brute force (SYN to port 21)"),
    "ssh":        ("SSH Brute Force",       ["SSH Brute Force"],       20,   "SSH brute force (SYN to port 22)"),
    "telnet":     ("Telnet Brute Force",    ["Telnet Brute Force"],                    20,   "Telnet brute force (port 23)"),
    "rdp":        ("RDP Brute Force",       ["RDP Brute Force"],                          20,   "RDP brute force (port 3389)"),
    "http":       ("HTTP Flood",            ["HTTP Flood"],                   100,   "HTTP SYN flood (port 80)"),
    "https":      ("HTTPS Flood",           ["HTTPS Flood"],                 100,   "HTTPS SYN flood (port 443)"),
    "smtp":       ("SMTP Flood",            ["SMTP Flood"],                        30,   "SMTP flood (port 25)"),
    "dns":        ("DNS Amplification",     ["DNS Amplification"],                  50,   "DNS flood (UDP port 53)"),
    "mysql":      ("MySQL Brute Force",     ["MySQL Brute Force"],                      20,   "MySQL brute force (port 3306)"),
    "smb":        ("SMB Flood",             ["SMB Flood"],                          30,   "SMB flood (port 445)"),
    "netbios":    ("NetBIOS Flood",         ["NetBIOS Flood"],                  40,   "NetBIOS flood (UDP 137)"),
    "ldap":       ("LDAP Flood",            ["LDAP Flood"],                        30,   "LDAP flood (port 389)"),
    "mssql":      ("MSSQL Brute Force",     ["MSSQL Brute Force"],                      20,   "MSSQL brute force (port 1433)"),
    "postgres":   ("PostgreSQL Brute Force",["PostgreSQL Brute Force"],20,   "PostgreSQL brute force (port 5432)"),
    "synack":     ("TCP SYN-ACK Flood",     ["SYN-ACK FLOOD", "SYNACK", "SYN ACK"],       100,   "TCP SYN-ACK flood"),
    "fin_flood":  ("TCP FIN Flood",         ["FIN FLOOD", "TCP FIN FLOOD"],               100,   "TCP FIN flood (high rate)"),
    "psh_ack":    ("TCP PSH-ACK Flood",     ["PSH-ACK FLOOD", "PSHACK", "PSH ACK"],       100,   "TCP PSH+ACK flood"),
    "winrm":      ("WinRM Brute Force",     ["WINRM BRUTE", "WINRM"],                      20,   "WinRM brute force (port 5985)"),
    "elastic":    ("Elasticsearch Attack",  ["ELASTICSEARCH", "ELASTIC"],                  20,   "Elasticsearch attack (port 9200)"),
    "ddos":       ("DDoS Multi-Source",     ["DDOS", "MULTI-SOURCE", "UNIQUE IPS",
                                             "UNIQUE SOURCE"],                            600,   "DDoS from 30 spoofed sources"),
    "sqli":       ("SQL Injection Attack",  ["SQL INJECTION", "SQLI", "Payload Attack"], 10,   "HTTP GET/POST with SQL injection payload"),
    "xss":        ("XSS Attack",            ["XSS", "CROSS-SITE SCRIPTING", "Payload Attack"], 10,   "HTTP GET/POST with XSS payload"),
    "shellcode":  ("Shellcode Injection",   ["Shellcode", "SHELL CODE", "Payload Attack"],      10,   "HTTP POST with NOP sled + shellcode"),
    "path_trav":  ("Path Traversal Attack", ["PATH TRAVERSAL", "DIRECTORY TRAVERSAL", "Payload Attack"], 10,   "HTTP GET with path traversal payload"),
    "rce":        ("Remote Code Execution", ["RCE", "REMOTE CODE EXECUTION", "Payload Attack"], 10,   "HTTP POST with command injection"),
    "normal":     ("Normal Traffic",        ["NORMAL TRAFFIC"],                            50,   "Benign traffic (HTTP/HTTPS/DNS/SSH) — should NOT trigger alerts"),
}

# ================================================================== #
#  UTILITY                                                             #
# ================================================================== #

def get_local_ip() -> str:
    """Get the machine's LAN IP address (not loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_last_capture_interface(log_path: str) -> str:
    """
    Parse nids.log and return the most recent capture interface string.
    Example line:
            Capture started on interface: \\Device\\NPF_{GUID}
    """
    try:
        if not os.path.exists(log_path):
            return ""
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for line in reversed(lines):
            m = re.search(r"Capture started on interface:\s*(.+)$", line)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return ""


def _is_loopback_iface(iface: str) -> bool:
    if not iface:
        return False
    return "loopback" in iface.lower()


def get_log_pos(log_path: str) -> int:
    """Return current end-of-file position in nids.log."""
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                return f.tell()
    except Exception:
        pass
    return 0


def read_new_log_lines(log_path: str, from_pos: int):
    """
    Read only NEW lines written to nids.log since from_pos.
    Returns (new_lines, new_pos).
    """
    lines = []
    new_pos = from_pos
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(from_pos)
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
                new_pos = f.tell()
    except Exception:
        pass
    return lines, new_pos


def check_log_for_detection(log_path: str, from_pos: int,
                             keywords: list, deadline: float):
    """
    Poll nids.log until deadline or until a keyword match is found.
    Returns (detected: bool, det_time: float, matched_line: str, new_pos: int)
    """
    pos = from_pos
    while time.time() < deadline:
        lines, pos = read_new_log_lines(log_path, pos)
        for line in lines:
            upper = line.upper()
            for kw in keywords:
                if kw.upper() in upper:
                    # Make sure it is an actual alert line
                    if ("ALERT" in upper or "WARNING" in upper or
                            "DETECT" in upper):
                        return True, line, pos
        time.sleep(0.3)
    return False, "", pos


def is_nids_capturing(log_path: str) -> bool:
    """
    Check if NIDS is actively capturing packets.
    Returns True if log shows "capture started" without "stopped".
    """
    if not os.path.exists(log_path):
        return False
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        
        # Count capture start/stop events in reverse
        for line in reversed(lines[-100:]):  # Check last 100 lines
            if "Capture started" in line:
                return True
            elif "Packet capture stopped" in line or "Capture stopped" in line:
                return False
        
        return False
    except Exception:
        return False


def print_banner():
    print(f"\n{CYAN}{'='*62}{RESET}")
    print(f"{CYAN}  NIDS ATTACK SIMULATOR — All 30 Rules  {RESET}")
    print(f"{CYAN}  Tests attacks from this PC and checks nids.log{RESET}")
    print(f"{CYAN}{'='*62}{RESET}")
    print(f"  Scapy  : {GREEN+'YES (raw packets)'+RESET if SCAPY_OK else RED+'NO  (socket fallback — limited)'+RESET}")
    print(f"  NOTE   : Targeting your own IP can be routed to loopback on Windows")
    print(f"           Ensure NIDS capture interface matches the traffic path")
    print(f"{CYAN}{'-'*62}{RESET}\n")


def _send_loop(pkt_fn, duration: float, rate: int, stop_evt):
    """
    Generic packet send loop.
    pkt_fn() must return a Scapy packet or None (to skip).
    """
    end  = time.time() + duration
    sent = 0
    delay = 1.0 / max(rate, 1)
    while time.time() < end and not stop_evt.is_set():
        try:
            pkt = pkt_fn()
            if pkt is not None:
                send(pkt, verbose=False)
                sent += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


def _port_variety_loop(pkt_fn, duration: float, rate: int, stop_evt):
    """
    Send loop that cycles through ports 1-1024 sequentially.
    pkt_fn(port) must return a Scapy packet.
    Used for all scan-type rules (port_variety=true).
    """
    end   = time.time() + duration
    ports = list(range(1, 1025))
    delay = 1.0 / max(rate, 1)
    sent  = 0
    idx   = 0
    while time.time() < end and not stop_evt.is_set():
        try:
            port = ports[idx % len(ports)]
            pkt  = pkt_fn(port)
            if pkt is not None:
                send(pkt, verbose=False)
                sent += 1
            idx  += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


# ================================================================== #
#  30 ATTACK FUNCTIONS                                                 #
# ================================================================== #

def attack_syn(target, duration, rate, stop_evt):
    """TCP SYN Flood — flags='S'"""
    if not SCAPY_OK:
        # Socket fallback
        end = time.time() + duration
        sent = 0
        while time.time() < end and not stop_evt.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                s.connect_ex((target, DEFAULT_PORT))
                s.close()
                sent += 1
                time.sleep(1/rate)
            except Exception:
                pass
        return sent
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=DEFAULT_PORT,
            flags="S", seq=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_udp(target, duration, rate, stop_evt):
    """UDP Flood — random destination ports"""
    if not SCAPY_OK:
        end = time.time() + duration
        sent = 0
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 512
        while time.time() < end and not stop_evt.is_set():
            try:
                s.sendto(payload, (target, random.randint(1, 65535)))
                sent += 1
                time.sleep(1/rate)
            except Exception:
                pass
        s.close()
        return sent
    return _send_loop(
        lambda: IP(dst=target)/UDP(
            sport=RandShort(), dport=random.randint(1, 65535)
        ),
        duration, rate, stop_evt
    )


def attack_icmp(target, duration, rate, stop_evt):
    """ICMP Flood — echo request storm (cross-platform)"""
    ping_proc = None
    try:
        # Cross-platform ping command
        if platform.system() == "Windows":
            ping_cmd = ["ping", "-n", str(duration * 200), "-l", "1400", "-w", "1", target]
        else:  # Linux, macOS
            ping_cmd = ["ping", "-c", str(duration * 200), "-s", "1400", "-W", "1", target]
        
        ping_proc = subprocess.Popen(
            ping_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass
    sent = 0
    if SCAPY_OK:
        sent = _send_loop(
            lambda: IP(dst=target)/ICMP(),
            duration, rate, stop_evt
        )
    else:
        time.sleep(duration)
    if ping_proc:
        try:
            ping_proc.terminate()
        except Exception:
            pass
    return sent


def attack_ack(target, duration, rate, stop_evt):
    """TCP ACK Flood — flags='A'"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=DEFAULT_PORT, flags="A",
            seq=random.randint(0, 2**32-1),
            ack=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_rst(target, duration, rate, stop_evt):
    """TCP RST Flood — flags='R'"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=DEFAULT_PORT, flags="R",
            seq=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_scan(target, duration, rate, stop_evt):
    """TCP SYN Port Scan — flags='S', cycles ports 1-1024"""
    if not SCAPY_OK:
        # Socket fallback for port scan
        end = time.time() + duration
        sent = 0
        ports = list(range(1, 1025))
        idx = 0
        while time.time() < end and not stop_evt.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.02)
                s.connect_ex((target, ports[idx % len(ports)]))
                s.close()
                sent += 1
                idx += 1
                time.sleep(1/rate)
            except Exception:
                idx += 1
        return sent
    return _port_variety_loop(
        lambda p: IP(dst=target)/TCP(sport=RandShort(), dport=p, flags="S"),
        duration, rate, stop_evt
    )


def attack_fin_scan(target, duration, rate, stop_evt):
    """TCP FIN Scan — flags='F', port variety"""
    if not SCAPY_OK:
        return 0
    return _port_variety_loop(
        lambda p: IP(dst=target)/TCP(sport=RandShort(), dport=p, flags="F"),
        duration, rate, stop_evt
    )


def attack_null(target, duration, rate, stop_evt):
    """
    TCP NULL Scan — flags=0 (no flags set).
    packet_capture.py decodes this as flags='' (empty string).
    The detection rule must have flags='' and the NULL scan bug
    in detection.py must be fixed (use `if rule.get('flags') is not None`).
    """
    if not SCAPY_OK:
        return 0
    return _port_variety_loop(
        lambda p: IP(dst=target)/TCP(sport=RandShort(), dport=p, flags=0),
        duration, rate, stop_evt
    )


def attack_xmas(target, duration, rate, stop_evt):
    """
    TCP XMAS Scan — FIN + PSH + URG flags.
    packet_capture.py decodes these flags in order S,A,R,F,P,U
    so FIN+PSH+URG produces the string 'FPU'.
    Rule in rules.json must have flags='FPU'.
    """
    if not SCAPY_OK:
        return 0
    return _port_variety_loop(
        lambda p: IP(dst=target)/TCP(
            sport=RandShort(), dport=p, flags="FPU"
        ),
        duration, rate, stop_evt
    )


def attack_udpscan(target, duration, rate, stop_evt):
    """UDP Port Scan — UDP, cycles ports 1-1024"""
    if not SCAPY_OK:
        return 0
    return _port_variety_loop(
        lambda p: IP(dst=target)/UDP(sport=RandShort(), dport=p),
        duration, rate, stop_evt
    )


def attack_heartbleed(target, duration, rate, stop_evt):
    """Heartbleed Attack — TCP SYN to port 443"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=443, flags="S",
            seq=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_ftp(target, duration, rate, stop_evt):
    """FTP Brute Force — TCP SYN to port 21"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=21, flags="S"),
        duration, rate, stop_evt
    )


def attack_ssh(target, duration, rate, stop_evt):
    """SSH Brute Force — TCP SYN to port 22"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=22, flags="S"),
        duration, rate, stop_evt
    )


def attack_telnet(target, duration, rate, stop_evt):
    """Telnet Brute Force — TCP SYN to port 23"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=23, flags="S"),
        duration, rate, stop_evt
    )


def attack_rdp(target, duration, rate, stop_evt):
    """RDP Brute Force — TCP SYN to port 3389"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=3389, flags="S"),
        duration, rate, stop_evt
    )


def attack_http(target, duration, rate, stop_evt):
    """HTTP Flood — TCP SYN to port 80"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=80, flags="S",
                                   seq=random.randint(0, 2**32-1)),
        duration, rate, stop_evt
    )


def attack_https(target, duration, rate, stop_evt):
    """HTTPS Flood — TCP SYN to port 443"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=443, flags="S",
                                   seq=random.randint(0, 2**32-1)),
        duration, rate, stop_evt
    )


def attack_smtp(target, duration, rate, stop_evt):
    """SMTP Flood — TCP SYN to port 25"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=25, flags="S"),
        duration, rate, stop_evt
    )


def attack_dns(target, duration, rate, stop_evt):
    """DNS Amplification — UDP to port 53"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/UDP(sport=RandShort(), dport=53)/b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        duration, rate, stop_evt
    )


def attack_mysql(target, duration, rate, stop_evt):
    """MySQL Brute Force — TCP SYN to port 3306"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=3306, flags="S"),
        duration, rate, stop_evt
    )


def attack_smb(target, duration, rate, stop_evt):
    """SMB Flood — TCP SYN to port 445"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=445, flags="S"),
        duration, rate, stop_evt
    )


def attack_netbios(target, duration, rate, stop_evt):
    """NetBIOS Flood — UDP to port 137"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/UDP(sport=RandShort(), dport=137)/b"\x00" * 16,
        duration, rate, stop_evt
    )


def attack_ldap(target, duration, rate, stop_evt):
    """LDAP Flood — TCP SYN to port 389"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=389, flags="S"),
        duration, rate, stop_evt
    )


def attack_mssql(target, duration, rate, stop_evt):
    """MSSQL Brute Force — TCP SYN to port 1433"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=1433, flags="S"),
        duration, rate, stop_evt
    )


def attack_postgres(target, duration, rate, stop_evt):
    """PostgreSQL Brute Force — TCP SYN to port 5432"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=5432, flags="S"),
        duration, rate, stop_evt
    )


def attack_synack(target, duration, rate, stop_evt):
    """TCP SYN-ACK Flood — flags='SA'"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=DEFAULT_PORT, flags="SA",
            seq=random.randint(0, 2**32-1),
            ack=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_fin_flood(target, duration, rate, stop_evt):
    """TCP FIN Flood — flags='F' at high rate (NOT port scan)"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=DEFAULT_PORT, flags="F",
            seq=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_psh_ack(target, duration, rate, stop_evt):
    """TCP PSH-ACK Flood — flags='PA'"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(
            sport=RandShort(), dport=DEFAULT_PORT, flags="PA",
            seq=random.randint(0, 2**32-1),
            ack=random.randint(0, 2**32-1)
        ),
        duration, rate, stop_evt
    )


def attack_winrm(target, duration, rate, stop_evt):
    """WinRM Brute Force — TCP SYN to port 5985"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=5985, flags="S"),
        duration, rate, stop_evt
    )


def attack_elastic(target, duration, rate, stop_evt):
    """Elasticsearch Attack — TCP SYN to port 9200"""
    if not SCAPY_OK:
        return 0
    return _send_loop(
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=9200, flags="S"),
        duration, rate, stop_evt
    )


def send_http_payload(target, port, payload, method="GET", path="/", stop_evt=None):
    """
    Send HTTP request with malicious payload (cross-platform).
    Works with raw sockets or urllib for maximum compatibility.
    """
    sent = 0
    try:
        if method == "GET":
            url = f"http://{target}:{port}{path}?{payload}"
        else:
            url = f"http://{target}:{port}{path}"
        
        req = urllib.request.Request(
            url,
            data=payload.encode() if method == "POST" else None,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            urllib.request.urlopen(req, timeout=1)
            sent = 1
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            sent = 1  # Count as sent even if target doesn't respond
    except Exception:
        pass
    return sent


def attack_sqli(target, duration, rate, stop_evt):
    """SQL Injection Attack — HTTP GET/POST with SQLi payload"""
    sql_payloads = [
        "user=admin' OR '1'='1",
        "id=1 UNION SELECT NULL,NULL--",
        "search=' OR DROP TABLE users--",
        "username=admin'; DROP TABLE credentials;--",
    ]
    
    end = time.time() + duration
    sent = 0
    delay = 1.0 / max(rate, 1)
    idx = 0
    
    while time.time() < end and not stop_evt.is_set():
        try:
            payload = sql_payloads[idx % len(sql_payloads)]
            send_http_payload(target, 80, payload, method="GET")
            sent += 1
            idx += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


def attack_xss(target, duration, rate, stop_evt):
    """XSS Attack — HTTP GET/POST with XSS payload"""
    xss_payloads = [
        "comment=<script>alert('XSS')</script>",
        "search=<img src=x onerror=alert('XSS')>",
        "message=<svg onload=alert('XSS')>",
        "input=<iframe src=\"javascript:alert('XSS')\">",
    ]
    
    end = time.time() + duration
    sent = 0
    delay = 1.0 / max(rate, 1)
    idx = 0
    
    while time.time() < end and not stop_evt.is_set():
        try:
            payload = xss_payloads[idx % len(xss_payloads)]
            send_http_payload(target, 80, payload, method="POST")
            sent += 1
            idx += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


def attack_shellcode(target, duration, rate, stop_evt):
    """Shellcode Injection — HTTP POST with NOP sled + shellcode pattern"""
    # Simulate NOP sled (0x90 repeated 20 times) + shellcode marker
    nop_sled = "\\x90" * 20
    shellcode_marker = "\\x55\\x8b\\xec\\x51\\x52"  # Common x86 prologue
    
    end = time.time() + duration
    sent = 0
    delay = 1.0 / max(rate, 1)
    
    while time.time() < end and not stop_evt.is_set():
        try:
            payload = f"data={nop_sled}{shellcode_marker}&buffer_size=4096"
            send_http_payload(target, 80, payload, method="POST", path="/upload")
            sent += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


def attack_path_trav(target, duration, rate, stop_evt):
    """Path Traversal Attack — HTTP GET with directory traversal"""
    trav_payloads = [
        "file=../../../etc/passwd",
        "path=..\\..\\..\\windows\\system32\\config\\sam",
        "include=....//....//....//etc/shadow",
        "dir=../../../../etc/hosts",
    ]
    
    end = time.time() + duration
    sent = 0
    delay = 1.0 / max(rate, 1)
    idx = 0
    
    while time.time() < end and not stop_evt.is_set():
        try:
            payload = trav_payloads[idx % len(trav_payloads)]
            send_http_payload(target, 80, payload, method="GET")
            sent += 1
            idx += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


def attack_rce(target, duration, rate, stop_evt):
    """Remote Code Execution — HTTP POST with command injection"""
    rce_payloads = [
        "cmd=; cat /etc/passwd",
        "command=| whoami",
        "input=; powershell -enc QQBkAGQALQBQAHMARABJAG4AdABlAHIAaQBvAHI=",
        "exec=`id`",
    ]
    
    end = time.time() + duration
    sent = 0
    delay = 1.0 / max(rate, 1)
    idx = 0
    
    while time.time() < end and not stop_evt.is_set():
        try:
            payload = rce_payloads[idx % len(rce_payloads)]
            send_http_payload(target, 80, payload, method="POST", path="/execute")
            sent += 1
            idx += 1
            time.sleep(delay)
        except Exception:
            pass
    return sent


def attack_ddos(target, duration, rate, stop_evt):
    """
    DDoS Multi-Source Simulation.
    Spawns 30 threads each spoofing a different source IP.
    Requires Scapy for IP spoofing.
    """
    if not SCAPY_OK:
        print(f"  {YELLOW}[DDoS] Scapy required for IP spoofing. Running SYN flood instead.{RESET}")
        return attack_syn(target, duration, rate, stop_evt)

    num_sources = DDOS_SOURCES
    total = [0]
    lock  = threading.Lock()

    def make_ip(i):
        if i < 10:  return f"10.10.{i+1}.{random.randint(10,250)}"
        if i < 20:  return f"10.20.{i-9}.{random.randint(10,250)}"
        return          f"172.16.{i-19}.{random.randint(10,250)}"

    spoof_ips = [make_ip(i) for i in range(num_sources)]

    def worker(src_ip):
        while not stop_evt.is_set():
            try:
                send(IP(src=src_ip, dst=target)/TCP(
                    sport=RandShort(), dport=80, flags="S",
                    seq=random.randint(0, 2**32-1)
                ), verbose=False)
                with lock:
                    total[0] += 1
                time.sleep(1.0 / DDOS_RATE)
            except Exception:
                pass

    threads = [
        threading.Thread(target=worker, args=(ip,), daemon=True)
        for ip in spoof_ips
    ]
    for t in threads:
        t.start()
        time.sleep(0.01)

    time.sleep(duration)
    stop_evt.set()
    for t in threads:
        t.join(timeout=3)
    return total[0]


def generate_normal_traffic(target, duration, rate, stop_evt):
    """
    Generate benign/normal traffic to test false positive rates.
    Mimics legitimate user activities (HTTP, HTTPS, DNS, SSH, etc.)
    with moderate packet rates that shouldn't trigger detection rules.
    
    Mix of traffic types:
      - HTTP GET requests (port 80)
      - HTTPS connections (port 443)
      - DNS queries (UDP port 53)
      - SSH connections (port 22)
      - Occasional ACK packets from established connections
    """
    if not SCAPY_OK:
        print(f"  {YELLOW}[Normal Traffic] Scapy required. Using socket fallback.{RESET}")
        # Fallback: just wait without sending packets
        time.sleep(duration)
        return 0

    sent = 0
    end_time = time.time() + duration
    
    # Define benign traffic patterns
    traffic_patterns = [
        # HTTP traffic (port 80)
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=80, flags="S"),
        # HTTPS traffic (port 443)
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=443, flags="S"),
        # DNS queries (port 53 UDP)
        lambda: IP(dst=target)/UDP(sport=RandShort(), dport=53),
        # SSH connections (port 22)
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=22, flags="S"),
        # ACK packets from established connections (simulated)
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=random.choice([80, 443, 22]), flags="A"),
        # HTTP traffic to alternate target
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=8080, flags="S"),
        # SMTP traffic (port 25)
        lambda: IP(dst=target)/TCP(sport=RandShort(), dport=25, flags="S"),
    ]
    
    packet_delay = 1.0 / max(rate, 1)
    pattern_idx = 0
    
    while time.time() < end_time and not stop_evt.is_set():
        try:
            # Cycle through traffic patterns
            pkt_fn = traffic_patterns[pattern_idx % len(traffic_patterns)]
            pkt = pkt_fn()
            
            send(pkt, verbose=False)
            sent += 1
            pattern_idx += 1
            
            time.sleep(packet_delay)
        except Exception:
            pass
    
    return sent

# ================================================================== #
#  ATTACK DISPATCH TABLE                                               #
# ================================================================== #

ATTACK_FUNCTIONS = {
    "syn":        attack_syn,
    "udp":        attack_udp,
    "icmp":       attack_icmp,
    "ack":        attack_ack,
    "rst":        attack_rst,
    "scan":       attack_scan,
    "fin_scan":   attack_fin_scan,
    "null":       attack_null,
    "xmas":       attack_xmas,
    "udpscan":    attack_udpscan,
    "heartbleed": attack_heartbleed,
    "ftp":        attack_ftp,
    "ssh":        attack_ssh,
    "telnet":     attack_telnet,
    "rdp":        attack_rdp,
    "http":       attack_http,
    "https":      attack_https,
    "smtp":       attack_smtp,
    "dns":        attack_dns,
    "mysql":      attack_mysql,
    "smb":        attack_smb,
    "netbios":    attack_netbios,
    "ldap":       attack_ldap,
    "mssql":      attack_mssql,
    "postgres":   attack_postgres,
    "synack":     attack_synack,
    "fin_flood":  attack_fin_flood,
    "psh_ack":    attack_psh_ack,
    "winrm":      attack_winrm,
    "elastic":    attack_elastic,
    "ddos":       attack_ddos,
    "sqli":       attack_sqli,
    "xss":        attack_xss,
    "shellcode":  attack_shellcode,
    "path_trav":  attack_path_trav,
    "rce":        attack_rce,
    "normal":     generate_normal_traffic,
}

# ================================================================== #
#  SINGLE ATTACK RUNNER WITH LOG CHECK                                 #
# ================================================================== #

# Global logging dictionary
ATTACK_LOG = []
LOG_FILE_PATH = None

def init_attack_log(base_dir="logs"):
    """Initialize attack logging with timestamp."""
    global LOG_FILE_PATH
    
    # Create logs directory if it doesn't exist
    log_dir = Path(base_dir)
    log_dir.mkdir(exist_ok=True)
    
    # Create timestamped log file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    LOG_FILE_PATH = log_dir / f"attack_simulation_log_{timestamp}.json"
    
    return LOG_FILE_PATH

def log_attack(attack_data):
    """Log attack to both memory and file."""
    global ATTACK_LOG, LOG_FILE_PATH
    
    # Add timestamp to attack data
    attack_data['logged_at'] = datetime.now().isoformat()
    
    ATTACK_LOG.append(attack_data)
    
    # Also write to file immediately
    if LOG_FILE_PATH:
        try:
            with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(ATTACK_LOG, f, indent=2)
        except Exception as e:
            print(f"  {YELLOW}Warning: Could not write to log file: {e}{RESET}")

def run_attack(sim_arg: str, target: str, duration: int,
               rate: int, log_path: str) -> dict:
    """
    Run one attack and check nids.log for detection.

    Returns a result dict:
      {
        "sim_arg":   str,
        "rule_name": str,
        "detected":  bool,
        "det_time":  float or None,   # seconds from attack start to detection
        "log_line":  str,             # matching log line
        "packets":   int,             # packets sent
        "duration":  int,
      }
    """
    rule_name, keywords, default_rate, desc = RULES[sim_arg]
    attack_fn = ATTACK_FUNCTIONS[sim_arg]
    use_rate = rate if rate != DEFAULT_RATE else default_rate

    print(f"\n  {CYAN}{'─'*58}{RESET}")
    print(f"  {BOLD}ATTACK:{RESET} {rule_name}")
    print(f"  {DIM}Method : {desc}{RESET}")
    print(f"  {DIM}Target : {target}  Rate: {use_rate} pkt/s  Duration: {duration}s{RESET}")

    # Record log position BEFORE starting
    log_pos    = get_log_pos(log_path)
    attack_start_time = datetime.now().isoformat()
    start_time = time.time()
    stop_evt   = threading.Event()
    packets    = [0]

    # Run attack in background thread so we can watch log simultaneously
    def attack_thread():
        packets[0] = attack_fn(target, duration, use_rate, stop_evt)

    t = threading.Thread(target=attack_thread, daemon=True)
    t.start()

    # Watch log for detection
    # Give extra time after attack for NIDS to process remaining packets
    extra_wait = 25
    if "scan" in sim_arg or "null" in sim_arg or "xmas" in sim_arg:
        extra_wait = 40  # scan rules take longer
    if sim_arg == "ddos":
        extra_wait = 45
    if sim_arg == "icmp":
        extra_wait = 35

    deadline   = start_time + duration + extra_wait
    detected   = False
    det_time   = None
    match_line = ""
    log_pos_now = log_pos

    print(f"  {DIM}Watching nids.log for: {keywords[:2]}...{RESET}")

    # Special handling for normal traffic: should NOT trigger alerts
    if sim_arg == "normal":
        print(f"  {DIM}(Benign traffic - looking for false positives){RESET}")
        alert_keywords = ["ALERT", "WARNING", "DETECTION"]  # Look for ANY alerts
    else:
        alert_keywords = keywords  # Look for specific attack keywords

    while time.time() < deadline:
        new_lines, log_pos_now = read_new_log_lines(log_path, log_pos_now)
        for line in new_lines:
            upper = line.upper()
            
            # For normal traffic, ANY alert is a false positive
            if sim_arg == "normal":
                if "ALERT" in upper or "WARNING: [ALERT]" in upper:
                    detected   = True  # False positive detected
                    det_time   = time.time() - start_time
                    match_line = line
                    break
            else:
                # For attacks, look for matching keywords
                for kw in keywords:
                    if kw.upper() in upper and ("ALERT" in upper or "WARNING" in upper):
                        detected   = True
                        det_time   = time.time() - start_time
                        match_line = line
                        break
            if detected:
                break
        if detected:
            break

        rem = deadline - time.time()
        elapsed = time.time() - start_time
        status = "GENERATING" if elapsed < duration else "MONITORING"
        print(f"\r  {DIM}[{status}] {elapsed:.0f}s elapsed, {rem:.0f}s remaining...  {RESET}",
              end="", flush=True)
        time.sleep(0.5)

    print()  # newline after \r

    # Stop attack thread if still running
    stop_evt.set()
    t.join(timeout=5)

    # Print result (different for normal traffic vs attacks)
    if sim_arg == "normal":
        # For normal traffic: NOT DETECTED = good (no false positives)
        #                    DETECTED = bad (false positive)
        if detected:
            print(f"  {YELLOW}⚠️  FALSE POSITIVE ALERT in {det_time:.1f}s{RESET}")
            print(f"  {DIM}Log: {match_line[:100]}{RESET}")
        else:
            print(f"  {GREEN}✅  CLEAN (no alerts){RESET}")
            print(f"  {DIM}Benign traffic generated no false positive alerts{RESET}")
    else:
        # For attacks: DETECTED = good, NOT DETECTED = bad
        if detected:
            print(f"  {GREEN}✅  DETECTED  in {det_time:.1f}s{RESET}")
            print(f"  {DIM}Log: {match_line[:100]}{RESET}")
        else:
            print(f"  {RED}❌  NOT DETECTED  (waited {extra_wait}s after attack){RESET}")
            if not SCAPY_OK and sim_arg not in ("syn", "udp", "icmp", "scan", "normal"):
                print(f"  {YELLOW}⚠️  Scapy not available — this attack requires Scapy{RESET}")

    result = {
        "sim_arg":   sim_arg,
        "rule_name": rule_name,
        "detected":  detected,
        "det_time":  det_time,
        "log_line":  match_line,
        "packets":   packets[0],
        "duration":  duration,
        "attack_started_at": attack_start_time,
        "elapsed_time": time.time() - start_time,
    }
    
    # Log the attack result
    log_attack(result)
    
    return result


# ================================================================== #
#  RESULTS REPORT                                                      #
# ================================================================== #

def generate_confusion_matrix(results: list):
    """
    Generate confusion matrix for all attacks.
    For single-attack testing:
      TP (True Positive)  = attack ran & was detected
      FN (False Negative) = attack ran & was NOT detected
      FP (False Positive) = benign traffic triggered alert (if "normal" traffic included)
      TN (True Negative)  = benign traffic did NOT trigger alert (part of FN count for normal)
    """
    # Separate normal traffic from attack results
    normal_results = [r for r in results if r["sim_arg"] == "normal"]
    attack_results = [r for r in results if r["sim_arg"] != "normal"]
    
    # Attacks: TP if detected, FN if not
    tp = sum(1 for r in attack_results if r["detected"])
    fn = sum(1 for r in attack_results if not r["detected"])
    
    # Normal traffic: FP if detected (false positive), else success (counted in TN)
    fp = sum(1 for r in normal_results if r["detected"])
    tn = sum(1 for r in normal_results if not r["detected"])
    
    return {
        "TP": tp,
        "FN": fn,
        "FP": fp,
        "TN": tn,
        "total": len(attack_results),  # Only count attacks in main total
        "normal_total": len(normal_results),
    }


def print_confusion_matrix(cm: dict):
    """Print a nicely formatted confusion matrix."""
    tp = cm["TP"]
    fn = cm["FN"]
    fp = cm.get("FP", 0)
    tn = cm.get("TN", 0)
    total = cm["total"]
    normal_total = cm.get("normal_total", 0)
    
    sensitivity = 100 * tp / total if total > 0 else 0
    
    print(f"\n{CYAN}{'='*62}{RESET}")
    print(f"{CYAN}{BOLD}  CONFUSION MATRIX{RESET}")
    print(f"{CYAN}{'='*62}{RESET}")
    print()
    
    if normal_total > 0:
        # Include benign traffic results
        print(f"  {BOLD}Attack Detection Performance:{RESET}")
        print(f"  {DIM}({total} attack rules + {normal_total} benign traffic){RESET}")
        print()
        print(f"  {'':30} {'Predicted Positive':<22}")
        print(f"  {'-'*54}")
        print(f"  {'Actual Positive':<30} {GREEN}{tp:>20}{RESET}")
        print()
        print(f"  {'-'*54}")
        print(f"  True Positive (TP)        : {GREEN}{tp:>2}{RESET} attacks correctly detected")
        print(f"  False Negative (FN)       : {RED}{fn:>2}{RESET} attacks missed")
        print(f"  False Positive (FP)       : {RED}{fp:>2}{RESET} benign traffic triggers alert")
        print(f"  True Negative (TN)        : {GREEN}{tn:>2}{RESET} benign traffic clean")
        print()
        print(f"  {CYAN}{BOLD}Performance Metrics:{RESET}")
        print(f"    • Attack Detection      : {GREEN}{sensitivity:.1f}%{RESET}  ({tp}/{total} attacks detected)")
        if normal_total > 0:
            false_positive_rate = 100 * fp / normal_total if normal_total > 0 else 0
            print(f"    • False Positive Rate   : {RED if fp > 0 else GREEN}{false_positive_rate:.1f}%{RESET}  ({fp}/{normal_total} benign alerts)")
    else:
        # Original format for attack-only tests
        print(f"  {BOLD}Predicted vs Actual{RESET}")
        print(f"  {DIM}(Attack detection test mode){RESET}")
        print()
        print(f"  {'':30} {'Predicted Positive':<22}")
        print(f"  {'-'*54}")
        print(f"  {'Actual Positive':<30} {GREEN}{tp:>20}{RESET}")
        print()
        print(f"  {'-'*54}")
        print(f"  True Positive (TP)        : {GREEN}{tp:>2}{RESET} attacks correctly detected")
        print(f"  False Negative (FN)       : {RED}{fn:>2}{RESET} attacks missed")
        print()
        print(f"  {CYAN}{BOLD}Performance Metrics:{RESET}")
        print(f"    • Sensitivity/Recall  : {GREEN}{sensitivity:.1f}%{RESET}  (TP / (TP+FN))")
        print(f"    • Accuracy            : {GREEN}{sensitivity:.1f}%{RESET}  (Correct / Total)")
    print(f"{CYAN}{'═'*62}{RESET}\n")


def print_report(results: list):
    """Print a summary table of all test results."""
    if not results:
        return

    # Separate attack and normal traffic results
    attack_results = [r for r in results if r["sim_arg"] != "normal"]
    normal_results = [r for r in results if r["sim_arg"] == "normal"]
    
    total    = len(attack_results)
    detected = sum(1 for r in attack_results if r["detected"])
    rate_pct = 100 * detected / total if total > 0 else 0

    print(f"\n{CYAN}{'='*62}{RESET}")
    print(f"{CYAN}{BOLD}  TEST RESULTS SUMMARY{RESET}")
    print(f"{CYAN}{'='*62}{RESET}")
    print(f"  {'RULE NAME':<35} {'RESULT':<10} {'TIME':<8}")
    print(f"  {'─'*35} {'─'*10} {'─'*8}")

    # Display attack results
    for r in attack_results:
        if r["detected"]:
            res = f"{GREEN}DETECTED{RESET}"
            t   = f"{r['det_time']:.1f}s" if r["det_time"] else "—"
        else:
            res = f"{RED}MISSED  {RESET}"
            t   = "—"
        name = r["rule_name"][:34]
        print(f"  {name:<35} {res}   {DIM}{t}{RESET}")
    
    # Display normal traffic results
    for r in normal_results:
        if r["detected"]:
            res = f"{RED}ALERT(FP){RESET}"
            t   = f"{r['det_time']:.1f}s" if r["det_time"] else "—"
        else:
            res = f"{GREEN}CLEAN   {RESET}"
            t   = "—"
        name = r["rule_name"][:34]
        print(f"  {name:<35} {res}   {DIM}{t}{RESET}")

    print(f"\n{CYAN}{'─'*62}{RESET}")
    color = GREEN if rate_pct >= 80 else YELLOW if rate_pct >= 50 else RED
    print(f"  Attack Detection: {color}{BOLD}{detected}/{total}  ({rate_pct:.0f}%){RESET}")
    
    if normal_results:
        false_pos = sum(1 for r in normal_results if r["detected"])
        false_pos_color = RED if false_pos > 0 else GREEN
        print(f"  False Positive Rate: {false_pos_color}{BOLD}{false_pos}/{len(normal_results)}{RESET}")

    if detected < total:
        print(f"\n  {YELLOW}Missed rules — possible causes:{RESET}")
        for r in attack_results:
            if not r["detected"]:
                print(f"  {RED}  •  {r['rule_name']}{RESET}")
                print(f"       → Check rules.json for rule definition")
                print(f"       → NIDS may not be capturing on this interface")
                print(f"       → Scapy not available (this attack needs raw packets)")
                print(f"       → Target IP is loopback (use your LAN IP, not 127.0.0.1)")
    
    if normal_results:
        false_pos = sum(1 for r in normal_results if r["detected"])
        if false_pos > 0:
            print(f"\n  {YELLOW}False Positive Alerts - Normal Traffic triggered detection:{RESET}")
            for r in normal_results:
                if r["detected"]:
                    print(f"  {RED}  •  {r['rule_name']}{RESET}")
    
    print(f"{CYAN}{'='*62}{RESET}\n")

    # Generate and display confusion matrix
    cm = generate_confusion_matrix(results)
    print_confusion_matrix(cm)

    # Save report to file
    report_path = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"{'='*62}\n")
            f.write(f"NIDS ATTACK SIMULATOR - TEST REPORT\n")
            f.write(f"{'='*62}\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total attacks: {total}\n")
            f.write(f"Detection rate: {detected}/{total} ({rate_pct:.0f}%)\n\n")
            f.write(f"-"*62 + "\n")
            f.write(f"DETAILED RESULTS\n")
            f.write(f"-"*62 + "\n")
            f.write(f"{'Rule Name':<35} {'Result':<12} {'Time':<8}\n")
            f.write(f"-" * 60 + "\n")
            for r in results:
                res = "DETECTED" if r["detected"] else "MISSED"
                t   = f"{r['det_time']:.1f}s" if r["det_time"] else "—"
                f.write(f"{r['rule_name']:<35} {res:<12} {t:<8}\n")
            f.write(f"\n{'-'*62}\n")
            f.write(f"CONFUSION MATRIX\n")
            f.write(f"-"*62 + "\n")
            f.write(f"True Positive  (TP)  : {cm['TP']}  (correctly detected)\n")
            f.write(f"False Negative (FN)  : {cm['FN']}  (missed / not detected)\n")
            f.write(f"False Positive (FP)  : {cm['FP']}  (N/A in single-attack mode)\n")
            f.write(f"True Negative  (TN)  : {cm['TN']}  (N/A in single-attack mode)\n")
            f.write(f"\nPerformance Metrics:\n")
            f.write(f"  Sensitivity/Recall : {100*cm['TP']/cm['total']:.1f}%  (TP / (TP+FN))\n")
            f.write(f"  Accuracy           : {100*cm['TP']/cm['total']:.1f}%  (Correct / Total)\n")
            f.write(f"\n{'='*62}\n")
        print(f"  Report saved to: {CYAN}{report_path}{RESET}")
    except Exception as e:
        print(f"  {YELLOW}Could not save report: {e}{RESET}")


# ================================================================== #
#  INTERACTIVE MENU                                                    #
# ================================================================== #

def interactive_menu(target, duration, rate, log_path):
    """Full interactive menu showing all 30 attack options."""
    print(f"\n  {CYAN}Available attacks:{RESET}")
    print()

    groups = [
        ("── Volume Floods ──",
         ["syn","udp","icmp","ack","rst","synack","fin_flood","psh_ack"]),
        ("── Port Scans ──",
         ["scan","fin_scan","null","xmas","udpscan"]),
        ("── Brute Force ──",
         ["heartbleed","ftp","ssh","telnet","rdp","mysql","mssql",
          "postgres","winrm"]),
        ("── Application Layer ──",
         ["http","https","smtp","dns","smb","netbios","ldap","elastic"]),
        ("── Payload Attacks ──",
         ["sqli","xss","shellcode","path_trav","rce"]),
        ("── DDoS ──",
         ["ddos"]),
        ("── Baseline ──",
         ["normal"]),
    ]

    num_to_arg = {}
    n = 1
    for group_name, args in groups:
        print(f"  {CYAN}{group_name}{RESET}")
        for arg in args:
            rule_name, keywords, dr, desc = RULES[arg]
            print(f"    {WHITE}{n:2}.{RESET} {arg:<12} → {rule_name}")
            num_to_arg[str(n)] = arg
            n += 1
        print()

    print(f"  {WHITE} A.{RESET} Run ALL attacks sequentially")
    print(f"  {WHITE} Q.{RESET} Quit")
    print()

    choice = input(f"  {CYAN}Enter number, letter, or sim_arg name: {RESET}").strip().lower()

    if choice == "q":
        return
    elif choice == "a":
        results = []
        for arg in ATTACK_FUNCTIONS:
            r = run_attack(arg, target, duration, rate, log_path)
            results.append(r)
            print(f"  {DIM}Cooldown 8s...{RESET}")
            time.sleep(8)
        print_report(results)
    elif choice in num_to_arg:
        r = run_attack(num_to_arg[choice], target, duration, rate, log_path)
        print_report([r])
    elif choice in ATTACK_FUNCTIONS:
        r = run_attack(choice, target, duration, rate, log_path)
        print_report([r])
    else:
        print(f"  {RED}Invalid choice.{RESET}")


# ================================================================== #
#  ENTRY POINT                                                         #
# ================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="NIDS Attack Simulator — all 30 rules",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--target", default=None,
        help="Target IP (default: auto-detect local LAN IP)"
    )
    parser.add_argument(
        "--attack", default=None,
        help=(
            "Attack to run. Options:\n"
            "  Volume:  syn, udp, icmp, ack, rst, synack, fin_flood, psh_ack\n"
            "  Scanning: scan, fin_scan, null, xmas, udpscan\n"
            "  Brute Force: heartbleed, ftp, ssh, telnet, rdp, mysql, mssql, postgres, winrm, ldap\n"
            "  Application: http, https, smtp, dns, smb, netbios, elastic\n"
            "  Payload: sqli, xss, shellcode, path_trav, rce\n"
            "  DDoS: ddos\n"
            "  Benign: normal\n"
            "  Multiple: syn,udp,icmp  (comma-separated)\n"
            "  All:     all"
        )
    )
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help=f"Attack duration in seconds (default: {DEFAULT_DURATION})")
    parser.add_argument("--rate",     type=int, default=DEFAULT_RATE,
                        help=f"Packets per second (default: uses per-attack default)")
    parser.add_argument("--log",      default=DEFAULT_LOG,
                        help=f"Path to nids.log (default: {DEFAULT_LOG})")
    parser.add_argument("--cooldown", type=int, default=8,
                        help="Seconds between attacks when running all (default: 8)")
    parser.add_argument("--list",     action="store_true",
                        help="List all available attacks and exit")
    args = parser.parse_args()

    # List mode
    if args.list:
        print(f"\n{'sim_arg':<14} {'Rule Name':<35} {'Default Rate':<14} Description")
        print("─" * 90)
        for arg, (rule_name, kws, dr, desc) in RULES.items():
            print(f"{arg:<14} {rule_name:<35} {str(dr)+' pkt/s':<14} {desc}")
        return

    print_banner()

    # Initialize attack logging
    log_file = init_attack_log()
    print(f"  {CYAN}Attack log will be saved to: {log_file}{RESET}\n")

    # Determine target
    local_ip = get_local_ip()
    
    if args.target:
        target = args.target
    else:
        # Interactive input for target IP
        print(f"  {CYAN}Target IP Configuration{RESET}")
        print(f"  {DIM}Auto-detected local IP: {local_ip}{RESET}")
        user_target = input(f"  {CYAN}Enter target IP (press Enter for {local_ip}): {RESET}").strip()
        target = user_target if user_target else local_ip

    if target == "127.0.0.1":
        print(f"  {YELLOW}⚠️  WARNING: Target is 127.0.0.1 (loopback).{RESET}")
        print(f"     Loopback packets do NOT pass through the NIC.")
        print(f"     Scapy/Npcap will NOT capture them.")
        print(f"     Use your LAN IP instead: {local_ip}")
        print(f"     Auto-switching to {local_ip}\n")
        target = local_ip

    # Verify log file exists
    log_path = args.log
    if not os.path.exists(log_path):
        # Try to find it
        for candidate in ["logs/nids.log", "../logs/nids.log", "nids.log"]:
            if os.path.exists(candidate):
                log_path = candidate
                break
        else:
            print(f"  {YELLOW}⚠️  nids.log not found at '{args.log}'.{RESET}")
            print(f"     Make sure NIDS is running before starting tests.")
            print(f"     Detection checks will show NOT DETECTED until log exists.")

    last_iface = get_last_capture_interface(log_path)

    print(f"  Target    : {CYAN}{target}{RESET}")
    print(f"  Duration  : {args.duration}s per attack")
    print(f"  Log file  : {log_path}")
    print(f"  Scapy     : {GREEN+'YES'+RESET if SCAPY_OK else RED+'NO'+RESET}")
    if last_iface:
        print(f"  NIDS iface: {last_iface}")

    # Windows routing note: traffic to your own local IP is often observed on
    # the loopback adapter. If NIDS is sniffing a physical NIC, tests may miss.
    if target == local_ip and last_iface and not _is_loopback_iface(last_iface):
        print(f"  {YELLOW}⚠️  Potential interface mismatch detected.{RESET}")
        print(f"     Target is your own host IP ({local_ip}), but NIDS is not on loopback.")
        print(f"     Start capture on Npcap Loopback or target another host on your LAN.")
    elif target != local_ip and last_iface and _is_loopback_iface(last_iface):
        print(f"  {YELLOW}⚠️  Potential interface mismatch detected.{RESET}")
        print(f"     Target is remote ({target}), but NIDS is currently sniffing loopback.")
        print(f"     Start capture on your active Wi-Fi/Ethernet adapter.")

    if not SCAPY_OK:
        print(f"  {YELLOW}  Install Scapy for full attack coverage: pip install scapy{RESET}")

    # ── PRE-FLIGHT CHECK: Verify NIDS is capturing ──────────────────────
    print(f"\n{CYAN}  PRE-FLIGHT CHECK{RESET}")
    print(f"  {DIM}Verifying NIDS is actively capturing packets...{RESET}")
    
    if not is_nids_capturing(log_path):
        print(f"  {RED}[x] NIDS is NOT capturing!{RESET}")
        print(f"    {YELLOW}The NIDS process must be running and capturing.{RESET}")
        print(f"    {YELLOW}Start NIDS with: py main.py{RESET}")
        print(f"    {DIM}Tests cannot reliably detect attacks if NIDS is stopped.{RESET}")
        response = input(f"  {CYAN}Continue anyway? (y/n): {RESET}").strip().lower()
        if response != "y":
            print(f"  {YELLOW}Test cancelled.{RESET}")
            return
        print(f"  {YELLOW}WARNING: Proceeding with NIDS not capturing.{RESET}")
        print(f"     {DIM}Expect many false negatives (MISSED detections).{RESET}")
    else:
        print(f"  {GREEN}[OK] NIDS is actively capturing{RESET}")

    results = []

    try:
        if args.attack is None:
            # Interactive
            interactive_menu(target, args.duration, args.rate, log_path)

        elif args.attack == "all":
            print(f"\n  {CYAN}Running all {len(ATTACK_FUNCTIONS)} attacks...{RESET}")
            for i, sim_arg in enumerate(ATTACK_FUNCTIONS, 1):
                print(f"\n  [{i}/{len(ATTACK_FUNCTIONS)}]", end="")
                r = run_attack(sim_arg, target, args.duration,
                               args.rate, log_path)
                results.append(r)
                if i < len(ATTACK_FUNCTIONS):
                    print(f"  {DIM}Cooldown {args.cooldown}s before next attack...{RESET}")
                    time.sleep(args.cooldown)
            print_report(results)

        else:
            # Single or comma-separated list
            attacks = [a.strip() for a in args.attack.split(",")]
            invalid = [a for a in attacks if a not in ATTACK_FUNCTIONS]
            if invalid:
                print(f"  {RED}Unknown attack(s): {invalid}{RESET}")
                print(f"  Use --list to see all available attacks.")
                return
            for i, sim_arg in enumerate(attacks, 1):
                if len(attacks) > 1:
                    print(f"\n  [{i}/{len(attacks)}]", end="")
                r = run_attack(sim_arg, target, args.duration,
                               args.rate, log_path)
                results.append(r)
                if i < len(attacks):
                    print(f"  {DIM}Cooldown {args.cooldown}s...{RESET}")
                    time.sleep(args.cooldown)
            print_report(results)

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Stopped by user (Ctrl+C).{RESET}")
        if results:
            print_report(results)

    print(f"  Done. Check NIDS dashboard for alerts.\n")


if __name__ == "__main__":
    main()
