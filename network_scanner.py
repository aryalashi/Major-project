#!/usr/bin/env python3
"""
network_scanner.py
------------------
Network Scanner & Vulnerability Assessment Module for NIDS

Provides:
  - ARP/ICMP/socket-based host discovery
  - TCP port scanning (Nmap if available, socket fallback)
  - OS fingerprinting (Nmap)
  - Vulnerability scanning integration (vuln_scanner.py + Gemini AI)
  - Alert channel integration (sends vuln reports to Telegram/Discord/Email etc.)
  - Thread-safe host tracking
  - Async scanning via result_queue

Integrates with:
  main.py      -> net_scanner = NetworkScanner()
                  net_scanner.alert_engine = alert_engine   # enables channel alerts
                  net_scanner.result_queue = gui_queue
  gui.py       -> scanner_tab uses net_scanner.scan_async()
  gui_tabs.py  -> NetworkScannerTab reads result_queue

Restored: March 2026 (pre-March-27 working version)
"""

import os
import time
import queue
import socket
import logging
import threading
import ipaddress
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

logger = logging.getLogger("NetworkScanner")

# ── Optional dependencies ────────────────────────────────────────────────────

try:
    import nmap as _nmap_lib  # type: ignore[import-not-found]
    import shutil as _shutil
    NMAP_AVAILABLE = _shutil.which("nmap") is not None
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, conf as _scapy_conf, IP, ICMP, sr  # type: ignore[import-not-found]
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Well-known service ports ─────────────────────────────────────────────────

COMMON_PORTS: Dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    902:   "VMware",
    1433:  "MSSQL",
    3268:  "LDAP-GC",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5985:  "WinRM-HTTP",
    5986:  "WinRM-HTTPS",
    6379:  "Redis",
    8080:  "HTTP-Proxy",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

HIGH_RISK_PORTS: Set[int] = {22, 23, 445, 139, 3389, 1433, 3306, 5432, 27017, 6379}
WEB_PORTS:       Set[int] = {80, 443, 8080, 8443}


# ── HostInfo dataclass ───────────────────────────────────────────────────────

@dataclass
class HostInfo:
    """Holds all discovered information about a single host."""
    ip:        str
    hostname:  str  = "Unknown"
    mac:       str  = "N/A"
    os_guess:  str  = "Unknown"
    ttl:       int  = 0
    open_ports: List[int] = field(default_factory=list)
    services:   Dict[int, str] = field(default_factory=dict)
    vuln_risk:  str = "UNKNOWN"        # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    threat_score: int = 0
    last_seen:  float = field(default_factory=time.time)
    status: str = "Online"

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "hostname":     self.hostname,
            "mac":          self.mac,
            "os":           self.os_guess,
            "ttl":          self.ttl,
            "ports":        self.open_ports,
            "services":     {str(k): v for k, v in self.services.items()},
            "vuln_risk":    self.vuln_risk,
            "threat_score": self.threat_score,
            "last_seen":    self.last_seen,
            "status":       self.status,
            "alive":        True,
        }


# ── NetworkScanner ───────────────────────────────────────────────────────────

class NetworkScanner:
    """
    Async network scanner.  Call pattern from GUI/main:

        scanner = NetworkScanner()
        scanner.result_queue = gui_queue          # required before scan_async
        scanner.alert_engine  = alert_engine      # optional - enables channel alerts

        scanner.scan_async("192.168.1.0/24")
        scanner.scan_async("192.168.1.50")
        scanner.stop()
    """

    def __init__(self, result_queue: queue.Queue = None):
        self.result_queue  = result_queue
        self._scanning     = False
        self.hosts:  Dict[str, HostInfo] = {}
        self.alert_engine  = None           # injected from main.py
        self._hosts_lock   = threading.Lock()
        self._stop_event   = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._hostname_cache: Dict[str, str] = {}  # Cache DNS lookups
        self._cache_lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_async(self, target: str, full_vuln: bool = False):
        """Start a background scan on target (CIDR / IP / range)."""
        if not self.result_queue:
            logger.error("[NetworkScanner] result_queue not set before scan_async")
            return
        self._stop_event.clear()
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, full_vuln),
            daemon=True,
            name="ns-scan",
        )
        self._scan_thread.start()

    def stop(self):
        """Cancel any running scan."""
        self._stop_event.set()
        self._scanning = False
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=3.0)
        logger.info("[NetworkScanner] Scan stopped.")

    def get_all_hosts(self) -> List[HostInfo]:
        with self._hosts_lock:
            return list(self.hosts.values())

    def get_host(self, ip: str) -> Optional[HostInfo]:
        with self._hosts_lock:
            return self.hosts.get(ip)

    # ── Internal scan pipeline ────────────────────────────────────────────────

    def _scan_worker(self, target: str, full_vuln: bool):
        """Full scan pipeline: discover -> ports -> OS -> vuln."""
        self._scanning = True
        logger.info(f"[NetworkScanner] Starting scan: {target}")
        self._push_status(f"Starting scan: {target}")

        try:
            hosts = self._parse_target(target)
            self._push_status(f"Probing {len(hosts)} address(es)...")

            # Step 1: Discover live hosts (parallel ARP + fallback ping)
            alive = self._discover_live_hosts(hosts)
            if not alive:
                self._push_status("No live hosts found.")
                return

            self._push_status(f"Found {len(alive)} live host(s). Scanning ports...")

            # Step 2: Port scan (parallel)
            self._scan_all_ports(alive)

            self._push_status("Port scan complete. Running OS fingerprint...")

            # Step 3: OS fingerprint (Nmap if available)
            if NMAP_AVAILABLE:
                self._fingerprint_all_hosts(alive)

            # Step 4: Vulnerability scan (optional, per host with open ports)
            if full_vuln:
                for ip_str in alive:
                    if self._stop_event.is_set():
                        break
                    host = self._get_or_create(ip_str)
                    if host.open_ports:
                        threading.Thread(
                            target=self._run_vuln_scan,
                            args=(ip_str, host),
                            daemon=True,
                        ).start()

            self._push_status(f"Scan complete. {len(alive)} host(s) found.")

        except Exception as e:
            logger.error(f"[NetworkScanner] Scan error: {e}")
            self._push_status(f"Scan error: {e}")
        finally:
            self._scanning = False

    # ── Host Discovery ────────────────────────────────────────────────────────

    def _discover_live_hosts(self, hosts: List) -> List[str]:
        """Parallel host discovery using ARP (local) + fallback ping."""
        alive = []
        
        # Try parallel ARP discovery first (fastest for local networks)
        if SCAPY_AVAILABLE and len(hosts) <= 256:
            arp_results = self._arp_discover(hosts)
            if arp_results:
                alive = arp_results
                for ip_str in alive:
                    host = HostInfo(ip=ip_str, hostname=self._resolve_hostname_cached(ip_str))
                    self._add_host(host)
                    logger.info(f"[NetworkScanner] Host alive (ARP): {ip_str}")
                return alive
        
        # Fallback: parallel socket/ping discovery (30 workers for fast scanning)
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self._host_is_alive, str(ip)): str(ip) for ip in hosts}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                ip_str = futures[future]
                try:
                    if future.result():
                        alive.append(ip_str)
                        host = HostInfo(ip=ip_str, hostname=self._resolve_hostname_cached(ip_str))
                        self._add_host(host)
                        logger.info(f"[NetworkScanner] Host alive: {ip_str}")
                except Exception as e:
                    logger.debug(f"[NetworkScanner] Host probe failed for {ip_str}: {e}")
        
        return alive

    def _arp_discover(self, hosts: List) -> List[str]:
        """Perform parallel ARP discovery on hosts."""
        if not SCAPY_AVAILABLE:
            return []
        
        alive = []
        try:
            # Query all targets instead of only the first host in the list.
            pdst_targets = [str(ip) for ip in hosts]
            arp_layer = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst_targets)

            # Send ARP requests with aggressive timeout for speed.
            ans, _ = srp(arp_layer, timeout=1.5, verbose=False, retry=1)
            
            for _, rcv in ans:
                ip_str = rcv.psrc
                if ip_str not in alive:
                    alive.append(ip_str)
        except Exception as e:
            logger.debug(f"[NetworkScanner] ARP discovery failed: {e}")
        
        return alive

    def _scan_all_ports(self, hosts: List[str]):
        """Parallel port scanning on all hosts."""
        with ThreadPoolExecutor(max_workers=min(20, len(hosts) + 5)) as executor:
            futures = {executor.submit(self._run_port_scan, ip): ip for ip in hosts}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                ip_str = futures[future]
                try:
                    future.result()
                    host = self._get_or_create(ip_str)
                    self._add_host(host)
                except Exception as e:
                    logger.error(f"[NetworkScanner] Port scan error for {ip_str}: {e}")

    def _fingerprint_all_hosts(self, hosts: List[str]):
        """Parallel OS fingerprinting using Nmap."""
        with ThreadPoolExecutor(max_workers=min(10, len(hosts) + 2)) as executor:
            futures = {executor.submit(self._run_os_fingerprint, ip): ip for ip in hosts}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                ip_str = futures[future]
                try:
                    future.result()
                    host = self._get_or_create(ip_str)
                    self._add_host(host)
                except Exception as e:
                    logger.debug(f"[NetworkScanner] OS fingerprint error for {ip_str}: {e}")

    @lru_cache(maxsize=512)
    def _resolve_hostname_cached(self, ip: str) -> str:
        """Cached hostname resolution."""
        return self._resolve_hostname(ip)

    def _host_is_alive(self, ip: str) -> bool:
        """Try ARP -> ICMP ping -> socket connect."""
        # Method 1: ARP (local subnet only, requires Scapy + Admin)
        if SCAPY_AVAILABLE:
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                    timeout=0.5, verbose=False
                )
                if ans:
                    return True
            except Exception as e:
                logger.debug(f"[NetworkScanner] ARP probe failed for {ip}: {e}")

        # Method 2: system ping (cross-platform)
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", "400", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=2
            )
            if result.returncode == 0:
                return True
        except Exception as e:
            logger.debug(f"[NetworkScanner] Ping failed for {ip}: {e}")

        # Method 3: socket connect on common ports
        return self._host_is_alive_socket(ip)

    def _host_is_alive_socket(self, ip: str, timeout: float = 0.3) -> bool:
        """Parallel socket probe on top ports for fast alive detection."""
        # Top 4 most common ports for parallel checking
        probe_ports = [80, 443, 22, 445]
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self._check_port, ip, port, timeout) for port in probe_ports]
            for future in as_completed(futures):
                try:
                    if future.result():
                        return True
                except Exception:
                    pass
        return False

    # ── Port Scanning ─────────────────────────────────────────────────────────

    def _run_port_scan(self, ip: str, host: HostInfo = None):
        """Port scan using Nmap if available, socket fallback otherwise."""
        if host is None:
            host = self._get_or_create(ip)
        
        if NMAP_AVAILABLE:
            self._nmap_port_scan(ip, host)
        else:
            self._socket_port_scan(ip, host)
        host.threat_score = self._calculate_threat_score(host.open_ports)

    def _nmap_port_scan(self, ip: str, host: HostInfo):
        """Nmap SYN scan with service version detection."""
        try:
            nm = _nmap_lib.PortScanner()
            port_str = ",".join(str(p) for p in COMMON_PORTS.keys())
            nm.scan(
                hosts=ip,
                ports=port_str,
                arguments="-sV --open -T5 --host-timeout 15s -n",
            )
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    for port, state in nm[ip][proto].items():
                        if state.get("state") == "open":
                            host.open_ports.append(port)
                            svc = state.get("name", COMMON_PORTS.get(port, "Unknown"))
                            ver = state.get("version", "")
                            host.services[port] = f"{svc} {ver}".strip()
                if host.hostname in ("Unknown", "", None):
                    try:
                        nmap_name = nm[ip].hostname() if hasattr(nm[ip], "hostname") else ""
                        if nmap_name:
                            host.hostname = nmap_name
                    except Exception:
                        pass
                try:
                    host.mac = nm[ip]["addresses"].get("mac", "N/A")
                except (KeyError, TypeError):
                    pass
                logger.info(f"[NetworkScanner] Nmap scan complete for {ip}: {len(host.open_ports)} ports open")
        except Exception as e:
            logger.warning(f"[NetworkScanner] Nmap port scan failed for {ip}: {e}")
            logger.info(f"[NetworkScanner] Falling back to socket scan for {ip}")
            self._socket_port_scan(ip, host)

    def _socket_port_scan(self, ip: str, host: HostInfo, timeout: float = 0.4):
        """Threaded socket connect scan on COMMON_PORTS."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {
                ex.submit(self._check_port, ip, p, timeout): p
                for p in COMMON_PORTS
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"[NetworkScanner] Port check error for {ip}:{port}: {e}")

        host.open_ports = sorted(open_ports)
        host.services = {p: COMMON_PORTS.get(p, "Unknown") for p in open_ports}
        if host.open_ports:
            logger.info(f"[NetworkScanner] Socket scan complete for {ip}: {len(host.open_ports)} ports open")

    def _check_port(self, ip: str, port: int, timeout: float) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port)) == 0
            s.close()
            return result
        except Exception:
            return False

    # ── OS Fingerprinting ─────────────────────────────────────────────────────

    def _run_os_fingerprint(self, ip: str, host: HostInfo = None):
        """Use Nmap -O for OS detection."""
        if host is None:
            host = self._get_or_create(ip)
            
        if not NMAP_AVAILABLE:
            host.os_guess = self._guess_os_by_ttl(host.ttl)
            return
        try:
            nm = _nmap_lib.PortScanner()
            nm.scan(hosts=ip, arguments="-O --host-timeout 10s -n", sudo=False)
            if ip in nm.all_hosts():
                osmatch = nm[ip].get("osmatch", [])
                if osmatch and len(osmatch) > 0:
                    host.os_guess = osmatch[0].get("name", "Unknown")
                    logger.info(f"[NetworkScanner] OS detected for {ip}: {host.os_guess}")
                else:
                    host.os_guess = "OS detection not available"
                
                # Try to get TTL info
                try:
                    ttl_raw = nm[ip].get("ipidsequence", {}).get("values", "")
                    if ttl_raw:
                        host.ttl = int(ttl_raw.split(",")[0])
                except (ValueError, IndexError, KeyError):
                    pass
        except Exception as e:
            logger.debug(f"[NetworkScanner] OS fingerprint failed for {ip}: {e}")
            host.os_guess = self._guess_os_by_ttl(host.ttl)

    def _guess_os_by_ttl(self, ttl: int) -> str:
        if ttl == 0:
            return "Unknown"
        if ttl <= 64:
            return "Linux/macOS (TTL<=64)"
        if ttl <= 128:
            return "Windows (TTL<=128)"
        return "Network Device (TTL>128)"

    # ── Vulnerability Scanning ────────────────────────────────────────────────

    def _run_vuln_scan(self, ip: str, host: HostInfo):
        """Run vuln scan, save report to attacks/, send to ALL alert channels."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        ip_tag = ip.replace(".", "_")
        report_file = f"attacks/vuln_{ip_tag}_{int(time.time())}.txt"

        SCAN_PORTS = (
            "21,22,23,25,53,80,135,139,443,445,"
            "902,1433,3268,3306,3389,5432,5985,5986,8080,8443"
        )

        logger.info(f"[NetworkScanner] Starting vuln scan on {ip}")
        self._push_status(f"Running vuln scan on {ip}")

        try:
            from vuln_scanner import Config, GeminiProvider, VulnerabilityScanner
            config = Config()
            provider = GeminiProvider(config)
            scanner = VulnerabilityScanner(provider)

            results = scanner.scan_and_analyze(
                target_input=ip,
                ports=SCAN_PORTS,
                no_cves=False,
                timeout=300
            )

            if results and isinstance(results, list) and len(results) > 0:
                risks = [r.get("analysis", {}).get("risk", "Unknown") for r in results]
                host.vuln_risk = (
                    "CRITICAL" if "Critical" in risks else
                    "HIGH" if "High" in risks else
                    "MEDIUM" if "Medium" in risks else "LOW"
                )
                self._add_host(host)

                os.makedirs("attacks", exist_ok=True)
                scanner.generate_report(
                    results, output_file=report_file, no_cves=False
                )
                logger.info(f"[NetworkScanner] Vuln report saved: {report_file}")

                if self.alert_engine:
                    self._send_vuln_alert(ip, host, ts, results, report_file)
                else:
                    logger.warning(
                        "[NetworkScanner] alert_engine not set - "
                        "report saved but NOT sent to channels. "
                        "Add: net_scanner.alert_engine = alert_engine in main.py"
                    )
            else:
                logger.warning(f"[NetworkScanner] No services found on {ip}")
                self._push_status(f"Vuln scan {ip}: no open services found")
                if self.alert_engine and self.alert_engine.telegram_enabled:
                    no_svc_msg = (
                        f"Network Scan Complete\\nHost: {ip}"
                        f"\\nNo open services found\\nTime: {ts}"
                    )
                    threading.Thread(
                        target=self.alert_engine.send_raw_telegram,
                        args=(no_svc_msg,), daemon=True
                    ).start()

        except Exception as e:
            logger.error(f"[NetworkScanner] Vuln scan error {ip}: {e}")
            self._push_status(f"Vuln scan error on {ip}: {e}")

    def _send_vuln_alert(self, ip, host, ts, results, report_file):
        """Send vuln scan results to all enabled alert channels."""
        ae = self.alert_engine
        if not ae:
            return

        risk_counts = {}
        for r in results:
            risk = r.get("analysis", {}).get("risk", "Unknown")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        msg_lines = [
            "NETWORK SCAN VULN REPORT",
            "",
            f"Host:    {ip}",
            f"OS:      {host.os_guess}",
            f"Ports:   {', '.join(str(p) for p in host.open_ports) or 'None'}",
            f"Scanned: {ts}",
            "",
            "Risk Summary:",
        ]
        for risk, count in sorted(risk_counts.items()):
            msg_lines.append(f"  {risk}: {count} service(s)")
        msg_lines += ["", "Top findings:"]
        for r in results[:5]:
            svc = r.get("service", "unknown")
            port = str(r.get("port", "?"))
            risk = r.get("analysis", {}).get("risk", "?")
            rec = r.get("analysis", {}).get("recommendation", "")[:80]
            msg_lines.append(f"  [{risk}] Port {port} ({svc}): {rec}")
        if report_file:
            msg_lines += ["", f"Full report: {report_file}"]

        msg = "\n".join(msg_lines)

        def _try(fn, *a, **kw):
            try:
                fn(*a, **kw)
            except Exception as ex:
                logger.debug(f"[NetworkScanner] Channel send error: {ex}")

        if ae.telegram_enabled:
            threading.Thread(
                target=_try, args=(ae.send_raw_telegram, msg), daemon=True
            ).start()
            time.sleep(0.2)
        if ae.discord_enabled and hasattr(ae, "send_raw_discord"):
            threading.Thread(
                target=_try, args=(ae.send_raw_discord, msg), daemon=True
            ).start()
            time.sleep(0.2)
        if ae.slack_enabled and hasattr(ae, "send_raw_slack"):
            threading.Thread(
                target=lambda: _try(ae.send_raw_slack, text=msg), daemon=True
            ).start()
            time.sleep(0.2)
        if ae.email_enabled and hasattr(ae, "send_raw_email"):
            subj = f"NIDS Network Scan: {ip} [{host.vuln_risk}]"
            threading.Thread(
                target=lambda: _try(ae.send_raw_email, subject=subj, body=msg),
                daemon=True
            ).start()
            time.sleep(0.2)
        if ae.whatsapp_enabled and hasattr(ae, "send_raw_whatsapp"):
            threading.Thread(
                target=_try, args=(ae.send_raw_whatsapp, msg), daemon=True
            ).start()
            time.sleep(0.2)
        if ae.desktop_enabled and hasattr(ae, "send_raw_desktop"):
            title_d = f"Vuln Scan: {ip} [{host.vuln_risk}]"
            body_d = f"{len(results)} services found"
            threading.Thread(
                target=lambda: _try(ae.send_raw_desktop, title=title_d, body=body_d),
                daemon=True
            ).start()

        logger.info("[NetworkScanner] Vuln report dispatched to all enabled channels")

    # ── Threat Scoring ────────────────────────────────────────────────────────

    def _calculate_threat_score(self, ports: List[int]) -> int:
        score = len(ports) * 5
        score += sum(15 for p in ports if p in HIGH_RISK_PORTS)
        score += sum(10 for p in ports if p in WEB_PORTS)
        return min(100, score)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_target(self, target: str):
        """Return list of IPv4Address objects from CIDR / range / single IP."""
        target = target.strip()
        hosts = []
        try:
            if "/" in target:
                net = ipaddress.IPv4Network(target, strict=False)
                hosts = list(net.hosts()) or [net.network_address]
            elif "-" in target:
                parts = target.split("-")
                base = ipaddress.IPv4Address(parts[0])
                try:
                    end = ipaddress.IPv4Address(parts[1])
                    hosts = [
                        ipaddress.IPv4Address(i)
                        for i in range(int(base), int(end) + 1)
                    ]
                except Exception:
                    # Format: 192.168.1.1-50
                    base_parts = parts[0].rsplit(".", 1)
                    prefix = base_parts[0] + "."
                    start_last = int(base_parts[1])
                    end_last = int(parts[1])
                    hosts = [
                        ipaddress.IPv4Address(prefix + str(i))
                        for i in range(start_last, end_last + 1)
                    ]
            else:
                hosts = [ipaddress.IPv4Address(target)]
        except Exception as e:
            logger.warning(f"[NetworkScanner] Could not parse target '{target}': {e}")
            return []
        return hosts

    def _resolve_hostname(self, ip: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            logger.debug(f"[NetworkScanner] Resolved {ip} -> {hostname}")
            if hostname and hostname.strip():
                return hostname.split(".")[0]
        except socket.herror:
            logger.debug(f"[NetworkScanner] Reverse DNS unavailable for {ip}")
        except Exception as e:
            logger.debug(f"[NetworkScanner] Hostname resolution failed for {ip}: {e}")

        # Fallback 1 (Windows): NetBIOS name via nbtstat
        netbios_name = self._resolve_netbios_name(ip)
        if netbios_name:
            return netbios_name

        # Fallback 2: ping -a (Windows resolver hint)
        ping_name = self._resolve_ping_name(ip)
        if ping_name:
            return ping_name

        return "Unknown"

    def _resolve_netbios_name(self, ip: str) -> str:
        """Best-effort NetBIOS hostname lookup (Windows only)."""
        if os.name != "nt":
            return ""
        try:
            cmd = ["nbtstat", "-A", ip]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode != 0:
                return ""
            for line in result.stdout.splitlines():
                line = line.strip()
                if "<00>" in line and "UNIQUE" in line:
                    candidate = line.split("<00>")[0].strip()
                    if candidate and candidate.upper() not in ("GROUP", "UNKNOWN"):
                        return candidate
        except Exception:
            return ""
        return ""

    def _resolve_ping_name(self, ip: str) -> str:
        """Extract hostname from ping output as a fallback."""
        if os.name != "nt":
            return ""
        try:
            cmd = ["ping", "-a", "-n", "1", "-w", "800", ip]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode != 0:
                return ""
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.lower().startswith("pinging ") and "[" in line and "]" in line:
                    # Example: Pinging DESKTOP-ABC123 [192.168.1.10] with 32 bytes of data:
                    ping_target = line[8:line.find("[")].strip()
                    if ping_target and ping_target.lower() != ip.lower():
                        return ping_target
        except Exception:
            return ""
        return ""

    def _valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except Exception:
            return False

    def _add_host(self, host: HostInfo):
        """Thread-safe host dict update and GUI push."""
        with self._hosts_lock:
            self.hosts[host.ip] = host
        self._push_result(host)

    def _get_or_create(self, ip: str) -> HostInfo:
        with self._hosts_lock:
            if ip not in self.hosts:
                self.hosts[ip] = HostInfo(ip=ip)
            return self.hosts[ip]

    # ── Queue helpers ─────────────────────────────────────────────────────────

    def _push_result(self, host: HostInfo):
        if self.result_queue:
            try:
                self.result_queue.put_nowait({
                    "__type": "scan_result",
                    "host": host.to_dict(),
                })
            except queue.Full:
                logger.debug(f"[NetworkScanner] Result queue full, dropping result for {host.ip}")

    def _push_status(self, status: str):
        if self.result_queue:
            try:
                self.result_queue.put_nowait({
                    "__type": "scan_status",
                    "status": status,
                })
            except queue.Full:
                logger.debug(f"[NetworkScanner] Status queue full: {status}")

    # ── Legacy compatibility shims ────────────────────────────────────────────

    def get_network_stats(self) -> dict:
        """Summary dict for NetworkScannerTab (gui_tabs.py compatibility)."""
        with self._hosts_lock:
            devices = {
                h.ip: {
                    "mac":              h.mac,
                    "os":               h.os_guess,
                    "packets_sent":     0,
                    "packets_received": 0,
                    "threat_level":     h.threat_score,
                    "alerts_count":     0,
                    "open_ports":       h.open_ports,
                    "vuln_risk":        h.vuln_risk,
                }
                for h in self.hosts.values()
            }
        return {
            "local_network": "192.168.x.x/24",
            "devices":       devices,
        }

    def start_continuous_discovery(self, network: str = "192.168.1.0/24"):
        logger.info("[NetworkScanner] Continuous discovery started on " + network)

    def stop_continuous_discovery(self):
        logger.info("[NetworkScanner] Continuous discovery stopped.")

    def discover_devices(self, network: str = "192.168.1.0/24") -> list:
        return []

    def search_devices(self, query: str) -> list:
        with self._hosts_lock:
            q = query.lower()
            return [
                h.to_dict() for h in self.hosts.values()
                if q in h.ip or q in h.hostname.lower()
            ]

    def get_all_devices(self) -> list:
        return [h.to_dict() for h in self.get_all_hosts()]

    def scan_ports(self, target: str, ports: str = "1-1000", timeout: int = 10) -> dict:
        host = HostInfo(ip=target)
        self._run_port_scan(target, host)
        return host.to_dict()

    def _identify_service(self, port: int) -> str:
        return COMMON_PORTS.get(port, "Unknown")

    def _parse_ports(self, port_spec: str) -> List[int]:
        ports = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    ports.extend(range(int(a), int(b) + 1))
                except Exception:
                    pass
            else:
                try:
                    ports.append(int(part))
                except Exception:
                    pass
        return sorted(set(ports))