#!/usr/bin/env python3
"""
Advanced Network Scanner Module
Handles network reconnaissance, device discovery, port scanning, and vulnerability detection
"""

import logging
import subprocess
import concurrent.futures
import shutil
import socket
import threading
import queue
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

logger = logging.getLogger('NetworkScanner')

try:
    import nmap
    NMAP_AVAILABLE = True
    nmap_path = shutil.which('nmap')
    NMAP_AVAILABLE = nmap_path is not None
except (ImportError, Exception):
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, conf, IP, ICMP, sr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger('NetworkScanner')
logger.setLevel(logging.INFO)
logger.propagate = True

# Common service ports for quick scanning
COMMON_PORTS = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 139: "NetBIOS",
    3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    25: "SMTP", 110: "POP3", 143: "IMAP", 3389: "RDP", 5900: "VNC",
    9200: "Elasticsearch", 27017: "MongoDB", 6379: "Redis", 1433: "MSSQL"
}


class NetworkScanner:
    """Advanced network scanning with device discovery and vulnerability assessment"""
    
    def __init__(self):
        self.devices = {}
        self.discovery_thread = None
        self.running = False
        self.result_queue = None  # Set by GUI before calling scan_async
        self._scan_thread = None
        self._stop_event = threading.Event()
    
    def scan_async(self, target: str, full_vuln: bool = False):
        """Async scan that sends results through result_queue"""
        if not self.result_queue:
            logger.error("result_queue not set before scan_async")
            return
        
        # Start scan in background thread
        self._stop_event.clear()
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, full_vuln),
            daemon=True
        )
        self._scan_thread.start()
    
    def _scan_worker(self, target: str, full_vuln: bool):
        """Background worker for async scanner"""
        logger.info(f"Starting scan on {target}")
        try:
            # Parse target (CIDR, IP range, or single IP)
            hosts = self._parse_target(target)
            
            # Discover devices
            self._send_status(f"Discovering {len(hosts)} host(s)...")
            discovered = []
            for host in hosts:
                if self._stop_event.is_set():
                    break
                
                try:
                    # Check if host is alive via socket
                    if self._host_is_alive_socket(str(host)):
                        discovered.append(str(host))
                        hostname = self._resolve_hostname(str(host))
                        device = {
                            "ip": str(host),
                            "hostname": hostname,
                            "mac": "N/A",
                            "os": "Unknown",
                            "ports": [],
                            "services": {},
                            "threat_score": 0
                        }
                        self._send_result(device)
                except Exception as e:
                    logger.debug(f"Error checking host {host}: {e}")
            
            if self._stop_event.is_set():
                self._send_status("Scan cancelled")
                return
            
            # Port scan discovered hosts
            if discovered:
                self._send_status(f"Scanning ports on {len(discovered)} host(s)...")
                for host in discovered:
                    if self._stop_event.is_set():
                        break
                    
                    try:
                        open_ports = self._scan_common_ports(host)
                        if open_ports:
                            device = {
                                "ip": host,
                                "hostname": self._resolve_hostname(host),
                                "mac": "N/A",
                                "os": "Unknown",
                                "ports": open_ports,
                                "services": {p: COMMON_PORTS.get(p, "Unknown") for p in open_ports},
                                "threat_score": self._calculate_threat_score(open_ports)
                            }
                            self._send_result(device)
                            logger.info(f"Found {len(open_ports)} open ports on {host}")
                    except Exception as e:
                        logger.debug(f"Error scanning ports on {host}: {e}")
            
            self._send_status(f"Scan complete. Found {len(discovered)} host(s)")
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self._send_status(f"Scan error: {e}")
    
    def stop(self):
        """Stop the running scan"""
        self._stop_event.set()
        self.running = False
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=2.0)
        logger.info("Scan stopped")
    
    def _parse_target(self, target: str) -> Set[ipaddress.IPv4Address]:
        """Parse CIDR, IP range, or single IP"""
        hosts = set()
        target = target.strip()
        
        try:
            if '/' in target:
                # CIDR notation
                network = ipaddress.IPv4Network(target, strict=False)
                hosts = set(network.hosts()) or {network.network_address}
            elif '-' in target:
                # IP range like 192.168.1.1-192.168.1.10
                parts = target.split('-')
                if len(parts) == 2:
                    try:
                        start = ipaddress.IPv4Address(parts[0])
                        end_num = int(parts[1])
                        for i in range(int(start), int(start) + end_num):
                            hosts.add(ipaddress.IPv4Address(i))
                    except:
                        hosts.add(ipaddress.IPv4Address(target))
            else:
                # Single IP
                hosts.add(ipaddress.IPv4Address(target))
        except Exception as e:
            logger.warning(f"Failed to parse target {target}: {e}")
            hosts.add(ipaddress.IPv4Address("127.0.0.1"))  # Fallback
        
        return hosts
    
    def _host_is_alive_socket(self, ip: str, timeout: float = 1.0) -> bool:
        """Check if host is alive via socket connection"""
        common_ports = [22, 80, 443, 445, 139, 3389, 8080]
        
        for port in common_ports:
            if self._stop_event.is_set():
                return False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                pass
        
        return False
    
    def _scan_common_ports(self, ip: str, timeout: float = 0.5) -> List[int]:
        """Scan common ports on target"""
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for port in COMMON_PORTS.keys():
                if self._stop_event.is_set():
                    break
                future = executor.submit(self._check_port, ip, port, timeout)
                futures[future] = port
            
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                if future.result():
                    open_ports.append(futures[future])
        
        return sorted(open_ports)
    
    def _check_port(self, ip: str, port: int, timeout: float) -> bool:
        """Check if single port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return "Unknown"
    
    def _calculate_threat_score(self, ports: List[int]) -> int:
        """Calculate threat score based on open ports"""
        score = 0
        dangerous_ports = [22, 445, 139, 3306, 5432, 3389, 27017, 6379]
        web_ports = [80, 443, 8080, 8443]
        
        score += len(ports) * 5  # +5 per port
        score += sum(1 for p in ports if p in dangerous_ports) * 15  # +15 per dangerous
        score += sum(1 for p in ports if p in web_ports) * 10  # +10 per web service
        
        return min(100, score)
    
    def _send_result(self, device: Dict):
        """Send device result through queue"""
        if self.result_queue:
            try:
                self.result_queue.put_nowait({
                    "__type": "scan_result",
                    "host": device
                })
            except queue.Full:
                pass
    
    def _send_status(self, status: str):
        """Send status message through queue"""
        if self.result_queue:
            try:
                self.result_queue.put_nowait({
                    "__type": "scan_status",
                    "status": status
                })
            except queue.Full:
                pass
    
    def start_continuous_discovery(self, network: str = "192.168.1.0/24"):
        """Start continuous network device discovery in background"""
        self.running = True
        logger.info(f"Starting continuous discovery on {network}")
    
    def stop_continuous_discovery(self):
        """Stop continuous discovery"""
        self.running = False
        logger.info("Stopped continuous discovery")
    
    def discover_devices(self, network: str = "192.168.1.0/24") -> List[Dict]:
        """Discover devices on network using multiple methods"""
        devices = []
        logger.info(f"Discovering devices on {network}")
        return devices
    
    def search_devices(self, query: str) -> List[Dict]:
        """Search for devices"""
        return []
    
    def get_all_devices(self) -> List[Dict]:
        """Get all discovered devices"""
        return list(self.devices.values())
    
    def scan_ports(self, target: str, ports: str = "1-1000", timeout: int = 10) -> Dict:
        """Scan ports on target"""
        return {}
    
    def _identify_service(self, port: int) -> str:
        """Identify service on port"""
        return COMMON_PORTS.get(port, "Unknown")
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification"""
        return []


# Global scanner instance
_scanner = None


def get_scanner() -> NetworkScanner:
    """Get or create global scanner instance"""
    global _scanner
    if _scanner is None:
        _scanner = NetworkScanner()
    return _scanner
