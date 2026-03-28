"""
packet_capture.py
-----------------
Packet Capture Engine for NIDS

Captures raw network packets via Scapy and converts them into a canonical,
normalized packet schema before pushing to the detection queue.

Normalization is handled by normalization.py — this module is ONLY
responsible for:
  1. Interface enumeration and selection
  2. Running the Scapy sniff loop
  3. Maintaining a raw-packet evidence buffer for PCAP export
  4. Delegating all field extraction to normalize_packet()

Protocol Classification
-----------------------
Protocol routing is done in normalization.py based on IP.proto field.
This module performs NO direct TCP/UDP/ICMP layer checks — it delegates
entirely to the normalization layer to prevent cross-protocol false positives.

Windows Requirements
--------------------
  Npcap must be installed in WinPcap-compatible mode.
  Application must run as Administrator.
  Download: https://npcap.com
"""

import logging
import subprocess
import sys
import re
import threading
import queue
from typing import Dict, List, Optional

logger = logging.getLogger("PacketCapture")

try:
    from scapy.all import sniff, get_if_list, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from normalization import normalize_packet
except ImportError:
    # Allow standalone import without the full project
    normalize_packet = None


# ── Interface Classification Keywords ────────────────────────────────────────

VM_KEYWORDS       = ["virtualbox","vmware","vbox","vmnet","hyper-v",
                     "hyperv","vethernet","docker","wsl","host-only",
                     "nat network","loopback host"]
VPN_KEYWORDS      = ["vpn","tap-windows","nordvpn","expressvpn",
                     "wireguard","openvpn","proton","mullvad",
                     "cisco","anyconnect","globalprotect","tap0"]
WIFI_KEYWORDS     = ["wi-fi","wifi","wireless","wlan","802.11",
                     "airport","wi fi"]
HOTSPOT_KEYWORDS  = ["local area connection*","microsoft wi-fi direct",
                     "hosted network","mobile hotspot","wi-fi direct",
                     "mshostednetwork"]
ETHERNET_KEYWORDS = ["ethernet","local area connection","gigabit",
                     "realtek pcie","intel(r) ethernet","broadcom",
                     "marvell","lan","e1000","e100"]
LOOPBACK_KEYWORDS = ["loopback","npcap loopback"]

TYPE_ICONS = {
    "wifi":     "[WiFi]    ",
    "ethernet": "[Ethernet]",
    "loopback": "[Loopback]",
    "vm":       "[VM]      ",
    "vpn":      "[VPN]     ",
    "hotspot":  "[Hotspot] ",
    "unknown":  "[Unknown] ",
}


# ── Interface Utilities ───────────────────────────────────────────────────────

def _guid_to_name_registry() -> Dict[str, str]:
    """Map Windows adapter GUID → friendly adapter name via Registry."""
    names = {}
    try:
        import winreg
        
        # Primary location: Network interfaces
        reg_paths = [
            r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}",
            r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        ]
        
        for reg_path in reg_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    i = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(key, i)
                            i += 1
                            
                            # Try connection subkey first (has "Name" = friendly name)
                            try:
                                with winreg.OpenKey(
                                    winreg.HKEY_LOCAL_MACHINE,
                                    rf"{reg_path}\{guid}\Connection"
                                ) as subkey:
                                    name = winreg.QueryValueEx(subkey, "Name")[0]
                                    # Store multiple key formats
                                    names[guid.upper()] = name
                                    names[guid.lower()] = name
                                    if "{" not in guid:
                                        names["{" + guid + "}"] = name
                                        names["{" + guid.upper() + "}"] = name
                                    logger.debug(f"Registry adapter: {guid} -> {name}")
                                    continue
                            except (FileNotFoundError, OSError):
                                pass
                            
                            # Fallback to Description in Class registry
                            try:
                                with winreg.OpenKey(
                                    winreg.HKEY_LOCAL_MACHINE,
                                    rf"{reg_path}\{guid}"
                                ) as subkey:
                                    desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                                    names[guid.upper()] = desc
                                    names[guid.lower()] = desc
                                    logger.debug(f"Registry device: {guid} -> {desc}")
                            except (FileNotFoundError, OSError):
                                pass
                        except OSError:
                            break
            except (FileNotFoundError, OSError):
                continue
                            
    except Exception as e:
        logger.debug(f"Registry read failed: {e}")
    
    return names


def _get_all_ips() -> Dict[str, str]:
    """Return {interface_name: IPv4} mapping from ipconfig output."""
    ips = {}
    try:
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.split('\n')
        
        current_adapter = None
        for line_num, line in enumerate(lines):
            # Adapter line format: "Ethernet adapter <name>:" or "Wireless LAN adapter <name>:"
            if 'adapter' in line.lower() and ':' in line:
                parts = line.split('adapter')
                if len(parts) > 1:
                    adapter_name = parts[1].split(':')[0].strip()
                    current_adapter = adapter_name.lower()
            
            # IPv4 line format: "   IPv4 Address. . . . . . . . . . . : 192.168.x.x"
            elif 'ipv4 address' in line.lower() and current_adapter:
                parts = line.split(':')
                if len(parts) > 1:
                    ip = parts[-1].strip()
                    if ip and ip != '(Preferred)':  # Filter out invalid entries
                        ips[current_adapter] = ip
                        logger.debug(f"IP mapping: {current_adapter} -> {ip}")
    except Exception as e:
        logger.debug(f"ipconfig parsing failed: {e}")
    
    return ips


def _classify(friendly_name: str, ip: str) -> str:
    """Classify interface type based on friendly name and IP."""
    n = friendly_name.lower()
    
    # Explicit loopback checks
    if ip == "127.0.0.1" or any(k in n for k in LOOPBACK_KEYWORDS):
        return "loopback"
    if "npcap loopback" in n:
        return "loopback"
    
    # Check other categories
    if any(k in n for k in HOTSPOT_KEYWORDS):
        return "hotspot"
    if any(k in n for k in VPN_KEYWORDS):
        return "vpn"
    if any(k in n for k in VM_KEYWORDS):
        return "vm"
    if any(k in n for k in WIFI_KEYWORDS):
        return "wifi"
    if any(k in n for k in ETHERNET_KEYWORDS):
        return "ethernet"
    
    # Default guessing for unclassified adapters with IP
    if ip and ip != "N/A" and not ip.startswith("127"):
        return "ethernet"  # Most common for unnamed adapters
    
    return "unknown"


def _priority(itype: str, ip: str) -> int:
    if itype == "ethernet" and not ip.startswith("127"):
        return 0
    if itype == "wifi":
        return 1
    if itype == "hotspot":
        return 2
    if itype == "vpn":
        return 10
    if itype == "vm":
        return 100
    return 1000


def get_labelled_interfaces() -> Dict[str, str]:
    """Get all interfaces with type labels and friendly names."""
    try:
        if not SCAPY_AVAILABLE:
            return {}
        
        ifaces = get_if_list()
        ips = _get_all_ips()
        guid_to_name = _guid_to_name_registry()
        logger.debug(f"Raw interfaces: {ifaces}")
        logger.debug(f"Registry GUID map: {guid_to_name}")
        logger.debug(f"IPs map: {ips}")
        
        labeled = {}
        
        for iface in ifaces:
            friendly_name = iface
            
            # Handle loopback special case
            if "Loopback" in iface:
                labeled["[Loopback] Npcap Loopback Adapter (127.0.0.1)"] = iface
                continue
            
            # Extract GUID from device path like \\Device\\NPF_{GUID}
            guid_match = re.search(r'\{([0-9A-F\-]+)\}', iface, re.IGNORECASE)
            if guid_match:
                guid = guid_match.group(1).upper()
                # Try multiple key formats
                for key in [guid, "{" + guid + "}", guid.lower(), "{" + guid.lower() + "}"]:
                    if key in guid_to_name:
                        friendly_name = guid_to_name[key]
                        logger.debug(f"Registry mapping found: {guid} -> {friendly_name}")
                        break
            
            # Try to match IP from ipconfig
            ip = ""
            for config_name, config_ip in ips.items():
                if config_name in friendly_name.lower() or friendly_name.lower() in config_name:
                    ip = config_ip
                    logger.debug(f"IP matched: {friendly_name} -> {config_ip}")
                    break
            
            # Classify the interface type
            itype = _classify(friendly_name, ip)
            icon = TYPE_ICONS.get(itype, '[Unknown] ')
            label = f"{icon} {friendly_name}{f' ({ip})' if ip else ''}"
            labeled[label] = iface
            logger.debug(f"Interface added: {label}")
        
        return labeled
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return {}


def get_best_interface(labelled: Dict[str, str]) -> Optional[str]:
    """Return display label of best real interface (WiFi > Ethernet > Hotspot)."""
    # Prefer real adapters over loopback/VM
    for label, iface in labelled.items():
        t = label.strip().lower()
        if "[wifi]" in t or "[ethernet]" in t or "[hotspot]" in t:
            return label  # Return the display label, not the device path
    
    # Fallback to first non-loopback, non-VM interface
    for label, iface in labelled.items():
        t = label.strip().lower()
        if "[loopback]" not in t and "[vm]" not in t:
            return label
    
    # Ultimate fallback: return first interface
    if labelled:
        return list(labelled.keys())[0]
    
    return None


# ── PacketCapture ─────────────────────────────────────────────────────────────

class PacketCapture:
    """
    Main packet capture engine for NIDS.
    Uses Scapy to sniff packets and normalize them.
    """
    
    def __init__(self, pkt_queue=None):
        self.queue = pkt_queue
        self.running = False
        self.packet_count = 0
        self._stop_event = threading.Event()  # Thread-safe stop signal
        self.evidence_packets = []  # Store recent packets for evidence
        self._sniff_thread = None
        
        logger.info("PacketCapture initialized")
    
    def start(self, iface: str, callback=None):
        """Start packet capture in background thread (non-blocking)."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return
        
        if self.running:
            logger.warning("Capture already running")
            return
        
        self.running = True
        self._stop_event.clear()
        
        # Start sniff in daemon thread so it doesn't block GUI
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            args=(iface,),
            daemon=True
        )
        self._sniff_thread.start()
        logger.info(f"Capture thread started on {iface}")
    
    def _sniff_loop(self, iface: str):
        """Background thread: runs the actual sniff loop."""
        logger.info(f"Sniff loop starting on {iface}")
        try:
            sniff(
                iface=iface,
                prn=self._on_packet,
                filter="ip",
                stop_filter=self._stop_condition,
                timeout=None  # Will use stop_filter
            )
        except KeyboardInterrupt:
            logger.info("Capture interrupted")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False
            logger.info("Sniff loop ended")
    
    def _stop_condition(self, pkt):
        """Return True to stop sniffing."""
        return self._stop_event.is_set()
    
    def stop(self):
        """Stop packet capture gracefully."""
        if not self.running:
            return
        
        logger.info("Stopping capture...")
        self._stop_event.set()  # Signal sniff loop to stop
        self.running = False
        
        # Wait for sniff thread to finish (max 2 seconds)
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=2.0)
        
        logger.info(f"Capture stopped. Total packets: {self.packet_count}")
    
    def _on_packet(self, raw_pkt):
        """Callback for each captured packet."""
        if not self.running:
            return
        
        self.packet_count += 1
        
        # Store for evidence (keep last 500)
        self.evidence_packets.append(raw_pkt)
        if len(self.evidence_packets) > 500:
            self.evidence_packets.pop(0)
        
        if normalize_packet:
            try:
                normalized = normalize_packet(raw_pkt)
                if normalized and self.queue:
                    try:
                        self.queue.put_nowait(normalized)
                    except queue.Full:
                        logger.debug("Packet queue full, dropping packet")
            except Exception as e:
                logger.debug(f"Packet normalization failed: {e}")
    
    def get_evidence_packets(self):
        """Get stored packets for evidence export."""
        return self.evidence_packets.copy()
