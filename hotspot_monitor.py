"""
hotspot_monitor.py  (v2 - Bidirectional)
-----------------------------------------
Monitors ALL traffic between:
  - Your laptop → connected devices  (you attacking them)
  - Connected devices → your laptop  (they attacking you)
  - Connected device A → device B    (cross-device attacks)

When hotspot is ON, all traffic between connected devices
passes through your laptop's hotspot interface.
Your laptop IS the router — it sees ALL packets.

This version:
  1. Monitors traffic in BOTH directions
  2. Detects if your laptop is the attacker (source = your IP)
  3. Detects cross-device attacks (device A attacks device B)
  4. Shows victim device in alerts
  5. Telegram notification includes attacker and victim
"""

import logging
import threading
import queue
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("HotspotMonitor")


@dataclass
class HotspotClient:
    """Represents a connected hotspot client device."""
    ip: str
    mac: str
    hostname: str = "Unknown"
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_attacking: bool = False


class HotspotMonitor:
    """
    Full bidirectional hotspot traffic monitor.

    Architecture:
      PacketCapture → process_packet()
                    → checks if src OR dst is a hotspot client
                    → runs detection engine on the packet
                    → if alert: records which device is attacker,
                                which is victim
                    → notifies GUI + Telegram
    """

    def __init__(self,
                 detection_engine=None,
                 gui_queue: queue.Queue = None,
                 alert_engine=None,
                 my_ip: str = ""):
        self.detection_engine = detection_engine
        self.gui_queue = gui_queue or queue.Queue()
        self.alert_engine = alert_engine
        self.my_ip = my_ip
        
        self.clients: Dict[str, HotspotClient] = {}
        self.running = False
        self.monitor_thread = None
        
        logger.info("HotspotMonitor initialized")

    # ------------------------------------------------------------------ #
    #  START / STOP                                                        #
    # ------------------------------------------------------------------ #

    def start(self):
        """Start the hotspot monitor."""
        self.running = True
        self._detect_my_hotspot_ip()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("HotspotMonitor started")

    def stop(self):
        """Stop the hotspot monitor."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("HotspotMonitor stopped")

    def _detect_my_hotspot_ip(self):
        """Detect our hotspot IP (e.g., 192.168.137.1)."""
        try:
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if "Hosted Network" in line or "Mobile Hotspot" in line:
                    # Found hotspot interface, next IPv4 Address is ours
                    idx = result.stdout.find(line)
                    section = result.stdout[idx:idx+500]
                    for subline in section.split('\n'):
                        if "IPv4 Address" in subline:
                            self.my_ip = subline.split(":")[-1].strip()
                            logger.info(f"Detected hotspot IP: {self.my_ip}")
                            return
        except Exception as e:
            logger.error(f"Failed to detect hotspot IP: {e}")

    # ------------------------------------------------------------------ #
    #  MAIN LOOP — Refresh client list                                     #
    # ------------------------------------------------------------------ #

    def _monitor_loop(self):
        """Main monitoring loop - refresh clients periodically."""
        while self.running:
            try:
                self._refresh_clients()
                threading.Event().wait(5)  # Refresh every 5 seconds
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

    def _refresh_clients(self):
        """Refresh connected hotspot clients via ARP table."""
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1]
                    
                    # Only track hotspot subnet (192.168.137.x)
                    if ip.startswith("192.168.137.") and ip != self.my_ip:
                        if ip not in self.clients:
                            self.clients[ip] = HotspotClient(ip=ip, mac=mac)
                            logger.info(f"New hotspot client: {ip} ({mac})")
        
        except Exception as e:
            logger.error(f"Failed to refresh clients: {e}")

    # ------------------------------------------------------------------ #
    #  PACKET PROCESSING — BIDIRECTIONAL                                  #
    # ------------------------------------------------------------------ #

    def process_packet(self, packet_info: dict) -> list:
        """
        Process packet for hotspot attacks.
        Returns list of alerts detected.
        """
        alerts = []
        
        src = packet_info.get("src")
        dst = packet_info.get("dst")
        
        # Check if packet involves hotspot clients
        src_is_client = src in self.clients or src == self.my_ip
        dst_is_client = dst in self.clients or dst == self.my_ip
        
        if not (src_is_client or dst_is_client):
            return alerts  # Not hotspot traffic
        
        # Run detection engine on this packet
        if self.detection_engine:
            try:
                detected_alerts = self.detection_engine.process_packet(packet_info)
                
                for alert in detected_alerts:
                    # Mark source as attacker
                    if src in self.clients:
                        self.clients[src].is_attacking = True
                    
                    # Record alert with direction
                    self._record_alert(src, dst, alert)
                    self.gui_queue.put({
                        "type": "hotspot_alert",
                        "alert": alert,
                        "attacker_ip": src,
                        "victim_ip": dst,
                        "attacker_device": self.clients.get(src, {}).ip if src in self.clients else "External",
                        "victim_device": self.clients.get(dst, {}).ip if dst in self.clients else "External"
                    })
                    
                    alerts.append(alert)
            
            except Exception as e:
                logger.error(f"Detection error: {e}")
        
        return alerts

    def _record_alert(self, src: str, dst: str, alert: dict):
        """Record an alert with attack direction."""
        direction = "UNKNOWN"
        
        if src in self.clients and dst == self.my_ip:
            direction = "client→laptop"
        elif src == self.my_ip and dst in self.clients:
            direction = "laptop→client"
        elif src in self.clients and dst in self.clients:
            direction = "client→client"
        elif src not in self.clients and dst in self.clients:
            direction = "external→client"
        
        alert["direction"] = direction
        logger.info(f"Attack: {direction} | {src}→{dst} | {alert.get('rule', 'N/A')}")

    # ------------------------------------------------------------------ #
    #  LAN ATTACK MONITOR (PC A attacks PC B)                             #
    # ------------------------------------------------------------------ #

    def register_lan_hosts(self, host_ips: list):
        """Register known LAN hosts for cross-device attack detection."""
        for ip in host_ips:
            if ip not in self.clients:
                self.clients[ip] = HotspotClient(ip=ip, mac="unknown")
                logger.info(f"Registered LAN host: {ip}")

    # ------------------------------------------------------------------ #
    #  NOTIFICATIONS                                                       #
    # ------------------------------------------------------------------ #

    def _notify_new_device(self, client: HotspotClient):
        """Notify about new device joining hotspot."""
        msg = f"🔔 New Device: {client.ip} ({client.mac})"
        if self.alert_engine:
            self.alert_engine.send_alert({
                "type": "NEW_DEVICE",
                "device_ip": client.ip,
                "device_mac": client.mac,
                "message": msg
            })

    def notify_attack(self, alert: dict):
        """Send attack notification."""
        msg = f"🚨 HOTSPOT ATTACK DETECTED!\n{alert}"
        if self.alert_engine:
            self.alert_engine.send_alert(alert)
        
        logger.warning(msg)

    # ------------------------------------------------------------------ #
    #  HELPERS                                                             #
    # ------------------------------------------------------------------ #

    def get_clients(self) -> Dict[str, HotspotClient]:
        """Return dictionary of connected clients."""
        return self.clients

    def get_attacking_clients(self) -> List[HotspotClient]:
        """Return list of clients that have attacked."""
        return [c for c in self.clients.values() if c.is_attacking]
