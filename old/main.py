"""
NIDS - Signature-Based Network Intrusion Detection System
=========================================================
Detection Algorithms:
  1. Sliding Window Rate Analysis   -> DoS detection
  2. Multi-Source Correlation       -> DDoS detection

Architecture: Modular multi-file (Windows + GUI + EXE ready)
Run as Administrator for packet capture to work.
"""

import sys
import queue
import logging
import threading
import os
from dotenv import load_dotenv

load_dotenv()

# Fix Windows Unicode encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

os.makedirs("logs",    exist_ok=True)
os.makedirs("attacks", exist_ok=True)

# ================================================================
#  CONFIGURATION (merged from config.py)
# ================================================================

class Config:
    """Centralised configuration - all credentials and parameters loaded from .env"""
    
    # Detection algorithm parameters
    DEFAULT_WINDOW        = int(os.getenv("NIDS_WINDOW",         10))
    ALERT_COOLDOWN        = int(os.getenv("NIDS_COOLDOWN",       15))  # Reduced from 30
    DDOS_SOURCE_THRESHOLD = int(os.getenv("NIDS_DDOS_THRESHOLD", 10))  # Reduced from 20
    MAX_EVIDENCE_PACKETS  = int(os.getenv("NIDS_MAX_EVIDENCE",   200))
    
    # Channel 1: Telegram
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "")
    
    # Channel 2: Email (Gmail SMTP)
    EMAIL_ADDRESS   = os.getenv("EMAIL_ADDRESS",   "")
    EMAIL_SENDER    = os.getenv("EMAIL_ADDRESS",   "")
    EMAIL_PASSWORD  = os.getenv("EMAIL_PASSWORD",  "")
    EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT", "")
    EMAIL_RECEIVER  = os.getenv("EMAIL_RECIPIENT", "")
    
    # Channel 3: Discord Webhook
    DISCORD_WEBHOOK_URL      = os.getenv("DISCORD_WEBHOOK_URL", "")
    DISCORD_RATE_LIMIT_DELAY = float(os.getenv("DISCORD_RATE_LIMIT_DELAY", "1.0"))
    
    # Channel 4: Slack Webhook
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    
    # Channel 5: WhatsApp (CallMeBot)
    CALLMEBOT_PHONE  = os.getenv("CALLMEBOT_PHONE",  "")
    CALLMEBOT_APIKEY = os.getenv("CALLMEBOT_APIKEY", "")
    WHATSAPP_PHONE   = os.getenv("CALLMEBOT_PHONE",  "")
    WHATSAPP_APIKEY  = os.getenv("CALLMEBOT_APIKEY", "")
    
    # Vulnerability scanner
    ENABLE_VULN_SCAN   = os.getenv("ENABLE_VULN_SCAN", "true").lower() == "true"
    VULN_SCAN_COOLDOWN = int(os.getenv("VULN_SCAN_COOLDOWN", "60"))
    
    # IP Whitelist
    WHITELIST_IPS = [ip.strip() for ip in os.getenv("WHITELIST_IPS", "").split(",") if ip.strip()]
    
    # File paths
    LOG_FILE    = "logs/nids.log"
    ATTACKS_DIR = os.getenv("ATTACKS_DIR", "attacks")
    LOGS_DIR    = os.getenv("LOGS_DIR", "logs")

# ------------------------------------------------------------------ #
#  LOGGING SETUP                                                       #
# ------------------------------------------------------------------ #
class _FlushFileHandler(logging.FileHandler):
    """File handler that flushes EVERY record immediately for zero-delay logging."""
    def emit(self, record):
        super().emit(record)
        self.flush()  # CRITICAL: Flush immediately after every log
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Disable buffering - write immediately
        self.stream.reconfigure(line_buffering=False, write_through=True) if hasattr(self.stream, 'reconfigure') else None


class _SafeStreamHandler(logging.StreamHandler):
    """Stream handler that is UTF-8 safe and flushes immediately."""
    def emit(self, record):
        try:
            super().emit(record)
        except UnicodeEncodeError:
            try:
                msg = self.format(record)
                self.stream.write(msg.encode("utf-8", errors="replace").decode("utf-8"))
                self.stream.write(self.terminator)
            except Exception:
                pass
        self.flush()

_file_handler   = _FlushFileHandler("logs/nids.log", encoding="utf-8")
_stream_handler = _SafeStreamHandler(sys.stdout)
_formatter      = logging.Formatter(
    "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
_file_handler.setFormatter(_formatter)
_stream_handler.setFormatter(_formatter)
logging.basicConfig(
    level    = logging.INFO,
    handlers = [_file_handler, _stream_handler]
)
logger = logging.getLogger("NIDS")

# ------------------------------------------------------------------ #
#  LOCAL IMPORTS                                                       #
# ------------------------------------------------------------------ #
from rule_engine      import RuleEngine
from detection        import DetectionEngine
from packet_capture   import PacketCapture
from alert            import AlertEngine, EvidenceLogger
from network_scanner  import NetworkScanner
from hotspot_monitor  import HotspotMonitor
from vuln_scanner     import AutoScanner


# ------------------------------------------------------------------ #
#  CAPTURE CONTROLLER                                                  #
# ------------------------------------------------------------------ #
class CaptureController:
    """
    Packet pipeline:
      PacketCapture
        -> Signature Engine  (sliding window + multi-source correlation)
        -> Alert Engine      (Telegram)
        -> Evidence Logger   (PCAP + JSON)
        -> Auto Scanner      (vuln scan on victim)
        -> GUI Queue         (dashboard update)
    """

    def __init__(self, detection_engine, alert_engine,
                 evidence_logger, auto_scanner, gui_queue, hotspot_monitor=None):
        self.detection_engine = detection_engine  # also used by LiveTestTab
        self.alert_engine     = alert_engine
        self.evidence_logger  = evidence_logger
        self.auto_scanner     = auto_scanner
        self.hotspot_monitor  = hotspot_monitor
        self.gui_queue        = gui_queue

        self.packet_queue   = queue.Queue(maxsize=5000)
        self.capture        = None
        self._worker_thread = None
        self._running       = False

    def start(self, iface=None):
        """Start packet capture on specified interface (raw device path)."""
        try:
            self._running = True
            self.capture  = PacketCapture(self.packet_queue)
            self.capture.start(iface)  # Pass raw device path
            self._worker_thread = threading.Thread(
                target=self._detection_loop, daemon=True
            )
            self._worker_thread.start()
            logger.info(f"Capture started on interface: {iface or 'default'}")
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            self._running = False

    def stop(self):
        self._running = False
        if self.capture:
            self.capture.stop()
        logger.info("Capture stopped.")

    def _detection_loop(self):
        """Worker thread — signature detection pipeline."""
        while self._running:
            try:
                pkt = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # Forward packet info to GUI packet log
            try:
                self.gui_queue.put_nowait({
                    "__type":    "packet",
                    "src":       pkt["src"],
                    "dst":       pkt["dst"],
                    "protocol":  pkt["protocol"],
                    "flags":     pkt.get("flags", ""),
                    "dst_port":  pkt.get("dst_port", 0),
                    "timestamp": pkt["timestamp"]
                })
            except queue.Full:
                pass

            # Run signature detection
            alerts = self.detection_engine.process_packet(pkt)

            for alert in alerts:
                self._dispatch_alert(alert, pkt)
            
            # Run hotspot-specific detection (phone attacks)
            if self.hotspot_monitor:
                try:
                    hotspot_alerts = self.hotspot_monitor.process_packet(pkt)
                    for alert in hotspot_alerts:
                        self._dispatch_alert(alert, pkt)
                except Exception as e:
                    logger.debug(f"Hotspot detection error: {e}")

    def _dispatch_alert(self, alert: dict, pkt: dict):
        """Send alert through all output channels."""
        logger.warning(
            f"[ALERT] {alert['rule_name']} | {alert['type']} | "
            f"src={alert['source']} -> dst={alert['target']} | "
            f"severity={alert['severity']}"
        )

        # Attach dst_port from packet to alert for GUI port column
        alert["dst_port"] = pkt.get("dst_port", 0)

        # 1. Telegram alert
        self.alert_engine.send_alert(alert)

        # 2. Evidence (PCAP + JSON)
        raw_packets = self.capture.get_evidence_packets() if self.capture else []
        self.evidence_logger.log_attack(alert, raw_packets)

        # 3. Auto vuln scan on victim (HIGH/CRITICAL only)
        self.auto_scanner.handle_alert(alert)

        # 4. GUI dashboard update
        try:
            gui_alert = dict(alert)
            gui_alert["__type"] = "alert"
            self.gui_queue.put_nowait(gui_alert)
        except queue.Full:
            pass


# ------------------------------------------------------------------ #
#  MAIN ENTRY POINT                                                    #
# ------------------------------------------------------------------ #
def main():
    logger.info("=" * 60)
    logger.info("NIDS Starting - Signature-Based Intrusion Detection System")
    logger.info("=" * 60)

    # Load all components
    config           = Config()
    rule_engine      = RuleEngine("rules.json")
    rules            = rule_engine.get_rules()
    
    # Log rule engine statistics
    rule_stats = rule_engine.get_stats()
    logger.info(f"Rules loaded: {rule_stats['total_rules']} total")
    logger.info(f"  Protocols: {rule_stats['protocols']}")
    logger.info(f"  Severity breakdown: {rule_stats['severities']}")
    
    detection_engine = DetectionEngine(rules)
    
    # Log detection engine initialization
    logger.info("Detection Engine initialized with EWMA-based adaptive thresholding")
    if hasattr(detection_engine, 'get_tuner_stats'):
        tuner_stats = detection_engine.get_tuner_stats()
        logger.info(f"  Tuner parameters: alpha={tuner_stats['alpha']}, "
                   f"headroom={tuner_stats['headroom']}x, "
                   f"max_mult={tuner_stats['max_multiplier']}x")
    
    logger.info(f"Detection engine ready with {len(rules)} active rules")
    logger.info("-" * 60)
    
    alert_engine     = AlertEngine()
    evidence_logger  = EvidenceLogger()
    auto_scanner     = AutoScanner(alert_engine=alert_engine, scan_cooldown=60)

    # Feature 1: Network Scanner
    net_scanner              = NetworkScanner()
    net_scanner.alert_engine  = alert_engine   # enables report saving + all-channel alerts after vuln scan

    # GUI bridge queue
    gui_queue = queue.Queue(maxsize=2000)

    # Feature 2: Hotspot Monitor
    hotspot_monitor = HotspotMonitor(
        detection_engine = detection_engine,
        gui_queue        = gui_queue,
        alert_engine     = alert_engine,
    )

    # Capture controller
    controller = CaptureController(
        detection_engine = detection_engine,
        alert_engine     = alert_engine,
        evidence_logger  = evidence_logger,
        auto_scanner     = auto_scanner,
        gui_queue        = gui_queue,
        hotspot_monitor  = hotspot_monitor
    )

    # Get interface list with proper friendly labels
    # Use iface_utils to build human-readable labels
    # Each interface is classified as WiFi / Ethernet / Loopback / VM / VPN
    iface_map = {}
    best_iface_path = None
    try:
        from packet_capture import get_labelled_interfaces, get_best_interface
        iface_map    = get_labelled_interfaces()
        display_list = list(iface_map.keys())
        best_label   = get_best_interface(iface_map)  # Returns display label
        logger.info(f"Available interfaces: {display_list}")
        if best_label:
            best_iface_path = iface_map[best_label]  # Get raw device path
            logger.info(f"Best interface detected: {best_label}")
        # Log all detected interfaces with their types
        for label, raw in iface_map.items():
            logger.info(f"  Interface: {label} -> {raw}")
    except Exception as e:
        logger.warning(f"iface_utils failed ({e}) — using raw names")
        # Get raw interface list from Scapy as fallback
        try:
            from scapy.all import get_if_list
            raw_ifaces = get_if_list()
        except ImportError:
            raw_ifaces = []
        iface_map = {}
        for iface in raw_ifaces:
            if "NPF_" in iface:
                short   = iface.split("NPF_")[-1].strip("{}")[:8]
                display = f"NPF_{{{short}...}}"
            else:
                display = iface
            iface_map[display] = iface
        display_list = list(iface_map.keys())
        # Use first non-loopback interface as best
        for label, path in iface_map.items():
            if "Loopback" not in label:
                best_iface_path = path
                break

    # Launch GUI
    try:
        from gui import launch_gui
        launch_gui(
            packet_queue       = None,
            alert_queue        = gui_queue,
            capture_controller = controller,
            iface_list         = display_list,
            iface_map          = iface_map,
            net_scanner        = net_scanner,
            hotspot_monitor    = hotspot_monitor,
        )
    except ImportError as e:
        logger.error(f"GUI import failed: {e}")
        logger.info("Running in headless mode (10 seconds)...")
        import time
        # Use best interface path if available
        if best_iface_path:
            controller.start(best_iface_path)
        else:
            logger.warning("No valid interface found")
        time.sleep(10)
        controller.stop()


if __name__ == "__main__":
    main()