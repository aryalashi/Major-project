#!/usr/bin/env python3
"""
ALERT & EVIDENCE LOGGING - Stores attack evidence (PCAP + JSON)
===============================================================

Features:
- Multi-channel alerts (Telegram, Discord, Email, Slack, WhatsApp)
- Save PCAP evidence for each attack
- Save JSON metadata for each attack
- Organized by attack type and timestamp
- Instant logging with thread-safe operations

Author: NIDS Team
Date: March 28, 2026
"""

import os
import json
import logging
import threading
import requests
import smtplib
from datetime import datetime
from typing import Dict, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Desktop notifications (no admin required)
try:
    from notifications import get_notification_manager
    NOTIFY_AVAILABLE = True
except ImportError:
    NOTIFY_AVAILABLE = False

logger = logging.getLogger("AlertEngine")


class AlertEngine:
    """
    Multi-channel alert system for coordinated attack notifications.
    Supports: Telegram, Discord, Email, Slack, WhatsApp
    """
    
    def __init__(self, env_config: Dict = None):
        """
        Initialize alert engine with configuration from environment variables.
        
        Args:
            env_config: Dictionary of environment variables (optional)
        """
        import os
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat = os.getenv("TELEGRAM_CHAT_ID", "")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_URL", "")
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        self.email_address = os.getenv("EMAIL_ADDRESS", "")
        self.email_password = os.getenv("EMAIL_PASSWORD", "")
        self.email_to = os.getenv("EMAIL_RECIPIENT", "")
        self.whatsapp_phone = os.getenv("CALLMEBOT_PHONE", "")
        self.whatsapp_key = os.getenv("CALLMEBOT_APIKEY", "")
        
        # Rate limiting
        self.rate_limit_delay = float(os.getenv("DISCORD_RATE_LIMIT_DELAY", "1.0"))
        self.last_alert_time = {}
        self.alert_cooldown = 15  # seconds between same alert type
        
        # Desktop notifications (no admin required)
        if NOTIFY_AVAILABLE:
            self.notifier = get_notification_manager()
            logger.info("✓ Desktop notifications: ENABLED")
        else:
            self.notifier = None
            logger.warning("✗ Desktop notifications: DISABLED (Plyer not available)")
        
        self.enabled_channels = []
        self._detect_enabled_channels()
        
        logger.info(f"AlertEngine initialized")
        logger.info(f"  Enabled channels: {', '.join(self.enabled_channels) if self.enabled_channels else 'None'}")
    
    def _detect_enabled_channels(self):
        """Detect which alert channels are enabled based on configuration."""
        if self.telegram_token and self.telegram_chat:
            self.enabled_channels.append("telegram")
        if self.discord_webhook:
            self.enabled_channels.append("discord")
        if self.email_address and self.email_password and self.email_to:
            self.enabled_channels.append("email")
        if self.slack_webhook:
            self.enabled_channels.append("slack")
        if self.whatsapp_phone and self.whatsapp_key:
            self.enabled_channels.append("whatsapp")
    
    def send_alert(self, alert: Dict, severity: str = None) -> bool:
        """
        Send alert through all enabled channels (non-blocking with background threads).
        
        Args:
            alert: Alert dictionary
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        
        Returns:
            True immediately (channels send in background)
        """
        try:
            severity = severity or alert.get("severity", "MEDIUM")
            alert_type = alert.get("type", "UNKNOWN")
            
            # Check rate limiting
            now = datetime.now().timestamp()
            last = self.last_alert_time.get(alert_type, 0)
            if now - last < self.alert_cooldown:
                logger.debug(f"Alert rate limited: {alert_type}")
                return False
            
            self.last_alert_time[alert_type] = now
            
            # Format message once
            message = self._format_message(alert)
            
            # CRITICAL: Send all channels in background threads to avoid blocking!
            # This allows logging and main detection loop to continue immediately
            
            if "telegram" in self.enabled_channels:
                thread = threading.Thread(
                    target=self._send_telegram_bg, args=(message, severity),
                    daemon=True
                )
                thread.start()
            
            if "discord" in self.enabled_channels:
                thread = threading.Thread(
                    target=self._send_discord_bg, args=(message, severity),
                    daemon=True
                )
                thread.start()
            
            if "email" in self.enabled_channels:
                thread = threading.Thread(
                    target=self._send_email_bg, args=(message, severity),
                    daemon=True
                )
                thread.start()
            
            if "slack" in self.enabled_channels:
                thread = threading.Thread(
                    target=self._send_slack_bg, args=(message, severity),
                    daemon=True
                )
                thread.start()
            
            if "whatsapp" in self.enabled_channels:
                thread = threading.Thread(
                    target=self._send_whatsapp_bg, args=(message, severity),
                    daemon=True
                )
                thread.start()
            
            # Desktop notification (always send if available - no admin needed)
            if self.notifier:
                if self.notifier.notify_alert(alert, show_async=True):
                    logger.debug(f"✓ Desktop notification sent")
            
            return True  # Return immediately, channels send in background
        
        except Exception as e:
            logger.error(f"[ERROR] Alert dispatch failed: {e}")
            return False
    
    def _send_telegram_bg(self, message: str, severity: str):
        """Send telegram in background thread."""
        try:
            if self._send_telegram(message, severity):
                logger.info(f"✓ Alert sent to Telegram")
        except Exception as e:
            logger.debug(f"Telegram bg send failed: {e}")
    
    def _send_discord_bg(self, message: str, severity: str):
        """Send discord in background thread."""
        try:
            if self._send_discord(message, severity):
                logger.info(f"✓ Alert sent to Discord")
        except Exception as e:
            logger.debug(f"Discord bg send failed: {e}")
    
    def _send_email_bg(self, message: str, severity: str):
        """Send email in background thread."""
        try:
            if self._send_email(message, severity):
                logger.info(f"✓ Alert sent to Email")
        except Exception as e:
            logger.debug(f"Email bg send failed: {e}")
    
    def _send_slack_bg(self, message: str, severity: str):
        """Send slack in background thread."""
        try:
            if self._send_slack(message, severity):
                logger.info(f"✓ Alert sent to Slack")
        except Exception as e:
            logger.debug(f"Slack bg send failed: {e}")
    
    def _send_whatsapp_bg(self, message: str, severity: str):
        """Send whatsapp in background thread."""
        try:
            if self._send_whatsapp(message, severity):
                logger.info(f"✓ Alert sent to WhatsApp")
        except Exception as e:
            logger.debug(f"WhatsApp bg send failed: {e}")
    
    def _format_message(self, alert: Dict) -> str:
        """Format alert message for display."""
        return (
            f"🚨 **SECURITY ALERT**\n"
            f"Type: {alert.get('type', 'Unknown')}\n"
            f"Severity: {alert.get('severity', 'MEDIUM')}\n"
            f"Source: {alert.get('source', 'N/A')}\n"
            f"Target: {alert.get('target', 'N/A')}\n"
            f"Time: {alert.get('timestamp', 'N/A')}\n"
            f"Rule: {alert.get('rule_name', 'N/A')}"
        )
    
    def _send_telegram(self, message: str, severity: str) -> bool:
        """Send alert via Telegram."""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat,
                "text": message,
                "parse_mode": "Markdown"
            }
            response = requests.post(url, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Telegram alert failed: {e}")
            return False
    
    def _send_discord(self, message: str, severity: str) -> bool:
        """Send alert via Discord webhook."""
        try:
            colors = {
                "CRITICAL": 16711680,  # Red
                "HIGH": 16744448,      # Orange
                "MEDIUM": 16776960,    # Yellow
                "LOW": 65280            # Green
            }
            
            embed = {
                "title": "🚨 NIDS Alert",
                "description": message,
                "color": colors.get(severity, 9807270),
                "timestamp": datetime.now().isoformat()
            }
            
            payload = {"embeds": [embed]}
            response = requests.post(self.discord_webhook, json=payload, timeout=5)
            return response.status_code in [200, 204]
        except Exception as e:
            logger.warning(f"Discord alert failed: {e}")
            return False
    
    def _send_email(self, message: str, severity: str) -> bool:
        """Send alert via Gmail SMTP."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = self.email_to
            msg['Subject'] = f"[NIDS {severity}] Security Alert"
            
            body = MIMEText(message, 'plain')
            msg.attach(body)
            
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as server:
                server.login(self.email_address, self.email_password)
                server.send_message(msg)
            
            return True
        except Exception as e:
            logger.warning(f"Email alert failed: {e}")
            return False
    
    def _send_slack(self, message: str, severity: str) -> bool:
        """Send alert via Slack webhook."""
        try:
            colors = {
                "CRITICAL": "danger",
                "HIGH": "warning",
                "MEDIUM": "#ff9900",
                "LOW": "good"
            }
            
            payload = {
                "attachments": [
                    {
                        "color": colors.get(severity, "#439FE0"),
                        "title": "NIDS Security Alert",
                        "text": message,
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(self.slack_webhook, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Slack alert failed: {e}")
            return False
    
    def _send_whatsapp(self, message: str, severity: str) -> bool:
        """Send alert via CallMeBot WhatsApp API."""
        try:
            url = "https://api.callmebot.com/whatsapp.php"
            params = {
                "phone": self.whatsapp_phone,
                "text": message[:1000],  # CallMeBot limit
                "apikey": self.whatsapp_key
            }
            response = requests.get(url, params=params, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"WhatsApp alert failed: {e}")
            return False


class EvidenceLogger:
    """
    Logs network evidence (PCAP files + JSON metadata) for detected attacks.
    Organizes evidence by attack type and timestamp.
    """
    
    def __init__(self, evidence_dir: str = "attacks"):
        """Initialize evidence logger."""
        self.evidence_dir = evidence_dir
        os.makedirs(evidence_dir, exist_ok=True)
        self.total_logged = 0
        self.lock = threading.Lock()
        logger.info(f"Evidence Logger initialized. Directory: {self.evidence_dir}")
    
    def log_attack(self, alert: Dict, packet_data=None) -> Dict:
        """
        Log attack evidence (PCAP + JSON metadata).
        
        Args:
            alert: Alert dictionary with attack details
            packet_data: Raw PCAP packet data (bytes) or list of Scapy packets
        
        Returns:
            Dictionary with evidence file references
        """
        try:
            with self.lock:
                # Generate filename components
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                attack_type = alert.get("type", "UNKNOWN").replace(" ", "_").replace("[", "").replace("]", "")
                
                # Create attack-specific directory
                attack_dir = os.path.join(self.evidence_dir, f"{attack_type}")
                os.makedirs(attack_dir, exist_ok=True)
                
                # Base filename
                base_name = f"{timestamp}_{attack_type}"
                
                # Save JSON metadata
                json_filename = f"{base_name}.json"
                json_path = os.path.join(attack_dir, json_filename)
                
                json_data = {
                    "alert": alert,
                    "metadata": {
                        "logged_at": datetime.now().isoformat(),
                        "attack_type": attack_type,
                        "source": alert.get("source", "unknown"),
                        "target": alert.get("target", "unknown"),
                        "severity": alert.get("severity", "UNKNOWN"),
                    }
                }
                
                with open(json_path, 'w') as f:
                    json.dump(json_data, f, indent=2, default=str)
                
                logger.info(f"[EVIDENCE] Saved: {json_path}")
                
                # Save PCAP data if available
                pcap_path = None
                if packet_data:
                    pcap_filename = f"{base_name}.pcap"
                    pcap_path = os.path.join(attack_dir, pcap_filename)
                    
                    # Handle both bytes and list of Scapy packets
                    if isinstance(packet_data, bytes):
                        # Already bytes, write directly
                        with open(pcap_path, 'wb') as f:
                            f.write(packet_data)
                    elif isinstance(packet_data, list):
                        # List of Scapy packets - convert to PCAP
                        try:
                            from scapy.all import wrpcap
                            wrpcap(pcap_path, packet_data)
                        except ImportError:
                            logger.warning("Scapy not available for PCAP export")
                            pcap_path = None
                    
                    if pcap_path and os.path.exists(pcap_path):
                        logger.info(f"[PCAP] Saved: {pcap_path}")
                
                self.total_logged += 1
                
                return {
                    "json_file": json_path,
                    "pcap_file": pcap_path,
                    "timestamp": timestamp,
                    "attack_dir": attack_dir,
                }
        
        except Exception as e:
            logger.error(f"[ERROR] Failed to log evidence: {e}")
            return {}


if __name__ == "__main__":
    # Test
    engine = AlertEngine()
    test_alert = {
        "type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "source": "192.168.1.100",
        "target": "10.0.0.1",
        "rule_name": "SQL Injection Attempt",
        "timestamp": datetime.now().isoformat()
    }
    engine.send_alert(test_alert)
