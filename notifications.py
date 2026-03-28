#!/usr/bin/env python3
"""
Windows Desktop Notifications - NO ADMIN REQUIRED
=================================================

Features:
- Uses Plyer library (no admin privileges needed)
- Cross-platform (Windows, Mac, Linux)
- Async notification delivery
- Severity-based styling
- Fallback graceful degradation

Author: NIDS Team
Date: March 28, 2026
"""

import logging
import threading
import re
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger("Notifications")

# Try plyer first (preferred - no admin needed)
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

# Windows fallback: win10toast
try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False

if not PLYER_AVAILABLE and not WIN10TOAST_AVAILABLE:
    logger.warning("Desktop notifications disabled (plyer/win10toast not available)")


class NotificationManager:
    """
    Send desktop notifications without requiring admin privileges.
    Uses Plyer library which works on Windows, Mac, and Linux.
    """
    
    # Severity to icon mapping and colors
    SEVERITY_CONFIG = {
        "CRITICAL": {
            "title_prefix": "🔴 CRITICAL ALERT",
            "emoji": "🔴",
            "timeout": 30,  # Show longer for critical
        },
        "HIGH": {
            "title_prefix": "🟠 HIGH ALERT",
            "emoji": "🟠",
            "timeout": 20,
        },
        "MEDIUM": {
            "title_prefix": "🟡 MEDIUM ALERT",
            "emoji": "🟡",
            "timeout": 15,
        },
        "LOW": {
            "title_prefix": "🔵 LOW ALERT",
            "emoji": "🔵",
            "timeout": 10,
        },
        "INFO": {
            "title_prefix": "ℹ️ INFO",
            "emoji": "ℹ️",
            "timeout": 10,
        },
    }
    
    def __init__(self, app_name: str = "NIDS - Network Security"):
        """
        Initialize notification manager.
        
        Args:
            app_name: Application name for notifications
        """
        self.app_name = app_name
        self.enabled = PLYER_AVAILABLE or WIN10TOAST_AVAILABLE
        self._toast = ToastNotifier() if WIN10TOAST_AVAILABLE else None
        self.notification_thread = None
        self.lock = threading.Lock()
        
        if self.enabled:
            backend = "plyer" if PLYER_AVAILABLE else "win10toast"
            logger.info(f"Desktop Notifications: ENABLED ({backend})")
        else:
            logger.warning("Desktop Notifications: DISABLED")

    @staticmethod
    def _normalize_text(text: str) -> str:
        """Keep popup text Windows-friendly by stripping emoji/symbol-only chars."""
        safe = text or ""
        safe = re.sub(r"[^\x20-\x7E\n\r\t]", "", safe)
        safe = re.sub(r"\s+", " ", safe).strip()
        return safe
    
    def notify_alert(
        self,
        alert: Dict,
        show_async: bool = True
    ) -> bool:
        """
        Send attack alert notification.
        
        Args:
            alert: Alert dictionary with attack details
            show_async: If True, send in background thread (non-blocking)
        
        Returns:
            True if notification was sent successfully
        """
        if not self.enabled:
            return False
        
        try:
            severity = alert.get("severity", "MEDIUM").upper()
            severity_config = self.SEVERITY_CONFIG.get(severity, self.SEVERITY_CONFIG["MEDIUM"])
            
            # Build notification message
            title = severity_config["title_prefix"]
            
            attack_type = alert.get("type", "Unknown").replace("_", " ")
            source = alert.get("source", "N/A")
            target = alert.get("target", "N/A")
            
            message = (
                f"{attack_type}\n"
                f"Source: {source}\n"
                f"Target: {target}"
            )
            
            if show_async:
                # Send in background thread to not block
                thread = threading.Thread(
                    target=self._send_notification,
                    args=(title, message, severity_config["timeout"]),
                    daemon=True
                )
                thread.start()
                return True
            else:
                # Send synchronously
                return self._send_notification(title, message, severity_config["timeout"])
        
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            return False
    
    def notify_scan(
        self,
        message: str,
        severity: str = "INFO",
        show_async: bool = True
    ) -> bool:
        """
        Send network scan notification.
        
        Args:
            message: Notification message
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            show_async: If True, send in background thread
        
        Returns:
            True if notification was sent successfully
        """
        if not self.enabled:
            return False
        
        try:
            severity = severity.upper()
            severity_config = self.SEVERITY_CONFIG.get(severity, self.SEVERITY_CONFIG["INFO"])
            
            title = f"🔍 Network Scan - {severity_config['emoji']}"
            
            if show_async:
                thread = threading.Thread(
                    target=self._send_notification,
                    args=(title, message, severity_config["timeout"]),
                    daemon=True
                )
                thread.start()
                return True
            else:
                return self._send_notification(title, message, severity_config["timeout"])
        
        except Exception as e:
            logger.error(f"Failed to send scan notification: {e}")
            return False
    
    def notify_status(
        self,
        message: str,
        show_async: bool = True
    ) -> bool:
        """
        Send status notification (non-blocking by default).
        
        Args:
            message: Notification message
            show_async: If True, send in background thread
        
        Returns:
            True if notification was sent successfully
        """
        if not self.enabled:
            return False
        
        try:
            title = "📊 NIDS Status"
            
            if show_async:
                thread = threading.Thread(
                    target=self._send_notification,
                    args=(title, message, 10),
                    daemon=True
                )
                thread.start()
                return True
            else:
                return self._send_notification(title, message, 10)
        
        except Exception as e:
            logger.error(f"Failed to send status notification: {e}")
            return False
    
    def _send_notification(
        self,
        title: str,
        message: str,
        timeout: int = 10
    ) -> bool:
        """
        Send a desktop notification using available backend.
        
        Args:
            title: Notification title
            message: Notification message body
            timeout: Display timeout in seconds
        
        Returns:
            True if notification was sent successfully
        """
        if not self.enabled:
            return False

        safe_title = self._normalize_text(title)[:64] or "NIDS Alert"
        safe_message = self._normalize_text(message)[:240] or "Security event detected"
        
        try:
            with self.lock:
                if PLYER_AVAILABLE:
                    notification.notify(
                        title=safe_title,
                        message=safe_message,
                        app_name=self.app_name,
                        timeout=timeout
                    )
                    logger.debug(f"[NOTIFY] {safe_title}: {safe_message}")
                    return True

                if self._toast is not None:
                    # duration in win10toast is seconds; threaded avoids blocking.
                    self._toast.show_toast(
                        safe_title,
                        safe_message,
                        duration=max(3, min(int(timeout), 15)),
                        threaded=True,
                    )
                    logger.debug(f"[NOTIFY] {safe_title}: {safe_message}")
                    return True

            return False
        
        except Exception as e:
            logger.debug(f"Notification backend error: {e}")
            # Fallback attempt if plyer failed at runtime and win10toast exists.
            if self._toast is not None:
                try:
                    self._toast.show_toast(
                        safe_title,
                        safe_message,
                        duration=max(3, min(int(timeout), 15)),
                        threaded=True,
                    )
                    return True
                except Exception as inner_e:
                    logger.debug(f"win10toast fallback error: {inner_e}")
            return False
    
    def test_notification(self) -> bool:
        """
        Send a test notification to verify system is working.
        
        Returns:
            True if test notification was sent successfully
        """
        if not self.enabled:
            logger.warning("Notifications not enabled")
            return False
        
        return self._send_notification(
            title="✓ NIDS Notifications Working",
            message="Desktop notifications are successfully configured!",
            timeout=10
        )


# Global notification manager instance
_notification_manager = None


def get_notification_manager() -> NotificationManager:
    """Get or create the global notification manager instance."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager


if __name__ == "__main__":
    # Test notifications
    logging.basicConfig(
        level=logging.INFO,
        format='[%(name)s] %(levelname)s: %(message)s'
    )
    
    notifier = get_notification_manager()
    
    # Test 1: Status notification
    print("\n📊 Testing status notification...")
    notifier.notify_status("NIDS system started successfully")
    
    # Test 2: Alert notifications
    print("🔴 Testing CRITICAL alert...")
    notifier.notify_alert({
        "severity": "CRITICAL",
        "type": "PORT_SCAN",
        "source": "192.168.1.100",
        "target": "192.168.1.1"
    })
    
    # Test 3: Scan notification
    print("🔍 Testing scan notification...")
    notifier.notify_scan("Found 5 open ports on 192.168.1.77", severity="HIGH")
    
    print("\n✓ All test notifications sent!")
    print("  (They should appear in your system notification center)")
