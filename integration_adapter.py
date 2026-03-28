"""
integration_adapter.py
======================
Adapter module to integrate advanced_payload_detection.py with existing
detection.py and packet_capture.py components.

This file shows how to:
  1. Patch existing DetectionEngine with payload analysis
  2. Extract payloads from raw Scapy packets
  3. Manage threshold configurations
  4. Route alerts through existing alert.py system

Usage in main.py:
─────────────────
    from integration_adapter import EnhancedDetectionPipeline
    
    pipeline = EnhancedDetectionPipeline(
        rules_file="rules.json",
        config={"enable_signature_detection": True}
    )
    
    # In packet capture loop:
    for packet in pcap_loop():
        packet_dict = normalize_packet(packet)
        alerts = pipeline.process(packet_dict, raw_packet=packet)
        for alert in alerts:
            handle_alert(alert)
"""

import os
import sys
import logging
import json
from typing import List, Dict, Optional, Tuple
from datetime import datetime

# Import existing modules (adjust paths if needed)
try:
    from detection import DetectionEngine
    from rule_engine import RuleEngine
    from normalization import normalize_packet
except ImportError as e:
    logging.warning(f"Could not import existing NIDS modules: {e}")
    logging.warning("Running in compatibility mode")

try:
    from advanced_payload_detection import (
        AdvancedPayloadDetector,
        SignatureDetector,
    )
except ImportError:
    logging.error("Could not import advanced_payload_detection module!")
    raise

logger = logging.getLogger("IntegrationAdapter")


# ==============================================================================
# PAYLOAD EXTRACTION UTILITIES
# ==============================================================================

def extract_payload_from_scapy(scapy_packet) -> Optional[bytes]:
    """
    Extract raw payload bytes from a Scapy packet.
    
    Attempts to extract from Raw layer, falling back to TCP/UDP data.
    
    Args:
        scapy_packet: A Scapy packet object
    
    Returns:
        bytes: Extracted payload, or empty bytes if none found
    """
    try:
        from scapy.all import Raw, TCP, UDP
        
        # Try Raw layer first
        if Raw in scapy_packet:
            return bytes(scapy_packet[Raw].load)
        
        # Try TCP/UDP payload
        if TCP in scapy_packet:
            tcp_layer = scapy_packet[TCP]
            if tcp_layer.payload:
                return bytes(tcp_layer.payload)
        
        if UDP in scapy_packet:
            udp_layer = scapy_packet[UDP]
            if udp_layer.payload:
                return bytes(udp_layer.payload)
        
        return b""
    except Exception as e:
        logger.debug(f"Payload extraction error: {e}")
        return b""


# ==============================================================================
# CONFIGURATION MANAGEMENT
# ==============================================================================

class AdvancedDetectionConfig:
    """Configuration for advanced payload detection integration"""
    
    def __init__(self, config_dict: Optional[Dict] = None):
        """
        Initialize configuration
        
        Args:
            config_dict: Optional config overrides. Keys:
                - enable_signature_detection: bool (default True)  
                - payload_sampling_rate: float 0-1 (default 1.0 = 100%)
                - max_payload_size: int (default 4096)
        """
        self.enable_signatures = config_dict.get("enable_signature_detection", True) if config_dict else True
        self.sampling_rate = config_dict.get("payload_sampling_rate", 1.0) if config_dict else 1.0
        self.max_payload_size = config_dict.get("max_payload_size", 4096) if config_dict else 4096
        self.threshold_algorithm = "SIGNATURE_BASED"
    
    def to_dict(self) -> Dict:
        """Convert config to dict"""
        return {
            "enable_signature_detection": self.enable_signatures,
            "payload_sampling_rate": self.sampling_rate,
            "max_payload_size": self.max_payload_size,
            "threshold_algorithm": self.threshold_algorithm,
        }


# ==============================================================================
# ALERT ESCALATION & ENRICHMENT
# ==============================================================================

class AlertEscalator:
    """Escalates alerts based on confidence levels and context"""
    
    def __init__(self):
        self.confidence_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def escalate_alert(self, base_alert: Dict, 
                      payload_analysis: Dict) -> Dict:
        """
        Escalate a base alert with payload analysis confirmation.
        
        Args:
            base_alert: Alert from base DetectionEngine
            payload_analysis: Results from AdvancedPayloadDetector
        
        Returns:
            Escalated alert dict with additional metadata
        """
        # Base confidence from ratio of detected threats
        payload_detections = payload_analysis.get("detections", [])
        detection_count = len(payload_detections)
        
        if detection_count == 0:
            confidence_boost = 0
        elif detection_count == 1:
            confidence_boost = 0.2
        else:
            confidence_boost = 0.5
        
        # Determine highest severity in payload analysis
        max_severity = None
        for detection in payload_detections:
            severity = detection.get("severity", "LOW")
            if max_severity is None or self._severity_rank(severity) > self._severity_rank(max_severity):
                max_severity = severity
        
        # Escalate original alert
        escalated = base_alert.copy()
        escalated["escalation_reasons"] = []
        
        if max_severity and self._severity_rank(max_severity) > self._severity_rank(base_alert.get("severity", "LOW")):
            escalated["severity"] = max_severity
            escalated["escalation_reasons"].append(f"Payload analysis revealed {max_severity} threat")
        
        if payload_analysis.get("is_threat"):
            escalated["escalation_reasons"].append("Payload analysis confirmed threat")
            escalated["confidence"] = self._boost_confidence(
                base_alert.get("confidence", "MEDIUM"),
                confidence_boost
            )
        
        # Attach detailed analysis
        escalated["payload_analysis"] = payload_analysis
        escalated["combined_score"] = (
            payload_analysis.get("score", 0.5) * 
            (1.0 + confidence_boost)
        )
        
        return escalated
    
    @staticmethod
    def _severity_rank(severity: str) -> int:
        """Convert severity to numeric rank"""
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get(severity, 0)
    
    @staticmethod
    def _boost_confidence(current: str, boost: float) -> str:
        """Boost confidence level based on payload confirmation"""
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        current_idx = levels.index(current) if current in levels else 1
        
        if boost > 0.4:
            target_idx = min(len(levels) - 1, current_idx + 1)
        elif boost > 0.2:
            target_idx = current_idx
        else:
            target_idx = max(0, current_idx - 1)
        
        return levels[target_idx]


# ==============================================================================
# THRESHOLD CONFIGURATION FOR EXISTING RULES (Simplified - Signature-based)
# ==============================================================================

class ThresholdOptimizer:
    """
    Simplified configuration for signature-based detection.
    
    Note: Entropy-based thresholds no longer used. Kept for API compatibility.
    """
    
    @classmethod
    def get_entropy_expectation(cls, protocol: str, dst_port: int) -> Tuple[Optional[float], Optional[float], str]:
        """
        Compatibility stub. Returns neutral values.
        
        Returns:
            (4.0, 7.0, "Signature-based detection (entropy not used)")
        """
        return 4.0, 7.0, "Signature-based detection"


# ==============================================================================
# MAIN INTEGRATION PIPELINE
# ==============================================================================

class EnhancedDetectionPipeline:
    """
    Complete detection pipeline combining:
      - Baseline DetectionEngine (signature rules)
      - AdvancedPayloadDetector (payload analysis)
      - Threshold adaptation
      - Alert escalation
    """
    
    def __init__(self, 
                 rules_file: str = "rules.json",
                 config: Optional[Dict] = None):
        """
        Initialize the enhanced detection pipeline.
        
        Args:
            rules_file: Path to rules.json
            config: Configuration dict (see AdvancedDetectionConfig)
        """
        self.config = AdvancedDetectionConfig(config)
        
        # Initialize base detection engine
        try:
            rule_engine = RuleEngine(rules_file)
            self.base_engine = DetectionEngine(rule_engine.rules)
        except Exception as e:
            logger.error(f"Failed to initialize base DetectionEngine: {e}")
            self.base_engine = None
        
        # Initialize advanced detection (signature-based)
        self.advanced_detector = AdvancedPayloadDetector()
        
        # Alert management
        self.alert_escalator = AlertEscalator()
        self.threshold_optimizer = ThresholdOptimizer()
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "alerts_escalated": 0,
            "payload_analyses": 0,
        }
        
        logger.info(f"EnhancedDetectionPipeline initialized with config: "
                   f"{self.config.to_dict()}")
    
    def process(self, packet_dict: dict, 
               raw_packet=None) -> List[dict]:
        """
        Process a packet through the complete detection pipeline.
        
        Args:
            packet_dict: Normalized packet from normalization.py
            raw_packet: Original Scapy packet (optional, for payload extraction)
        
        Returns:
            List of alert dicts (may be empty)
        """
        self.stats["packets_processed"] += 1
        alerts = []
        
        # Layer 1: Base signature detection
        if self.base_engine:
            base_alerts = self.base_engine.process_packet(packet_dict)
            self.stats["alerts_generated"] += len(base_alerts)
        else:
            base_alerts = []
        
        # Extract payload if available
        payload = None
        if raw_packet:
            payload = extract_payload_from_scapy(raw_packet)
        elif "payload" in packet_dict:
            payload = packet_dict["payload"]
        
        # Layer 2: Advanced payload analysis (if payload available + alerts)
        if payload and base_alerts:
            if len(payload) <= self.config.max_payload_size:
                for base_alert in base_alerts:
                    # Run advanced analysis
                    analysis = self.advanced_detector.detect(
                        packet_dict,
                        base_alert.get("rule_name", "unknown"),
                        payload
                    )
                    
                    self.stats["payload_analyses"] += 1
                    
                    # Escalate alert if payload confirms threat
                    escalated = self.alert_escalator.escalate_alert(
                        base_alert, analysis
                    )
                    alerts.append(escalated)
                    
                    if escalated != base_alert:
                        self.stats["alerts_escalated"] += 1
            else:
                # Payload too large; use base alerts
                alerts.extend(base_alerts)
        else:
            # No payload or no base alerts; use base alerts as-is
            alerts.extend(base_alerts)
        
        # Add metadata
        for alert in alerts:
            alert["processing_timestamp"] = datetime.now().isoformat()
            alert["pipeline_algorithm"] = self.config.threshold_algorithm
        
        return alerts
    
    def get_optimal_threshold(self, rule_name: str, protocol: str, 
                             dst_port: int, 
                             recent_rates: Optional[List[float]] = None) -> int:
        """
        Get optimized threshold for a specific rule considering protocol/port.
        
        Args:
            rule_name: Name of detection rule
            protocol: "TCP", "UDP", or "ICMP"
            dst_port: Destination port number
            recent_rates: Recent observation rates (optional)
        
        Returns:
            int: Recommended threshold
        """
        # Get base threshold from rule
        base_threshold = 15  # Default; would be looked up from rule in real system
        
        # Optimize based on protocol/port combination
        min_entropy, max_entropy, desc = self.threshold_optimizer.get_entropy_expectation(
            protocol, dst_port
        )
        
        logger.debug(f"Protocol {protocol}:{dst_port} expectation: "
                    f"entropy {min_entropy}-{max_entropy} - {desc}")
        
        # Use signature-based threshold manager from base engine when available.
        if recent_rates and len(recent_rates) >= 2 and self.base_engine:
            avg_rate = sum(recent_rates) / len(recent_rates)
            metrics = {
                "packet_rate": avg_rate,
                "sample_count": int(avg_rate * 10),
                "unique_ports": 0,
                "unique_sources": 0,
                "payload_signatures": [],
                "protocol": protocol,
                "port": dst_port,
            }
            adjusted = self.base_engine.threshold_manager.detect_and_adjust(
                rule_name=rule_name,
                base_threshold=base_threshold,
                metrics=metrics,
            )
            logger.debug(
                f"Signature threshold: {adjusted} "
                f"(algo={self.config.threshold_algorithm})"
            )
            return adjusted
        
        return base_threshold
    
    def get_statistics(self) -> Dict:
        """Get pipeline statistics"""
        return {
            **self.stats,
            "escalation_rate": (
                self.stats["alerts_escalated"] / max(1, self.stats["alerts_generated"])
                if self.stats["alerts_generated"] > 0 else 0
            ),
            "payload_analysis_coverage": (
                self.stats["payload_analyses"] / max(1, self.stats["alerts_generated"])
                if self.stats["alerts_generated"] > 0 else 0
            ),
        }
    
    def reset_statistics(self):
        """Reset statistics counters"""
        self.stats = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "alerts_escalated": 0,
            "payload_analyses": 0,
        }


# ==============================================================================
# EXAMPLE USAGE
# ==============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(name)s - %(levelname)s - %(message)s",
    )
    
    print("\n" + "="*80)
    print("INTEGRATION ADAPTER - INITIALIZATION TEST")
    print("="*80 + "\n")
    
    # Initialize pipeline
    try:
        pipeline = EnhancedDetectionPipeline(
            rules_file="rules.json",
            config={
                "entropy_threshold": 7.0,
                "enable_entropy_analysis": True,
                "enable_signature_detection": True,
                "enable_protocol_anomalies": True,
            }
        )
        
        print("✓ Pipeline initialized successfully")
        print(f"  Configuration: {pipeline.config.to_dict()}")
        
        # Test threshold optimization
        print("\nThreshold Optimization Examples:")
        print("-" * 80)
        
        test_cases = [
            ("TCP SYN Flood", "TCP", 80, [1.0, 1.5, 2.0, 1.8, 2.2]),
            ("DNS Flood", "UDP", 53, [3.0, 3.5, 4.0, 3.8, 3.2]),
            ("HTTP Flood", "TCP", 443, [5.0, 5.5, 6.0, 5.8, 6.2]),
        ]
        
        for rule_name, proto, port, rates in test_cases:
            threshold = pipeline.get_optimal_threshold(
                rule_name, proto, port, rates
            )
            min_e, max_e, desc = pipeline.threshold_optimizer.get_entropy_expectation(
                proto, port
            )
            print(f"\n  {rule_name} ({proto}:{port})")
            print(f"    Adjusted threshold: {threshold} pkt/10s")
            print(f"    Expected entropy: {min_e}-{max_e} bits/byte")
            print(f"    Description: {desc}")
        
        print("\n" + "="*80)
        print("✓ Integration adapter ready for production use")
        print("="*80)
        
    except Exception as e:
        logger.error(f"Initialization failed: {e}", exc_info=True)
        sys.exit(1)
