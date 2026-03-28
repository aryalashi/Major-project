"""
example_complete_workflow.py
============================
Signature-only workflow example for the NIDS stack.

Demonstrates:
  1. Base DetectionEngine processing
  2. Signature payload analysis integration
  3. Signature-based threshold stats reporting
"""

import logging
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("WorkflowExample")


def run_signature_workflow_demo():
    """Run a minimal end-to-end signature workflow demo."""
    from rule_engine import RuleEngine
    from detection import DetectionEngine
    from advanced_payload_detection import AdvancedPayloadDetector

    logger.info("=" * 72)
    logger.info("SIGNATURE WORKFLOW DEMO")
    logger.info("=" * 72)

    rule_engine = RuleEngine("rules.json")
    detection_engine = DetectionEngine(rule_engine.get_rules())
    payload_detector = AdvancedPayloadDetector()

    # Minimal normalized packet example
    packet = {
        "src": "192.168.1.25",
        "dst": "192.168.1.10",
        "protocol": "TCP",
        "flags": "S",
        "dst_port": 80,
        "src_port": 55123,
        "icmp_type": None,
        "icmp_code": None,
        "size": 128,
        "timestamp": datetime.now().timestamp(),
        "payload": b"GET /index.php?id=1 UNION SELECT password FROM users",
    }

    alerts = detection_engine.process_packet(packet)
    payload_result = payload_detector.detect(packet, "TCP SYN Flood", packet["payload"])

    logger.info("Base alerts: %d", len(alerts))
    logger.info("Payload threat detected: %s", payload_result.get("is_threat", False))
    logger.info("Tuner stats: %s", detection_engine.get_tuner_stats())

    if alerts:
        logger.info("First alert summary: %s", alerts[0])
    if payload_result.get("detections"):
        logger.info("Payload detections: %s", payload_result["detections"])


def main():
    run_signature_workflow_demo()


if __name__ == "__main__":
    main()
