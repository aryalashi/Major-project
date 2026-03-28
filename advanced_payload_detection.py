"""
advanced_payload_detection.py (Simplified - Signature-Based Detection Only)
===========================================================================

Simplified payload analysis focusing on signature-based threat detection.

This module provides:
  1. Signature Matching - Pattern detection in raw payload bytes
  2. Integration with existing NIDS detection pipeline

Architecture
============
  
  + AdvancedPayloadDetector (Main orchestrator)
  + SignatureDetector (Pattern matching / payload scanning)
  + MockPacketCapture (For unit testing)

Integration with existing NIDS modules:
  - Imports Config from main.py
  - Consumes normalized packets from normalization.py
  - Chains with DetectionEngine.process_packet() results
  - Compatible with alert.py alerting system
"""

import os
import sys
import logging
import json
import hashlib
import urllib.parse
from collections import defaultdict
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime

# Try importing from main.py; fall back to defaults
try:
    from main import Config
except ImportError:
    class Config:
        """Fallback config for standalone testing"""
        DEFAULT_WINDOW = 10
        ALERT_COOLDOWN = 30
        MAX_EVIDENCE_PACKETS = 200
        LOG_FILE = "logs/nids.log"
        LOGS_DIR = "logs"

logger = logging.getLogger("AdvancedPayloadDetection")


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclass
class PayloadSignature:
    """Represents a threat signature pattern in raw payload bytes"""
    name: str                      # Unique signature ID
    pattern: bytes                 # Hex pattern to match
    description: str               # Human-readable description
    category: str                  # Attack category (SQLi, RCE, XSS, etc.)
    severity: str                  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    reference: str                 # CVE/attack database reference
    confidence: float              # 0.0 to 1.0 (prior probability of match)
    case_insensitive: bool = True
    min_occurrences: int = 1


# ==============================================================================
# SIGNATURE DETECTOR
# ==============================================================================

class SignatureDetector:
    """
    Detects threat pattern signatures within raw payload bytes.
    
    Signature matching: Exact byte patterns characteristic of known malware,
    exploits, and attack payloads.
    """
    
    def __init__(self):
        """Initialize with common threat signatures"""
        self.minimum_alert_score = 0.82
        self.signatures = [
            # Shellcode detections
            PayloadSignature(
                name="NOP_Sled_Shellcode",
                pattern=b"\x90" * 16,  # require a sustained sled to avoid random byte noise
                description="NOP sled (common shellcode prefix)",
                category="Shellcode",
                severity="HIGH",
                reference="Generic shellcode pattern",
                confidence=0.85,
                case_insensitive=False,
            ),
            
            # SQL Injection
            PayloadSignature(
                name="SQLi_UNION_SELECT",
                pattern=b"UNION SELECT",
                description="SQL UNION injection attempt",
                category="SQL Injection",
                severity="CRITICAL",
                reference="OWASP A1:2021",
                confidence=0.9,
            ),
            PayloadSignature(
                name="SQLi_DROP_TABLE",
                pattern=b"DROP TABLE",
                description="SQL DROP statement in payload",
                category="SQL Injection",
                severity="CRITICAL",
                reference="OWASP A1:2021",
                confidence=0.9,
            ),
            PayloadSignature(
                name="SQLi_OR_TRUE",
                pattern=b"' OR '1'='1",
                description="Boolean-based SQL injection predicate",
                category="SQL Injection",
                severity="HIGH",
                reference="OWASP A1:2021",
                confidence=0.85,
            ),
            PayloadSignature(
                name="SQLi_INFORMATION_SCHEMA",
                pattern=b"INFORMATION_SCHEMA",
                description="SQL metadata enumeration attempt",
                category="SQL Injection",
                severity="HIGH",
                reference="OWASP A1:2021",
                confidence=0.8,
            ),

            # Command injection / RCE
            PayloadSignature(
                name="CMD_Injection_WGET",
                pattern=b";wget ",
                description="Command injection using wget",
                category="Command Injection",
                severity="CRITICAL",
                reference="OWASP A03:2021",
                confidence=0.9,
            ),
            PayloadSignature(
                name="CMD_Injection_CURL",
                pattern=b";curl ",
                description="Command injection using curl",
                category="Command Injection",
                severity="CRITICAL",
                reference="OWASP A03:2021",
                confidence=0.9,
            ),
            PayloadSignature(
                name="CMD_Injection_CAT_PASSWD",
                pattern=b"; cat /etc/passwd",
                description="Command injection invoking /etc/passwd read",
                category="Command Injection",
                severity="CRITICAL",
                reference="OWASP A03:2021",
                confidence=0.9,
            ),
            PayloadSignature(
                name="CMD_Injection_WHOAMI",
                pattern=b"| whoami",
                description="Command injection using pipe with whoami",
                category="Command Injection",
                severity="HIGH",
                reference="OWASP A03:2021",
                confidence=0.88,
            ),
            PayloadSignature(
                name="CMD_Injection_Backtick_ID",
                pattern=b"`id`",
                description="Backtick command substitution execution",
                category="Command Injection",
                severity="HIGH",
                reference="OWASP A03:2021",
                confidence=0.86,
            ),
            PayloadSignature(
                name="Log4Shell_JNDI",
                pattern=b"${jndi:",
                description="JNDI injection pattern (Log4Shell-like)",
                category="RCE Exploit",
                severity="CRITICAL",
                reference="CVE-2021-44228",
                confidence=0.95,
            ),

            # Web exploitation
            PayloadSignature(
                name="XSS_Script_Tag",
                pattern=b"<script",
                description="Reflected/stored XSS script tag",
                category="XSS",
                severity="HIGH",
                reference="OWASP A03:2021",
                confidence=0.82,
            ),
            PayloadSignature(
                name="Path_Traversal",
                pattern=b"../",
                description="Path traversal sequence in payload",
                category="Path Traversal",
                severity="HIGH",
                reference="OWASP A01:2021",
                confidence=0.8,
                min_occurrences=2,
            ),
            PayloadSignature(
                name="SSRF_Metadata_AWS",
                pattern=b"169.254.169.254",
                description="SSRF target to cloud instance metadata",
                category="SSRF",
                severity="CRITICAL",
                reference="OWASP A10:2021",
                confidence=0.9,
            ),

            # Credential and post-exploitation indicators
            PayloadSignature(
                name="PowerShell_EncodedCommand",
                pattern=b"powershell -enc",
                description="Encoded PowerShell command execution",
                category="Post Exploitation",
                severity="CRITICAL",
                reference="MITRE ATT&CK T1059.001",
                confidence=0.92,
            ),
            PayloadSignature(
                name="Mimikatz_Indicator",
                pattern=b"sekurlsa::logonpasswords",
                description="Credential dumping command indicator",
                category="Credential Access",
                severity="CRITICAL",
                reference="MITRE ATT&CK T1003",
                confidence=0.95,
            ),
            
            # Known exploit patterns
            PayloadSignature(
                name="ELF_Binary_Header",
                pattern=b"\x7FELF",  # ELF magic bytes
                description="ELF executable binary detected",
                category="Binary Payload",
                severity="HIGH",
                reference="Binary upload detection",
                confidence=0.8,
                case_insensitive=False,
            ),
            PayloadSignature(
                name="Windows_PE_Header",
                pattern=b"MZ\x90",  # PE header
                description="Windows PE executable detected",
                category="Binary Payload",
                severity="HIGH",
                reference="Binary upload detection",
                confidence=0.8,
                case_insensitive=False,
            ),
        ]
        logger.info(f"SignatureDetector initialized with {len(self.signatures)} signatures")
    
    def detect_signatures(self, payload: bytes) -> Dict:
        """
        Scan payload for signature matches.
        
        Args:
            payload: Raw bytes to scan
        
        Returns:
            Dict with:
                matched_signatures: List[str] - Names of matched sigs
                total_score: float (0.0 to 1.0)
                is_alert: bool - True if score > threshold
                details: List[Dict] - Details per signature
        """
        if not payload:
            return {
                "matched_signatures": [],
                "total_score": 0.0,
                "is_alert": False,
                "details": [],
            }
        
        matches = []
        total_score = 0.0

        # Expand matching view with decoded URL payload when possible.
        matching_payload = payload
        try:
            decoded_text = urllib.parse.unquote_plus(payload.decode("latin-1", errors="ignore"))
            decoded_payload = decoded_text.encode("latin-1", errors="ignore")
            if decoded_payload and decoded_payload != payload:
                matching_payload = payload + b"\n" + decoded_payload
        except Exception:
            matching_payload = payload

        payload_upper = matching_payload.upper()

        for sig in self.signatures:
            haystack = payload_upper if sig.case_insensitive else payload
            needle = sig.pattern.upper() if sig.case_insensitive else sig.pattern
            if self._is_signature_match(sig, matching_payload, haystack, needle):
                match_data = {
                    "signature_name": sig.name,
                    "description": sig.description,
                    "category": sig.category,
                    "severity": sig.severity,
                    "reference": sig.reference,
                    "confidence": sig.confidence,
                }
                matches.append(match_data)
                total_score += sig.confidence
        
        # Score is sum of matched signature confidences (cap at 1.0)
        if total_score > 0:
            total_score = min(total_score / len(matches), 1.0)
        
        # Alert gate: require strong confidence or explicit critical indicators.
        has_critical = any(m["severity"] == "CRITICAL" for m in matches)
        is_alert = bool(matches) and (total_score >= self.minimum_alert_score or has_critical)
        
        if matches:
            # If we have matches, calculate average confidence
            avg_confidence = sum(m["confidence"] for m in matches) / len(matches)
            total_score = round(avg_confidence, 3)
        
        categories = sorted(set(m["category"] for m in matches))
        severities = [m["severity"] for m in matches]
        highest_severity = "LOW"
        if "CRITICAL" in severities:
            highest_severity = "CRITICAL"
        elif "HIGH" in severities:
            highest_severity = "HIGH"
        elif "MEDIUM" in severities:
            highest_severity = "MEDIUM"

        return {
            "matched_signatures": [m["signature_name"] for m in matches],
            "categories": categories,
            "highest_severity": highest_severity,
            "total_score": round(total_score, 3),
            "is_alert": is_alert,
            "num_matches": len(matches),
            "details": matches,
        }

    def _is_signature_match(self,
                            sig: PayloadSignature,
                            payload: bytes,
                            haystack: bytes,
                            needle: bytes) -> bool:
        """Context-aware match checks to reduce benign substring false positives."""
        if not needle:
            return False

        occurrence_count = haystack.count(needle)
        if occurrence_count < sig.min_occurrences:
            return False

        name = sig.name
        if name == "XSS_Script_Tag":
            xss_context = [b"ALERT(", b"ONERROR=", b"ONLOAD=", b"DOCUMENT.COOKIE", b"JAVASCRIPT:"]
            return any(token in haystack for token in xss_context)

        if name == "Path_Traversal":
            return (
                occurrence_count >= 2
                or b"%2E%2E%2F" in haystack
                or b"%252E%252E%252F" in haystack
            )

        if name == "NOP_Sled_Shellcode":
            return len(payload) >= 32

        if name in {"ELF_Binary_Header", "Windows_PE_Header"}:
            return len(payload) >= 128

        return True
    
    def add_custom_signature(self, name: str, pattern: bytes, 
                            description: str, severity: str,
                            reference: str, confidence: float):
        """
        Add a custom threat signature.
        
        Args:
            name: Unique signature identifier
            pattern: Byte pattern to match
            description: Human-readable description
            severity: "CRITICAL", "HIGH", "MEDIUM", "LOW"
            reference: CVE or threat database reference
            confidence: Score 0.0-1.0
        """
        sig = PayloadSignature(
            name=name,
            pattern=pattern,
            description=description,
            category="Custom",
            severity=severity,
            reference=reference,
            confidence=confidence,
        )
        self.signatures.append(sig)
        logger.info(f"Added custom signature: {name}")


# ==============================================================================
# ADVANCED PAYLOAD DETECTOR (Main Orchestrator)
# ==============================================================================

class AdvancedPayloadDetector:
    """
    Signature-based payload threat detection.
    
    Uses pattern matching to identify known malware and attack signatures.
    
    Usage:
        detector = AdvancedPayloadDetector()
        packet_with_payload = {...normalized packet..., "payload": b"..."}
        results = detector.detect(packet_with_payload, rule_name="TCP SYN Flood")
    """
    
    def __init__(self):
        self.signature_detector = SignatureDetector()
        self.detection_history = defaultdict(list)
        logger.info("AdvancedPayloadDetector initialized (Signature-based detection only)")
    
    def detect(self, packet: dict, rule_name: str,
               payload: Optional[bytes] = None) -> Dict:
        """
        Perform payload-level signature detection.
        
        Args:
            packet: Normalized packet dict
            rule_name: Associated rule name for context
            payload: Raw payload bytes (if None, attempts extraction)
        
        Returns:
            Dict with detection results
        """
        if payload is None:
            payload = packet.get("payload", b"")
        
        if not payload:
            return {
                "status": "no_payload",
                "payload_label": "NO_PAYLOAD",
                "category": "No Payload",
                "detections": [],
                "is_threat": False,
            }
        
        detections = []
        
        # Signature detection
        sig_result = self.signature_detector.detect_signatures(payload)
        if sig_result.get("is_alert"):
            detections.append({
                "type": "signature_match",
                "details": sig_result,
                "severity": sig_result.get("highest_severity", "HIGH"),
                "category": ", ".join(sig_result.get("categories", [])) or "Payload Threat",
            })
        
        result = {
            "rule_name": rule_name,
            "packet_src": packet.get("src"),
            "packet_dst": packet.get("dst"),
            "payload_size": len(payload),
            "payload_hash": hashlib.sha256(payload).hexdigest()[:16],
            "detections": detections,
            "is_threat": len(detections) > 0,
            "payload_label": "ATTACK" if len(detections) > 0 else "NORMAL",
            "category": detections[0].get("category", "Normal Payload") if detections else "Normal Payload",
            "timestamp": datetime.now().isoformat(),
        }
        
        # Store in history
        self.detection_history[rule_name].append(result)
        
        return result


# ==============================================================================
# INTEGRATION WITH DETECTION ENGINE
# ==============================================================================

def integrate_advanced_detection(base_detection_engine, 
                                  advanced_detector: AdvancedPayloadDetector) -> callable:
    """
    Return a wrapped process_packet() that includes advanced payload detection.
    
    Usage:
        from detection import DetectionEngine
        from advanced_payload_detection import (
            AdvancedPayloadDetector, integrate_advanced_detection
        )
        
        base_engine = DetectionEngine(rules)
        advanced = AdvancedPayloadDetector()
        enhanced_process = integrate_advanced_detection(base_engine, advanced)
        
        alerts = enhanced_process(normalized_packet)
    
    Args:
        base_detection_engine: Original DetectionEngine instance
        advanced_detector: AdvancedPayloadDetector instance
    
    Returns:
        Enhanced process_packet() function
    """
    def enhanced_process_packet(packet_info: dict) -> List[dict]:
        # Get base alerts from signature rules
        base_alerts = base_detection_engine.process_packet(packet_info)
        
        # For each base alert, run advanced payload analysis
        advanced_alerts = []
        
        if "payload" in packet_info:
            # Find matching rule
            for rule in base_detection_engine.rules:
                if base_detection_engine._match_rule(packet_info, rule):
                    payload_detection = advanced_detector.detect(
                        packet_info, rule["name"], packet_info["payload"]
                    )
                    
                    if payload_detection.get("is_threat"):
                        # Escalate base alert if advanced detection confirms threat
                        advanced_alerts.append({
                            **payload_detection,
                            "reason": "Advanced payload analysis escalation",
                        })
        
        return base_alerts + advanced_alerts
    
    return enhanced_process_packet


# ==============================================================================
# MOCK PACKET CAPTURE FOR TESTING
# ==============================================================================

class MockPacketCapture:
    """Generate synthetic packets for testing and demonstrations"""
    
    @staticmethod
    def http_normal_payload() -> Tuple[dict, bytes]:
        """Normal HTTP GET request"""
        packet = {
            "src": "192.168.1.100",
            "dst": "192.168.1.77",
            "protocol": "TCP",
            "src_port": 54321,
            "dst_port": 80,
            "flags": "SA",
            "size": 256,
            "timestamp": datetime.now().timestamp(),
        }
        payload = b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'
        return packet, payload
    
    @staticmethod
    def http_malicious_payload() -> Tuple[dict, bytes]:
        """HTTP payload with embedded shellcode signature"""
        packet = {
            "src": "192.168.1.50",
            "dst": "192.168.1.77",
            "protocol": "TCP",
            "src_port": 44444,
            "dst_port": 80,
            "flags": "PA",
            "size": 512,
            "timestamp": datetime.now().timestamp(),
        }
        # Embed known signature
        payload = b'GET /shell.php HTTP/1.1\r\n' + b'\x90\x90\x90\x90' * 32
        return packet, payload
    
    @staticmethod
    def sql_injection_payload() -> Tuple[dict, bytes]:
        """Payload with SQL injection signature"""
        packet = {
            "src": "203.0.113.5",
            "dst": "192.168.1.77",
            "protocol": "TCP",
            "src_port": 32768,
            "dst_port": 80,
            "flags": "PA",
            "size": 256,
            "timestamp": datetime.now().timestamp(),
        }
        payload = b"GET /search?q=admin' UNION SELECT * FROM users-- HTTP/1.1\r\n"
        return packet, payload


# ==============================================================================
# UNIT TESTS & EXAMPLES
# ==============================================================================

if __name__ == "__main__":
    # Set up logging for demo
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(name)s - %(levelname)s - %(message)s",
    )
    
    print("\n" + "="*80)
    print("ADVANCED PAYLOAD DETECTION - DEMONSTRATION (Signature-Based)")
    print("="*80 + "\n")
    
    # Initialize detector
    detector = AdvancedPayloadDetector()
    
    # Test 1: Normal HTTP
    print("Test 1: Normal HTTP request")
    print("-" * 40)
    packet, payload = MockPacketCapture.http_normal_payload()
    result = detector.detect(packet, "HTTP_Normal", payload)
    print(f"Payload: {payload}")
    print(f"Is Threat: {result['is_threat']}")
    print(f"Detections: {result['detections']}")
    print()
    
    # Test 2: Shellcode Detection
    print("Test 2: Shellcode signature detection")
    print("-" * 40)
    packet, payload = MockPacketCapture.http_malicious_payload()
    result = detector.detect(packet, "Shellcode_Attack", payload)
    print(f"Payload: {payload[:60]}...")
    print(f"Is Threat: {result['is_threat']}")
    print(f"Detections: {result['detections']}")
    print()
    
    # Test 3: SQL Injection
    print("Test 3: SQL Injection detection")
    print("-" * 40)
    packet, payload = MockPacketCapture.sql_injection_payload()
    result = detector.detect(packet, "SQLi_Attack", payload)
    print(f"Payload: {payload}")
    print(f"Is Threat: {result['is_threat']}")
    print(f"Detections: {result['detections']}")
    print()
    
    print("="*80)
    print("Demonstration complete")
    print("="*80)
