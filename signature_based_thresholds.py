"""
signature_based_thresholds.py
==============================
Signature-Based Adaptive Threshold Management

Deterministic rule-based signature matching for automatic threshold adjustment.

APPROACH
========

Instead of learning thresholds from data distributions, use pre-defined signatures
to detect traffic patterns and adjust thresholds accordingly:

1. Traffic Signature Detection
   - DDoS attack signature → Lower packet threshold (aggressive)
   - Slow scan signature → Raise timeout threshold (patient)
   - Burst pattern signature → Adjust window size
   - Anomaly signature → Emergency threshold

2. Attack Context Signatures
   - Known CVE exploit → Specific payload threshold
   - SQL injection detected → Flag SQL patterns
   - Shellcode detected → Flag execution patterns

3. Threshold Adjustment Rules
   - rule_name: str (unique ID)
   - trigger_pattern: Dict (condition to match)
   - threshold_adjustment: int/float (multiplier or absolute)
   - duration: int (seconds this threshold stays active)
   - priority: int (higher = override lower priority rules)
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List
from datetime import datetime
from enum import Enum
from collections import defaultdict, deque
import re

logger = logging.getLogger("SignatureBasedThresholds")


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

class TriggerType(Enum):
    """Types of signature triggers"""
    TRAFFIC_SPIKE = "traffic_spike"           # Sudden rate increase
    SLOW_SCAN = "slow_scan"                   # Low-rate sustained pattern
    PAYLOAD_SIGNATURE = "payload_signature"   # Known malware signature
    PROTOCOL_ANOMALY = "protocol_anomaly"     # Unusual header/protocol combo
    ATTACK_CHAIN = "attack_chain"             # Multi-stage attack pattern
    NETWORK_STATE = "network_state"           # Based on overall network  health


@dataclass
class ThresholdSignature:
    """Defines a signature-based threshold adjustment rule"""
    rule_id: str                           # Unique rule identifier
    trigger_type: TriggerType              # What pattern triggers this
    description: str                       # Human-readable description
    
    # Detection conditions
    detect_pattern: Dict                   # Conditions to match (see examples)
    confidence_threshold: float            # Required confidence (0.0-1.0)
    
    # Threshold adjustment
    adjustment_type: str                   # "multiplier" or "absolute"
    adjustment_value: float                # Multiplier (2.0 = 2x) or absolute pkt count
    min_threshold: int                     # Floor value
    max_threshold: int                     # Ceiling value
    
    # Temporal properties
    duration_seconds: int                  # How long this threshold stays active
    priority: int                          # 0-100 (higher overrides lower)
    
    # Metadata
    severity: str                          # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    reference: str                         # CVE/attack database reference
    active: bool = True


@dataclass
class ThresholdContext:
    """Current detection context"""
    current_threshold: int
    base_threshold: int
    active_signatures: List[ThresholdSignature] = field(default_factory=list)
    triggered_at: float = 0.0
    expires_at: float = 0.0
    last_adjusted: float = field(default_factory=lambda: datetime.now().timestamp())


# ==============================================================================
# SIGNATURE-BASED THRESHOLD MANAGER
# ==============================================================================

class SignatureBasedThresholdManager:
    """
    Manages thresholds using signature-based rules instead of statistics.
    
    Concept:
        1. Define signature rules for traffic patterns
        2. Monitor incoming traffic/patterns
        3. When signature matches, adjust threshold
        4. Threshold remains active for duration_seconds
        5. Higher priority rules override lower priority
    """
    
    def __init__(self, base_threshold: int = 100):
        self.base_threshold = base_threshold
        self.signatures: Dict[str, ThresholdSignature] = {}
        self.contexts: Dict[str, ThresholdContext] = {}  # rule_name -> context
        self.last_applied: Dict[str, Dict] = {}
        self.normal_baselines = defaultdict(lambda: deque(maxlen=300))
        self.min_baseline_samples = 25
        self.calibration_factor = 1.6
        self._load_default_signatures()

    @property
    def algorithm_name(self) -> str:
        return "Signature-based threshold tuning"
    
    def _load_default_signatures(self):
        """Initialize with common attack signatures"""
        
        # SIGNATURE 1: DDoS Traffic Spike
        # Detects sudden traffic increase (3x+ baseline)
        self.add_signature(ThresholdSignature(
            rule_id="ddos_traffic_spike",
            trigger_type=TriggerType.TRAFFIC_SPIKE,
            description="DDoS detected: Traffic spike > 300% baseline",
            detect_pattern={
                "condition": "traffic_spike",
                "multiplier": 3.0,          # 3x baseline
                "min_packets": 50,          # Absolute minimum to trigger
                "time_window": 10,          # Seconds
            },
            confidence_threshold=0.8,
            adjustment_type="multiplier",
            adjustment_value=0.3,           # Reduce to 30% of base (aggressive)
            min_threshold=20,               # At least 20 packets
            max_threshold=300,              # Cap at 300
            duration_seconds=300,           # 5 minutes
            priority=95,
            severity="CRITICAL",
            reference="DDoS Pattern",
        ))
        
        # SIGNATURE 2: Port Scan Detection
        # Detects slow/stealthy scan (low rate, all ports)
        self.add_signature(ThresholdSignature(
            rule_id="port_scan_slow",
            trigger_type=TriggerType.SLOW_SCAN,
            description="Port scan detected: Low-rate sustained connections",
            detect_pattern={
                "condition": "port_scan",
                "ports_unique": 10,         # Trying 10+ unique ports
                "packet_rate": 5,           # Only 5 packets/sec
                "duration": 60,             # Over 60 seconds
            },
            confidence_threshold=0.7,
            adjustment_type="multiplier",
            adjustment_value=1.5,           # Raise to 150% (patient detection)
            min_threshold=50,
            max_threshold=500,
            duration_seconds=600,           # 10 minutes
            priority=70,
            severity="HIGH",
            reference="Nmap-style scan",
        ))
        
        # SIGNATURE 3: SQL Injection Signature Pattern
        # Detects SQL injection attempts
        self.add_signature(ThresholdSignature(
            rule_id="sql_injection_detected",
            trigger_type=TriggerType.PAYLOAD_SIGNATURE,
            description="SQL Injection: Detected SQL keywords in payload",
            detect_pattern={
                "condition": "payload_contains",
                "keywords": [
                    b"UNION SELECT", b"DROP TABLE", b"'; DROP", 
                    b"1' OR '1'='1"
                ],
                "confidence": 0.9,          # High confidence match
            },
            confidence_threshold=0.85,
            adjustment_type="absolute",
            adjustment_value=30,            # Reduce to exactly 30 packets
            min_threshold=10,
            max_threshold=100,
            duration_seconds=1800,          # 30 minutes
            priority=90,
            severity="CRITICAL",
            reference="OWASP A1:2021",
        ))
        
        # SIGNATURE 4: Shellcode/Binary Payload
        # High entropy + known shellcode patterns
        self.add_signature(ThresholdSignature(
            rule_id="shellcode_detected",
            trigger_type=TriggerType.PAYLOAD_SIGNATURE,
            description="Shellcode: Binary/executable payload detected",
            detect_pattern={
                "condition": "payload_characteristics",
                "entropy_min": 6.5,         # High entropy (encryption/obfuscation)
                "contains_patterns": [b"\x90\x90\x90\x90"],  # NOP sled
                "binary_signatures": [b"\x7FELF", b"MZ\x90"],  # ELF/PE headers
            },
            confidence_threshold=0.8,
            adjustment_type="absolute",
            adjustment_value=15,            # Very aggressive (15 packets)
            min_threshold=5,
            max_threshold=50,
            duration_seconds=3600,          # 1 hour
            priority=95,
            severity="CRITICAL",
            reference="Shellcode detection",
        ))
        
        # SIGNATURE 5: Protocol Anomaly
        # Unusual combinations (e.g., FTP over HTTPS port)
        self.add_signature(ThresholdSignature(
            rule_id="protocol_anomaly",
            trigger_type=TriggerType.PROTOCOL_ANOMALY,
            description="Protocol mismatch: Non-HTTPS on port 443",
            detect_pattern={
                "condition": "protocol_mismatch",
                "port": 443,
                "expected_protocol": "HTTPS",
                "actual_protocol": "FTP",
                "match_count": 5,           # At least 5 mismatches
            },
            confidence_threshold=0.7,
            adjustment_type="multiplier",
            adjustment_value=0.5,           # Reduce to 50%
            min_threshold=25,
            max_threshold=200,
            duration_seconds=1200,          # 20 minutes
            priority=75,
            severity="HIGH",
            reference="Protocol anomaly",
            active=False,
        ))
        
        # SIGNATURE 6: Multi-Stage Attack Chain
        # Signature → Exploitation → Payload delivery
        self.add_signature(ThresholdSignature(
            rule_id="attack_chain_multi_stage",
            trigger_type=TriggerType.ATTACK_CHAIN,
            description="Multi-stage attack: Recon + Exploit + Payload",
            detect_pattern={
                "condition": "sequence",
                "stages": [
                    {"name": "recon", "type": "port_scan", "count": 1},
                    {"name": "exploit", "type": "vulnerability", "count": 1},
                    {"name": "payload", "type": "shellcode", "count": 1},
                ],
                "time_window": 300,         # Within 5 minutes
            },
            confidence_threshold=0.85,
            adjustment_type="absolute",
            adjustment_value=5,             # MAXIMUM aggression
            min_threshold=1,
            max_threshold=30,
            duration_seconds=7200,          # 2 hours
            priority=99,
            severity="CRITICAL",
            reference="Multi-stage attack",
        ))
        
        # SIGNATURE 7: Network State - Traffic Baseline OK
        # No attack detected → Restore normal threshold
        self.add_signature(ThresholdSignature(
            rule_id="network_normal_state",
            trigger_type=TriggerType.NETWORK_STATE,
            description="Network normal: Restoring baseline threshold",
            detect_pattern={
                "condition": "network_health",
                "no_alerts": True,
                "traffic_stable": True,
                "entropy_normal": True,
            },
            confidence_threshold=0.95,
            adjustment_type="absolute",
            adjustment_value=100,           # Restore base threshold
            min_threshold=50,
            max_threshold=200,
            duration_seconds=3600,          # 1 hour
            priority=10,
            severity="LOW",
            reference="Baseline",
        ))

        # SIGNATURE 8: DNS tunneling behavior
        self.add_signature(ThresholdSignature(
            rule_id="dns_tunneling_pattern",
            trigger_type=TriggerType.PAYLOAD_SIGNATURE,
            description="DNS tunneling suspected from repeated encoded payload tokens",
            detect_pattern={
                "condition": "payload_contains",
                "keywords": [
                    "BASE64_CHUNK",
                    "LONG_DNS_LABEL",
                    "TXT_EXFIL",
                ],
                "confidence": 0.8,
            },
            confidence_threshold=0.75,
            adjustment_type="multiplier",
            adjustment_value=0.4,
            min_threshold=15,
            max_threshold=120,
            duration_seconds=1200,
            priority=88,
            severity="HIGH",
            reference="DNS tunneling heuristic",
        ))

        # SIGNATURE 9: RDP brute-force behavior
        self.add_signature(ThresholdSignature(
            rule_id="rdp_bruteforce_pattern",
            trigger_type=TriggerType.TRAFFIC_SPIKE,
            description="RDP brute-force pattern detected on port 3389",
            detect_pattern={
                "condition": "rdp_bruteforce",
                "port": 3389,
                "min_attempt_rate": 8,
                "confidence": 0.85,
            },
            confidence_threshold=0.8,
            adjustment_type="absolute",
            adjustment_value=18,
            min_threshold=8,
            max_threshold=80,
            duration_seconds=1800,
            priority=92,
            severity="CRITICAL",
            reference="RDP brute-force signature",
        ))

        # SIGNATURE 10: UDP amplification behavior
        self.add_signature(ThresholdSignature(
            rule_id="udp_amplification_pattern",
            trigger_type=TriggerType.TRAFFIC_SPIKE,
            description="UDP amplification signature detected",
            detect_pattern={
                "condition": "udp_amplification",
                "sensitive_ports": [53, 123, 1900, 11211],
                "min_source_fanout": 15,
                "confidence": 0.9,
            },
            confidence_threshold=0.8,
            adjustment_type="multiplier",
            adjustment_value=0.25,
            min_threshold=10,
            max_threshold=100,
            duration_seconds=1500,
            priority=94,
            severity="CRITICAL",
            reference="UDP amplification signature",
        ))
        
        logger.info(f"Loaded {len(self.signatures)} default threshold signatures")
    
    def add_signature(self, sig: ThresholdSignature):
        """Register a threshold signature"""
        self.signatures[sig.rule_id] = sig
        self.contexts[sig.rule_id] = ThresholdContext(
            current_threshold=self.base_threshold,
            base_threshold=self.base_threshold,
            active_signatures=[]
        )
        logger.debug(f"Added signature: {sig.rule_id}")
    
    def detect_and_adjust(self, rule_name: str, base_threshold: int, metrics: Dict) -> int:
        """
        Detect signature patterns and adjust threshold.
        
        Args:
            metrics: Dict with keys like:
                - packet_rate: float (packets/sec)
                - payload_entropy: float (0.0-8.0)
                - payload_signatures: List[str] (matched signatures)
                - port_count: int (unique ports)
                - protocol: str
                - port: int
        
        Returns:
            int: Adjusted threshold (after applying matching rules)
        """
        calibrated_base = self._estimate_baseline_threshold(rule_name, base_threshold)
        current_threshold = calibrated_base
        matched_rules = []
        similarity_candidates = []

        rule_tokens = self._tokenize(rule_name)
        metric_protocol = str(metrics.get("protocol", "")).upper()
        metric_port = int(metrics.get("port", 0) or 0)
        
        # Check each signature
        for rule_id, sig in self.signatures.items():
            if not sig.active:
                continue
            
            confidence = self._match_pattern(sig.detect_pattern, metrics)

            similarity = self._signature_similarity(
                sig=sig,
                rule_tokens=rule_tokens,
                metric_protocol=metric_protocol,
                metric_port=metric_port,
            )

            # Mathematical similarity calibration candidate (non-payload signatures).
            soft_confidence = confidence
            if sig.trigger_type != TriggerType.PAYLOAD_SIGNATURE and soft_confidence <= 0.0:
                soft_confidence = self._soft_match_non_payload(sig.detect_pattern, metrics)

            if (
                sig.trigger_type != TriggerType.PAYLOAD_SIGNATURE
                and soft_confidence > 0.0
                and similarity >= 0.20
            ):
                weight = soft_confidence * similarity * (sig.priority / 100.0)
                similarity_candidates.append((sig, weight))
            
            if confidence >= sig.confidence_threshold:
                matched_rules.append({
                    "rule_id": rule_id,
                    "confidence": confidence,
                    "priority": sig.priority,
                    "adjustment": sig,
                })
                logger.warning(
                    f"[ThresholdSig] Matched: {sig.rule_id} "
                    f"(confidence={confidence:.2f}, priority={sig.priority})"
                )

        if similarity_candidates:
            blended_threshold = self._blend_similarity_threshold(
                calibrated_base=calibrated_base,
                candidates=similarity_candidates,
            )
            current_threshold = blended_threshold
        
        # Sort by priority (highest first)
        matched_rules.sort(key=lambda x: x["priority"], reverse=True)
        
        # Apply highest priority adjustment
        if matched_rules:
            best_match = matched_rules[0]
            sig = best_match["adjustment"]
            
            if sig.adjustment_type == "multiplier":
                current_threshold = int(calibrated_base * sig.adjustment_value)
            else:  # absolute
                current_threshold = int(sig.adjustment_value)
            
            # Clamp to min/max
            current_threshold = max(sig.min_threshold, 
                                   min(current_threshold, sig.max_threshold))
            
            logger.info(
                f"[ThresholdSig] Applied: {sig.rule_id} on {rule_name} -> threshold={current_threshold}"
            )
            self.last_applied[rule_name] = {
                "rule_id": sig.rule_id,
                "algorithm": self.algorithm_name,
                "threshold": current_threshold,
                "base_threshold": calibrated_base,
                "priority": sig.priority,
            }
        else:
            self.last_applied[rule_name] = {
                "rule_id": "none",
                "algorithm": self.algorithm_name,
                "threshold": current_threshold,
                "base_threshold": calibrated_base,
                "priority": 0,
            }
        
        return current_threshold

    def _blend_similarity_threshold(self,
                                    calibrated_base: int,
                                    candidates: List[tuple]) -> int:
        """
        Blend related non-payload signature thresholds mathematically.

        Formula:
            w_i = confidence_i * similarity_i * (priority_i / 100)
            T_i = transformed threshold by signature i
            T_blend = (1 - alpha) * T_base + alpha * (sum(w_i * T_i) / sum(w_i))
            alpha = clamp(sum(w_i), 0.0, 0.85)
        """
        weighted_sum = 0.0
        total_weight = 0.0

        for sig, weight in candidates:
            if weight <= 0:
                continue

            if sig.adjustment_type == "multiplier":
                candidate = int(calibrated_base * sig.adjustment_value)
            else:
                candidate = int(sig.adjustment_value)

            candidate = max(sig.min_threshold, min(candidate, sig.max_threshold))
            weighted_sum += weight * candidate
            total_weight += weight

        if total_weight <= 0:
            return calibrated_base

        weighted_candidate = weighted_sum / total_weight
        alpha = min(max(total_weight, 0.0), 0.85)
        blended = ((1.0 - alpha) * calibrated_base) + (alpha * weighted_candidate)
        return max(1, int(round(blended)))

    @staticmethod
    def _tokenize(text: str) -> set:
        return set(re.findall(r"[A-Za-z0-9]+", str(text).upper()))

    def _signature_similarity(self,
                              sig: ThresholdSignature,
                              rule_tokens: set,
                              metric_protocol: str,
                              metric_port: int) -> float:
        """Compute semantic similarity between active rule context and signature intent."""
        sig_tokens = self._tokenize(f"{sig.rule_id} {sig.description}")
        if not rule_tokens or not sig_tokens:
            token_similarity = 0.0
        else:
            inter = len(rule_tokens & sig_tokens)
            union = len(rule_tokens | sig_tokens)
            token_similarity = (inter / union) if union else 0.0

        proto_bonus = 0.0
        if metric_protocol:
            if metric_protocol in sig_tokens:
                proto_bonus = 0.25
            elif metric_protocol == "TCP" and any(tok in sig_tokens for tok in {"SYN", "ACK", "PSH", "RDP", "HTTPS", "SSH"}):
                proto_bonus = 0.15
            elif metric_protocol == "UDP" and any(tok in sig_tokens for tok in {"DNS", "AMPLIFICATION", "UDP"}):
                proto_bonus = 0.15

        port_bonus = 0.0
        if metric_port > 0:
            pattern_port = int(sig.detect_pattern.get("port", 0) or 0)
            if pattern_port and pattern_port == metric_port:
                port_bonus = 0.25
            else:
                sensitive = sig.detect_pattern.get("sensitive_ports", []) or []
                if metric_port in sensitive:
                    port_bonus = 0.2

        similarity = token_similarity + proto_bonus + port_bonus
        return min(max(similarity, 0.0), 1.0)

    def _soft_match_non_payload(self, pattern: Dict, metrics: Dict) -> float:
        """Return smooth proximity confidence for non-payload signatures."""
        condition = pattern.get("condition", "")

        if condition == "traffic_spike":
            rate = float(metrics.get("packet_rate", 0.0) or 0.0)
            target = float(pattern.get("min_packets", 50) or 50)
            if target <= 0:
                return 0.0
            return min(rate / target, 1.0) * 0.6

        if condition == "port_scan":
            unique_ports = float(metrics.get("unique_ports", 0) or 0)
            target_ports = float(pattern.get("ports_unique", 10) or 10)
            if target_ports <= 0:
                return 0.0
            return min(unique_ports / target_ports, 1.0) * 0.6

        if condition == "rdp_bruteforce":
            if int(metrics.get("port", 0) or 0) != int(pattern.get("port", 3389) or 3389):
                return 0.0
            rate = float(metrics.get("packet_rate", 0.0) or 0.0)
            min_rate = float(pattern.get("min_attempt_rate", 8) or 8)
            if min_rate <= 0:
                return 0.0
            return min(rate / min_rate, 1.0) * 0.7

        if condition == "udp_amplification":
            if str(metrics.get("protocol", "")).upper() != "UDP":
                return 0.0
            fanout = float(metrics.get("unique_sources", 0) or 0)
            min_fanout = float(pattern.get("min_source_fanout", 15) or 15)
            if min_fanout <= 0:
                return 0.0
            return min(fanout / min_fanout, 1.0) * 0.7

        return 0.0

    def record_normal_metrics(self, rule_name: str, metrics: Dict):
        """Learn baseline packet characteristics from likely-benign traffic."""
        if metrics.get("payload_signatures"):
            return

        sample_count = int(metrics.get("sample_count", 0) or 0)
        unique_ports = int(metrics.get("unique_ports", 0) or 0)
        unique_sources = int(metrics.get("unique_sources", 0) or 0)
        packet_rate = float(metrics.get("packet_rate", 0.0) or 0.0)

        # Skip obvious outliers likely representing attacks.
        if sample_count <= 0:
            return
        if packet_rate > 120:
            return
        if unique_sources > 12:
            return
        if unique_ports > 80:
            return

        if unique_ports > 0:
            value = unique_ports
        elif unique_sources > 0:
            value = unique_sources
        else:
            value = sample_count

        self.normal_baselines[rule_name].append(max(1, int(value)))

    def _estimate_baseline_threshold(self, rule_name: str, configured_threshold: int) -> int:
        """Estimate rule baseline using robust percentile from recent normal samples."""
        samples = list(self.normal_baselines.get(rule_name, []))
        if len(samples) < self.min_baseline_samples:
            return configured_threshold

        samples.sort()
        idx_95 = int((len(samples) - 1) * 0.95)
        p95 = samples[idx_95]

        estimated = int(p95 * self.calibration_factor)
        lower_bound = max(1, int(configured_threshold * 0.6))
        upper_bound = int(configured_threshold * 3.0)
        return max(lower_bound, min(estimated, upper_bound))
    
    def _match_pattern(self, pattern: Dict, metrics: Dict) -> float:
        """
        Match detection pattern against metrics.
        
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        condition = pattern.get("condition", "")
        
        if condition == "traffic_spike":
            return self._match_traffic_spike(pattern, metrics)
        elif condition == "port_scan":
            return self._match_port_scan(pattern, metrics)
        elif condition == "payload_contains":
            return self._match_payload_signature(pattern, metrics)
        elif condition == "payload_characteristics":
            return self._match_payload_characteristics(pattern, metrics)
        elif condition == "protocol_mismatch":
            return self._match_protocol_anomaly(pattern, metrics)
        elif condition == "sequence":
            return self._match_attack_sequence(pattern, metrics)
        elif condition == "network_health":
            return self._match_network_health(pattern, metrics)
        elif condition == "rdp_bruteforce":
            return self._match_rdp_bruteforce(pattern, metrics)
        elif condition == "udp_amplification":
            return self._match_udp_amplification(pattern, metrics)
        
        return 0.0
    
    def _match_traffic_spike(self, pattern: Dict, metrics: Dict) -> float:
        """Detect sudden traffic increase"""
        if "packet_rate" not in metrics:
            return 0.0
        
        rate = metrics["packet_rate"]
        multiplier = pattern.get("multiplier", 3.0)
        min_packets = pattern.get("min_packets", 50)
        
        # Check if rate exceeded threshold
        if rate >= min_packets and rate >= multiplier:
            confidence = min(rate / (multiplier * 2), 1.0)
            return confidence
        return 0.0
    
    def _match_port_scan(self, pattern: Dict, metrics: Dict) -> float:
        """Detect slow port scan"""
        unique_ports = metrics.get("unique_ports", 0)
        packet_rate = metrics.get("packet_rate", 0)
        
        ports_expected = pattern.get("ports_unique", 10)
        rate_threshold = pattern.get("packet_rate", 5)
        
        if unique_ports >= ports_expected and packet_rate <= rate_threshold:
            confidence = min(unique_ports / (ports_expected * 2), 1.0)
            return confidence
        return 0.0
    
    def _match_payload_signature(self, pattern: Dict, metrics: Dict) -> float:
        """Detect SQL injection or known keywords"""
        keywords = pattern.get("keywords", [])
        detected_sigs = metrics.get("payload_signatures", [])
        
        normalized = [str(item).upper() for item in detected_sigs]
        matches = sum(1 for kw in keywords if str(kw).upper() in normalized)
        if matches > 0:
            return pattern.get("confidence", 0.9)
        return 0.0
    
    def _match_payload_characteristics(self, pattern: Dict, metrics: Dict) -> float:
        """Detect shellcode/binary payload"""
        entropy = metrics.get("payload_entropy", 0.0)
        entropy_min = pattern.get("entropy_min", 6.5)
        
        if entropy >= entropy_min:
            return min(entropy / 8.0, 1.0)  # Normalize to 0-1
        return 0.0
    
    def _match_protocol_anomaly(self, pattern: Dict, metrics: Dict) -> float:
        """Detect protocol mismatches using app-layer protocol context."""
        port = metrics.get("port", 0)
        app_protocol = str(metrics.get("app_protocol", "")).upper()
        expected = str(pattern.get("expected_protocol", "")).upper()

        # App protocol context is required; without it, this rule is not reliable.
        if not app_protocol or not expected:
            return 0.0

        if port == pattern.get("port") and app_protocol != expected:
            return 0.7  # Moderate confidence
        return 0.0
    
    def _match_attack_sequence(self, pattern: Dict, metrics: Dict) -> float:
        """Detect multi-stage attack chains"""
        stages = pattern.get("stages", [])
        detected_stages = metrics.get("detected_stages", [])
        
        matches = sum(1 for stage in stages if stage["name"] in detected_stages)
        if matches >= len(stages):
            return 0.95  # High confidence when all stages detected
        return 0.0
    
    def _match_network_health(self, pattern: Dict, metrics: Dict) -> float:
        """Check if network is in normal state"""
        if (metrics.get("no_alerts", False) and 
            metrics.get("traffic_stable", False) and
            metrics.get("entropy_normal", False)):
            return 0.95
        return 0.0

    def _match_rdp_bruteforce(self, pattern: Dict, metrics: Dict) -> float:
        """Detect RDP brute-force by port and attempt rate."""
        if metrics.get("port") != pattern.get("port", 3389):
            return 0.0
        attempt_rate = metrics.get("packet_rate", 0)
        min_rate = pattern.get("min_attempt_rate", 8)
        if attempt_rate >= min_rate:
            return min(attempt_rate / float(min_rate * 2), 1.0)
        return 0.0

    def _match_udp_amplification(self, pattern: Dict, metrics: Dict) -> float:
        """Detect UDP amplification traffic profile."""
        if metrics.get("protocol") != "UDP":
            return 0.0
        if metrics.get("port") not in pattern.get("sensitive_ports", []):
            return 0.0
        fanout = metrics.get("unique_sources", 0)
        minimum = pattern.get("min_source_fanout", 15)
        if fanout >= minimum:
            return min(fanout / float(minimum * 2), 1.0)
        return 0.0

    def get_stats(self) -> Dict:
        """Return active manager stats and last applied rule info."""
        return {
            "algorithm": self.algorithm_name,
            "signature_count": len(self.signatures),
            "last_applied": self.last_applied,
            "baseline_samples": {
                rule_name: len(samples)
                for rule_name, samples in self.normal_baselines.items()
            },
            "min_baseline_samples": self.min_baseline_samples,
            "calibration_factor": self.calibration_factor,
        }

    def get_threshold_report(self) -> Dict:
        """Get current threshold status for all rules"""
        report = {
            "base_threshold": self.base_threshold,
            "active_rules": [],
            "inactive_rules": [],
        }
        
        for rule_id, sig in self.signatures.items():
            if sig.active:
                report["active_rules"].append({
                    "rule_id": rule_id,
                    "priority": sig.priority,
                    "adjustment_value": sig.adjustment_value,
                    "description": sig.description,
                })
            else:
                report["inactive_rules"].append(rule_id)
        
        return report


# ==============================================================================
# USAGE EXAMPLE
# ==============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    
    # Initialize manager
    manager = SignatureBasedThresholdManager(base_threshold=100)
    
    print("\n" + "="*80)
    print("SIGNATURE-BASED THRESHOLD MANAGEMENT DEMO")
    print("="*80)
    
    # Scenario 1: Normal traffic
    print("\n[Scenario 1] Normal Traffic")
    metrics = {
        "packet_rate": 5,
        "payload_entropy": 3.5,
        "unique_ports": 1,
        "protocol": "HTTP",
    }
    threshold = manager.detect_and_adjust("normal_traffic_demo", 100, metrics)
    print(f"  Metrics: {metrics}")
    print(f"  → Threshold: {threshold} pkt/10s")
    
    # Scenario 2: DDoS spike detected
    print("\n[Scenario 2] DDoS Traffic Spike (4x baseline)")
    metrics = {
        "packet_rate": 400,
        "payload_entropy": 2.0,
        "unique_ports": 1,
        "protocol": "TCP",
    }
    threshold = manager.detect_and_adjust("ddos_spike_demo", 100, metrics)
    print(f"  Metrics: {metrics}")
    print(f"  → Threshold: {threshold} pkt/10s (AGGRESSIVE)")
    
    # Scenario 3: SQL Injection
    print("\n[Scenario 3] SQL Injection Detected")
    metrics = {
        "packet_rate": 10,
        "payload_entropy": 4.2,
        "payload_signatures": ["UNION SELECT", "DROP TABLE"],
    }
    threshold = manager.detect_and_adjust("sqli_demo", 100, metrics)
    print(f"  Metrics: {metrics}")
    print(f"  → Threshold: {threshold} pkt/10s")
    
    # Scenario 4: Shellcode/Binary
    print("\n[Scenario 4] Shellcode Detected (High Entropy + NOP Sled)")
    metrics = {
        "packet_rate": 15,
        "payload_entropy": 7.8,
        "payload_signatures": ["\x90\x90\x90\x90"],
    }
    threshold = manager.detect_and_adjust("shellcode_demo", 100, metrics)
    print(f"  Metrics: {metrics}")
    print(f"  → Threshold: {threshold} pkt/10s (MAXIMUM ALERT)")
    
    # Report
    print("\n" + "="*80)
    print("ACTIVE THRESHOLD SIGNATURES")
    print("="*80)
    report = manager.get_threshold_report()
    for rule in report["active_rules"]:
        print(f"\n  [{rule['priority']}] {rule['rule_id']}")
        print(f"      {rule['description']}")
        print(f"      Adjustment: {rule['adjustment_value']}")
