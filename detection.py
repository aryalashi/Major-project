"""
detection.py
------------
Core Detection Engine for NIDS

Implements sliding-window rate analysis and multi-source DDoS correlation.
Consumes normalized packet dicts produced by normalization.py.

False-Positive Elimination Architecture
----------------------------------------
Three concentric isolation layers prevent cross-protocol false positives:

  Layer 0 — Normalization (normalization.py)
      Ensures protocol fields are pre-isolated: ICMP packets arrive with
      flags=None, src_port=None, dst_port=None — so they can never satisfy
      TCP or UDP rule conditions even if the rule check were mis-routed.

  Layer 1 — Protocol Gate (this file, _match_rule)
      The FIRST check in every rule evaluation is a strict protocol comparison.
      If packet.protocol != rule.protocol the rule is skipped immediately
      via `continue` — no further fields are evaluated. O(1) early exit.

  Layer 2 — Safe Attribute Guards (this file, _match_rule)
      Even after the protocol gate passes, attribute checks treat None as a
      non-match signal. flags=None → rule's flag check fails immediately.
      dst_port=None → rule's port check fails. This is a belt-and-suspenders
      guard against any upstream normalization gaps.

Detection Algorithms
---------------------
  1. Sliding Window Rate Analysis  → DoS detection (per rule, per source/dest)
  2. Port Variety Tracking         → Port scan detection
  3. Multi-Source Correlation      → DDoS detection (many sources → one target)

Performance Characteristics
-----------------------------
  - Protocol gate exits in O(1) without evaluating any other fields
  - Sliding window uses collections.deque for O(1) append/popleft
  - Periodic tracker cleanup (every TRACKER_CLEANUP_N packets) prevents
    unbounded memory growth in long capture sessions
  - Smart 30-second per-source cooldown prevents alert storms

Enhanced with Signature-Based Threshold Tuning (March 28, 2026)
----------------------------------------------------------------
    - SignatureBasedThresholdManager for deterministic threshold tuning
    - No hybrid algorithms in automatic tuning path
    - Payload/traffic pattern signatures control threshold changes
    - Alerts include applied algorithm metadata
"""

import os
import time
import logging
from collections import defaultdict, deque
from typing import List, Optional

from signature_based_thresholds import SignatureBasedThresholdManager

try:
    from main import Config
except ImportError:
    class Config:
        DEFAULT_WINDOW         = int(os.getenv("NIDS_WINDOW", 10))
        ALERT_COOLDOWN         = int(os.getenv("NIDS_COOLDOWN", 30))
        DDOS_SOURCE_THRESHOLD  = int(os.getenv("NIDS_DDOS_THRESHOLD", 20))
        MAX_EVIDENCE_PACKETS   = int(os.getenv("NIDS_MAX_EVIDENCE", 200))

logger = logging.getLogger("DetectionEngine")


class DetectionEngine:
    """
    Core IDS detection engine.

    Accepts normalized packet dicts from PacketCapture and evaluates them
    against a list of signature rules loaded by RuleEngine.

    Instantiate once and call process_packet() for each incoming packet.
    Includes signature-based auto-tuning of thresholds.
    """

    SMART_COOLDOWN    = 15     # Reduced from 30s for faster re-detections
    TRACKER_CLEANUP_N = 2500   # Increased frequency from 5000 for real-time accuracy

    def __init__(self, rules: list):
        self.rules  = rules or self._default_rules()
        self.config = Config()
        self.threshold_manager = SignatureBasedThresholdManager(base_threshold=100)

        # Sliding window: {rule_name: {tracking_key: deque[timestamps]}}
        self.trackers: dict = defaultdict(lambda: defaultdict(deque))

        # Port scan: {src_ip: deque[(dst_port, timestamp)]}
        self.port_trackers: dict = defaultdict(deque)

        # DDoS: {dst_ip: deque[(src_ip, timestamp)]}
        self.dst_src_tracker: dict = defaultdict(deque)

        # Alert cooldown caches
        self.alert_cache:      dict = {}   # {(rule_name, key): last_alert_ts}
        self.ddos_alert_cache: dict = {}   # {dst_ip: last_alert_ts}

        # Packet counter for periodic cleanup
        self._pkt_count: int = 0

        # Log initialization
        self._log_initialization()

    # ── Public Interface ──────────────────────────────────────────────────────

    def process_packet(self, packet_info: dict) -> List[dict]:
        """
        Evaluate a normalized packet dict against all signature rules.

        Args:
            packet_info: Canonical dict from normalization.normalize_packet().
                         Required keys: src, dst, protocol, flags, dst_port,
                                        src_port, icmp_type, icmp_code,
                                        size, timestamp.

        Returns:
            List of alert dicts (empty list if no rules triggered).
        """
        alerts: List[dict] = []
        self._pkt_count += 1

        if self._pkt_count % self.TRACKER_CLEANUP_N == 0:
            self._cleanup_trackers(packet_info["timestamp"])

        # ── Layer 1 & 2: Signature rule evaluation ────────────────────────────
        for rule in self.rules:
            if not self._match_rule(packet_info, rule):
                continue   # Protocol mismatch or field mismatch — fast skip

            alert = (
                self._apply_port_scan(packet_info, rule)
                if rule.get("port_variety")
                else self._apply_sliding_window(packet_info, rule)
            )
            if alert:
                alerts.append(alert)

        # ── DDoS correlation (protocol-agnostic) ─────────────────────────────
        ddos_alert = self._apply_ddos_correlation(packet_info)
        if ddos_alert:
            alerts.append(ddos_alert)

        return alerts

    # ── Rule Matching ─────────────────────────────────────────────────────────

    def _match_rule(self, pkt: dict, rule: dict) -> bool:
        """
        Match a normalized packet against a single signature rule.

        Evaluation order (early-exit on first failure):
          1. Protocol gate      — O(1) string comparison, discards ~99% of
                                  mismatched packets before any other check.
          2. Flags check        — TCP only; None means packet is non-TCP state.
          3. Port check         — TCP/UDP only; None means packet is ICMP.
          4. ICMP type/code     — ICMP only.
          5. Local-source gate  — optional RFC-1918 filter.

        Returns True only if ALL applicable conditions match.
        """
        pkt_proto  = pkt["protocol"]    # "TCP" | "UDP" | "ICMP"
        rule_proto = rule["protocol"]

        if pkt_proto != rule_proto:
            return False

        if "flags" in rule and rule["flags"] is not None:
            pkt_flags = pkt.get("flags")
            if pkt_flags is None:
                return False
            if set(pkt_flags) != set(rule["flags"]):
                return False

        rule_port = rule.get("dst_port")
        if rule_port:
            pkt_port = pkt.get("dst_port")
            if pkt_port is None or pkt_port != rule_port:
                return False

        rule_icmp_type = rule.get("icmp_type")
        if rule_icmp_type is not None:
            if pkt.get("icmp_type") != rule_icmp_type:
                return False

        rule_icmp_code = rule.get("icmp_code")
        if rule_icmp_code is not None:
            if pkt.get("icmp_code") != rule_icmp_code:
                return False

        if rule.get("local_src_only"):
            if not self._is_local_ip(pkt.get("src", "")):
                return False

        return True

    # ── Sliding Window Rate Analysis ─────────────────────────────────────────

    def _apply_sliding_window(self, pkt: dict, rule: dict) -> Optional[dict]:
        """Sliding Window Rate Analysis for DoS detection with signature tuning."""
        key         = pkt[rule["track"]]
        now         = pkt["timestamp"]
        window_size = rule["window"]
        threshold   = rule["threshold"]
        cutoff      = now - window_size

        tracker = self.trackers[rule["name"]][key]
        tracker.append(now)

        while tracker and tracker[0] < cutoff:
            tracker.popleft()

        count = len(tracker)

        metrics = self._build_threshold_metrics(
            pkt=pkt,
            window=window_size,
            sample_count=count,
            unique_ports=0,
        )
        self.threshold_manager.record_normal_metrics(rule["name"], metrics)

        # Only run threshold calibration when the base rule threshold is reached.
        if count < threshold:
            return None

        cache_key = (rule["name"], key)
        if not self._cooldown_ok(cache_key, now):
            return None

        tuned_threshold = self.threshold_manager.detect_and_adjust(
            rule_name=rule["name"],
            base_threshold=threshold,
            metrics=metrics,
        )

        if count < tuned_threshold:
            return None
        self.alert_cache[cache_key] = now

        logger.info(
            f"[DETECTION] {rule['name']} | "
            f"src={pkt['src']} -> dst={pkt['dst']} | "
            f"count={count}/{tuned_threshold} in {window_size}s"
        )
        return {
            "type":         "DoS",
            "rule_name":    rule["name"],
            "protocol":     rule["protocol"],
            "severity":     rule["severity"],
            "source":       pkt["src"],
            "target":       pkt["dst"],
            "dst_port":     pkt.get("dst_port"),
            "packet_count": count,
            "window":       window_size,
            "threshold":    tuned_threshold,
            "algorithm":    self.threshold_manager.algorithm_name,
            "timestamp":    now,
        }

    # ── Port Scan Detection ───────────────────────────────────────────────────

    def _apply_port_scan(self, pkt: dict, rule: dict) -> Optional[dict]:
        """Port Scan Detection with signature tuning for port variety."""
        src       = pkt["src"]
        dst_port  = pkt.get("dst_port", 0)
        now       = pkt["timestamp"]
        window    = rule["window"]
        threshold = rule["threshold"]
        cutoff    = now - window

        tracker = self.port_trackers[src]
        tracker.append((dst_port, now))
        
        while tracker and tracker[0][1] < cutoff:
            tracker.popleft()

        if not tracker:
            return None
        
        unique_ports = len({entry[0] for entry in tracker})

        metrics = self._build_threshold_metrics(
            pkt=pkt,
            window=window,
            sample_count=len(tracker),
            unique_ports=unique_ports,
        )
        self.threshold_manager.record_normal_metrics(rule["name"], metrics)

        # Only run threshold calibration when the base rule threshold is reached.
        if unique_ports < threshold:
            return None

        cache_key = (rule["name"], src)
        if not self._cooldown_ok(cache_key, now):
            return None

        tuned_threshold = self.threshold_manager.detect_and_adjust(
            rule_name=rule["name"],
            base_threshold=threshold,
            metrics=metrics,
        )

        if unique_ports < tuned_threshold:
            return None
        self.alert_cache[cache_key] = now

        logger.info(
            f"[DETECTION] Port Scan | "
            f"src={src} | {unique_ports} unique ports in {window}s (thr={tuned_threshold})"
        )
        return {
            "type":         "Port Scan",
            "rule_name":    rule["name"],
            "protocol":     rule["protocol"],
            "severity":     rule["severity"],
            "source":       src,
            "target":       pkt["dst"],
            "dst_port":     dst_port,
            "packet_count": unique_ports,
            "window":       window,
            "threshold":    tuned_threshold,
            "algorithm":    self.threshold_manager.algorithm_name,
            "timestamp":    now,
        }

    # ── Multi-Source DDoS Correlation ─────────────────────────────────────────

    def _apply_ddos_correlation(self, pkt: dict) -> Optional[dict]:
        """Multi-Source DDoS Correlation with signature tuning."""
        dst       = pkt["dst"]
        src       = pkt["src"]
        now       = pkt["timestamp"]
        window    = self.config.DEFAULT_WINDOW
        threshold = self.config.DDOS_SOURCE_THRESHOLD
        cutoff    = now - window

        tracker = self.dst_src_tracker[dst]
        tracker.append((src, now))
        
        while tracker and tracker[0][1] < cutoff:
            tracker.popleft()

        if not tracker:
            return None
        
        unique_sources = {entry[0] for entry in tracker}
        source_count   = len(unique_sources)

        metrics = self._build_threshold_metrics(
            pkt=pkt,
            window=window,
            sample_count=source_count,
            unique_ports=0,
            unique_sources=source_count,
        )
        self.threshold_manager.record_normal_metrics("DDoS Multi-Source", metrics)

        # Only run threshold calibration when the base rule threshold is reached.
        if source_count < threshold:
            return None
        if not self._ddos_cooldown_ok(dst, now):
            return None

        tuned_threshold = self.threshold_manager.detect_and_adjust(
            rule_name="DDoS Multi-Source",
            base_threshold=threshold,
            metrics=metrics,
        )

        if source_count < tuned_threshold:
            return None

        self.ddos_alert_cache[dst] = now
        logger.info(
            f"[DETECTION] DDoS Multi-Source | "
            f"dst={dst} | {source_count} unique sources in {window}s"
        )
        return {
            "type":           "DDoS",
            "rule_name":      "DDoS Multi-Source",
            "protocol":       pkt["protocol"],
            "severity":       "CRITICAL",
            "source":         f"{source_count} unique IPs",
            "target":         dst,
            "dst_port":       pkt.get("dst_port"),
            "packet_count":   len(tracker),
            "unique_sources": source_count,
            "top_attackers":  list(unique_sources)[:5],
            "threshold":      tuned_threshold,
            "algorithm":      self.threshold_manager.algorithm_name,
            "timestamp":      now,
        }

    def _build_threshold_metrics(self,
                                 pkt: dict,
                                 window: int,
                                 sample_count: int,
                                 unique_ports: int,
                                 unique_sources: int = 0) -> dict:
        """Build metrics consumed by SignatureBasedThresholdManager."""
        payload = pkt.get("payload", b"")
        signatures = self._extract_payload_signatures(payload)
        packet_rate = sample_count / float(window) if window > 0 else 0.0
        return {
            "packet_rate": packet_rate,
            "sample_count": sample_count,
            "unique_ports": unique_ports,
            "unique_sources": unique_sources,
            "payload_signatures": signatures,
            "protocol": pkt.get("protocol", ""),
            "port": pkt.get("dst_port", 0),
        }

    @staticmethod
    def _extract_payload_signatures(payload: bytes) -> List[str]:
        """Lightweight payload signature extraction for threshold tuning."""
        if not payload:
            return []

        signatures: List[str] = []
        upper = payload.upper()
        if b"UNION SELECT" in upper:
            signatures.append("SQLI_UNION_SELECT")
        if b"DROP TABLE" in upper:
            signatures.append("SQLI_DROP_TABLE")
        if b"\x90\x90\x90\x90" in payload:
            signatures.append("NOP_SLED")
        if b"\x7FELF" in payload:
            signatures.append("ELF_BINARY")
        if b"MZ\x90" in payload:
            signatures.append("PE_BINARY")
        return signatures

    # ── Cooldown Helpers ──────────────────────────────────────────────────────

    def _cooldown_ok(self, cache_key: tuple, now: float) -> bool:
        """Return True if enough time has elapsed since the last alert."""
        last = self.alert_cache.get(cache_key)
        if last is None:
            return True
        elapsed = now - last
        if elapsed < self.SMART_COOLDOWN:
            logger.debug(f"[COOLDOWN] {cache_key[0]} suppressed ({elapsed:.0f}s)")
            return False
        return True

    def _ddos_cooldown_ok(self, dst: str, now: float) -> bool:
        last = self.ddos_alert_cache.get(dst)
        return last is None or (now - last) > self.SMART_COOLDOWN

    # ── Local IP Helper ───────────────────────────────────────────────────────

    @staticmethod
    def _is_local_ip(ip: str) -> bool:
        """Return True if IP is RFC-1918 private address."""
        if not ip:
            return False
        if ip.startswith(("127.", "10.")):
            return True
        if ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                if 16 <= int(ip.split(".")[1]) <= 31:
                    return True
            except (IndexError, ValueError):
                pass
        return False

    # ── Memory Management ─────────────────────────────────────────────────────

    def _cleanup_trackers(self, now: float):
        """Evict stale tracker entries to prevent unbounded memory growth."""
        cutoff = now - 120

        for rule_name in list(self.trackers.keys()):
            for key in list(self.trackers[rule_name].keys()):
                dq = self.trackers[rule_name][key]
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    del self.trackers[rule_name][key]

        for src in list(self.port_trackers.keys()):
            dq = self.port_trackers[src]
            while dq and dq[0][1] < cutoff:
                dq.popleft()
            if not dq:
                del self.port_trackers[src]

        for dst in list(self.dst_src_tracker.keys()):
            dq = self.dst_src_tracker[dst]
            while dq and dq[0][1] < cutoff:
                dq.popleft()
            if not dq:
                del self.dst_src_tracker[dst]

        for key in list(self.alert_cache.keys()):
            if now - self.alert_cache[key] > 300:
                del self.alert_cache[key]
        for dst in list(self.ddos_alert_cache.keys()):
            if now - self.ddos_alert_cache[dst] > 300:
                del self.ddos_alert_cache[dst]

        logger.debug(f"[DetectionEngine] Tracker cleanup completed")

    def get_stats(self) -> dict:
        """Return snapshot of active tracker state for GUI dashboard."""
        return {
            rule_name: {key: len(dq) for key, dq in key_tracker.items() if dq}
            for rule_name, key_tracker in self.trackers.items()
        }

    # ── Initialization & Stats ───────────────────────────────────────────────

    def _log_initialization(self):
        """Log initialization details."""
        logger.info("=" * 70)
        logger.info("DetectionEngine Initialized")
        logger.info("=" * 70)
        logger.info(f"Rules Loaded: {len(self.rules)}")

        proto_count = {}
        severity_count = {}
        for rule in self.rules:
            p = rule.get("protocol", "UNKNOWN")
            s = rule.get("severity", "UNKNOWN")
            proto_count[p] = proto_count.get(p, 0) + 1
            severity_count[s] = severity_count.get(s, 0) + 1

        logger.info(f"  By Protocol: {proto_count}")
        logger.info(f"  By Severity: {severity_count}")
        logger.info(f"\nAuto-Tuner: {self.threshold_manager.algorithm_name}")
        logger.info("=" * 70)

    def get_tuner_stats(self) -> dict:
        """Return signature threshold manager state for compatibility."""
        return self.threshold_manager.get_stats()

    # ── Defaults ─────────────────────────────────────────────────────────────

    @staticmethod
    def _default_rules() -> list:
        """Default rules fallback if rules.json missing."""
        cfg = Config()
        return [
            {
                "name": "TCP SYN Flood",
                "protocol": "TCP",
                "flags": "S",
                "dst_port": 80,
                "severity": "HIGH",
                "track": "src",
                "window": cfg.DEFAULT_WINDOW,
                "threshold": 20,
            },
            {
                "name": "UDP Flood",
                "protocol": "UDP",
                "severity": "HIGH",
                "track": "src",
                "window": cfg.DEFAULT_WINDOW,
                "threshold": 30,
            },
            {
                "name": "ICMP Ping Flood",
                "protocol": "ICMP",
                "icmp_type": 8,
                "severity": "MEDIUM",
                "track": "src",
                "window": cfg.DEFAULT_WINDOW,
                "threshold": 40,
            },
            {
                "name": "TCP Port Scan",
                "protocol": "TCP",
                "severity": "MEDIUM",
                "track": "src",
                "window": cfg.DEFAULT_WINDOW,
                "threshold": 10,
                "port_variety": True,
            },
        ]
