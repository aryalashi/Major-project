"""
rule_engine.py
--------------
Signature Rule Engine for NIDS

Loads detection rules from rules.json and validates them for use by
the DetectionEngine. Provides sensible defaults if rules.json is missing.

Rule Schema (Canonical)
------------------------
{
    "name":         str,      # Unique rule identifier
    "protocol":     str,      # "TCP" | "UDP" | "ICMP" | "OTHER"
    "severity":     str,      # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    "track":        str,      # "src" | "dst" | "src_dst"
    "window":       int,      # Time window in seconds
    "threshold":    int,      # Packet threshold for alert
    "description":  str,      # Human-readable explanation (optional)
    "reference":    str,      # CVE/CIC-IDS reference (optional)
    
    # Protocol-specific fields (optional)
    "flags":        str|None, # TCP only: "S", "SA", "A", etc.
    "dst_port":     int|None, # TCP/UDP only: destination port
    "icmp_type":    int|None, # ICMP only: type (e.g., 8 for echo)
    "icmp_code":    int|None, # ICMP only: code
    
    # Detection mode (optional)
    "port_variety": bool,     # Enable port scan detection
    "local_src_only": bool,   # Track RFC-1918 sources only
}

Validation Rules
----------------
1. Required fields: name, protocol, severity, track, window, threshold
2. Protocol must be one of: TCP, UDP, ICMP, OTHER
3. Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW
4. Track must be one of: src, dst, src_dst
5. Window must be > 0 (typically 5-60 seconds)
6. Threshold must be >= 1
7. TCP rules must have protocol="TCP" if flags are specified
8. ICMP rules must have icmp_type specified
"""

import os
import json
import logging
from typing import List, Optional, Dict

logger = logging.getLogger("RuleEngine")


class RuleEngine:
    """
    Load and validate signature rules for the IDS detection engine.

    Strategy: Try to load from rules.json, fall back to rules_tuned.json,
    then use hardcoded defaults if both missing.
    """

    VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "OTHER"}
    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    VALID_TRACK_MODES = {"src", "dst", "src_dst"}

    def __init__(self, rules_file: str = "rules.json", auto_validate: bool = True):
        self.rules_file = rules_file
        self.rules: List[Dict] = []
        self.load_rules()

        if auto_validate:
            invalid = self.validate_rules()
            if invalid:
                logger.warning(f"Found {len(invalid)} invalid rules:")
                for rule_name, errors in invalid:
                    logger.warning(f"  {rule_name}: {errors}")
                # Filter out invalid rules
                self.rules = [r for r in self.rules 
                             if r["name"] not in [rn for rn, _ in invalid]]
                logger.info(f"Proceeding with {len(self.rules)} valid rules")

    def load_rules(self) -> bool:
        """
        Load rules from file (or fallback to defaults).

        Try in order:
          1. rules.json (user-tuned)
          2. rules_tuned.json (backup tuned)
          3. Hardcoded defaults

        Returns True if loaded from file, False if using defaults.
        """
        # Try primary rules file
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    self.rules = json.load(f)
                logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file}")
                return True
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load {self.rules_file}: {e}")

        # Try backup tuned rules
        tuned_file = "rules_tuned.json"
        if os.path.exists(tuned_file):
            try:
                with open(tuned_file, 'r', encoding='utf-8') as f:
                    self.rules = json.load(f)
                logger.info(f"Loaded {len(self.rules)} rules from {tuned_file} (backup)")
                return True
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load {tuned_file}: {e}")

        # Fallback to defaults
        self.rules = self._default_rules()
        logger.info(
            f"Using {len(self.rules)} hardcoded default rules "
            f"(rules.json not found)"
        )
        return False

    def validate_rules(self) -> List[tuple]:
        """
        Validate all loaded rules against schema.

        Returns list of (rule_name, error_messages) tuples for invalid rules.
        """
        invalid = []

        for rule in self.rules:
            errors = []

            # Required fields
            if not rule.get("name"):
                errors.append("'name' missing")
            if not rule.get("protocol"):
                errors.append("'protocol' missing")
            if not rule.get("severity"):
                errors.append("'severity' missing")
            if not rule.get("track"):
                errors.append("'track' missing")
            if "window" not in rule:
                errors.append("'window' missing")
            if "threshold" not in rule:
                errors.append("'threshold' missing")

            if errors:
                invalid.append((rule.get("name", "UNNAMED"), errors))
                continue

            # Enum validations
            if rule["protocol"] not in self.VALID_PROTOCOLS:
                errors.append(
                    f"protocol={rule['protocol']} not in {self.VALID_PROTOCOLS}"
                )

            if rule["severity"] not in self.VALID_SEVERITIES:
                errors.append(
                    f"severity={rule['severity']} not in {self.VALID_SEVERITIES}"
                )

            if rule["track"] not in self.VALID_TRACK_MODES:
                errors.append(
                    f"track={rule['track']} not in {self.VALID_TRACK_MODES}"
                )

            # Numeric validations
            if not isinstance(rule.get("window"), int) or rule["window"] <= 0:
                errors.append(f"window={rule.get('window')} must be int > 0")

            if not isinstance(rule.get("threshold"), int) or rule["threshold"] < 1:
                errors.append(f"threshold={rule.get('threshold')} must be int >= 1")

            # Protocol-specific validations
            if rule["protocol"] == "TCP":
                if "flags" in rule and rule["flags"] is not None:
                    if not isinstance(rule["flags"], str):
                        errors.append("TCP flags must be a string (e.g., 'S', 'SA')")

            if rule["protocol"] == "ICMP":
                if "icmp_type" not in rule:
                    errors.append("ICMP rule must specify 'icmp_type'")
                elif not isinstance(rule["icmp_type"], int):
                    errors.append(f"icmp_type must be int, got {type(rule['icmp_type'])}")

            if errors:
                invalid.append((rule["name"], errors))

        return invalid

    def get_rules(self) -> List[Dict]:
        """Return the loaded rule list."""
        return self.rules

    def get_rule_by_name(self, name: str) -> Optional[Dict]:
        """Get a single rule by name."""
        for rule in self.rules:
            if rule.get("name") == name:
                return rule
        return None

    def get_rules_by_protocol(self, protocol: str) -> List[Dict]:
        """Get all rules for a specific protocol."""
        return [r for r in self.rules if r.get("protocol") == protocol]

    def get_rules_by_severity(self, severity: str) -> List[Dict]:
        """Get all rules for a specific severity level."""
        return [r for r in self.rules if r.get("severity") == severity]

    def get_stats(self) -> Dict:
        """Return statistics about loaded rules."""
        protocols = {}
        severities = {}
        for rule in self.rules:
            p = rule.get("protocol", "UNKNOWN")
            s = rule.get("severity", "UNKNOWN")
            protocols[p] = protocols.get(p, 0) + 1
            severities[s] = severities.get(s, 0) + 1

        return {
            "total_rules": len(self.rules),
            "protocols": protocols,
            "severities": severities,
        }

    # ── Defaults ──────────────────────────────────────────────────────────────

    @staticmethod
    def _default_rules() -> List[Dict]:
        """
        Hardcoded default rules for standalone operation.

        Covers common attack signatures from CIC-IDS-2017 dataset:
          - DoS: SYN Flood, UDP Flood, ICMP Flood
          - Port Scans: TCP SYN, FIN, NULL, XMAS, UDP
          - Brute Force: FTP, SSH, HTTP
          - Exploits: Heartbleed
        """
        return [
            # ── DoS Attacks ───────────────────────────────────────────────────
            {
                "name": "TCP SYN Flood",
                "protocol": "TCP",
                "flags": "S",
                "severity": "HIGH",
                "track": "src",
                "window": 10,
                "threshold": 20,
                "description": "High-rate TCP SYN packets (half-open connection flood)",
                "reference": "CIC-IDS-2017: DoS Hulk",
            },
            {
                "name": "UDP Flood",
                "protocol": "UDP",
                "severity": "HIGH",
                "track": "src",
                "window": 10,
                "threshold": 30,
                "description": "High-rate UDP packets (bandwidth saturation)",
                "reference": "CIC-IDS-2017: UDP Flood",
            },
            {
                "name": "ICMP Ping Flood",
                "protocol": "ICMP",
                "icmp_type": 8,
                "severity": "MEDIUM",
                "track": "src",
                "window": 10,
                "threshold": 40,
                "description": "High-rate ICMP Echo Request (ping flood)",
                "reference": "CIC-IDS-2017: ICMP Flood",
            },
            {
                "name": "TCP ACK Flood",
                "protocol": "TCP",
                "flags": "A",
                "severity": "MEDIUM",
                "track": "src",
                "window": 10,
                "threshold": 25,
                "description": "Stateless ACK flood (bypasses SYN cookies)",
                "reference": "CIC-IDS-2017: DoS Slowhttptest",
            },
            {
                "name": "TCP RST Flood",
                "protocol": "TCP",
                "flags": "R",
                "severity": "HIGH",
                "track": "src",
                "window": 10,
                "threshold": 20,
                "description": "High-rate RST packets (connection termination)",
                "reference": "CIC-IDS-2017: DoS GoldenEye",
            },

            # ── Port Scans ────────────────────────────────────────────────────
            {
                "name": "TCP SYN Port Scan",
                "protocol": "TCP",
                "flags": "S",
                "severity": "MEDIUM",
                "track": "src",
                "window": 5,
                "threshold": 12,
                "port_variety": True,
                "description": "SYN packets to many different ports (classic SYN scan)",
                "reference": "CIC-IDS-2017: PortScan",
            },
            {
                "name": "TCP FIN Scan",
                "protocol": "TCP",
                "flags": "F",
                "severity": "MEDIUM",
                "track": "src",
                "window": 5,
                "threshold": 12,
                "port_variety": True,
                "description": "FIN packets to many ports (stealthy FIN scan)",
                "reference": "Nmap -sF",
            },
            {
                "name": "TCP NULL Scan",
                "protocol": "TCP",
                "flags": "",
                "severity": "MEDIUM",
                "track": "src",
                "window": 5,
                "threshold": 12,  
                "port_variety": True,
                "description": "TCP packets with NO flags to many ports (NULL scan)",
                "reference": "Nmap -sN",
            },
            {
                "name": "TCP XMAS Scan",
                "protocol": "TCP",
                "flags": "FPU",
                "severity": "MEDIUM",
                "track": "src",
                "window": 5,
                "threshold": 12,
                "port_variety": True,
                "description": "TCP FIN+PSH+URG packets (XMAS scan)",
                "reference": "Nmap -sX",
            },
            {
                "name": "UDP Port Scan",
                "protocol": "UDP",
                "severity": "LOW",
                "track": "src",
                "window": 5,
                "threshold": 12,
                "port_variety": True,
                "description": "UDP packets to many different ports (UDP scan)",
                "reference": "Nmap -sU",
            },

            # ── Brute Force ───────────────────────────────────────────────────
            {
                "name": "HTTPS/TLS Brute Force",
                "protocol": "TCP",
                "flags": "S",
                "dst_port": 443,
                "severity": "CRITICAL",
                "track": "src",
                "window": 10,
                "threshold": 15,
                "description": "High-rate connections to HTTPS port 443 (credential brute force)",
                "reference": "CIC-IDS-2017: Heartbleed",
            },
            {
                "name": "FTP Brute Force",
                "protocol": "TCP",
                "flags": "S",
                "dst_port": 21,
                "severity": "MEDIUM",
                "track": "src",
                "window": 10,
                "threshold": 12,
                "description": "Repeated connections to FTP port 21 (credential brute force)",
                "reference": "CIC-IDS-2017: FTP-Patator",
            },
            {
                "name": "SSH Brute Force",
                "protocol": "TCP",
                "flags": "S",
                "dst_port": 22,
                "severity": "MEDIUM",
                "track": "src",
                "window": 10,
                "threshold": 12,
                "description": "Repeated SSH connections (credential brute force)",
                "reference": "CIC-IDS-2017: SSH-Patator",
            },
            {
                "name": "HTTP Brute Force",
                "protocol": "TCP",
                "flags": "S",
                "dst_port": 80,
                "severity": "MEDIUM",
                "track": "src",
                "window": 10,
                "threshold": 12,
                "description": "High-rate HTTP connections (web login brute force)",
                "reference": "CIC-IDS-2017: HttpBrute",
            },
        ]


# ── Module-level loader ───────────────────────────────────────────────────────

_engine = None


def get_engine() -> RuleEngine:
    """Get or create singleton RuleEngine instance."""
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine


def load_rules(rules_file: str = "rules.json") -> List[Dict]:
    """Convenience function to load and return rules."""
    engine = RuleEngine(rules_file)
    return engine.get_rules()
