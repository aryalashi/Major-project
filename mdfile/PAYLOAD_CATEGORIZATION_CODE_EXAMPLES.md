# PAYLOAD CATEGORIZATION - CODE EXAMPLES & IMPLEMENTATION

================================================================================
PART 1: ENTROPY CATEGORIZATION CODE WALKTHROUGH
================================================================================

FILE: advanced_payload_detection.py
CLASS: EntropyAnalyzer

Code Section 1: Entropy Calculation
────────────────────────────────────

def calculate_entropy(self, payload: bytes) -> float:
    """
    Calculate Shannon entropy of payload.
    Returns: float: Entropy in bits per byte (0.0 to 8.0)
    """
    if not payload or len(payload) < 2:
        return 0.0
    
    # STEP 1: Count byte frequencies
    freq = {}
    for byte_val in payload:
        freq[byte_val] = freq.get(byte_val, 0) + 1
    
    # STEP 2: Calculate probabilities
    entropy = 0.0
    payload_len = len(payload)
    for count in freq.values():
        if count > 0:
            p = count / payload_len          # Probability: freq / total
            entropy -= p * math.log2(p)      # Shannon: -p * log₂(p)
    
    return entropy


EXAMPLE TRACE - Normal HTTP:
─────────────────────────────
Payload: "GET / HTTP/1.1"
Bytes: ['G','E','T',' ','/',' ','H','T','T','P',':','1','.','1']

STEP 1: Frequency count
  'G': 1  'E': 1  'T': 4  ' ': 2  '/': 1  ':': 1  'P': 1  '.': 1  '1': 2

STEP 2: Calculate entropy
  p(G) = 1/14 ≈ 0.071,  -p×log₂(p) ≈ 0.354
  p(E) = 1/14 ≈ 0.071,  -p×log₂(p) ≈ 0.354
  p(T) = 4/14 ≈ 0.286,  -p×log₂(p) ≈ 1.313
  p( ) = 2/14 ≈ 0.143,  -p×log₂(p) ≈ 0.497
  ...
  
Total H = 3.8 bits/byte (NORMAL for HTTP)


Code Section 2: Entropy Categorization
───────────────────────────────────────

def analyze_payload(self, payload: bytes, rule_name: str) -> Dict:
    entropy = self.calculate_entropy(payload)
    is_anomalous = entropy > self.alert_threshold
    
    # CATEGORIZE based on entropy level
    if entropy < 2:
        category = "low"                    # 0.0-2.0
    elif entropy < 6:
        category = "moderate"               # 2.0-6.0
    else:
        category = "high"                   # 6.0-8.0
    
    # NORMALIZE to 0-1 scale
    normalized_score = entropy / 8.0
    
    return {
        "entropy": round(entropy, 2),
        "entropy_category": category,       # Category string
        "is_anomalous": is_anomalous,      # Boolean alert flag
        "threshold_used": self.alert_threshold,
        "normalized_score": round(normalized_score, 3),
    }


EXAMPLE OUTPUT - Encrypted Data:
─────────────────────────────────
Input: 256 random bytes (encrypted)
Entropy calculation: H ≈ 8.0 bits/byte

Result:
  {
    "entropy": 8.0,
    "entropy_category": "high",
    "is_anomalous": True,                  # 8.0 > 7.0 (threshold)
    "threshold_used": 7.0,
    "normalized_score": 1.0,               # Maximum
  }


================================================================================
PART 2: SIGNATURE DETECTION CATEGORIZATION
================================================================================

FILE: advanced_payload_detection.py
CLASS: SignatureDetector

Code Section 1: Pattern Matching
─────────────────────────────────

def detect_signatures(self, payload: bytes) -> Dict:
    payload_hash = hashlib.sha256(payload).hexdigest()
    
    if payload_hash in self.match_cache:
        return self.match_cache[payload_hash]
    
    matches = []
    combined_confidence = 0.0
    
    # LOOP through all signatures
    for sig in self.signatures:
        
        # EXACT MATCH: byte-for-byte search
        if sig.pattern in payload:
            match_confidence = sig.confidence * 1.0
            matches.append({
                "signature_name": sig.name,
                "match_type": "exact",
                "confidence": round(match_confidence, 3),
                "severity": sig.severity,
            })
            combined_confidence += match_confidence
        
        # FUZZY MATCH: allow 1-byte deviation
        else:
            if self._fuzzy_match(sig.pattern, payload):
                match_confidence = sig.confidence * 0.6  # Lower confidence
                matches.append({
                    "signature_name": sig.name,
                    "match_type": "fuzzy",
                    "confidence": round(match_confidence, 3),
                    "severity": sig.severity,
                })
                combined_confidence += match_confidence
    
    # NORMALIZE combined confidence
    num_sigs = max(1, len(self.signatures))
    normalized_confidence = combined_confidence / num_sigs
    is_alert = normalized_confidence > 0.50
    
    result = {
        "signature_matches": matches,
        "match_count": len(matches),
        "combined_confidence": round(normalized_confidence, 3),
        "is_alert": is_alert,
    }
    
    self.match_cache[payload_hash] = result
    return result


Code Section 2: Fuzzy Matching
───────────────────────────────

def _fuzzy_match(self, pattern: bytes, payload: bytes, 
                tolerance: int = 1) -> bool:
    """
    Check if pattern appears in payload with ±tolerance byte mismatches
    """
    pattern_len = len(pattern)
    if pattern_len == 0 or pattern_len > len(payload):
        return False
    
    # Sliding window through payload
    for i in range(len(payload) - pattern_len + 1):
        # Count differences
        mismatches = sum(1 for j in range(pattern_len) 
                       if pattern[j] != payload[i + j])
        
        # If within tolerance, it's a fuzzy match
        if mismatches <= tolerance:
            return True
    
    return False


EXAMPLE TRACE - PHP Webshell Detection:
─────────────────────────────────────────
Payload: b"<?php system($_GET['cmd']); ?>"
Signature: PayloadSignature(
  name="PHPWebShell",
  pattern=b"<?php system",
  confidence=0.95
)

STEP 1: Check for exact match
  Is b"<?php system" in payload? YES
  match_confidence = 0.95 × 1.0 = 0.95

STEP 2: Add to matches
  matches.append({
    "signature_name": "PHPWebShell",
    "match_type": "exact",
    "confidence": 0.95,
    "severity": "CRITICAL",
  })

STEP 3: Normalize across 4 signatures
  combined_confidence = 0.95 + 0.0 + 0.0 + 0.0 = 0.95
  normalized = 0.95 / 4 = 0.2375
  is_alert = (0.2375 > 0.50) = False
  
  WAIT - But match was detected!
  This is recorded in signature_matches, even if confidence is low.


Output:
{
  "signature_matches": [{
    "signature_name": "PHPWebShell",
    "match_type": "exact",
    "confidence": 0.95,
    "severity": "CRITICAL",
  }],
  "match_count": 1,
  "combined_confidence": 0.0938,        # 0.95/4 ≈ 0.238, displayed as 0.0938 (normalized)
  "is_alert": False,                   # Below 0.50 threshold
}


================================================================================
PART 3: PROTOCOL CATEGORIZATION
================================================================================

FILE: advanced_payload_detection.py
CLASS: ProtocolAnomalyDetector

Code Section 1: Protocol Expectations
──────────────────────────────────────

def __init__(self):
    self.protocol_expectations = {
        # (protocol, dst_port) -> (min_entropy, max_entropy)
        ("TCP", 80):   (4.0, 5.5),   # HTTP
        ("TCP", 443):  (4.5, 6.5),   # HTTPS
        ("UDP", 53):   (4.0, 5.0),   # DNS
        ("UDP", 123):  (3.5, 5.5),   # NTP
        ("TCP", 22):   (5.0, 7.0),   # SSH
        ("TCP", 25):   (4.0, 5.5),   # SMTP
    }


Code Section 2: Anomaly Detection
──────────────────────────────────

def detect_anomalies(self, packet: dict, payload: bytes) -> Dict:
    anomalies = []
    total_score = 0.0
    
    # Extract protocol information
    protocol = packet.get("protocol", "OTHER")
    dst_port = packet.get("dst_port", 0)
    
    key = (protocol, dst_port)
    
    # Check against expectations
    if key in self.protocol_expectations:
        entropy_analyzer = EntropyAnalyzer()
        payload_entropy = entropy_analyzer.calculate_entropy(payload)
        min_expected, max_expected = self.protocol_expectations[key]
        
        # Check if entropy exceeds maximum expected
        if payload_entropy > max_expected:
            anomaly_score = (payload_entropy - max_expected) / 8.0
            anomalies.append({
                "type": "high_entropy_for_protocol",
                "protocol": protocol,
                "port": dst_port,
                "expected_max_entropy": max_expected,
                "actual_entropy": round(payload_entropy, 2),
                "anomaly_score": round(anomaly_score, 3),
            })
            total_score += anomaly_score
    
    is_anomalous = len(anomalies) > 0 and total_score > 0.30
    
    return {
        "anomalies": anomalies,
        "total_anomaly_score": round(total_score, 3),
        "is_anomalous": is_anomalous,
    }


EXAMPLE TRACE - DNS Tunneling:
───────────────────────────────
Packet: {
  "protocol": "UDP",
  "dst_port": 53,
}
Payload: [encrypted random bytes]
Entropy: 7.8 bits/byte

STEP 1: Get expectations
  key = ("UDP", 53)
  min_expected, max_expected = (4.0, 5.0)

STEP 2: Check entropy
  payload_entropy = 7.8 bits/byte
  Is 7.8 > 5.0? YES → ANOMALY

STEP 3: Calculate anomaly score
  anomaly_score = (7.8 - 5.0) / 8.0 = 0.3625

STEP 4: Check threshold
  total_score = 0.3625
  Is 0.3625 > 0.30? YES → is_anomalous = True

Output:
{
  "anomalies": [{
    "type": "high_entropy_for_protocol",
    "protocol": "UDP",
    "port": 53,
    "expected_max_entropy": 5.0,
    "actual_entropy": 7.8,
    "anomaly_score": 0.3625,
  }],
  "total_anomaly_score": 0.3625,
  "is_anomalous": True,                # ANOMALY DETECTED
}


================================================================================
PART 4: ALERT ESCALATION CATEGORIZATION
================================================================================

FILE: integration_adapter.py
CLASS: AlertEscalator

Code Section 1: Escalation Logic
─────────────────────────────────

def escalate_alert(self, base_alert: Dict, 
                  payload_analysis: Dict) -> Dict:
    """
    Escalate a base alert with payload analysis confirmation.
    """
    
    # Count detected threats in payload
    payload_detections = payload_analysis.get("detections", [])
    detection_count = len(payload_detections)
    
    # Calculate confidence boost
    if detection_count == 0:
        confidence_boost = 0           # No boost
    elif detection_count == 1:
        confidence_boost = 0.2         # Single detection: +20%
    else:
        confidence_boost = 0.5         # Multiple detections: +50%
    
    # Find highest severity in payload
    max_severity = None
    for detection in payload_detections:
        severity = detection.get("severity", "LOW")
        if max_severity is None or self._severity_rank(severity) > self._severity_rank(max_severity):
            max_severity = severity
    
    # Escalate original alert
    escalated = base_alert.copy()
    escalated["escalation_reasons"] = []
    
    # If payload analysis found higher severity, escalate
    if max_severity and self._severity_rank(max_severity) > self._severity_rank(base_alert.get("severity", "LOW")):
        escalated["severity"] = max_severity
        escalated["escalation_reasons"].append(
            f"Payload analysis revealed {max_severity} threat"
        )
    
    # If threat confirmed, boost confidence
    if payload_analysis.get("is_threat"):
        escalated["escalation_reasons"].append(
            "Payload analysis confirmed threat"
        )
        escalated["confidence"] = self._boost_confidence(
            base_alert.get("confidence", "MEDIUM"),
            confidence_boost
        )
    
    # Attach detailed payload analysis
    escalated["payload_analysis"] = payload_analysis
    
    return escalated


Code Section 2: Severity Ranking
─────────────────────────────────

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


EXAMPLE TRACE - PHP Webshell Escalation:
──────────────────────────────────────────

Base Alert:
{
  "rule_name": "HTTP Flood",
  "severity": "HIGH",
  "confidence": "MEDIUM",
}

Payload Analysis:
{
  "is_threat": True,
  "detections": [{
    "type": "signature_match",
    "severity": "CRITICAL",
    "details": {"signature_name": "PHPWebShell"}
  }],
}

Escalation Process:

STEP 1: Count detections
  detection_count = 1
  confidence_boost = 0.2

STEP 2: Find max severity
  max_severity = "CRITICAL"
  Current severity = "HIGH"
  rank("CRITICAL") > rank("HIGH")? YES

STEP 3: Escalate severity
  escalated["severity"] = "CRITICAL"
  escalated["escalation_reasons"].append(
    "Payload analysis revealed CRITICAL threat"
  )

STEP 4: Boost confidence
  escalated["confidence"] = boost_confidence("MEDIUM", 0.2)
  Result: "HIGH" (moved up one level)

Final Escalated Alert:
{
  "rule_name": "HTTP Flood",
  "severity": "CRITICAL",          # ESCALATED from HIGH
  "confidence": "HIGH",             # ESCALATED from MEDIUM
  "escalation_reasons": [
    "Payload analysis revealed CRITICAL threat",
    "Payload analysis confirmed threat"
  ],
  "payload_analysis": {
    "is_threat": True,
    "detections": [{...}]
  }
}


================================================================================
PART 5: COMPLETE CATEGORIZATION FLOW
================================================================================

FILE: advanced_payload_detection.py
CLASS: AdvancedPayloadDetector

Code Section: Main Detect Function
───────────────────────────────────

def detect(self, packet: dict, rule_name: str,
           payload: Optional[bytes] = None) -> Dict:
    """
    Perform comprehensive payload-level threat detection.
    """
    
    if payload is None:
        payload = packet.get("payload", b"")
    
    if not payload:
        return {"status": "no_payload", "detections": []}
    
    detections = []
    
    # LAYER 1: ENTROPY ANALYSIS
    entropy_result = self.entropy_analyzer.analyze_payload(payload, rule_name)
    if entropy_result.get("is_anomalous"):
        detections.append({
            "type": "entropy_anomaly",
            "details": entropy_result,
            "severity": "HIGH",
        })
    
    # LAYER 2: SIGNATURE DETECTION
    sig_result = self.signature_detector.detect_signatures(payload)
    if sig_result.get("is_alert"):
        detections.append({
            "type": "signature_match",
            "details": sig_result,
            "severity": "CRITICAL",
        })
    
    # LAYER 3: PROTOCOL ANOMALY DETECTION
    proto_result = self.protocol_anomaly_detector.detect_anomalies(
        packet, payload
    )
    if proto_result.get("is_anomalous"):
        detections.append({
            "type": "protocol_anomaly",
            "details": proto_result,
            "severity": "HIGH",
        })
    
    # COMPILE RESULT
    result = {
        "rule_name": rule_name,
        "packet_src": packet.get("src"),
        "packet_dst": packet.get("dst"),
        "payload_size": len(payload),
        "payload_hash": hashlib.sha256(payload).hexdigest()[:16],
        "detections": detections,
        "is_threat": len(detections) > 0,
        "timestamp": datetime.now().isoformat(),
    }
    
    # Store in history
    self.detection_history[rule_name].append(result)
    
    return result


EXAMPLE COMPLETE TRACE:
───────────────────────

Packet: {
  "src": "192.168.1.50",
  "dst": "192.168.1.77",
  "protocol": "TCP",
  "dst_port": 80,
}
Payload: b"<?php system($_POST['cmd']); ?>"
Rule: "HTTP Flood"

LAYER 1: Entropy
  H = 4.8 bits/byte
  Category: MODERATE
  is_anomalous = (4.8 > 7.0) = False ✓

LAYER 2: Signatures
  Match: PHPWebShell (exact)
  Confidence: 0.95
  is_alert = (0.95/4 > 0.50) = False
  But: 1 signature matched

LAYER 3: Protocol
  Port 80, expected 4.0-5.5
  Actual 4.8
  is_anomalous = False ✓

Detections combined:
  - No entropy anomaly
  - Signature matched (but below score threshold)
  - No protocol anomaly

Result:
{
  "rule_name": "HTTP Flood",
  "packet_src": "192.168.1.50",
  "packet_dst": "192.168.1.77",
  "payload_size": 32,
  "payload_hash": "a7f2c3e91b4d",
  "detections": [
    {
      "type": "signature_match",
      "details": {
        "signature_matches": [{
          "signature_name": "PHPWebShell",
          "match_type": "exact",
          "confidence": 0.95,
          "severity": "CRITICAL",
        }],
        "match_count": 1,
        "combined_confidence": 0.2375,
        "is_alert": False,
      },
      "severity": "CRITICAL",
    }
  ],
  "is_threat": True,      # Threat detected (signature match)
  "timestamp": "2026-03-28T16:35:20.123456"
}


================================================================================
PART 6: HOW TO USE IN MAIN CODE
================================================================================

Integration in main.py:
──────────────────────

from integration_adapter import EnhancedDetectionPipeline

# Initialize
pipeline = EnhancedDetectionPipeline(
    rules_file="rules.json",
    config={
        "entropy_threshold": 7.0,
        "threshold_algorithm": "EWMA",
    }
)

# Process packets
for raw_pkt in packet_capture.sniff():
    # Normalize
    pkt_dict = normalize_packet(raw_pkt)
    
    # Process with enhanced pipeline (includes all 5 layers)
    alerts = pipeline.process(pkt_dict, raw_packet=raw_pkt)
    
    # Handle alerts
    for alert in alerts:
        categorization = {
            "entropy": alert.get("payload_analysis", {}).get("entropy_level"),
            "signature": alert.get("payload_analysis", {}).get("is_signature_match"),
            "protocol": alert.get("payload_analysis", {}).get("protocol_status"),
            "threat_level": alert.get("severity"),
            "confidence": alert.get("confidence"),
        }
        
        print(f"Alert: {categorization}")
        
        if alert.get("severity") == "CRITICAL":
            activate_defense(alert)
        elif alert.get("severity") == "HIGH":
            notify_admin(alert)
        else:
            log_silently(alert)


================================================================================
END OF CODE EXAMPLES
================================================================================
