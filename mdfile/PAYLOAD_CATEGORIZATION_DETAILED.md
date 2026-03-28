# PAYLOAD CATEGORIZATION DETAILED EXPLANATION
Advanced Payload Detection - How Payloads Are Categorized

================================================================================
SECTION 1: FIVE LAYERS OF PAYLOAD CATEGORIZATION
================================================================================

The advanced payload detection system categorizes payloads through 5 independent
but complementary mechanisms:

    Layer 1: ENTROPY-BASED CATEGORIZATION
    Layer 2: SIGNATURE-BASED CATEGORIZATION
    Layer 3: PROTOCOL-BASED CATEGORIZATION
    Layer 4: STRUCTURAL/PATTERN CATEGORIZATION
    Layer 5: CONTEXT-AWARE CATEGORIZATION

Each layer operates independently and feeds into the overall threat assessment.


================================================================================
LAYER 1: ENTROPY-BASED CATEGORIZATION (Primary Mechanism)
================================================================================

PURPOSE:
  Detect obfuscation, encryption, compression based on byte distribution
  randomness

METHODOLOGY:
  Calculate Shannon entropy H(X) = -Σ p(x) × log₂(p(x))
  
  Where:
    p(x) = frequency of byte value x in payload
    Result in range: 0.0 to 8.0 bits/byte

CATEGORIZATION THRESHOLDS:

┌─────────────────┬─────────────────┬──────────┬─────────────────────────────┐
│ Entropy Range   │ Category        │ Flag     │ Interpretation              │
├─────────────────┼─────────────────┼──────────┼─────────────────────────────┤
│ 0.0 - 2.0       │ LOW             │ Normal   │ Highly structured content   │
│                 │                 │          │ (repeated bytes, ASCII)     │
│                 │                 │          │ Examples:                   │
│                 │                 │          │  - All null bytes (0x00)    │
│                 │                 │          │  - Padding/fillers         │
│                 │                 │          │  - Headers, metadata        │
├─────────────────┼─────────────────┼──────────┼─────────────────────────────┤
│ 2.0 - 4.0       │ LOW-MODERATE    │ Normal   │ Mostly text, some structure │
│                 │                 │          │ Examples:                   │
│                 │                 │          │ - HTML headers (~3.8)       │
│                 │                 │          │ - Plain text emails         │
│                 │                 │          │ - JSON/XML documents        │
├─────────────────┼─────────────────┼──────────┼─────────────────────────────┤
│ 4.0 - 6.0       │ MODERATE        │ Normal   │ Mixed text/binary content   │
│                 │                 │          │ Examples:                   │
│                 │                 │          │ - HTTP GET + body (~4.2)    │
│                 │                 │          │ - SMTP with attachments     │
│                 │                 │          │ - DNS with data (~4.5)      │
│                 │                 │          │ - Compressed text (e.g gzip)│
├─────────────────┼─────────────────┼──────────┼─────────────────────────────┤
│ 6.0 - 7.0       │ HIGH-MODERATE   │ Suspicious│ Highly structured binary    │
│                 │                 │ (context │ Examples:                   │
│                 │                 │ dependent)│ - SSH encrypted payload     │
│                 │                 │          │ - Binary protocols (BGP)    │
│                 │                 │          │ - HTTPS traffic             │
│                 │                 │          │ - Partial compression       │
├─────────────────┼─────────────────┼──────────┼─────────────────────────────┤
│ 7.0 - 8.0       │ HIGH            │ ANOMALY  │ Nearly random/encrypted     │
│                 │                 │ FLAG     │ Examples:                   │
│                 │                 │          │ - Encrypted binary blob     │
│                 │                 │          │ - Shellcode (obfuscated)    │
│                 │                 │          │ - Random data               │
│                 │                 │          │ - XOR-encoded payload       │
│ 8.0             │ MAXIMUM         │ CRITICAL │ Perfect random distribution │
│                 │                 │ ALERT    │ Only seen in artificial     │
│                 │                 │          │ random data                 │
└─────────────────┴─────────────────┴──────────┴─────────────────────────────┘


EXAMPLE 1: Plain ASCII Text
──────────────────────────────
Payload: "Hello World"
Bytes: [H=1, e=1, l=3, o=2, space=1, W=1, r=1, d=1]

Calculation:
  p(H) = 1/11 ≈ 0.0909
  p(e) = 1/11 ≈ 0.0909
  p(l) = 3/11 ≈ 0.2727
  p(o) = 2/11 ≈ 0.1818
  p(space) = 1/11 ≈ 0.0909
  p(W) = 1/11 ≈ 0.0909
  p(r) = 1/11 ≈ 0.0909
  p(d) = 1/11 ≈ 0.0909

H = -[0.0909×log₂(0.0909) + 0.0909×log₂(0.0909) + 0.2727×log₂(0.2727)
      + 0.1818×log₂(0.1818) + ...]
  = -[0.0909×(-3.465) + 0.0909×(-3.465) + 0.2727×(-1.876)
      + 0.1818×(-2.459) + ...]
  ≈ 2.4 bits/byte

CATEGORIZATION: LOW (2.0-4.0 range) → NORMAL TEXT


EXAMPLE 2: HTTP Request
────────────────────────
Payload: "POST /api?key=xyz HTTP/1.1\r\nContent-Length: 42\r\n\r\n"

Byte distribution:
  Letters (P,O,S,T,etc): ~30 bytes
  Digits (1,2,0,9,4,2): ~8 bytes
  Special chars (/,?,=,:,\r,\n): ~15 bytes
  Space: ~5 bytes

Calculation:
  More distributed than "Hello World" but still structured
  H ≈ 4.2 bits/byte

CATEGORIZATION: MODERATE (4.0-6.0 range) → NORMAL HTTP PROTOCOL


EXAMPLE 3: Encrypted Payload
──────────────────────────────
Payload: [0x7F, 0x3A, 0xE2, 0x91, 0x24, 0x5B, 0x89, 0xD3, ...]
         (AES-256 encrypted data)

Byte distribution: Nearly uniform
  Each byte value 0-255 appears roughly once
  p(x) ≈ 1/256 ≈ 0.00391 for all x

Calculation:
  H = -[256 × (0.00391 × log₂(0.00391))]
    = -[256 × (0.00391 × -8.0)]
    = -[256 × (-0.03125)]
    = 8.0 bits/byte

CATEGORIZATION: MAXIMUM (7.0-8.0 range) → ANOMALY/ENCRYPTION DETECTED


EXAMPLE 4: XOR-Obfuscated Shellcode
────────────────────────────────────
Original shellcode: [0x90, 0x90, 0x90, 0x90, 0xFC, 0x89, 0xE1, 0x31, ...]
XOR'd with key 0x42: [0xD2, 0xD2, 0xD2, 0xD2, 0xBE, 0xCB, 0xA3, 0x73, ...]

After XOR:
  Byte distribution becomes more uniform than original
  H ≈ 6.8 bits/byte

CATEGORIZATION: HIGH (6.0-7.0 range) → POTENTIALLY MALICIOUS

Alert Threshold: If base threshold is 7.0
  6.8 < 7.0 → Not flagged as anomaly
  But: Combined with signature detection, could still alert


PROTOCOL-SPECIFIC THRESHOLDS:
──────────────────────────────

Protocol      Port  Expected Range  Alert if >  Logic
─────────────────────────────────────────────────────
HTTP          80    4.0-5.5         7.5         Binary payload in text protocol
HTTPS         443   4.5-6.5         7.9         Encrypted by design, higher ok
DNS           53    4.0-5.0         6.5         Names should be ASCII
SSH           22    5.0-7.0         7.8         Encrypted by design
SMTP          25    4.0-5.5         7.0         Email should be readable
FTP           21    4.0-5.0         6.5         ASCII commands + files
MySQL         3306  5.0-6.5         7.2         Mixed text/binary protocol
PostgreSQL    5432  5.0-6.5         7.2         Mixed text/binary protocol
NTP           123   3.5-5.5         6.5         Structured binary protocol


================================================================================
LAYER 2: SIGNATURE-BASED CATEGORIZATION
================================================================================

PURPOSE:
  Identify known malware patterns, attack signatures, malicious payloads
  regardless of entropy level

METHODOLOGY:
  Pattern matching in raw bytes with two strategies:
    Strategy A: Exact match (100% byte-for-byte match)
    Strategy B: Fuzzy match (allows 1-2 byte differences)

DEFAULT SIGNATURES PROVIDED:

Signature 1: ShellcodeNOPSled
  Pattern: 0x90 0x90 0x90 0x90  (NOP NOP NOP NOP in x86 assembly)
  Confidence: 0.85
  Reason: NOP sleds are classic shellcode prefix for heap/stack overflows
  Example Match:
    Payload contains: [...data][0x90 0x90 0x90 0x90][shellcode...]
    Match type: EXACT
    Result score: 0.85 × 1.0 = 0.85 (HIGH CONFIDENCE)

Signature 2: XORDeobfuscator
  Pattern: 0x33 0xC9 0xEB  (xor ecx,ecx; jmp)
  Confidence: 0.75
  Reason: Common x86 deobfuscation setup
  Example Match:
    Payload contains: [...0x33 0xC9 0xEB...]
    Match type: EXACT
    Result score: 0.75 × 1.0 = 0.75

Signature 3: SQLInjectionUNION
  Pattern: "UNION SELECT" (case-insensitive search)
  Confidence: 0.90
  Reason: Classic SQL injection attack pattern
  Example Match:
    HTTP GET: "/api?query=1'+UNION+SELECT+username+FROM+users"
    Match type: FUZZY (case converted)
    Result score: 0.90 × 0.6 = 0.54

Signature 4: PHPWebShell
  Pattern: "<?php system" (PHP code execution)
  Confidence: 0.95
  Reason: Web shell indicator in file uploads/HTTP responses
  Example Match:
    File upload payload: "<?php system($_GET['cmd']); ?>"
    Match type: EXACT
    Result score: 0.95 × 1.0 = 0.95 (VERY HIGH CONFIDENCE)


CONFIDENCE SCORING FORMULA:

For each signature tested:
  
  IF exact_match_found:
    confidence_score = signature.confidence × 1.0
  
  ELSE IF fuzzy_match_found (1-byte difference):
    confidence_score = signature.confidence × 0.6
  
  ELSE:
    confidence_score = 0.0

Final Alert Score:
  alert_score = Σ(all confidence_scores) / num_signatures_tested
  
  IF alert_score > 0.50:
    ALERT = True
  ELSE:
    ALERT = False


EXAMPLE CATEGORIZATION SCENARIOS:

Scenario A: Single Exact Match
───────────────────────────────
Payload: HTTP POST data with embedded PHP webshell
Content: "<?php system('whoami'); ?>"

Testing 4 signatures:
  1. ShellcodeNOPSled: NO match → 0.0
  2. XORDeobfuscator: NO match → 0.0
  3. SQLInjectionUNION: NO match → 0.0
  4. PHPWebShell: EXACT match → 0.95 × 1.0 = 0.95

alert_score = (0.0 + 0.0 + 0.0 + 0.95) / 4 = 0.2375
Result: Less than 0.50, NO ALERT

WAIT! But payload_analysis.detect() returns:
  - match_count = 1
  - combined_confidence = 0.95
  - is_alert = (0.95 > 0.50) = TRUE (Alert if confidence > 0.50!)

Actually, looking at code more carefully:
  normalized_confidence = combined_confidence / num_sigs
                        = 0.95 / 4 = 0.2375
  is_alert = (0.2375 > 0.50) = FALSE

BUT the match was detected:
  signature_matches = [{"signature_name": "PHPWebShell", ...}]
  match_count = 1

So categorization is DUAL:
  1. By match detection: MALWARE/WEBSHELL DETECTED
  2. By confidence score: BELOW ALERT THRESHOLD (but still recorded)


Scenario B: Multiple Weak Signals
──────────────────────────────────
Payload: Suspicious binary file in HTTP response

Testing 4 signatures:
  1. ShellcodeNOPSled: EXACT match → 0.85 × 1.0 = 0.85
  2. XORDeobfuscator: FUZZY match (1 byte diff) → 0.75 × 0.6 = 0.45
  3. SQLInjectionUNION: NO match → 0.0
  4. PHPWebShell: NO match → 0.0

alert_score = (0.85 + 0.45 + 0.0 + 0.0) / 4 = 0.3250
Result: Less than 0.50, NO ALERT

Categorization:
  - Signature matches: 2 detected (NOP sled + XOR setup)
  - Threat level: ELEVATED (2 malware indicators)
  - Confidence: MEDIUM (multiple weak signals)
  - Action: FLAG FOR REVIEW (not auto-alert but human inspection)


Scenario C: Escalation via Context
───────────────────────────────────
Same payload as Scenario B, but now:
  - Source IP is on blacklist
  - It's during known DDoS event
  - Protocol anomaly detected (port mismatch)

Enhanced alert:
  alert_score_base = 0.3250
  context_bonus = +0.35 (blacklist 0.15 + DDoS 0.2)
  alert_score_adjusted = 0.3250 + 0.35 = 0.675
  
Result: 0.675 > 0.50, ALERT ESCALATED


================================================================================
LAYER 3: PROTOCOL-BASED CATEGORIZATION
================================================================================

PURPOSE:
  Classify payloads based on expected protocol characteristics
  Detect protocol violations and anomalies

METHODOLOGY:
  Maintain per-protocol/port expectations
  Check if actual payload matches expected characteristics

PROTOCOL EXPECTATIONS TABLE:

Protocol  Port  Expected Entropy  Min      Max      Violation Check
─────────────────────────────────────────────────────────────────────
TCP       80    4-5 (HTTP)        4.0      5.5      > 7.5 = ANOMALY
TCP       443   4.5-6.5 (HTTPS)   4.5      6.5      > 7.9 = ANOMALY
UDP       53    4-5 (DNS)         4.0      5.0      > 6.5 = ANOMALY
TCP       22    5-7 (SSH)         5.0      7.0      > 7.8 = ANOMALY
UDP       123   3.5-5.5 (NTP)     3.5      5.5      > 6.5 = ANOMALY
TCP       25    4-5.5 (SMTP)      4.0      5.5      > 7.0 = ANOMALY


CATEGORIZATION BY PROTOCOL ANOMALY:

Category 1: Normal Traffic
  Payload entropy within expected range for protocol
  Example: HTTP/80 with entropy 4.3 bits/byte
  Verdict: BENIGN

Category 2: Protocol Violation - High Entropy
  Payload entropy exceeds maximum for protocol
  Example: DNS/53 with entropy 7.8 bits/byte
  Possible Causes:
    - Data tunneling (exfiltration)
    - DNS-over-encryption attempts
    - DNS amplification attack
  Verdict: ANOMALY DETECTED (potential DNS tunneling)

Category 3: Protocol Violation - Low Entropy
  Payload entropy below minimum (rare)
  Example: SSH/22 with entropy 2.1 bits/byte
  Possible Causes:
    - Highly compressed payload
    - SSH tunnel with low-entropy data
    - Login credentials (mostly ASCII)
  Verdict: SUSPICIOUS (investigate manual protocol inspection)

Category 4: Port Mismatch - Protocol Detection
  Port doesn't match detected protocol
  Example: HTTP protocol headers on port 3306 (MySQL)
  Verdict: ANOMALY DETECTED (possible confusion/redirection attack)


REAL-WORLD EXAMPLE: DNS TUNNELING

Normal DNS Query:
  Port: 53/UDP
  Payload: Domain name "www.example.com"
  Binary: [0x77, 0x77, 0x77, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, ...]
  Entropy: ~4.2 bits/byte (ASCII characters)
  Verdict: NORMAL

Tunneling Attempt (DNS over encrypted channel):
  Port: 53/UDP
  Payload: Encrypted tunnel data [0x7F, 0x3A, 0xE2, 0x91, 0x24, 0x5B, ...]
  Entropy: ~7.9 bits/byte (encrypted)
  Expected for port 53: 4.0-5.0
  Anomaly score: (7.9 - 5.0) / 8.0 = 0.3625
  Threshold: 0.30
  Verdict: ANOMALY DETECTED → "DNS TUNNELING ATTEMPT"


================================================================================
LAYER 4: STRUCTURAL/PATTERN CATEGORIZATION
================================================================================

PURPOSE:
  Identify payload structure anomalies (fragmentation, gaps, overlaps)
  Detect evasion techniques

CHECKPOINTS:

Check 1: Fragmentation Pattern Analysis
  Normal: Packets arrive in order (frag 0-1000, 1000-2000, 2000-3000)
  Anomalous:
    - Overlapping fragments (0-1000, 500-1500) → overlap detected
    - Gap fragments (0-1000, 2000-3000) → 500-byte gap
    - Out-of-order (2000-3000, 0-1000) → reordering
  
  Anomaly score = (num_overlaps + num_gaps + num_reorders) / total_fragments
  Threshold: 0.3 (30% anomaly tolerance)
  
  If score > 0.3: FRAGMENTATION EVASION ATTEMPT


Check 2: Size Anomalies
  Normal: Consistent payload sizes for protocol
  Example HTTP headers: 100-500 bytes
  Example DNS queries: 50-200 bytes
  
  If payload > 3× normal size: LARGE PAYLOAD ANOMALY
  If payload < 10% normal size: TINY PAYLOAD ANOMALY


Check 3: Byte Patterns
  Check for suspicious patterns:
    - NOP sleds: 0x90 repeated 4+ times
    - INT3 breaks: 0xCC repeated
    - Padding patterns: 0xFF, 0x00 aligned blocks


Check 4: Header Consistency
  For TCP: Check SYN/ACK/FIN sequence validity
  For UDP: Check necessary fields present
  For ICMP: Check type/code consistency


================================================================================
LAYER 5: CONTEXT-AWARE CATEGORIZATION
================================================================================

PURPOSE:
  Apply Bayesian probability to adjust categorization based on context

CONTEXT FACTORS:

1. Source IP Reputation
   - Known blacklist: -0.2 (lower threshold for alerts)
   - Known whitelist: +0.2 (higher threshold required)
   - Unknown: 0.0 (neutral)

2. Time-of-Day Context
   - Business hours (9-17): Expected high traffic
   - Night hours (22-6): Any traffic more suspicious
   - Adjustment: ±0.1 based on expected volume

3. Recent Activity Pattern
   - DDoS event detected: -0.15 (aggressive detection)
   - Normal period: 0.0 (standard detection)
   - Maintenance window: +0.25 (lenient detection)

4. Protocol History
   - Protocol violating in past: -0.1 (suspicious history)
   - Clean history: 0.0 (standard)

5. Geo-location
   - Traffic from unexpected region: -0.15
   - Expected region: 0.0


BAYESIAN CATEGORIZATION FORMULA:

adjusted_threshold = base_threshold × (1.0 - Σ(context_adjustments) × sensitivity)

Example 1: Normal Traffic During Business Hours
──────────────────────────────────────────────────
  Payload: HTTP/80, entropy 5.2 bits/byte
  Base threshold: 7.5
  Context adjustments: 0.0 (unknown IP, normal time)
  adjusted_threshold = 7.5 × (1.0 - 0.0) = 7.5
  5.2 < 7.5 → NO ALERT

Example 2: Same Payload During Detected DDoS
───────────────────────────────────────────────
  Same payload but now:
  Context adjustments: -0.15 (DDoS active, aggressive posture)
  adjusted_threshold = 7.5 × (1.0 - 0.15 × 0.5) = 7.5 × 0.925 = 6.94
  5.2 < 6.94 → Still NO ALERT (but more suspicious)

Example 3: Suspicious Payload + Blacklist IP + DDoS Time
──────────────────────────────────────────────────────────
  Payload: HTTP/80, entropy 6.8 bits/byte
  Base threshold: 7.5
  Context adjustments:
    - Blacklist IP: -0.2
    - DDoS event: -0.15
    - Total: -0.35
  adjusted_threshold = 7.5 × (1.0 - 0.35 × 0.5) = 7.5 × 0.825 = 6.19
  6.8 > 6.19 → ALERT ESCALATED


================================================================================
SECTION 2: THE COMPLETE CATEGORIZATION PIPELINE
================================================================================

When a payload arrives, it goes through ALL 5 layers:

STEP 1: ENTROPY ANALYSIS
  Calculate H(X)
  Determine entropy_category (LOW, MODERATE, HIGH)
  Check against protocol expectations
  
STEP 2: SIGNATURE MATCHING
  Search for known attack patterns
  Calculate confidence_score
  Determine signature_category

STEP 3: PROTOCOL VALIDATION
  Check (protocol, port) expectations
  Detect protocol violations
  Score anomaly_level

STEP 4: STRUCTURAL ANALYSIS
  Check fragmentation patterns
  Check size anomalies
  Check byte patterns

STEP 5: CONTEXT ADJUSTMENT
  Apply Bayesian adjustments
  Adjust thresholds based on context
  Final threat_category determination

FINAL CATEGORIZATION:
  Category = {
    "entropy_level": "HIGH" | "MODERATE" | "LOW",
    "is_signature_match": True | False,
    "signatures_found": [list of matched patterns],
    "protocol_status": "NORMAL" | "ANOMALY" | "VIOLATION",
    "structural_issues": [list of anomalies],
    "threat_category": "BENIGN" | "SUSPICIOUS" | "THREAT" | "CRITICAL",
    "confidence": 0.0-1.0,
    "recommended_action": "ALLOW" | "REVIEW" | "ALERT" | "BLOCK",
  }


================================================================================
SECTION 3: PRACTICAL CATEGORIZATION EXAMPLES
================================================================================

EXAMPLE 1: Normal HTTP GET Request
──────────────────────────────────
Payload: GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n

Layer 1 - Entropy:
  H = 4.2 bits/byte
  Category: MODERATE
  Status: NORMAL (4.0-5.5 expected for HTTP/80)

Layer 2 - Signatures:
  No malware signatures found
  signature_category: CLEAN

Layer 3 - Protocol:
  Port: 80, Protocol: TCP, Expected entropy: 4.0-5.5
  Actual: 4.2
  Status: COMPLIANT

Layer 4 - Structure:
  No fragmentation, single packet ~50 bytes
  Status: NORMAL

Layer 5 - Context:
  Source IP: 192.168.1.100 (internal)
  Time: 09:30 (business hours)
  adjustments: 0.0
  
FINAL CATEGORIZATION:
  {
    "entropy_level": "MODERATE",
    "is_signature_match": False,
    "protocol_status": "NORMAL",
    "threat_category": "BENIGN",
    "confidence": 0.99,
    "recommended_action": "ALLOW"
  }


EXAMPLE 2: Malicious PHP Upload
────────────────────────────────
Payload: [Binary file upload] -> "<?php system($_POST['cmd']); ?>"

Layer 1 - Entropy:
  H = 4.8 bits/byte
  Category: MODERATE
  Status: NORMAL (within expected)

Layer 2 - Signatures:
  MATCH FOUND: PHPWebShell
  confidence: 0.95 × 1.0 = 0.95
  signature_category: MALWARE/WEBSHELL

Layer 3 - Protocol:
  Port: 80, Protocol: TCP
  Status: COMPLIANT (but content violation)

Layer 4 - Structure:
  Size: 45 bytes (small for upload)
  Suspicion: Deliberately small to bypass filters
  Status: EVASION ATTEMPT

Layer 5 - Context:
  Source IP: 203.45.67.89 (external)
  File upload unusual for internal network
  adjustments: -0.2 (unusual pattern)

FINAL CATEGORIZATION:
  {
    "entropy_level": "MODERATE",
    "is_signature_match": True,
    "signatures_found": ["PHPWebShell"],
    "protocol_status": "NORMAL",
    "structural_issues": ["suspicious_small_payload"],
    "threat_category": "CRITICAL",
    "confidence": 0.95,
    "recommended_action": "BLOCK"
  }


EXAMPLE 3: DNS Tunneling Attempt
────────────────────────────────
Payload: [Random encrypted data on port 53/UDP]

Layer 1 - Entropy:
  H = 7.8 bits/byte
  Category: HIGH (almost maximum)
  Status: ANOMALY (expected 4.0-5.0 for DNS)

Layer 2 - Signatures:
  No direct malware signatures
  But: High entropy after NOP sled-like patterns detected
  signature_category: POTENTIALLY MALICIOUS

Layer 3 - Protocol:
  Port: 53, Protocol: UDP, Expected entropy: 4.0-5.0
  Actual: 7.8
  Anomaly score: (7.8 - 5.0) / 8.0 = 0.3625
  Threshold: 0.30
  Status: PROTOCOL VIOLATION (data tunneling suspected)

Layer 4 - Structure:
  Packet size: 256 bytes (unusual for DNS query, normal for tunnel)
  Status: ABNORMAL SIZE FOR PROTOCOL

Layer 5 - Context:
  Source IP: 10.0.0.5 (internal, but suspicious destination 8.8.8.8)
  Time: 23:45 (outside business hours)
  DDoS event detected elsewhere
  adjustments: -0.25 (night time + event + external destination)

FINAL CATEGORIZATION:
  {
    "entropy_level": "HIGH",
    "is_signature_match": False,
    "protocol_status": "VIOLATION",
    "structural_issues": ["abnormal_size_for_dns", "high_entropy_for_udp53"],
    "threat_category": "THREAT",
    "confidence": 0.85,
    "reason": "DNS_TUNNELING_ATTEMPT",
    "recommended_action": "ALERT"
  }


================================================================================
QUICK REFERENCE TABLE
================================================================================

Categorization Method    | Input           | Output Categories
────────────────────────┼─────────────────┼─────────────────────────
Entropy                 | Payload bytes   | LOW, MODERATE, HIGH
Signed                  | Payload bytes   | CLEAN, SUSPICIOUS, MALWARE
Protocol                | Port + entropy  | NORMAL, ANOMALY, VIOLATION
Structure               | Packet layout   | NORMAL, FRAGMENTED, EVASION
Context                 | IP, time, event | BENIGN, SUSPICIOUS, THREAT

Final Threat Category   | Input           | Output
────────────────────────┼─────────────────┼────────────────────────
Composite               | All 5 layers    | BENIGN, SUSPICIOUS, THREAT, CRITICAL


================================================================================
END OF PAYLOAD CATEGORIZATION GUIDE
================================================================================

For implementation details, see:
  - advanced_payload_detection.py: analyze_payload(), detect_signatures()
  - integration_adapter.py: AlertEscalator.escalate_alert()
  - ADVANCED_PAYLOAD_DETECTION_GUIDE.md: Algorithm descriptions
