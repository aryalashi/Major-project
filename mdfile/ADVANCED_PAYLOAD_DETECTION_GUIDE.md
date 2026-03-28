"""
ADVANCED PAYLOAD DETECTION - INTEGRATION GUIDE & FORMULA REFERENCE
===================================================================

This document explains:
  1. How to integrate advanced_payload_detection.py with existing NIDS
  2. Complete formula reference with worked examples
  3. Threshold tuning guidance
  4. Real-world deployment scenarios

================================================================================
SECTION 1: INTEGRATION ARCHITECTURE
================================================================================

Existing NIDS Flow (detection.py):
─────────────────────────────────
Raw Packet
    ↓
[normalization.py]  → Canonical packet dict
    ↓
[detection.py]      → Signature rule evaluation
    ↓
Alert (if rule matched)


Proposed Flow (with advanced_payload_detection.py):
────────────────────────────────────────────────────
Raw Packet
    ↓
[normalization.py]  → Canonical packet dict with payload
    ↓
[detection.py]      → Signature rule evaluation
    ↓
[advanced_payload_detection.py]  → Payload analysis
    ├─ EntropyAnalyzer          (obfuscation detection)
    ├─ SignatureDetector        (malware patterns)
    ├─ ProtocolAnomalyDetector  (unusual combinations)
    └─ AdaptiveThresholdManager (threshold adjustment)
    ↓
ESCALATED Alert (if payload analysis confirms threat)


Integration Example in main.py:
────────────────────────────────

    from detection import DetectionEngine
    from advanced_payload_detection import (
        AdvancedPayloadDetector, integrate_advanced_detection
    )
    
    # Initialize both engines
    base_engine = DetectionEngine(rules)
    advanced_detector = AdvancedPayloadDetector(entropy_threshold=7.0)
    
    # Create enhanced processor
    process_packet = integrate_advanced_detection(base_engine, advanced_detector)
    
    # Use in packet loop
    def process_capture(pkt):
        normalized = normalize_packet(pkt)
        if normalized:
            # Extract payload
            normalized["payload"] = extract_payload(pkt)
            
            # Process with both engines
            alerts = process_packet(normalized)
            
            # Handle alerts
            for alert in alerts:
                handle_alert(alert)


================================================================================
SECTION 2: ENTROPY ANALYSIS - COMPLETE FORMULA REFERENCE
================================================================================

SHANNON ENTROPY FORMULA
───────────────────────
H(X) = -Σ(i=0 to 255) p(i) × log₂(p(i))

Where:
  p(i) = (count of byte value i) / (total payload length)
  Sum over all 256 possible byte values
  log₂() = logarithm base 2

Example #1: HTTP GET Request
─────────────────────────────
Payload: "GET /index.html HTTP/1.1\r\n"
Length: 28 bytes

Character frequencies:
  'G':  1 → p(G) = 1/28 ≈ 0.0357
  'E':  2 → p(E) = 2/28 ≈ 0.0714
  'T':  2 → p(T) = 2/28 ≈ 0.0714
  ' ':  3 → p( ) = 3/28 ≈ 0.107
  '/':  2 → p(/) = 2/28 ≈ 0.0714
  'i':  1 → p(i) = 1/28 ≈ 0.0357
  'n':  1 → p(n) = 1/28 ≈ 0.0357
  'd':  1 → p(d) = 1/28 ≈ 0.0357
  'e':  2 → p(e) = 2/28 ≈ 0.0714
  'x':  1 → p(x) = 1/28 ≈ 0.0357
  'h':  1 → p(h) = 1/28 ≈ 0.0357
  't':  1 → p(t) = 1/28 ≈ 0.0357
  'l':  1 → p(l) = 1/28 ≈ 0.0357
  'H':  1 → p(H) = 1/28 ≈ 0.0357
  'P':  1 → p(P) = 1/28 ≈ 0.0357
  '1':  1 → p(1) = 1/28 ≈ 0.0357
  '.':  1 → p(.) = 1/28 ≈ 0.0357
  '\r': 1 → p(\r) = 1/28 ≈ 0.0357
  '\n': 1 → p(\n) = 1/28 ≈ 0.0357

H = -[1 × (0.0357 × log₂(0.0357)) 
    + 2 × (0.0714 × log₂(0.0714))
    + 3 × (0.107 × log₂(0.107))
    + ... for all 19 unique bytes]

H ≈ 4.2 bits/byte (moderate entropy - expected for ASCII HTTP)


Example #2: All Identical Bytes
────────────────────────────────
Payload: "\x00" × 100 (100 null bytes)

Character frequencies:
  '\x00': 100 → p(0) = 100/100 = 1.0
  All others: 0 → p(i) = 0 for i ≠ 0

H = -[1.0 × log₂(1.0)] = -[1.0 × 0] = 0 bits/byte

(Minimum entropy - completely predictable)


Example #3: Encrypted/Random Data
──────────────────────────────────
Payload: 256 random bytes with uniform distribution

Character frequencies:
  Each byte value appears ~1 time → p(i) ≈ 1/256 ≈ 0.00391 for all i

H = -[256 × (0.00391 × log₂(0.00391))]
  = -[256 × (0.00391 × -8.0)]
  = 256 × 0.03125
  = 8.0 bits/byte

(Maximum entropy - completely random/encrypted)


ENTROPY ANOMALY DETECTION THRESHOLD
────────────────────────────────────

Protocol      Expected Range   Alert if >   Intuition
─────────────────────────────────────────────────────
HTTP          4-5 bits/byte    7.5          Binary/encrypted content in text protocol
DNS           4-5 bits/byte    6.5          Domain names are ASCII
SMTP          4-5 bits/byte    7.0          Email should be mostly readable
SSH           6-7 bits/byte    7.8          Encrypted by design
FTP           4-5 bits/byte    6.5          Commands + data transfer
HTTPS         6.5-7 bits/byte  7.9 (high)   Encrypted, expect high entropy
Binary Proto  6.5-7 bits/byte  7.95         Protocol overhead often compresses


Example Threshold Tuning:
─────────────────────────

Case 1: HTTP on port 80
  - Baseline: 4.2 bits/byte (HTTP headers + moderate payload)
  - Threshold: 7.5
  - Incident: Payload has entropy 7.9
  - Decision: ALERT (likely encrypted binary in HTTP)
  - Action: Quarantine, inspect for tunneling

Case 2: HTTPS on port 443  
  - Baseline: 7.1 bits/byte (high due to encryption)
  - Threshold: 7.9
  - Incident: Payload has entropy 7.5
  - Decision: NO ALERT (normal for encrypted protocol)
  - Action: Continue monitoring

Case 3: DNS on port 53 (Abnormal)
  - Baseline: 4.8 bits/byte (domain names, ASCII)
  - Threshold: 6.5
  - Incident: Payload has entropy 7.8
  - Decision: ALERT (likely data tunneling)
  - Action: Inspect for DNS exfiltration


================================================================================
SECTION 3: THRESHOLD ADAPTATION FORMULAS & EXAMPLES
================================================================================

ALGORITHM A: EWMA (Exponential Weighted Moving Average)
════════════════════════════════════════════════════════

Formula:
  baseline(t) = α × rate(t) + (1 - α) × baseline(t-1)
  
  threshold(t) = max(
                   min_threshold,
                   min(
                     max(base_threshold, baseline(t) × window × headroom),
                     hard_cap
                   )
                 )

Parameters:
  α         = 0.2        (smoothing factor, 0<α<1)
  window    = 10         (detection window in seconds)
  headroom  = 3.0        (multiplier above baseline)
  hard_cap  = 5000       (absolute maximum)
  min_threshold = 3

Use Case: Real-time adaptation to legitimate traffic spikes


Example: DDoS Detection with EWMA
───────────────────────────────────

Scenario: Multi-day network monitoring
Time granularity: Every 10 seconds

Day 1 - Morning (8 AM, Low traffic):
  t=0 (08:00:00): observed_rate = 1.0 pkt/s
    baseline(0) = 0.2 × 1.0 + 0.8 × ∞ = 1.0 pkt/s (initialization)
    threshold(0) = max(3, min(15, max(15, 1.0 × 10 × 3)))
                 = max(3, min(15, max(15, 30)))
                 = max(3, 15) = 15 packets/10s
  
  t=1 (08:00:10): observed_rate = 1.2 pkt/s
    baseline(1) = 0.2 × 1.2 + 0.8 × 1.0 = 0.24 + 0.80 = 1.04 pkt/s
    threshold(1) = min(15, max(15, 1.04 × 10 × 3.0))
                 = min(15, max(15, 31.2))
                 = 15 (capped at base)

[Continue for several iterations...]

Day 1 - Evening (6 PM, Peak traffic):
  observed_rate = 5.0 pkt/s (increase during business hours)
  baseline(n) = 0.2 × 5.0 + 0.8 × 3.5 = 1.0 + 2.8 = 3.8 pkt/s
  threshold(n) = min(15, max(15, 3.8 × 10 × 3))
               = min(15, max(15, 114))
               = 15 (still capped)

[After many iterations, baseline stabilizes...]

Day 2 - Evening (6 PM, Attack begins):
  Previous baseline = 4.5 pkt/s (learned from Day 1)
  Previous threshold = 15 (base minimum)
  
  Attack sends rate = 180 pkt/s (40x normal)
  baseline(t) = 0.2 × 180 + 0.8 × 4.5 = 36 + 3.6 = 39.6 pkt/s
  threshold(t) = min(15×6, max(15, 39.6 × 10 × 3.0))
               = min(90, max(15, 1188))
               = min(90, 1188)
               = 90 packets/10s

Attack rate = 180 > threshold 90? YES → ALERT!

Subsequent windows build up baseline gradually:
  threshold(t+1) = ... 85, 80, 75, ... (gradually decreases as sustained high rate becomes baseline)
  After 5 samples: baseline ≈ 120, threshold ≈ 80
  Attack continues at 180 > 80 → ALERT every window

Benefits:
  ✓ Auto-recovers from temporary spikes
  ✓ Adapts to legitimate traffic increases
  ✓ Exponential decay favors recent trends
  ✗ May lag behind sudden attacks


ALGORITHM B: MAD (Median Absolute Deviation)
═════════════════════════════════════════════

Formula:
  Median = middle value of sorted dataset
  MAD = median(|x_i - median(x)|) for all observations
  threshold = median + k × MAD

Parameters:
  k = 2.5  (confidence scale, typically 2.5 for 99% detection)

Use Case: Robustness against outliers; doesn't assume normal distribution
Breakdown point: 50% (tolerates 50% corrupted data)


Example: Port Scan Detection with MAD
──────────────────────────────────────

Scenario: Normal port scans per 10-second window

Baseline observations (legitimate traffic):
  [8, 7, 9, 8, 6, 7, 8, 9, 7, 8, 1000]

Note: The 1000 is an outlier from a previous attack.

Step 1: Sort observations
  [6, 7, 7, 7, 8, 8, 8, 8, 9, 9, 1000]

Step 2: Calculate median
  Median = 8 (middle value of 11 items)

Step 3: Calculate deviations from median
  Deviations:
    |6-8|=2, |7-8|=1, |7-8|=1, |7-8|=1, |8-8|=0,
    |8-8|=0, |8-8|=0, |8-8|=0, |9-8|=1, |9-8|=1, |1000-8|=992
  
  Sorted deviations: [0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 992]

Step 4: Calculate MAD
  MAD = median of deviations = 1

Step 5: Compute threshold
  threshold = 8 + 2.5 × 1 = 10.5 ≈ 11 scans/10s

Detection:
  - Normal traffic (6-9 scans): < 11 → NO ALERT ✓
  - Increased traffic (10 scans): < 11 → NO ALERT ✓
  - Attack (15 scans): > 11 → ALERT ✓
  - Old outlier (1000): Doesn't affect calculation ✓

Comparison with Standard Deviation:
  std_dev = sqrt(Σ(x-mean)²/N)
          = sqrt((2² + 1² + 1² + 1² + 0² + ... + 992²)/11)
          = sqrt(89520/11) ≈ 90.3
  
  threshold_std = mean + 3×std = 82.5 + 3×90.3 = 353
  
  This is WAY too high! The outlier 1000 inflates std deviation.
  
  Result: MAD threshold (11) is much more accurate than std (353)


ALGORITHM C: Z-Score Adaptive Thresholding
═══════════════════════════════════════════

Formula:
  Mean(x)   = (1/N) × Σ(x_i)
  Variance  = (1/N) × Σ(x_i - mean)²
  StdDev    = √Variance
  threshold = mean + z × StdDev

Parameters:
  z = standard deviation multiplier
      z=1.0  → 68% normal traffic below (32% false positives)
      z=1.96 → 95% normal traffic below (5% false positives)
      z=2.33 → 99% normal traffic below (1% false positive)
      z=3.0  → 99.7% normal traffic below (0.3% false positives)

Use Case: Standard statistical approach; assumes normal distribution
Caveat: Sensitive to outliers (not recommended if outliers expected)


Example: Tuning FP Rate for HTTP Flood
───────────────────────────────────────

Baseline observations (legitimate HTTP requests per 10s):
  [100, 102, 98, 101, 99, 102, 100, 99, 101, 100]

Step 1: Calculate mean
  mean = (100+102+98+101+99+102+100+99+101+100) / 10 = 1000 / 10 = 100

Step 2: Calculate variance
  deviations² = [0, 4, 4, 1, 1, 4, 0, 1, 1, 0]
  variance = 16 / 10 = 1.6

Step 3: Calculate std deviation
  std_dev = √1.6 ≈ 1.26

Step 4: Choose z based on acceptable FP rate
  - For 5% FP rate: z = 1.96
    threshold = 100 + 1.96×1.26 ≈ 102.5
    → 102.5 requests/10s
    
    Traffic 102 → < 102.5 → NO ALERT
    Traffic 103 → > 102.5 → ALERT
  
  - For 1% FP rate: z = 2.33
    threshold = 100 + 2.33×1.26 ≈ 103
    → 103 requests/10s
    
    More conservative, fewer false positives
  
  - For 0.3% FP rate: z = 3.0
    threshold = 100 + 3.0×1.26 ≈ 104
    → 104 requests/10s
    
    Most conservative, best for minimal alerts

Guidelines for Choosing z:
  Network Type          Acceptable FP Rate    Recommended z
  ─────────────────────────────────────────────────────────
  Enterprise (low toler) 0.3-1%              2.33-3.0
  Cloud (moderate)       1-5%                1.96-2.33
  ISP/Carrier            5-10%               1.64-1.96  
  Lab/Testing            10%+                1.0-1.64


ALGORITHM D: Bayesian Threshold Adaptation
═══════════════════════════════════════════

Formula:
  P(A|obs) = [P(obs|A) × P(A)] / [P(obs|A)×P(A) + P(obs|¬A)×P(¬A)]
  
  Where:
    P(A|obs)      = posterior probability of attack given observation
    P(obs|A)      = likelihood of observation if attack
    P(obs|¬A)     = likelihood of observation if normal
    P(A)          = prior probability of attack (base rate)
  
  threshold_adjusted = base_threshold × (1.0 - P(A|obs) × sensitivity)

Parameters:
  P(A)        = prior attack probability (e.g., 0.01 for 1% baseline)
  sensitivity = 0.5 to 1.0 (how much posterior affects threshold)

Use Case: Incorporating domain knowledge; context-aware detection


Example: DDoS in High-Risk vs Low-Risk Times
──────────────────────────────────────────────

Scenario 1: Normal Tuesday Afternoon
────────────────────────────────────
Context: Routine operations, no known threats
  Prior: P(attack) = 0.001 (0.1% baseline)
  Base threshold = 100 pkt/10s
  
Observation: 80 packets/10s in monitored window

Likelihoods (from historical data):
  P(80 pkt|attack) = 0.05    (unlikely under attack → few high attacks at 80 pkt)
  P(80 pkt|normal) = 0.90    (likely under normal → reasonable traffic)
  
Posterior calculation:
  P(attack|80) = (0.05 × 0.001) / (0.05×0.001 + 0.90×0.999)
               = 0.00005 / (0.00005 + 0.8991)
               = 0.00005 / 0.8991
               ≈ 0.000056 (0.0056% posterior)

Adjusted threshold:
  threshold_adjusted = 100 × (1.0 - 0.000056 × 0.5)
                     ≈ 100.0 (no change in practice)

Decision: 80 pkt < 100 → Continue normal monitoring


Scenario 2: Known Botnet Campaign Active
─────────────────────────────────────────
Context: IDS detected botnet probing this network
  Prior: P(attack) = 0.50 (50% elevated threat)
  Base threshold = 100 pkt/10s
  
Same observation: 80 packets/10s

Posterior calculation (with higher prior):
  P(attack|80) = (0.05 × 0.50) / (0.05×0.50 + 0.90×0.50)
               = 0.025 / (0.025 + 0.45)
               = 0.025 / 0.475
               ≈ 0.053 (5.3% posterior)

Adjusted threshold:
  threshold_adjusted = 100 × (1.0 - 0.053 × 0.5)
                     = 100 × (1.0 - 0.0265)
                     = 100 × 0.9735
                     ≈ 97.35

Decision: 80 pkt < 97.35 → Wait for more evidence (lower threshold)
          But still not aggressive enough for automated defense.

Scenario 3: Active DDoS Attack Under Way
─────────────────────────────────────────
Context: Real-time attack detected, defensive posture
  Prior: P(attack) = 0.99 (99% likelihood of ongoing attack)
  Base threshold = 100 pkt/10s
  
Same observation: 80 packets/10s

Posterior calculation (with very high prior):
  P(attack|80) = (0.05 × 0.99) / (0.05×0.99 + 0.90×0.01)
               = 0.0495 / (0.0495 + 0.009)
               = 0.0495 / 0.0585
               ≈ 0.846 (84.6% posterior)

Adjusted threshold:
  threshold_adjusted = 100 × (1.0 - 0.846 × 0.5)
                     = 100 × (1.0 - 0.423)
                     = 100 × 0.577
                     ≈ 57.7

Decision: 80 pkt > 57.7 → ALERT! Escalate defenses!

Key Insight:
  Same observation (80 pkt) produces different decisions based on context:
    - Normal time: 80 < 100 → Continue monitoring
    - Elevated threat: 80 < 97 → Wait
    - Active attack: 80 > 58 → Escalate defense!


================================================================================
SECTION 4: INTEGRATION PATTERNS & BEST PRACTICES
================================================================================

Pattern #1: Chained Detection
──────────────────────────────

    def handle_packet(normalized_pkt):
        # Layer 1: Base signature rules
        base_alerts = base_detection_engine.process_packet(normalized_pkt)
        
        if base_alerts:
            # Layer 2: Payload-level confirmation
            for alert in base_alerts:
                payload_analysis = advanced_detector.detect(
                    normalized_pkt, 
                    alert["rule_name"],
                    normalized_pkt.get("payload")
                )
                
                if payload_analysis["is_threat"]:
                    # Escalate alert certainty
                    alert["confidence"] = "HIGH"
                    alert["analysis"] = payload_analysis
                    send_alert(alert)
                else:
                    # Potential false positive
                    alert["confidence"] = "LOW"
                    log_silently(alert)


Pattern #2: Adaptive Learning
──────────────────────────────

    class AdaptiveNIDS:
        def __init__(self):
            self.threshold_manager = AdaptiveThresholdManager()
            self.baseline_learner = BaselineTracker()
            self.algorithm = "EWMA"  # Start with EWMA
        
        def update_algorithm(self):
            # After collecting baslines, evaluate which algorithm fits best
            if self.baseline_learner.has_outliers():
                self.algorithm = "MAD"  # Robust to outliers
            elif self.baseline_learner.is_gaussian():
                self.algorithm = "ZSCORE"  # Assuming normal distribution
        
        def process_packet(self, pkt):
            # Get context
            context = self.baseline_learner.get_context(pkt)  # Time of day, day of week, etc.
            
            # Adjust threshold based on context
            threshold = self.threshold_manager.compute_threshold(
                rule_name=pkt["rule"],
                base_threshold=pkt["base_threshold"],
                recent_rates=context.rates,
                algorithm=self.algorithm
            )
            
            # Evaluate with adaptive threshold
            if pkt["rate"] > threshold:
                return self.create_alert(pkt, threshold, context)

Pattern #3: Multi-Algorithm Consensus
──────────────────────────────────────

    def consensus_alert(normalized_pkt, base_threshold):
        # Compute threshold using all algorithms
        results = {}
        for algo in ["EWMA", "MAD", "ZSCORE", "BAYESIAN"]:
            threshold, meta = threshold_manager.compute_threshold(
                "TEST_RULE",
                base_threshold,
                recent_rates,
                algo
            )
            results[algo] = {"threshold": threshold, "meta": meta}
        
        # Require majority vote
        alert_votes = sum(1 for r in results.values() 
                         if pkt["rate"] > r["threshold"])
        
        if alert_votes >= 3:  # 3 out of 4 algorithms agree
            # Confidence alert
            return {
                "status": "ALERT",
                "confidence": "HIGH",
                "consensus": results,
            }
        elif alert_votes >= 2:
            # Suspicious, needs review
            return {
                "status": "REVIEW_NEEDED",
                "confidence": "MEDIUM",
                "consensus": results,
            }
        else:
            # Likely benign
            return {
                "status": "BENIGN",
                "confidence": "HIGH",
                "consensus": results,
            }


================================================================================
SECTION 5: DEPLOYMENT CHECKLIST
================================================================================

Pre-Deployment Configuration:
☐ Collect 7-14 days of baseline traffic (different times/days)
☐ Calculate initial entropy thresholds per protocol/port
☐ Train Bayesian priors from historical attack data
☐ Calibrate Z-score multiplier based on acceptable FP rate
☐ Load signature database (maintained separately)
☐ Configure protocol expectations (Section 2, tables)
☐ Test on past zero-day samples (if available)
☐ Set up logging for threshold adjustments
☐ Configure alert channels for escalated alerts

Operational Monitoring:
☐ Track false positive rate weekly
☐ Monitor algorithm selection changes
☐ Review baseline shifts (legitimate traffic growth?)
☐ Analyze missed attacks (signature gap or threshold too high?)
☐ Maintain signature update schedule
☐ Periodic threshold recalibration (quarterly)

Performance Metrics:
☐ Mean detection latency < 100ms
☐ Memory usage stable (check tracker cleanup frequency)
☐ CPU usage < 20% peak
☐ Alert correlation rate (% verified as true positive)


================================================================================
END OF INTEGRATION GUIDE
================================================================================
"""

# Save as reference documentation
if __name__ == "__main__":
    print(__doc__)
    
    # Save to file
    with open("ADVANCED_PAYLOAD_DETECTION_GUIDE.md", "w", encoding="utf-8") as f:
        f.write(__doc__)
    
    print("\n✓ Integration guide saved to: ADVANCED_PAYLOAD_DETECTION_GUIDE.md")
