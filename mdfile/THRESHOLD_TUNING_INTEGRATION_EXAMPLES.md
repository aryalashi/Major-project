# AUTOMATIC THRESHOLD TUNING - INTEGRATION & EXAMPLES

================================================================================
HOW THRESHOLDS ARE APPLIED IN THE DETECTION PIPELINE
================================================================================

OVERALL FLOW:

  Packet arrives
       │
       ▼
  Normalize packet (normalization.py)
       │
       ▼
  Base detection engine checks rules (detection.py)
       │
       ├─── No rule match? PASS
       │
       └─── Rule match! Get base threshold
            │
            ▼
       Retrieve recent observations (last 10 measurements)
            │
            ▼
       ADAPTIVE THRESHOLD ALGORITHM
       ├─ EWMA: Smooth trend following
       ├─ MAD: Robust statistical bounds
       ├─ Z-SCORE: Standard deviation based
       └─ BAYESIAN: Context-aware
            │
            ▼
       Compute adjusted_threshold
            │
            ▼
       Compare: current_rate > adjusted_threshold?
            │
            ├─ NO → Log and continue
            │
            └─ YES → Generate ALERT
                     │
                     ▼
                Extract & analyze payload
                     │
                     ▼
                Escalate alert if payload confirms threat
                     │
                     ▼
                Output final alert with metadata


================================================================================
STEP 1: DETECT RULE MATCH
================================================================================

Code location: detection.py (DetectionEngine)

Example Rule: "TCP SYN Flood"
  Pattern: Rapid SYN packets to same destination
  Base threshold: 50 packets/10s

When rule matches:
  ✓ "TCP SYN Flood" detected
  ✓ Base threshold retrieved: 50 pkt/10s
  ✓ Query observation history
  ✓ Next: Compute adaptive threshold


Sample Base Rule (from rules.json):

  {
    "name": "TCP SYN Flood",
    "rule_type": "rate_based",
    "base_threshold": 50,
    "protocol": "TCP",
    "src_ports": "any",
    "dst_ports": [80, 443],
    "flags": ["SYN"],
    "description": "Rapid SYN packets indicate possible SYN flood",
    "detection_window": 10
  }


================================================================================
STEP 2: COLLECT OBSERVATIONS
================================================================================

Code location: advanced_payload_detection.py (AdaptiveThresholdManager)

Observation window: Last 100 measurements (configurable)
Measurement interval: 10 seconds each
Storage: Sliding window deque

Example observation history:

  Time       Observed Rate (pkt/s)  Comment
  ─────────────────────────────────────────
  14:00:00   1.0                   Idle
  14:00:10   1.2                   Idle
  14:00:20   1.1                   Idle
  14:00:30   1.3                   Idle
  14:00:40   1.0                   Idle
  ...
  14:09:10   2.0                   Business hours
  14:09:20   2.1                   Business hours
  14:09:30   2.2                   Business hours
  14:09:40   2.0                   Business hours
  14:09:50   2.1                   Business hours


Current code snippet:

  class AdaptiveThresholdManager:
      def __init__(self, window_size: int = 100):
          self.window_size = window_size
          self.states: Dict[str, ThresholdState] = {}
      
      def _fetch_observations(self, rule_name: str) -> List[float]:
          """Get recent observations for this rule"""
          if rule_name not in self.states:
              return []  # First time seeing this rule
          return list(self.states[rule_name].observations)


================================================================================
STEP 3: CHOOSE ALGORITHM & COMPUTE THRESHOLD
================================================================================

Code location: integration_adapter.py (EnhancedDetectionPipeline)

Selection logic:

  if config.threshold_algorithm == "EWMA":
      algorithm = "EWMA"
  elif config.threshold_algorithm == "MAD":
      algorithm = "MAD"
  elif config.threshold_algorithm == "ZSCORE":
      algorithm = "ZSCORE"
  elif config.threshold_algorithm == "BAYESIAN":
      algorithm = "BAYESIAN"


Usage in pipeline:

  def process(self, packet_dict: dict, raw_packet=None) -> List[dict]:
      # ... rule matching ...
      
      if rule_matches:
          base_threshold = rule.get("base_threshold", 15)
          recent_rates = get_observation_history(rule_name)
          
          # COMPUTE ADAPTIVE THRESHOLD
          adjusted_threshold, metadata = self.advanced_detector.threshold_manager.compute_threshold(
              rule_name=rule_name,
              base_threshold=base_threshold,
              current_observations=recent_rates,
              algorithm=self.config.threshold_algorithm  # ← From config
          )
          
          # Compare
          if current_rate > adjusted_threshold:
              alert = create_alert(...)
              alerts.append(alert)
          
          # Add metadata to alert
          alert["adaptive_threshold"] = adjusted_threshold
          alert["threshold_algorithm"] = self.config.threshold_algorithm
          alert["threshold_metadata"] = metadata


================================================================================
STEP 4: APPLY THRESHOLD & GENERATE ALERT
================================================================================

Example: HTTP Flood Detection with EWMA

Scenario:
  Time: 2:30 PM
  Rule: "HTTP Flood"
  Base threshold: 50 req/10s
  Algorithm: EWMA with α=0.2
  
Recent observations (last 10 windows):
  [12, 11, 13, 12, 11, 12, 13, 11, 12, 10]
  
Calculation:
  
  Step 1: Current rate (last measurement)
    current_rate = 10 req/s (seems normal)
  
  Step 2: EWMA baseline calculation
    baseline_old = mean([12, 11, 13...]) ≈ 11.7
    baseline_new = 0.2 × 10 + 0.8 × 11.7
                 = 2 + 9.36
                 = 11.36 req/s
  
  Step 3: Compute threshold
    headroom = 3.0
    window = 10 seconds
    threshold = 11.36 × 10 × 3.0 = 340.8 ≈ 341 req/10s
  
  Step 4: Apply bounds
    bounded = max(3, min(341, 5000)) = 341
  
  Step 5: Compare
    current_rate (10) < threshold (341)? YES
    ACTION: No alert


Example: HTTP Flood Detection with MAD during attack

Scenario:
  Time: 2:35 PM (attack starts)
  Same rule, now with MAD
  k = 2.5
  
Observations with attack:
  Previous: [12, 11, 13, 12, 11, 12, 13, 11, 12, 10]
  Current: 500 req/s (attack!)
  
Calculation:
  
  Step 1: Median baseline
    sorted = [10, 11, 11, 12, 12, 12, 13, 13, 12, 500]
    median = 12 (middle value, ignores outlier!)
  
  Step 2: Deviations from median
    dev = [2, 1, 1, 0, 0, 0, 1, 1, 0, 488]
  
  Step 3: MAD (median of deviations)
    sorted_dev = [0, 0, 0, 1, 1, 1, 1, 2, 488]
    MAD = 1
  
  Step 4: Compute threshold
    threshold = 12 + 2.5 × 1 = 14.5 ≈ 15 req/10s
  
  Step 5: Apply bounds
    bounded = max(3, min(15, 5000)) = 15
  
  Step 6: Compare
    current_rate (500) > threshold (15)? YES
    ACTION: ALERT!


Example: Z-SCORE with tuned false positive rate

Scenario:
  Different network, target 5% false positive rate
  Algorithm: Z-SCORE with z=2.0
  
Observations:
  [15, 14, 16, 15, 15, 14, 16, 15]
  
Calculation:
  
  Step 1: Mean
    mean = (15+14+16+15+15+14+16+15) / 8 = 120/8 = 15
  
  Step 2: Variance
    deviations² = [0, 1, 1, 0, 0, 1, 1, 0]
    variance = 4/8 = 0.5
  
  Step 3: Standard deviation
    std_dev = sqrt(0.5) ≈ 0.707
  
  Step 4: Compute threshold
    z = 2.0 (for 5% FP rate)
    threshold = 15 + 2.0 × 0.707 = 15 + 1.414 = 16.414 ≈ 16
  
  Step 5: Apply bounds
    bounded = max(3, min(16, 5000)) = 16
  
  Step 6: Compare
    If current_rate = 17: ALERT
    If current_rate = 15: No alert


================================================================================
STEP 5: PAYLOAD ANALYSIS & ALERT ESCALATION
================================================================================

Code location: integration_adapter.py (AlertEscalator)

After threshold triggers alert, advanced payload analysis runs:

Timeline:

  t=0: Rule matches, threshold exceeded
       → Base alert generated
       │
       ▼
  t=1: Extract payload from packet
       │
       ▼
  t=2: Analyze payload (entropy, signatures, protocol)
       │
       ├─ Entropy analysis: 7.8 bits/byte
       ├─ Signatures: 1 match (PHP webshell)
       ├─ Protocol anomaly: None
       │
       ▼
  t=3: Calculate payload threat score
       │
       ▼
  t=4: Escalate alert if payload confirms
       │
       └─ Severity: HIGH → CRITICAL
          Confidence: MEDIUM → HIGH


Example: Escalation in action

Base Alert:
  {
    "rule_name": "HTTP Flood",
    "severity": "HIGH",
    "confidence": "MEDIUM",
    "threshold": 15,
    "observed_rate": 50,
  }

Payload Analysis:
  {
    "entropy": 7.8,           # High entropy suspicious
    "signature_matches": [{
      "name": "PHPWebShell",
      "severity": "CRITICAL"
    }],
    "protocol_anomaly": 0.0,  # None
  }

Escalation Decision:
  - Signature match detected (severity CRITICAL)
  - Payload entropy high (suspicious)
  - Decision: Escalate to CRITICAL
  
Escalated Alert:
  {
    "rule_name": "HTTP Flood",
    "severity": "CRITICAL",      # ESCALATED
    "confidence": "HIGH",         # ESCALATED
    "threshold": 15,
    "observed_rate": 50,
    "escalation_reason": "Payload analysis revealed CRITICAL threat (webshell)",
    "payload_analysis": {...}
  }


================================================================================
REAL-WORLD SCENARIO: DDOS DETECTION OVER TIME
================================================================================

Timeline: March 28, 2026, 2:00 PM - 3:30 PM

Initial Baseline (2:00-2:20 PM):
  Algorithm: EWMA (α=0.2)
  Base threshold: 50 pkt/10s
  
  Observations:
    t=0: 12 pkt/s, threshold = 50 (baseline: 12)
    t=1: 11 pkt/s, threshold = 50 (baseline: 11.8)
    t=2: 13 pkt/s, threshold = 50 (baseline: 12.1)
    t=3: 12 pkt/s, threshold = 50 (baseline: 12.08)


Business Hours Ramp-up (2:20-2:25 PM):
  Traffic increasing (expected for afternoon)
  Observations:
    t=4: 20 pkt/s, threshold = 60 (baseline updated)
    t=5: 18 pkt/s, threshold = 58
    t=6: 22 pkt/s, threshold = 62
    t=7: 19 pkt/s, threshold = 59
    t=8: 21 pkt/s, threshold = 61
  
  Status: NORMAL (no alerts, threshold adapting smoothly)


ATTACK BEGINS (2:30 PM):
  Immediate spike to 200 pkt/s
  
  t=9: 200 pkt/s (ATTACK!)
       baseline = 0.2 × 200 + 0.8 × 20 = 40 + 16 = 56 pkt/s
       threshold = 56 × 10 × 3.0 = 1680
       Observed (200) > threshold (1680)? NO
       ❌ No alert (threshold too high on first spike!)
  
  α=0.2 is too conservative. It learns slowly.
  
  Workaround: Switch to α=0.5 for faster adaptation OR
              use MAD which is more robust to spikes


ATTACK CONTINUES (2:31 PM):
  Sustained high rate 150-200 pkt/s
  
  t=10: 150 pkt/s
        baseline = 0.2 × 150 + 0.8 × 56 = 30 + 44.8 = 74.8
        threshold = 74.8 × 10 × 3.0 = 2244
        Still no alert (learning curve)
  
  t=11: 180 pkt/s
        baseline = 0.2 × 180 + 0.8 × 74.8 = 36 + 59.84 = 95.84
        threshold = 95.84 × 10 × 3.0 = 2875
        Still no alert
  
  t=12: 190 pkt/s
        baseline = 0.2 × 190 + 0.8 × 95.84 = 38 + 76.67 = 114.67
        threshold = 114.67 × 10 × 3.0 = 3440
        Still no alert (threshold rising with attack!)


⚠️ PROBLEM: EWMA with low α misses sustained attacks
SOLUTION: 
  1. Reduce α to 0.5 for faster response
  2. Reduce headroom to 2.0 for sensitivity
  3. Or switch to MAD algorithm


With MAD Instead (same observations):
  
  t=9-12: [20, 18, 22, 19, 21] + [200, 150, 180, 190]
          = [20, 18, 22, 19, 21, 200, 150, 180, 190]
  
  sorted = [18, 19, 20, 21, 22, 150, 180, 190, 200]
  median = 22
  
  MAD calculation:
  deviations = [4, 3, 2, 1, 0, 128, 158, 168, 178]
  sorted_dev = [0, 1, 2, 3, 4, 128, 158, 168, 178]
  MAD = 4
  
  threshold = 22 + 2.5 × 4 = 22 + 10 = 32 pkt/10s
  
  t=9: 200 > 32? YES → ✓ ALERT! (much faster)


================================================================================
CONFIGURATION FOR DEPLOYMENT
================================================================================

File: in code or config.json

# Option 1: Conservative (fewer false positives)
{
  "threshold_algorithm": "ZSCORE",
  "z_multiplier": 3.0,              # 0.3% false positive rate
  "min_observations": 5,
  "window_size": 10,
}

# Option 2: Balanced (5% false positive acceptable)
{
  "threshold_algorithm": "MAD",
  "mad_k_factor": 2.5,              # 1% false positive rate
  "min_observations": 3,
  "window_size": 10,
}

# Option 3: Fast-response (requires tuning)
{
  "threshold_algorithm": "EWMA",
  "ewma_alpha": 0.3,                # Medium smoothing
  "ewma_headroom": 2.5,             # Sensitive
  "ewma_window": 10,
}

# Option 4: Context-aware (during known threats)
{
  "threshold_algorithm": "BAYESIAN",
  "bayesian_prior": 0.20,           # 20% attack probability
  "bayesian_adjustment": 0.7,       # 70% posterior weight
}


================================================================================
MONITORING & TROUBLESHOOTING
================================================================================

1. Check Alert Rate

   Query: Last hour alerts per rule
   
   Normal: 2-5% of packets generate alerts
   
   Too high (> 20%): 
     → Threshold too low
     → Solution: Increase z/k or α
   
   Too low (< 0.1%):
     → Threshold too high
     → Solution: Decrease z/k or α


2. Check Threshold Drift

   Track: threshold value over time for specific rule
   
   Expected: Smooth following of traffic
   
   Spiky:
     → Algorithm too sensitive to outliers
     → Solution: Use MAD or increase smoothing


3. Check False Positive Ratio

   Compare: Known-benign sources vs alert count
   
   High FP on specific sources:
     → Whitelist might be needed
     → Or adjust algorithm for that source


4. Check Detection Latency

   Measure: Time from attack start to first alert
   
   Acceptable: < 30 seconds
   Poor: > 60 seconds (threshold learning too slow)
   
   Fix: Increase α or switch to faster algorithm


================================================================================
END OF INTEGRATION GUIDE
================================================================================
