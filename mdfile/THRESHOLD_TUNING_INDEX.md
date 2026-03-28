# AUTOMATIC THRESHOLD TUNING DOCUMENTATION - INDEX & SUMMARY

================================================================================
OVERVIEW: WHAT IS AUTOMATIC THRESHOLD TUNING?
================================================================================

In traditional NIDS, thresholds are manually tuned and fixed:
  - Fixed threshold doesn't adapt to changing network conditions
  - Too high: Misses real attacks
  - Too low: Floods with false alarms

AUTOMATIC THRESHOLD TUNING solves this by learning from live traffic:

  ✓ Adapts to business hours vs night traffic
  ✓ Detects attack campaigns early
  ✓ Reduces false positives and false negatives
  ✓ No manual re-tuning required


================================================================================
FOUR ADAPTIVE ALGORITHMS PROVIDED
================================================================================

1. EWMA (Exponential Weighted Moving Average)
   ├─ Formula: baseline(t) = α × rate(t) + (1-α) × baseline(t-1)
   ├─ Speed: FAST (O(1) computation)
   ├─ Response: Quick trend following
   └─ Use: Real-time adaptive systems

2. MAD (Median Absolute Deviation)
   ├─ Formula: threshold = median + k × MAD
   ├─ Speed: MEDIUM (O(n log n) due to sort)
   ├─ Response: Robust to outliers and noise
   └─ Use: Noisy/unreliable sensors

3. Z-SCORE ADAPTIVE
   ├─ Formula: threshold = mean + z × std_dev
   ├─ Speed: FAST (O(n) computation)
   ├─ Response: Tunable false-positive rate
   └─ Use: Normal distributions, predictable

4. BAYESIAN THRESHOLD
   ├─ Formula: threshold ∝ Likelihood ratio × prior probability
   ├─ Speed: SLOW (PDF calculations)
   ├─ Response: Context-aware, incorporates domain knowledge
   └─ Use: Known threat patterns, contextual adaptation


================================================================================
DOCUMENTATION FILES & STRUCTURE
================================================================================

📂 /old/ folder (all files in this location)

┌─ CORE ALGORITHM DOCUMENTATION ─────────────────────────────────────────────┐
│                                                                             │
│ 1. AUTOMATIC_THRESHOLD_TUNING_DETAILED.md (MAIN REFERENCE)                │
│    ├─ Conceptual overview (3 pages)                                       │
│    ├─ ALGORITHM 1: EWMA detailed explanation (4 pages)                    │
│    ├─  - Step-by-step examples with real numbers                          │
│    ├─  - Worked example 1: Baseline learning                              │
│    ├─  - Worked example 2: Surge detection                                │
│    ├─  - Advantages & disadvantages                                       │
│    ├─  - Parameter tuning guide                                           │
│    │                                                                      │
│    ├─ ALGORITHM 2: MAD detailed explanation (5 pages)                     │
│    ├─  - Robustness properties                                            │
│    ├─  - Example 1: Normal traffic with outlier (7x better than std dev)  │
│    ├─  - Example 2: Legitimate traffic increase                           │
│    ├─  - MAD advantages/disadvantages                                     │
│    │                                                                      │
│    ├─ ALGORITHM 3: Z-SCORE detailed explanation (4 pages)                │
│    ├─  - Z-value to false-positive mapping (1%, 5%, 0.3%)                │
│    ├─  - Example 1: Tuning for 5% FP rate                                 │
│    ├─  - Example 2: Attack detection under load                           │
│    │                                                                      │
│    ├─ ALGORITHM 4: BAYESIAN detailed explanation (4 pages)               │
│    ├─  - Bayes' theorem application                                       │
│    ├─  - Example 1: Silent learning phase (1% prior)                      │
│    ├─  - Example 2: DDoS campaign context (50% prior)                     │
│    │                                                                      │
│    ├─ Comparison table (all 4 algorithms)                                 │
│    ├─ Decision tree for choosing algorithm                                │
│    ├─ Practical recommendations by network size                           │
│    └─ Real-world deployment example (HTTP web server)                     │
│                                                                             │
│    ~30 pages total, most comprehensive guide                              │
│    READ THIS FIRST for complete understanding                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─ QUICK REFERENCE MATERIALS ─────────────────────────────────────────────────┐
│                                                                             │
│ 2. THRESHOLD_TUNING_QUICK_REFERENCE.md (CHEAT SHEET)                      │
│    ├─ One-page formula summary for all 4 algorithms                       │
│    ├─ Z-SCORE false positive rate table                                    │
│    │  (Convert desired FP% to z-multiplier)                               │
│    ├─ MAD k-value scaling factor table                                    │
│    ├─ Visual diagrams:                                                    │
│    │  - EWMA adaptation over time                                         │
│    │  - MAD handling of outliers                                          │
│    │  - Z-SCORE with z=2.0 vs z=3.0                                      │
│    │  - Bayesian with context shift                                       │
│    ├─ Decision flowchart                                                   │
│    ├─ Initial setup checklist                                             │
│    ├─ Parameter selection per algorithm                                   │
│    ├─ Validation checklist                                                │
│    ├─ Common mistakes & fixes                                             │
│    └─ Python code snippets for testing                                     │
│                                                                             │
│    ~20 pages, quick lookup reference                                      │
│    USE THIS for parameter selection & troubleshooting                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─ INTEGRATION & DEPLOYMENT ─────────────────────────────────────────────────┐
│                                                                             │
│ 3. THRESHOLD_TUNING_INTEGRATION_EXAMPLES.md (PRACTICAL GUIDE)             │
│    ├─ Overall detection pipeline flow                                     │
│    ├─ STEP 1: Detect rule match (with code)                              │
│    ├─ STEP 2: Collect observations (sliding window examples)              │
│    ├─ STEP 3: Choose algorithm & compute threshold (pipeline code)        │
│    ├─ STEP 4: Apply threshold & generate alert                           │
│    │  - Example 1: HTTP Flood with EWMA (no alert)                       │
│    │  - Example 2: HTTP Flood with MAD (attack detected)                  │
│    │  - Example 3: Z-SCORE with tuning                                    │
│    ├─ STEP 5: Payload analysis & escalation                              │
│    ├─ Real-world DDoS scenario timeline (2:00-3:30 PM)                   │
│    │  - Initial baseline learning                                         │
│    │  - Business hours ramp-up                                            │
│    │  - Attack begins & detection comparison                              │
│    │  - Problem: Why EWMA with α=0.2 misses sustained attacks             │
│    │  - Solution: Switch to MAD or adjust α                               │
│    ├─ Configuration for deployment (4 options)                            │
│    ├─ Monitoring & troubleshooting checklist                              │
│    └─ Detection latency measurement                                        │
│                                                                             │
│    ~25 pages, step-by-step integration guide                              │
│    USE THIS when you want to understand flow & troubleshoot               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─ SOURCE CODE REFERENCE ────────────────────────────────────────────────────┐
│                                                                             │
│ 4. Source files in /old/ folder:                                          │
│    ├─ advanced_payload_detection.py                                       │
│    │  ├─ Class: AdaptiveThresholdManager (line 573+)                      │
│    │  ├─ Method: compute_threshold()                                      │
│    │  ├─ Method: _ewma_threshold()                                        │
│    │  ├─ Method: _mad_threshold()                                         │
│    │  ├─ Method: _zscore_threshold()                                      │
│    │  └─ Method: _bayesian_threshold()                                    │
│    │                                                                      │
│    └─ integration_adapter.py                                              │
│       ├─ Class: ThresholdOptimizer (line 234+)                            │
│       └─ Class: EnhancedDetectionPipeline                                  │
│          └─ Method: process() - uses adaptive thresholds                   │
│          └─ Method: get_optimal_threshold()                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


================================================================================
QUICK START: WHERE TO BEGIN
================================================================================

SCENARIO 1: I want to understand the concept
  → Read: AUTOMATIC_THRESHOLD_TUNING_DETAILED.md (start of file)
  → Time: 15 minutes
  → Covers: Why automatic tuning needed, conceptual overview

SCENARIO 2: I need to choose which algorithm to use
  → Read: THRESHOLD_TUNING_QUICK_REFERENCE.md → Decision Flowchart
  → Time: 5 minutes
  → Then verify: AUTOMATIC_THRESHOLD_TUNING_DETAILED.md → Comparison Table

SCENARIO 3: I need to tune parameters for MY network
  → Read: THRESHOLD_TUNING_QUICK_REFERENCE.md → Practical Tuning Checklist
  → Time: 30 minutes
  → Includes: Baseline measurement, parameter selection, validation

SCENARIO 4: I want to understand each algorithm deeply
  → Read: AUTOMATIC_THRESHOLD_TUNING_DETAILED.md (entire file)
  → Time: 2-3 hours
  → Covers: All 4 algorithms with 10+ worked examples each

SCENARIO 5: I'm integrating into my system / debugging issues
  → Read: THRESHOLD_TUNING_INTEGRATION_EXAMPLES.md
  → Time: 1 hour
  → Covers: Real code flow, DDoS timeline example, troubleshooting

SCENARIO 6: I need formulas for quick lookup
  → Read: THRESHOLD_TUNING_QUICK_REFERENCE.md → One-Page Formula Summary
  → Time: 5 minutes
  → Get: Exact formula for each algorithm


================================================================================
KEY FORMULAS QUICK LOOKUP
================================================================================

Algorithm     Formula                          Key Parameters
─────────────────────────────────────────────────────────────────────────────
EWMA          baseline = α×rate + (1-α)×old   α=0.2, headroom=3.0
              threshold = baseline×w×h

MAD           MAD = median(|x-median|)        k=2.5 for 1% FP
              threshold = median + k×MAD

Z-SCORE       σ = sqrt(variance)               z=2.5 for 0.6% FP
              threshold = μ + z×σ

BAYESIAN      P(A|O) ∝ P(O|A)×P(A)            prior=0.05, adjust=0.5
              threshold = base×(1-posterior)


================================================================================
WORKED EXAMPLES BY SCENARIO
================================================================================

Scenario: Normal office network morning

  Observation: [5, 4, 6, 5, 4] packets/10s
  
  EWMA:    threshold ≈ 15 pkt/10s  (adaptive to baseline)
  MAD:     threshold ≈ 7.5 pkt/10s (robust bounds)
  Z-SCORE: threshold ≈ 13.5 pkt/10s (statistical)
  BAYESIAN: threshold ≈ 12 pkt/10s (context: low attack prior)
  
  → All reasonable, pick based on preference


Scenario: Attack spike (200 pkt/s suddenly)

  EWMA (α=0.2):
    ✗ Detects slowly (trend following)
    ✗ Takes 3-4 cycles to respond
    ✓ Smooth (no jitter)
  
  EWMA (α=0.5):
    ✓ Detects faster (less smoothing)
    ⚠️ May chase outliers more
  
  MAD:
    ✓ Detects very quickly
    ✓ Ignores outlier in calculation
    ✓ Recommended for this scenario
  
  Z-SCORE:
    ⚠️ Sensitive to outlier inflation of std_dev
    → Can be solved with outlier filtering
  
  BAYESIAN:
    ✓ Detects quickly with high prior
    ⚠️ Needs accurate prior knowledge


Scenario: Multiple protocols mixed

  EWMA: Separate baseline per protocol (good)
  MAD:  Separate history per protocol (better)
  Z-SCORE: Separate mean/std per protocol (good)
  BAYESIAN: Use protocol-specific priors (best)


================================================================================
DECISION MATRIX: ALGORITHM SELECTION
================================================================================

Network Type          Recommended Algorithm    Reason
─────────────────────────────────────────────────────────────
Small office (< 50    MAD                      Robust, tuned for FP
hosts)                                         rate easily

Medium (100-1K        EWMA or Z-SCORE         Balance between
hosts)                with Z preferred        simplicity & control

Large datacenter      Z-SCORE with careful    Scalable, predictable
(> 10K hosts)         tuning

Security critical     BAYESIAN +              Maximum control,
network               context

Noisy/unreliable      MAD                      Handles corrupted
data (bad sensors)                            data up to 50%

High-speed DDoS       EWMA (α > 0.3) or       Need fast response
detection             Bayesian

Known threat          BAYESIAN                Incorporate threat
campaign                                      intelligence


================================================================================
PARAMETER REFERENCE TABLE
================================================================================

Algorithm    Parameter       Conservative      Default        Aggressive
─────────────────────────────────────────────────────────────────────────────
EWMA         α (smoothing)   0.10             0.20           0.50
             headroom        5.0              3.0            2.0
             window          15s              10s            5s

MAD          k factor        3.0              2.5            2.0
             observations    10               5              3

Z-SCORE      z multiplier    3.0              2.5            2.0
             FP rate         0.3%             0.6%           5%

BAYESIAN     prior attack    0.01             0.05           0.20
             adjustment      0.3              0.5            0.8


"Conservative": Lower false positive rate (may miss real attacks)
"Aggressive": Higher detection rate (more false positives)


================================================================================
TROUBLESHOOTING GUIDE
================================================================================

Problem                     Symptom              Algorithm          Fix
─────────────────────────────────────────────────────────────────────────────
Too many alerts             Alert rate > 10%     Any              Increase param
                                                                  (↑ z, k, etc)

Missing real attacks        Alert rate << 0.1%   Any              Decrease param
                                                                  (↓ z, k, etc)

Slow attack detection       Alert after 60s      EWMA             ↑ α (0.2→0.5)
(using EWMA)                                                      → MAD

Threshold oscillates        High variance        EWMA or          ↓ α or use MAD
                           in threshold         ZSCORE

False positives on          Spike in alerts      Any              Increase bound
known-benign sources        from these IPs                        or whitelist

Context changes ignored    No threshold change   EWMA/MAD/        Switch to
(DDoS event starts)        despite context       ZSCORE           BAYESIAN +
                                                                  update prior


================================================================================
DEPLOYMENT CHECKLIST
================================================================================

PRE-DEPLOYMENT:
  ☐ Review your network baseline (peak, trough, average)
  ☐ Measure current false alert rate
  ☐ Define acceptable false positive rate (typically 1-5%)
  ☐ Choose algorithm (use decision matrix above)
  ☐ Set parameters (use quick reference)
  ☐ Test in shadow mode (log but don't alert)

INITIAL DEPLOYMENT:
  ☐ Enable for single rule first
  ☐ Monitor for 1 week minimum
  ☐ Check alert logs for pattern
  ☐ Adjust parameters if needed
  ☐ Expand to more rules gradually

ONGOING OPERATION:
  ☐ Track alert rate trend
  ☐ Monitor known-benign sources for false alerts
  ☐ Review escalated thresholds monthly
  ☐ Adjust if network conditions change
  ☐ Document any parameter changes

INCIDENT RESPONSE:
  ☐ If real attack missed: Lower threshold (↓ param)
  ☐ If false alarms increase: Raise threshold (↑ param)
  ☐ If slow detection: Use faster algorithm (EWMA/Bayesian)
  ☐ If unstable: Use MAD (most stable)


================================================================================
NEXT STEPS
================================================================================

1. Read AUTOMATIC_THRESHOLD_TUNING_DETAILED.md (this week)
   → Understand all 4 algorithms

2. Run quick tests with sample data (test_threshold_tuning.py if available)
   → See formulas in action

3. Choose algorithm for your environment using decision matrix
   → Review THRESHOLD_TUNING_QUICK_REFERENCE.md

4. Set initial parameters using checklist
   → Measure baseline traffic rates

5. Deploy in shadow mode for 1 week
   → Log but don't generate alerts

6. Analyze logs and tune parameters
   → Iteratively adjust based on results

7. Move to production gradually (rule by rule)
   → Full monitoring with escalation


================================================================================
RELATED DOCUMENTATION
================================================================================

Also in /old/ folder:

- PAYLOAD_CATEGORIZATION_DETAILED.md
  (How payloads are analyzed for threat assessment)

- PAYLOAD_CATEGORIZATION_CODE_EXAMPLES.md
  (Code walkthroughs of payload analysis)

- advanced_payload_detection.py (source code)
  Lines 573-850: AdaptiveThresholdManager implementation

- integration_adapter.py (source code)
  Lines 234-450: ThresholdOptimizer integration


================================================================================
END OF INDEX
================================================================================

Document created: March 28, 2026
Updated for: Comprehensive automatic threshold tuning system
Status: COMPLETE and ready for deployment
