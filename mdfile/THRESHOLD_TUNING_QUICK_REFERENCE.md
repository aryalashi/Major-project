# AUTOMATIC THRESHOLD TUNING - QUICK REFERENCE & FORMULAE

================================================================================
ONE-PAGE FORMULA SUMMARY
================================================================================

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ALGORITHM 1: EWMA (Exponential Weighted Moving Average)               ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                        ┃
┃  baseline(t) = α × rate(t) + (1-α) × baseline(t-1)                    ┃
┃  threshold = baseline × window × headroom                             ┃
┃                                                                        ┃
┃  Parameters: α ∈ [0.1, 0.5]  (default 0.2)                           ┃
┃              headroom ∈ [2.0, 5.0] (default 3.0)                     ┃
┃              window = seconds per detection window                    ┃
┃                                                                        ┃
┃  Use when: Traffic trend following, real-time adaptation              ┃
┃  Speed: FAST (O(1) computation)                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

QUICK EXAMPLE:
  Current rate: 5 pkt/s
  Baseline: 3 pkt/s
  α=0.2, headroom=3.0, window=10
  
  baseline = 0.2 × 5 + 0.8 × 3 = 1 + 2.4 = 3.4
  threshold = 3.4 × 10 × 3.0 = 102 packets/10s


┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ALGORITHM 2: MAD (Median Absolute Deviation)                         ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                        ┃
┃  1. median = middle value of sorted(observations)                     ┃
┃  2. deviations = |x_i - median| for each observation                  ┃
┃  3. MAD = median(deviations)                                          ┃
┃  4. threshold = median + k × MAD                                      ┃
┃                                                                        ┃
┃  Parameters: k ∈ [1.0, 3.0]                                           ┃
┃              k=2.0  (5% false positive)                               ┃
┃              k=2.5  (1% false positive) ← DEFAULT                     ┃
┃              k=3.0  (0.3% false positive)                             ┃
┃                                                                        ┃
┃  Use when: Noisy data, outliers present, unknown distribution         ┃
┃  Speed: MEDIUM (O(n log n) for sort)                                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

QUICK EXAMPLE:
  Observations: [5, 4, 6, 5, 4, 5, 100]  (100 = outlier)
  
  sorted = [4, 4, 5, 5, 5, 6, 100]
  median = 5
  deviations = [1, 1, 0, 0, 0, 1, 95]
  MAD = median([0, 0, 0, 1, 1, 1, 95]) = 1
  threshold = 5 + 2.5 × 1 = 7.5 packets/10s


┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ALGORITHM 3: Z-SCORE ADAPTIVE                                        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                        ┃
┃  mean = (1/N) × Σ(x_i)                                                ┃
┃  variance = (1/N) × Σ(x_i - mean)²                                    ┃
┃  std_dev = sqrt(variance)                                             ┃
┃  threshold = mean + z × std_dev                                       ┃
┃                                                                        ┃
┃  Parameters: z ∈ [1.0, 3.0]                                           ┃
┃              z=2.0  (5% false positive) ← common                      ┃
┃              z=2.5  (0.6% false positive) ← default                   ┃
┃              z=3.0  (0.3% false positive)                             ┃
┃                                                                        ┃
┃  Use when: Normal distribution, tunable FP rate needed                ┃
┃  Speed: FAST (O(n) computation)                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

QUICK EXAMPLE:
  Observations: [10, 12, 11, 9, 10, 11, 10, 12, 9, 11]
  
  mean = 10.5
  variance = 1.45
  std_dev = 1.20
  threshold = 10.5 + 2.5 × 1.20 = 13.5 packets/10s


┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ALGORITHM 4: BAYESIAN THRESHOLD                                      ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                        ┃
┃  P(obs|normal) = Gaussian_PDF(obs, μ_normal, σ_normal)                ┃
┃  P(obs|attack) = Gaussian_PDF(obs, μ_attack, σ_attack)                ┃
┃                                                                        ┃
┃  LR = P(obs|attack) / P(obs|normal)  [Likelihood ratio]               ┃
┃                                                                        ┃
┃  P(attack|obs) = (LR × prior) / (LR × prior + (1-prior))              ┃
┃                                                                        ┃
┃  threshold = base × (1.0 - P(attack|obs) × adjustment)                ┃
┃                                                                        ┃
┃  Parameters: prior ∈ [0.01, 0.50] (default 0.05)                     ┃
┃              adjustment ∈ [0.2, 1.0] (default 0.5)                    ┃
┃                                                                        ┃
┃  Use when: Domain knowledge available, contextual adaptation          ┃
┃  Speed: SLOW (PDF calculations)                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

QUICK EXAMPLE:
  Observation: 25 pkt/s
  Normal: μ=20, σ=3
  Attack: μ=100, σ=20
  Prior: 0.05 (5% chance of attack baseline)
  Base threshold: 100 pkt/s
  
  P(obs|normal) ≈ 0.033
  P(obs|attack) ≈ 0.000018
  LR ≈ 0.545
  
  P(attack|obs) ≈ 0.003 (0.3% likely attack)
  threshold ≈ 100 × (1 - 0.003 × 0.5) ≈ 99 pkt/s


================================================================================
Z-SCORE FALSE POSITIVE RATE TABLE
================================================================================

Convert false positive budget to z-multiplier:

  Desired FP Rate    Threshold (z)      Standard Deviations
  ───────────────────────────────────────────────────────
  32%                1.0                ±1σ (too aggressive)
  20%                1.28               ±1.28σ
  15.9%              1.5                ±1.5σ
  13.4%              1.5                ±1.5σ
  10%                1.645              ±1.645σ
  5%                 2.0                ±2σ ← COMMON
  2.5%               2.17               ±2.17σ
  1%                 2.33               ±2.33σ
  0.6%               2.5                ±2.5σ ← DEFAULT
  0.3%               3.0                ±3σ ← CONSERVATIVE
  0.1%               3.29               ±3.29σ
  0.05%              3.5                ±3.5σ


================================================================================
MAD k-VALUE SCALING FACTOR TABLE
================================================================================

For Normal distribution via MAD robustification:

  k Value    Effective Coverage    False Positive Rate
  ──────────────────────────────────────────────────
  1.0        ~68%                  32%
  1.35       ~75%                  25%
  1.5        ~86.6%                13.4%
  2.0        ~95%                  5%
  2.5        ~99.4%                0.6% ← DEFAULT
  3.0        ~99.7%                0.3%
  3.5        ~99.95%               0.05%


================================================================================
VISUAL: HOW THRESHOLDS CHANGE OVER TIME
================================================================================

EWMA Adaptation (α=0.2):

rate (pkt/s)
  │
 50┤                                    ╱╲
   │                                  ╱    ╲
 40┤                               ╱        ╲
   │    ┌─threshold             ╱            ╲
 30┤    │                     ╱                ╲─── threshold increases
   │    │                   ╱                      with traffic spike
 20┤────┤─baseline────────╱─────
   │    │              ╱
 10┤    └─observations╱─╱
   │           ╱╱
  0┼──────────────────────────────────────────── time →
     Morning    Noon (spike)    Peak       Afternoon


MAD Adaptation (handles outlier):

rate (pkt/s)    threshold (MAD)
  100├──── outlier spike        250├─── threshold IGNORES outlier
   50┤╱╲                         100├─── baseline follows normal
   10┤  ╲╱╭─────────────────       10├─── adapts smoothly
    1├─────────────────              1└─ remains stable
      └─ time →


Z-SCORE + Tuning (z=2.0 vs z=3.0):

rate (pkt/s)
  50┤
    │            threshold_z=2.0 (5% FP)
  40├────────────▔▔───────────────
    │
  30├──────┐    threshold_z=3.0 (0.3% FP)
    │      │ ▔▔▔▔───────────────────
  20├──observations─────────────────
    │   ╱─╲  ╱─╲  ╱─╲
  10├─╱     ╱    ╱
    │
   0└─────────────────────────────── time →


Bayesian (with context shift):

rate (pkt/s)  Prior P(attack): 0.01        Prior P(attack): 0.50
  100├                                    ├─ threshold_aggressive
     │                                    │
   50├─ threshold_normal                  ├─────
     │ ╱╲╱╲╱╲╱                            │ ╱╲╱╲╱
   25├────╱──────                         ├─╱──────
     │  observations                      │ observations (same)
   10├
     │
    0└────────────────────────────────── time →


================================================================================
DECISION FLOWCHART: WHICH ALGORITHM TO USE?
================================================================================

                     START
                       │
                       ▼
              Is traffic normal
              distributed?
                    /        \
                  YES         NO
                  │            │
                  ▼            ▼
            Z-SCORE?     Do you have
                         outliers/noise?
              (z=2-3)          /      \
                            YES      NO
                             │        │
                             ▼        ▼
                          MAD?     Real-time
                        (k=2-3)  trending?
                                  /      \
                                YES      NO
                                 │        │
                                 ▼        ▼
                              EWMA?    Bayesian?
                            (α=0.2)   (prior)
                             │          │
                             ▼          ▼
                          FAST        CONTEXTUAL
                         ADAPT        AWARE

Summary:
  • Most networks: MAD or Z-SCORE (robust, simple)
  • Trending networks: EWMA (fast adaptation)
  • Known threats: BAYESIAN (incorporate priors)
  • Unsure: Start with MAD


================================================================================
PRACTICAL TUNING CHECKLIST
================================================================================

1. INITIAL SETUP
   ☐ Identify baseline traffic rate (packets/second)
   ☐ Identify peak traffic rate
   ☐ Define acceptable false positive rate (1-5% typical)
   ☐ Choose algorithm based on distribution shape


2. PARAMETER SELECTION

   For EWMA:
   ☐ Set α = 0.2 (or higher if need fast response)
   ☐ Set headroom = 3.0 (or lower for sensitive)
   ☐ Set window = 10 seconds (or longer for stability)

   For MAD:
   ☐ Collect 10+ observations
   ☐ Convert FP rate to k-value (see table)
   ☐ k = 2.5 is safe default

   For Z-SCORE:
   ☐ Collect 5+ observations
   ☐ Convert FP rate to z-multiplier (see table)
   ☐ z = 2.5 is safe default

   For BAYESIAN:
   ☐ Estimate prior P(attack) from history
   ☐ Set attack parameters (μ_attack, σ_attack)
   ☐ Set adjustment factor = 0.5 (balance)


3. VALIDATION
   ☐ Monitor alert rate for 1 week
   ☐ If alerts > 10% of packets: threshold too low (increase by 20%)
   ☐ If alerts < 0.1% of packets: threshold too high (decrease by 20%)
   ☐ If known attacks missed: Algorithm sensitivity insufficient


4. ONGOING TUNING
   ☐ Review alert logs monthly
   ☐ Check for alert creep (false positive increase)
   ☐ Adjust parameters if network changes dramatically
   ☐ Re-validate after network upgrades


================================================================================
COMMON MISTAKES & FIXES
================================================================================

Problem: Threshold too high, missing real attacks
  Symptoms: 
    - 0.1% alert rate (too low)
    - Known attacks not detected
  Fixes:
    □ Decrease z-multiplier (2.5 → 2.0)
    □ Decrease k value (2.5 → 2.0)
    □ Increase α in EWMA (0.2 → 0.4)
    □ Decrease baseline headroom (3.0 → 2.0)
    □ Switch to more sensitive algorithm (ZSCORE → EWMA)


Problem: Threshold too low, false alarms
  Symptoms:
    - > 5% alert rate (too high)
    - Clear false positives (spammy alerts)
  Fixes:
    □ Increase z-multiplier (2.5 → 3.0)
    □ Increase k value (2.5 → 3.0)
    □ Decrease α in EWMA (0.2 → 0.1)
    □ Increase baseline headroom (3.0 → 5.0)
    □ Switch to more conservative algorithm (EWMA → ZSCORE or MAD)


Problem: Threshold oscillates wildly
  Symptoms:
    - High variance in computed threshold
    - Inconsistent alert timing
  Fixes:
    □ Increase smoothing: higher α in EWMA
    □ Use MAD instead (more stable)
    □ Increase observation window size
    □ Use larger k or z multiplier


Problem: Slow attack detection
  Symptoms:
    - DDoS starts, but no alert for 60+ seconds
  Fixes:
    □ Increase α in EWMA (0.2 → 0.5)
    □ Use Bayesian with high prior for active threat
    □ Decrease window size (10s → 5s)
    □ Lower headroom/z multiplier


================================================================================
CODE SNIPPETS FOR MANUAL TESTING
================================================================================

Python: Test EWMA with real rates

  from advanced_payload_detection import AdaptiveThresholdManager
  
  mgr = AdaptiveThresholdManager()
  
  # Simulate traffic spike
  rates = [1.0, 1.2, 1.1, 1.3, 5.0, 10.0, 8.5, 7.0]
  
  base = 15
  for i, rate in enumerate(rates):
    threshold, meta = mgr.compute_threshold(
        "TestRule", base, [rate],
        algorithm="EWMA"
    )
    print(f"t={i}: rate={rate}, threshold={threshold}")


Python: Compare all algorithms

  rates = [10, 11, 10, 12, 9, 10, 8, 11]
  
  for algo in ["EWMA", "MAD", "ZSCORE", "BAYESIAN"]:
    threshold, meta = mgr.compute_threshold(
        "TestRule", 15, rates,
        algorithm=algo
    )
    print(f"{algo:10} → threshold = {threshold}")


================================================================================
END OF QUICK REFERENCE
================================================================================
