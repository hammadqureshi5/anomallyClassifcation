# Improving the Anomaly Detection Module: Technical Evaluation Report

**Project:** Autonomous Cyber Defense System (FYP), network anomaly detection module
**Date:** 6 November 2026
**Datasets:** NSL-KDD and CIC-IDS2017
**Reproduce:** `bash experiments/run_all.sh` (about 15 minutes on 12 CPU cores)

---

## 1. Project overview

The module flags malicious or unusual network flows and writes alerts for the response
module. It is **unsupervised**: it learns only what normal traffic looks like, so it can
flag attack types it has never seen. Attack labels are used only to measure performance
and, in this study, to tune settings on a validation split.

This report covers the following, all on the same data:
- the original model (v1), measured first;
- its weaknesses;
- an improved model (v2), with every setting chosen on validation data only;
- an optional hybrid that adds a supervised classifier to v2.

**Main results** (test set, mean of 3 seeds):

| Dataset | F1 (v1 → v2) | Recall (v1 → v2) | False alarms (v1 → v2) | PR-AUC (v1 → v2) |
|---|---|---|---|---|
| NSL-KDD | 0.522 → **0.899** | 36.9% → **89.1%** | 5.5% → **11.9%** (worse) | 0.911 → 0.901 (≈ same) |
| CIC-IDS2017 | 0.071 → **0.835** | 3.9% → **82.2%** | 0.9% → **2.9%** (worse) | 0.534 → **0.891** |

The hybrid (v2 + Random Forest) is the best model on validation for both datasets.
On test it reaches F1 0.904 (NSL-KDD) and **0.931** (CIC-IDS2017).

## 2. Original model (v1): architecture and method

| Component | v1 setting |
|---|---|
| Preprocessing | inf → NaN → training median; signed `log1p`; one-hot encoding (top 50 categories); constant columns dropped; `RobustScaler`; clipped to ±50 |
| Detectors | Robust z-score (max \|z\|); Isolation Forest (200 trees, 256 samples per tree); LOF (k = 20, fitted on 10,000 rows); autoencoder (`MLPRegressor`, input → n/2 → n/4 → n/2 → input, at most 60 epochs, early stopping) |
| Combination | Each detector's score is converted to its rank among benign validation scores, then the four ranks are **averaged** |
| Training data | Benign rows only (at most 50,000); 20% of benign rows held out to calibrate the threshold |
| Alert threshold | 99th percentile of benign hold-out scores (about 1% false alarms by design) |
| Evaluation | Precision, recall, F1, false-positive rate, ROC-AUC, PR-AUC, recall per attack type |

The v1 code, config, tests and results are preserved unchanged in `archive/original_v1/`.
The current package reproduces them **exactly** with `configs/baseline.yaml`: every
metric in `metrics.json` matched to full precision on both datasets.

## 3. Dataset analysis

| | NSL-KDD | CIC-IDS2017 |
|---|---|---|
| Files | `KDDTrain+.txt` (training), `KDDTest+.txt` (testing) | 8 CSV files, 2,830,743 flows |
| Features | 41 (3 categorical) → 75 after encoding | 78 numeric → 70 after dropping constant columns |
| Share of attacks | 46.5% (training), 56.9% (test) | 19.7% |
| Attack types | 22 in training; **37 in test, 17 never seen in training** (3,750 of 12,833 test attacks) | 14, dominated by DoS Hulk, PortScan and DDoS |
| Data quality | Clean; 9 duplicate rows; 1 constant column | **308,381 exact duplicate rows (10.9%; 23.6% of attack rows)**; **1,396 rows with identical features but conflicting labels**; 4,376 infinite and 1,358 missing values in `Flow Bytes/s` and `Flow Packets/s`; 8 constant and 4 duplicated columns (e.g. `Fwd Header Length.1`); some negative durations |

**Evaluation protocol** (`experiments/protocol.py`):
- **NSL-KDD:** the official train and test files.
- **CIC-IDS2017 (corrected):**
  - Duplicates and conflicting-label rows are removed **before** splitting.
  - A 10% random sample is taken (fixed seed).
  - The sample is split into a stratified 70% for training (176,467 flows) and 30% for testing (75,630 flows).
- **Tuning:** a stratified 80/20 split of the **training data only**, into fit and
  validation parts. Every tuning decision uses the validation part. The test sets are
  loaded only by `experiments/evaluate.py`, after all choices were fixed.

## 4. Baseline evaluation

**Original protocol** (as first reported; archived in `archive/original_v1/results/`):

| Dataset | Precision | Recall | F1 | False alarms | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| NSL-KDD | 0.896 | 0.401 | 0.554 | 6.2% | 0.938 | 0.913 |
| CIC-IDS2017 (with duplicates) | 0.290 | 0.016 | 0.030 | 1.0% | 0.878 | 0.557 |

**Corrected protocol**, which all comparisons below use (test set, mean ± std, 3 seeds):

| Dataset | Accuracy | Precision | Recall | F1 | False alarms | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| NSL-KDD | 0.617 ± 0.016 | 0.899 ± 0.017 | 0.369 ± 0.037 | 0.522 ± 0.036 | 5.5% ± 1.4 | 0.936 ± 0.002 | 0.911 ± 0.003 |
| CIC-IDS2017 | 0.830 ± 0.006 | 0.403 ± 0.204 | 0.039 ± 0.036 | 0.071 ± 0.062 | 0.9% ± 0.0 | 0.913 ± 0.007 | 0.534 ± 0.049 |

## 5. Weaknesses identified

| # | Weakness | Evidence |
|---|---|---|
| W1 | **The combined score averages in weak detectors.** | CIC-IDS2017 validation PR-AUC: robust z-score 0.18, Isolation Forest 0.46, LOF 0.49, autoencoder 0.75. The average of all four (0.56) is worse than the autoencoder alone. |
| W2 | **The threshold is fixed, not tuned.** At the 99th percentile, most attacks fall below it. | CIC-IDS2017 v1: ROC-AUC 0.91, yet recall is only 3.9%. |
| W3 | **The detectors were never tuned.** | Validation PR-AUC rose with tuning: LOF 0.54 → 0.74 and Isolation Forest 0.48 → 0.63 (CIC-IDS2017). |
| W4 | **Redundant features count twice** in distance-based detectors. | CIC-IDS2017 has many near-identical columns (e.g. `Subflow Fwd Bytes` vs `Total Length of Fwd Packets`). |
| W5 | **Duplicate flows leak** between training and test on CIC-IDS2017. | 23.6% of attack rows are duplicates. It inflates the supervised comparison (99.7% recall under the original protocol) more than the unsupervised detectors. |
| W6 | **Unstable between runs.** | CIC-IDS2017 v1 F1 ranges from 0.031 to 0.143 across seeds. |
| W7 | Rank normalisation gives every flow above the benign maximum the same score (1.0), which could hide differences between attacks. | **Hypothesis only; tested in section 6 and rejected.** |

Checks that found **no** problem:
- **Missing and infinite values:** already handled correctly.
- **Leakage into preprocessing:** none; the preprocessor is fitted on benign training rows only.
- **Class imbalance:** not a problem for unsupervised training, which uses benign data only. The supervised classifier uses `class_weight="balanced"`.

## 6. Methods selected and why

Methods were chosen to match the weaknesses, not applied wholesale. The tuning script
(`experiments/tune.py`) has five stages, in order. **A change is adopted only if it beats
the current (v1) choice on validation by more than 0.002**, so v1 wins ties and no change
is made without evidence.

| Stage | Addresses | Search space | Validation metric |
|---|---|---|---|
| 0. Feature selection | W4 | Drop features with \|correlation\| > {none, 0.99, 0.95}, measured on benign training data | Mean PR-AUC of the 4 detectors |
| 1. Detector settings (grid search) | W3 | Robust z-score: average of top-k \|z\|, k ∈ {1, 3, 10}<br>Isolation Forest: samples per tree ∈ {256, 1024, 4096} × features per tree ∈ {1.0, 0.5}<br>LOF: k ∈ {10, 20, 50} × training rows ∈ {10,000, 30,000}<br>Autoencoder: epochs ∈ {60, 200}, L2 strength ∈ {1e-4, 1e-3}, bottleneck ∈ {25%, 50%} of features | That detector's PR-AUC |
| 2. Ensemble redesign | W1, W7 | All 15 subsets of detectors × normalisation {rank, tail} × combination {mean, max}: 60 options. Among near-ties, the fewest detectors wins. | Ensemble PR-AUC |
| 3. Threshold | W2 | Percentile of benign scores ∈ {90, 95, 97, 98, 99, 99.5} | F1 |
| 4. Hybrid | Known attacks | Random Forest (100 trees, balanced class weights) on the same features; flag a flow if the classifier **or** v2 flags it | F1 |

W5 was fixed in the evaluation protocol (section 3). W6 is addressed by reporting
mean ± std over 3 seeds.

Methods **not** used, and why:
- **SMOTE / resampling:** the detectors train on benign data only, so there is no imbalance to correct.
- **XGBoost and other deep models:** not installed, and not needed for the comparison.
- **Bayesian optimisation:** the search space is small enough for a full grid.
- **Transfer learning:** no suitable pre-trained model exists for flow features.

## 7. Implementation

| Change | Where | Default (= v1) |
|---|---|---|
| Option to drop correlated features | `features/preprocess.py` (`corr_threshold`) | off |
| Robust z-score: average of the top-k \|z\| | `detectors/statistical.py` (`top_k`) | 1 (max) |
| Isolation Forest: samples and features per tree | `detectors/iforest.py` | `auto`, 1.0 |
| Autoencoder: L2 strength, bottleneck size | `detectors/autoencoder.py` | 1e-4, 0.25 |
| Ensemble: tail normalisation and max combination | `detectors/ensemble.py` | rank, mean |
| CIC-IDS2017: deduplication and conflict removal | `data/loaders.py` (`drop_duplicates`) | off |
| Accuracy metric | `evaluation.py` | – |
| Hybrid detector | `hybrid.py` (new) | – |
| Experiments | `experiments/` (`protocol`, `tune`, `evaluate`, `make_figures`, `figures`, `run_all.sh`) | – |
| Tests | `tests/test_improvements.py` (4 new; 15/15 pass) | – |

Reproducibility and leakage controls:
- **Fixed seeds:** split seed 42; model seeds 42, 43 and 44.
- **No test data in fitting:** every preprocessing step is fitted on benign training rows only.
- **Test set used once:** for the final measurement only.
- **Recorded choices:** the exact settings chosen are written to `configs/improved_<dataset>.yaml`, and every candidate's score to `reports/improvement/<dataset>/tuning.json`.

## 8. Improved model (v2): configuration

| Setting | NSL-KDD | CIC-IDS2017 |
|---|---|---|
| Feature selection | none (0.99 removed nothing; 0.95 scored worse) | \|r\| > 0.99: 70 → 48 features |
| Detectors in the combined score | **Isolation Forest + LOF** | **LOF + autoencoder** |
| Combination | rank, **max** | rank, mean |
| Isolation Forest | 4,096 samples per tree, 50% of features | (not used) |
| LOF | **k = 10, 30,000 training rows** | **k = 10, 30,000 training rows** |
| Autoencoder | (not used) | 200 epochs (early stopping), L2 1e-4, bottleneck 25% |
| Alert threshold | **95th** percentile of benign scores | **97th** percentile |

Validation results (fit part → validation part of the training data):

| Dataset | Model | F1 | Recall | False alarms | PR-AUC |
|---|---|---|---|---|---|
| NSL-KDD | v1 | 0.707 | 55.3% | 1.1% | 0.971 |
| NSL-KDD | v2 | 0.960 | 97.4% | 4.9% | 0.989 |
| NSL-KDD | Hybrid | 0.972 | 99.9% | 4.9% | 1.000 |
| CIC-IDS2017 | v1 | 0.041 | 2.2% | 1.0% | 0.556 |
| CIC-IDS2017 | v2 | 0.886 | 91.1% | 2.9% | 0.935 |
| CIC-IDS2017 | Hybrid | 0.931 | 99.7% | 3.0% | 0.997 |

**Best model by validation: the hybrid, for both datasets.**

## 9. Final evaluation (test set)

All three models were trained on the same training data and tested on the same,
untouched test set, with 3 seeds. Full tables, including per-seed values, are in
`reports/improvement/<dataset>/results.md` and `results.json`.

### NSL-KDD

| Metric | Original (v1) | Improved (v2) | Change | Hybrid | Change |
|---|---|---|---|---|---|
| Accuracy | 0.617 ± 0.016 | **0.886 ± 0.009** | +0.269 | **0.891 ± 0.005** | +0.274 |
| Precision | 0.899 ± 0.017 | 0.908 ± 0.002 | +0.009 | 0.908 ± 0.001 | +0.009 |
| Recall | 0.369 ± 0.037 | **0.891 ± 0.014** | +0.521 | **0.900 ± 0.007** | +0.531 |
| F1 | 0.522 ± 0.036 | **0.899 ± 0.009** | +0.377 | **0.904 ± 0.004** | +0.381 |
| False alarms ↓ | **0.055 ± 0.014** | 0.119 ± 0.001 | +0.064 (worse) | 0.121 ± 0.001 | +0.065 (worse) |
| ROC-AUC | 0.936 ± 0.002 | 0.925 ± 0.005 | −0.011 | **0.952 ± 0.002** | +0.016 |
| PR-AUC | 0.911 ± 0.003 | 0.901 ± 0.021 | −0.010 | **0.956 ± 0.002** | +0.045 |
| Training time (s) ↓ | 14.5 ± 1.6 | **4.5 ± 0.3** | −10.0 | 6.9 ± 0.4 | −7.6 |
| Inference (ms per 1,000 flows) ↓ | **23.9 ± 1.0** | 51.8 ± 1.0 | +27.9 | 55.2 ± 1.7 | +31.3 |

**Attack types never seen in training** (17 types, 3,750 flows, seed 42): recall is
41.2% for v1, **84.5%** for v2 and 85.1% for the hybrid. Types seen in training: 39.6%,
92.9% and 93.2%.

### CIC-IDS2017 (corrected protocol)

| Metric | Original (v1) | Improved (v2) | Change | Hybrid | Change |
|---|---|---|---|---|---|
| Accuracy | 0.830 ± 0.006 | **0.946 ± 0.015** | +0.116 | **0.975 ± 0.000** | +0.145 |
| Precision | 0.403 ± 0.204 | **0.850 ± 0.015** | +0.447 | **0.873 ± 0.002** | +0.469 |
| Recall | 0.039 ± 0.036 | **0.822 ± 0.086** | +0.782 | **0.997 ± 0.000** | +0.958 |
| F1 | 0.071 ± 0.062 | **0.835 ± 0.052** | +0.763 | **0.931 ± 0.001** | +0.860 |
| False alarms ↓ | **0.009 ± 0.000** | 0.029 ± 0.000 | +0.020 (worse) | 0.030 ± 0.001 | +0.020 (worse) |
| ROC-AUC | 0.913 ± 0.007 | **0.978 ± 0.007** | +0.065 | **0.999 ± 0.000** | +0.087 |
| PR-AUC | 0.534 ± 0.049 | **0.891 ± 0.018** | +0.357 | **0.998 ± 0.000** | +0.464 |
| Training time (s) ↓ | **16.4 ± 1.2** | 31.2 ± 6.1 | +14.7 | 35.8 ± 6.3 | +19.3 |
| Inference (ms per 1,000 flows) ↓ | **26.3 ± 1.1** | 34.9 ± 1.4 | +8.6 | 37.9 ± 1.0 | +11.6 |

**Confusion matrices** (seed 42; TN = correctly passed benign, FP = false alarm,
FN = missed attack, TP = caught attack):

| Dataset | Model | TN | FP | FN | TP |
|---|---|---|---|---|---|
| NSL-KDD | v1 | 9,113 | 598 | 7,688 | 5,145 |
| NSL-KDD | v2 | 8,563 | 1,148 | 1,227 | 11,606 |
| NSL-KDD | Hybrid | 8,547 | 1,164 | 1,180 | 11,653 |
| CIC-IDS2017 | v1 | 62,247 | 590 | 11,763 | 1,030 |
| CIC-IDS2017 | v2 | 60,998 | 1,839 | 1,393 | 11,400 |
| CIC-IDS2017 | Hybrid | 60,976 | 1,861 | 34 | 12,759 |

### Training vs test (generalisation, seed 42)

| Dataset | Model | F1 train → test | False alarms train → test |
|---|---|---|---|
| NSL-KDD | v1 | 0.878 → 0.554 | 0.9% → 6.2% |
| NSL-KDD | v2 | 0.962 → 0.907 | 4.6% → 11.8% |
| NSL-KDD | Hybrid | 0.974 → 0.909 | 4.6% → 12.0% |
| CIC-IDS2017 | v1 | 0.137 → 0.143 | 0.9% → 0.9% |
| CIC-IDS2017 | v2 | 0.876 → 0.876 | 2.9% → 2.9% |
| CIC-IDS2017 | Hybrid | 0.934 → 0.931 | 2.9% → 3.0% |

**Learning curves** (PR-AUC on the fit part vs the validation part, by number of benign
training flows):
- The two curves stay within **0.01** of each other at every size, for both models and
  both datasets, so there is **no overfitting**.
- **NSL-KDD:** v2 levels off at about 0.988 from 10,000 flows; v1 is still rising at 30,000 (0.975).
- **CIC-IDS2017:** v2 rises steadily (0.60 → 0.94 from 1,000 to 50,000 flows) and gains
  little past 30,000. v1 is unstable (0.63 at 30,000, then 0.56 at 50,000).
- **Autoencoder:** training loss falls smoothly, and the early-stopping validation R²
  settles at about 0.88 with no upturn (CIC-IDS2017).

### Figures

| Figure | NSL-KDD | CIC-IDS2017 |
|---|---|---|
| Before vs after metrics | `nsl-kdd/figures/1_metric_comparison.png` | `cicids2017/figures/1_metric_comparison.png` |
| Confusion matrices | `…/2_confusion_matrices.png` | `…/2_confusion_matrices.png` |
| Learning curve | `…/3_learning_curve.png` | `…/3_learning_curve.png` |
| Autoencoder training | `…/3b_autoencoder_training.png` | `…/3b_autoencoder_training.png` |
| Feature importance (Random Forest) | `…/4_feature_importance.png` | `…/4_feature_importance.png` |
| Most common alert reasons (v2) | `…/4b_alert_reasons.png` | `…/4b_alert_reasons.png` |
| ROC and precision-recall curves | `…/5_roc_pr_curves.png` | `…/5_roc_pr_curves.png` |
| Recall per attack type | `…/6_per_attack_recall.png` | `…/6_per_attack_recall.png` |
| Ablation | `…/7_ablation.png` | `…/7_ablation.png` |

## 10. Before-and-after summary (test set, mean of 3 seeds)

| Metric | NSL-KDD v1 | NSL-KDD v2 | Change | CIC-IDS2017 v1 | CIC-IDS2017 v2 | Change |
|---|---|---|---|---|---|---|
| Accuracy | 0.617 | 0.886 | **+0.269** | 0.830 | 0.946 | **+0.116** |
| Precision | 0.899 | 0.908 | +0.009 | 0.403 | 0.850 | **+0.447** |
| Recall | 0.369 | 0.891 | **+0.521** | 0.039 | 0.822 | **+0.782** |
| F1 | 0.522 | 0.899 | **+0.377** | 0.071 | 0.835 | **+0.763** |
| False alarms ↓ | 0.055 | 0.119 | −0.064 (worse) | 0.009 | 0.029 | −0.020 (worse) |
| ROC-AUC | 0.936 | 0.925 | −0.011 | 0.913 | 0.978 | **+0.065** |
| PR-AUC | 0.911 | 0.901 | −0.010 | 0.534 | 0.891 | **+0.357** |
| Training time | 14.5 s | 4.5 s | **3.2× faster** | 16.4 s | 31.2 s | 1.9× slower |
| Inference | 23.9 ms | 51.8 ms | 2.2× slower | 26.3 ms | 34.9 ms | 1.3× slower |

**Which change contributed what** (ablation, test set, seed 42; each step adds to the
previous one; all choices were fixed beforehand on validation):

| Step | NSL-KDD F1 | NSL-KDD PR-AUC | CIC-IDS2017 F1 | CIC-IDS2017 PR-AUC |
|---|---|---|---|---|
| Original (v1) | 0.554 | 0.913 | 0.143 | 0.590 |
| + feature selection | 0.554 (no change) | 0.913 | 0.068 | 0.605 |
| + tuned detector settings | 0.562 | 0.917 | 0.242 | 0.722 |
| + ensemble redesign | 0.795 | 0.898 | 0.734 | **0.905** |
| + tuned threshold (= v2) | **0.907** | 0.898 | **0.876** | 0.905 |

## 11. Discussion

1. **On CIC-IDS2017 the detector itself got better, not just the threshold.** PR-AUC
   rose from 0.53 to 0.89 and ROC-AUC from 0.91 to 0.98. The biggest single gains came
   from dropping the weak detectors (W1, +0.18 PR-AUC) and from tuning LOF and the
   autoencoder (W3, +0.12 PR-AUC). Training and test results match closely, so the
   gain generalises.
2. **On NSL-KDD most of the F1 gain is an operating-point trade.** v2's ranking quality
   (ROC-AUC and PR-AUC) is about **0.01 lower** than v1's on test, even though it was
   higher on validation. The F1 gain (0.52 → 0.90) comes from the ensemble redesign and
   the lower threshold. It catches 2.4× as many attacks at the cost of **twice the false
   alarms** (5.5% → 11.9%). Precision stayed at about 0.91, so most alerts are still
   real attacks. Whether this trade is acceptable is an operational decision.
3. **Why false alarms rise more on test than planned:** NSL-KDD's normal traffic in the
   test file looks different from that in the training file. The 95th-percentile
   threshold gave 4.6% false alarms on training data but 11.8% on test. v1 shows the
   same jump (0.9% → 6.2%). This is a property of the dataset, not overfitting:
   CIC-IDS2017, with no such shift, shows identical training and test false-alarm rates.
4. **Unknown attacks — the main argument for this module:**
   - **NSL-KDD:** v2 catches **84.5%** of attack types never seen in training (v1: 41.2%).
     The hybrid's classifier adds almost nothing there (85.1%), because a supervised
     model cannot recognise new attack types.
   - **CIC-IDS2017** (every test attack type also appears in training): the classifier
     lifts recall from 82% to **99.7%**.
   - So the two parts do complementary jobs, which justifies the hybrid design.
5. **Remaining blind spots of v2 on CIC-IDS2017** (seed 42): SSH-Patator (1% caught),
   web attacks (0–2%), Bot (6%), DoS Slowhttptest (46%; v1 caught 62%). These flows look
   statistically like normal traffic. Only the hybrid's classifier catches them, and only
   because they appear in training. On NSL-KDD, `mailbomb` (1%) and `snmpgetattack` (26%)
   remain hard.
6. **What did not work:**
   - The **"tail" score normalisation** (W7) lost to the original rank method on both
     datasets (best tail option: CIC-IDS2017 0.825 vs rank 0.935 PR-AUC), so W7 was not
     a real problem. The code is kept as an option, off by default.
   - **Correlation-based feature selection** on its own *lowered* F1 at the original
     threshold on CIC-IDS2017 (0.143 → 0.068), though PR-AUC rose (0.590 → 0.605). It
     helped once combined with the later stages.
   - On NSL-KDD, the **autoencoder** grid gave no gain, so its v1 setting was kept, and
     the autoencoder was then dropped from the ensemble.
7. **Speed:** v2 trains 3.2× faster on NSL-KDD because it uses only two detectors. It
   trains 1.9× slower on CIC-IDS2017 because the autoencoder runs for up to 200 epochs.
   Inference is slower on both (LOF now compares each flow against 30,000 reference
   flows), but at under 60 ms per 1,000 flows it is still fast enough for batch use.
8. **Stability:** v2 is more stable than v1 in F1, but not fully stable. CIC-IDS2017 F1
   was 0.876, 0.852 and 0.776 across seeds; the spread comes from the autoencoder's
   random initialisation. The hybrid is very stable (F1 0.930–0.932).

## 12. Limitations and future work

**Limitations:**
- **One validation split, not k-fold cross-validation.** Repeated seeds measure model
  variance but not split variance.
- **Small search space.** 19 detector settings and 60 ensemble options were tried; a
  wider search might find more.
- **The test set was seen once before this study.** In my earlier status analysis, I
  looked at CIC-IDS2017 test results and noticed that LOF and the autoencoder were the
  strongest pair. The automated validation search independently chose the same pair, but
  this earlier look is disclosed as a possible source of bias.
- **CIC-IDS2017 is a 10% sample** of the deduplicated data, and its labels are known to
  contain errors.
- **The hybrid needs labelled attacks** for training, and its classifier part will not
  generalise to new attack types (see 11.4).
- **The thresholds were tuned for F1.** A real deployment may need a fixed false-alarm
  budget instead; use `threshold_percentile` in the config for that.

**Future work:**
- Recalibrate thresholds on recent normal traffic to handle drift (the NSL-KDD false-alarm jump).
- Use k-fold or time-based validation.
- Add flow-sequence features to catch slow or low-volume attacks (SSH-Patator, Slowhttptest, Bot).
- Average several autoencoder seeds to reduce variance.
- Try gradient boosting for the hybrid's classifier.
- Evaluate on a different dataset than the one tuned on (e.g. tune on CIC-IDS2017, test on UNSW-NB15).

## 13. Conclusion

The improved model (v2) is a genuine, measured improvement on unseen test data:

- **CIC-IDS2017:** F1 0.07 → **0.84** and PR-AUC 0.53 → **0.89**, with false alarms at 2.9%.
- **NSL-KDD:** F1 0.52 → **0.90**, and unseen attack types caught 41% → **85%**. In
  exchange, false alarms roughly double (5.5% → 11.9%), and threshold-free ranking is
  unchanged (−0.01).

Most of the gain came from:
1. **removing weak detectors from the combined score**;
2. **tuning LOF** (fewer neighbours, more training rows) **and Isolation Forest**;
3. **choosing the alert threshold on validation** instead of fixing it at the 99th percentile.

The **hybrid** (v2 + Random Forest) was the best model on validation and on test
(F1 0.904 and 0.931). It is the recommended configuration when labelled attack data is
available. The anomaly part still covers attack types the classifier has never seen.

## Deliverables

| Item | Location |
|---|---|
| Original model (preserved) | `archive/original_v1/` (code, config, tests, results); `configs/baseline.yaml` |
| Improved model | `anomaly_detection/` (v2 options), `anomaly_detection/hybrid.py`, `configs/improved_nsl-kdd.yaml`, `configs/improved_cicids2017.yaml` |
| Scripts | `experiments/run_all.sh`, `experiments/tune.py`, `experiments/evaluate.py`, `experiments/make_figures.py` |
| Results and tables | `reports/improvement/<dataset>/results.md`, `results.json`, `tuning.json`; logs in `reports/improvement/*_log.txt` |
| Figures | `reports/improvement/<dataset>/figures/` (9 per dataset) |
| Saved models (seed 42) | Best by validation: `models/hybrid_nsl-kdd.joblib`, `models/hybrid_cicids2017.joblib`. Also `models/improved_*.joblib` and `models/baseline_*.joblib`. |
| Dependencies | `requirements.txt` (unchanged; no new packages needed) |
