# Anomaly Detection Module: Easy Guide

> Part of the FYP **"AI-Based Autonomous Cyber Defense System"** (SZABIST, BS AI, Fall 2026).
> This folder is **Hammad Qureshi's module**: anomaly detection.

This guide explains the project in simple words. Read it from top to bottom once, and you
will understand what the module does, how it works, what the results mean, and how to run it.

---

## 1. The big picture (whole FYP)

Our FYP is a security system made of separate "AI helpers". Each helper looks at a
different kind of evidence:

| Module | Who | What it does | Status |
|---|---|---|---|
| Network Threat Classification | Muhammad Bilal Khan | Looks at network traffic and says **which known attack** it is (DoS, PortScan, …) | Done (prototype) |
| Malware Classification | Nair Abbas | Looks at a Windows program's features and says **malware or not**, and which type | Done (prototype) |
| **Anomaly Detection** | **Hammad Qureshi** (this folder) | Looks at network traffic and says **"this looks unusual"**, even for attacks never seen before | Done (prototype) |
| Log Analysis | Team | Reads system logs | In progress |
| Dashboard, backend, investigation agent, risk analysis, … | Team | Join everything together | Planned |

Right now the three modules work **separately**. Joining them is the next phase.

---

## 2. What does *my* module do? (one-minute version)

Think of a **security guard who has watched a building for months**. The guard doesn't
know every crime in the world, but knows what a **normal day** looks like. When something
odd happens, like someone walking in at 3 a.m. or carrying 50 boxes, the guard notices
it, even if it's a crime the guard has never seen before.

My module works the same way:

1. It studies **only normal network traffic** and learns what "normal" looks like.
2. When new traffic arrives, it measures **how different** each connection is from normal.
3. If it is too different, it raises an **alert** with:
   - a **severity** (low, medium or high), and
   - **why** it looks suspicious, for example "sent 23 MB of data, 10 times more than normal".

**Why is this useful?** The other module (Network Threat Classification) only knows
attacks it was trained on. My module can catch **new, unknown attacks** ("zero-days").
The two complement each other.

---

## 3. How it works, step by step

```
 network traffic  →  1. clean   →  2. detectors  →  3. combine  →  4. threshold  →  5. alert
 (CSV of flows)      the data      give scores      the scores     "too unusual?"     (JSON)
```

**What is a "flow"?** One connection between two computers, summarised as numbers:
how long it lasted, how many bytes and packets were sent, which port was used, and so on.
The datasets give us millions of these rows.

**Step 1: Clean the data (preprocessing).**
Fix missing or broken values. Shrink very large numbers with a log, so that 1,000,000
bytes doesn't overpower everything. Turn words such as "tcp" into numbers. Put all
features on the same scale.

**Step 2: Detectors give each flow a score.** There are four "judges", each with its own way of spotting oddness:

| Detector | Simple idea |
|---|---|
| **Robust z-score** | "Is any single number far from its usual value?" |
| **Isolation Forest** | "Can I separate this flow from the others with just a few random cuts?" Odd points are easy to isolate. |
| **LOF** (Local Outlier Factor) | "Is this flow in an empty area, far from its neighbours?" |
| **Autoencoder** | A small neural network learns to **copy** normal traffic. If it can't copy a flow well, that flow is unusual. |

**Step 3: Combine the scores.** The judges use different scales, so each score is
converted into "how much higher than normal traffic is this?" (a rank from 0 to 1). The
judges' ranks are then combined into one final score.

**Step 4: Threshold.** We choose a cut-off line. Anything above it becomes an alert. The
line is set using normal traffic. For example, "the top 3% most unusual normal flows",
which means about 3% false alarms.

**Step 5: Alert.** Alerts are saved to a JSON file, so later modules (the dashboard and
the response module) can read them. One alert looks like this:

```json
{ "src_ip": "10.0.0.4", "dst_port": 443, "severity": "high",
  "top_features": [{"feature": "src_bytes", "z_score": 10.06, "direction": "high"}] }
```

---

## 4. Version 1 vs version 2 (the improvement work)

- **Version 1 (original):** used all 4 judges equally, with a strict threshold. On real
  data it missed most attacks: only **3.9%** were caught on CIC-IDS2017. The reason was
  that the weak judges "watered down" the strong ones.
- **Version 2 (improved):** we tested many settings and kept only what helped. For
  example, CIC-IDS2017 now uses only LOF + autoencoder, and the threshold is tuned. All
  of this was decided on **validation data**; the test data was never used for choices.
  That's important for honest results.
- **Hybrid:** version 2 plus a Random Forest that learned the known attacks. It catches
  almost everything known, while version 2 covers the unknown ones.

### Results (test data, average of 3 runs)

| Dataset | Model | Attacks caught (recall) | False alarms | F1-score |
|---|---|---|---|---|
| NSL-KDD | Version 1 | 36.9% | 5.5% | 0.52 |
| NSL-KDD | **Version 2** | **89.1%** | 11.9% | **0.90** |
| NSL-KDD | Hybrid | 90.0% | 12.1% | 0.90 |
| CIC-IDS2017 | Version 1 | 3.9% | 0.9% | 0.07 |
| CIC-IDS2017 | **Version 2** | **82.2%** | 2.9% | **0.83** |
| CIC-IDS2017 | Hybrid | 99.7% | 3.0% | 0.93 |

**Best result to remember:** on NSL-KDD, version 2 catches **85% of attack types it has
never seen** (version 1 caught 41%). This is the main reason anomaly detection is needed.

**Be honest about these weak points (examiners like this):**
- False alarms went up, especially on NSL-KDD: 5.5% → 11.9%.
- Some attacks still look "normal" and are missed: SSH brute force, web attacks, Bot.
- Everything is tested on public datasets, not on a real live network yet.

---

## 5. The datasets

| Dataset | What it is | Notes |
|---|---|---|
| **NSL-KDD** | Older but classic network-attack dataset | Its test file has **17 attack types not in the training file**, which makes it perfect for testing unknown attacks |
| **CIC-IDS2017** | Modern traffic recorded over 5 days (DoS, DDoS, PortScan, brute force, web attacks, botnet) | 2.8 million flows. We found **11% duplicate rows** and removed them before splitting, so results aren't inflated. |

The data files are in the repository-level `data/anomaly_detection/NSL-KDD/` and `data/anomaly_detection/CIC-IDS2017/`.

---

## 6. What is in each folder?

```
modules/anomaly_detection/
├── anomaly_detection/      ← the actual module (the code)
│   ├── data/               ← reads datasets; can also make fake test traffic
│   ├── features/           ← step 1: cleaning and scaling
│   ├── detectors/          ← step 2–3: the 4 judges + combining them
│   ├── thresholding.py     ← step 4: the cut-off line and severity
│   ├── explain.py          ← "why" each alert happened
│   ├── alerts.py           ← step 5: the alert format
│   ├── pipeline.py         ← joins all steps (train / detect / save / load)
│   ├── hybrid.py           ← version 2 + Random Forest
│   ├── evaluation.py       ← calculates scores and draws graphs
│   └── cli.py              ← the commands you type in the terminal
├── configs/                ← settings files (baseline = v1, improved_* = v2)
├── experiments/            ← scripts used for the v1 vs v2 study
├── models/                 ← saved, trained models (ready to use)
├── reports/
│   ├── improvement/        ← ★ full results, graphs, TECHNICAL_REPORT.md
│   └── alerts.json         ← example alerts
├── tests/                  ← automatic checks that the code works (15 tests)
└── archive/original_v1/    ← untouched copy of version 1
```

**The three most useful files for you to read:**
1. `reports/improvement/TECHNICAL_REPORT.md`: full details of the improvement study.
2. `reports/improvement/cicids2017/figures/` and `reports/improvement/nsl-kdd/figures/`: all graphs.
3. `docs/FYP_Midterm_Report/main.pdf` (at the repository root): the mid-term report.

---

## 7. How to run it

Open a terminal in this folder. The libraries are already installed in `.venv`.

**Check that everything works (about 5 seconds):**
```bash
.venv/bin/python -m pytest -q
```

**Quick demo with fake traffic (no dataset needed):**
```bash
.venv/bin/python -m anomaly_detection.cli evaluate --dataset synthetic
```

**Find alerts in a CSV file of traffic:**
```bash
.venv/bin/python -m anomaly_detection.cli generate --out ../../data/anomaly_detection/processed/sample_traffic.csv
.venv/bin/python -m anomaly_detection.cli detect --input ../../data/anomaly_detection/processed/sample_traffic.csv --output reports/alerts.json
```
Then open `reports/alerts.json` to see the alerts.

**Run the improved model (v2) on the real datasets:**
```bash
.venv/bin/python -m anomaly_detection.cli --config configs/improved_nsl-kdd.yaml evaluate --dataset nsl-kdd
.venv/bin/python -m anomaly_detection.cli --config configs/improved_cicids2017.yaml evaluate --dataset cicids2017
```

**Repeat the whole v1 vs v2 study (about 15 minutes):**
```bash
bash experiments/run_all.sh
```

---

## 8. Words you should know (glossary)

| Word | Simple meaning |
|---|---|
| **Anomaly** | Something unusual, different from normal |
| **Unsupervised** | Learns without being told the right answers; here, it learns from normal traffic only |
| **Supervised** | Learns from labelled examples ("this is DoS", "this is normal") |
| **Zero-day attack** | A new attack nobody has seen before |
| **Flow** | A summary of one connection between two computers |
| **Feature** | One number describing a flow (e.g. bytes sent) |
| **Threshold** | The cut-off score; above it, we raise an alert |
| **Recall** | Out of all real attacks, how many we caught |
| **Precision** | Out of all our alerts, how many were real attacks |
| **False alarm (false-positive rate)** | Normal traffic wrongly flagged as an attack |
| **F1-score** | One number that balances precision and recall (1.0 is perfect) |
| **ROC-AUC / PR-AUC** | How well the model ranks attacks above normal traffic, at any threshold (1.0 is perfect) |
| **Validation data** | Data used to choose settings |
| **Test data** | Data kept hidden until the very end, for the final honest score |
| **Data leakage** | When test data accidentally helps training, so results look better than they really are |

---

## 9. Likely viva questions, with short answers

**Q: Why anomaly detection if you already have a classifier?**
The classifier only knows attacks it was trained on. Anomaly detection learns "normal"
and can flag new attacks. On NSL-KDD it caught 85% of attack types never seen in training.

**Q: Why not just use accuracy?**
Attacks are rare. A model that says "everything is normal" can still have high accuracy
while catching nothing. That's why we report recall, precision, F1 and PR-AUC.

**Q: How did you make sure your results are honest?**
We tuned only on validation data, kept the test data hidden until the end, removed
duplicate rows from CIC-IDS2017, and averaged over 3 runs.

**Q: What is the main weakness?**
More false alarms (11.9% on NSL-KDD) and some attacks that look normal (SSH brute force,
Bot). The threshold also needs re-tuning for each real network.

**Q: How will it connect to the other modules?**
It writes alerts in JSON. The planned backend will collect these alerts together with
the network and malware modules' results and show them on the dashboard.

---

## 10. For developers (technical reference)

- **Use it from Python:**
  ```python
  from anomaly_detection import AnomalyPipeline, load_csv
  pipe = AnomalyPipeline.load("models/improved_cicids2017.joblib")
  result = pipe.detect(load_csv("flows.csv"))
  ```
- **Alert fields:** `id, row_index, timestamp, src_ip, dst_ip, dst_port, score, threshold,
  severity, detector, top_features`.
- **Add a new detector:** subclass `BaseDetector`, implementing `fit` and `score` (a higher
  score means more unusual). Then register it in `detectors/__init__.py` and add its name
  to `detectors:` in the config.
- **Setup from scratch:**
  ```bash
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
  ```
