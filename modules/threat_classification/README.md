# ACDS — Threat Classification Module

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![LightGBM](https://img.shields.io/badge/tier%201-LightGBM-success)
![CatBoost](https://img.shields.io/badge/tier%202-CatBoost-yellow)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Network threat detection and classification for the **Autonomous Cyber Defense
System (ACDS)**. This repository contains the machine-learning module only: it
consumes a single network flow and returns a structured, severity-scored alert
mapped to MITRE ATT&CK. It is designed to be imported by the other ACDS
components (dashboard, API layer, response engine) rather than run standalone.

---

## Architecture

Detection is split into two tiers so that the expensive multi-class model only
sees traffic the cheap binary model has already flagged.

```
                     ┌────────────────────────────────┐
  raw flow (dict) ──▶│  Preprocessing pipeline        │
                     │  · drop identifier columns     │
                     │  · log1p + RobustScaler        │
                     │  · OneHot (Protocol)           │
                     │  · TargetEncoder (Dst Port)    │
                     │  · median imputation           │
                     └───────────────┬────────────────┘
                                     ▼
                     ┌────────────────────────────────┐
         TIER 1      │  LightGBM binary detector      │
                     │  Normal  ·  Anomalous          │
                     └───────┬────────────────┬───────┘
                   Normal    │                │  Anomalous
                   (fast     │                ▼
                    path)    │  ┌────────────────────────────────┐
                             │  │  CatBoost multi-class          │
                             │  │  DoS · Brute Force · PortScan  │
                             │  │  Web Exploit · Exfiltration …  │
                             │  └───────────────┬────────────────┘
                             │                  ▼
                             │  ┌────────────────────────────────┐
                             │  │  MITRE ATT&CK / ATLAS mapping  │
                             │  └───────────────┬────────────────┘
                             ▼                  ▼
                     ┌────────────────────────────────┐
                     │  structured alert context JSON │
                     │  verdict · severity · action   │
                     └────────────────────────────────┘
```

**Why two tiers.** Benign traffic dominates real networks, so Tier 1 is tuned
for recall on anomalies (`scale_pos_weight`) and returns immediately on normal
flows. Only anomalous flows reach Tier 2, which is trained exclusively on the
anomalous subset with `SMOTETomek` resampling — this keeps the rare attack
classes from being drowned out by benign samples.

---

## Repository layout

```
acds-threat-classification/
├── acds/
│   ├── __init__.py              # public API surface
│   └── threat_classifier.py     # pipeline, both tiers, CLI
├── acds_models/                 # trained artifacts (committed, ~29 MB)
│   ├── preprocessor.pkl
│   ├── tier1_lgbm.pkl
│   ├── tier2_catboost.cbm
│   ├── label_encoder.pkl
│   └── meta.json
├── examples/
│   └── integration_demo.py      # how other modules call this one
├── tests/
│   └── test_pickle_compat.py
├── data/                        # datasets live here, git-ignored
│   └── README.md                # download instructions
├── docs/
│   └── alert_schema.md
├── requirements.txt
└── pyproject.toml
```

---

## Installation

Python 3.10 or newer.

```bash
git clone https://github.com/<owner>/acds-threat-classification.git
cd acds-threat-classification

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

To import the package from anywhere in your own project, install it in editable
mode instead:

```bash
pip install -e .
```

Verify the install without needing a dataset — this runs the interface with
mocked models:

```bash
python -m acds.threat_classifier
```

---

## Using this module from another ACDS component

This is the integration path for the dashboard / API / response engine. Load the
models **once** at process start, then call `inspect_traffic_flow` per flow.

```python
from acds import ThreatClassificationSystem

# Load once — this reads ~29 MB from disk, do not do it per request.
system = ThreatClassificationSystem.load("acds_models")

flow = {
    "Flow Duration":    1_200_000,
    "Tot Fwd Pkts":     450,
    "Tot Bwd Pkts":     5,
    "TotLen Fwd Pkts":  580_000,
    "Flow Byts/s":      483_333,
    "Flow Pkts/s":      379,
    "Protocol":         "6",      # 6 = TCP
    "Dst Port":         "80",
    "Src IP":           "192.168.1.50",   # identifiers are dropped internally
}

alert = system.inspect_traffic_flow(flow)
print(alert["severity"], alert["tier2"]["threat_category"])
```

Notes for callers:

- **Missing keys are tolerated.** The pipeline imputes absent numeric features
  with training-time medians, so a partial telemetry row will not raise.
- **Identifier columns are dropped automatically** (`Src IP`, `Dst IP`,
  `Timestamp`, `Flow ID`, and the Edge-IIoTset equivalents). You can pass them
  through without filtering first.
- **The return value is JSON-serialisable** — safe to hand straight to
  `jsonify`, a WebSocket frame, or a message queue.
- **`load()` is not thread-safe**; call it during startup, not inside a request
  handler. The resulting object is read-only afterwards and safe to share.

---

## Alert context schema

Full field reference in [`docs/alert_schema.md`](docs/alert_schema.md). An
anomalous flow returns:

```json
{
  "schema_version": "1.2",
  "timestamp_utc": "2026-11-11T15:42:08.511430+00:00",
  "tier1": {
    "verdict": "Anomalous",
    "confidence": 0.951204
  },
  "tier2": {
    "threat_category": "DoS attacks-Hulk",
    "confidence": 0.873102,
    "class_probabilities": {
      "Benign": 0.001204,
      "DoS attacks-Hulk": 0.873102,
      "SSH-Bruteforce": 0.041203,
      "FTP-BruteForce": 0.084491
    }
  },
  "mitre": {
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service",
    "tactic": "Impact"
  },
  "severity": "HIGH",
  "action": "BLOCK"
}
```

A normal flow short-circuits after Tier 1, with `tier2` and `mitre` set to
`null`, `severity` `"INFO"` and `action` `"ALLOW"`.

Severity is derived from the Tier 2 confidence:

| Tier 2 confidence | Severity   | Action  |
| ----------------- | ---------- | ------- |
| ≥ 0.90            | `CRITICAL` | `BLOCK` |
| ≥ 0.70            | `HIGH`     | `BLOCK` |
| ≥ 0.50            | `MEDIUM`   | `ALERT` |
| < 0.50            | `LOW`      | `ALERT` |

---

## MITRE ATT&CK coverage

Predicted labels are fuzzy-matched against a built-in mapping table
(`acds.MITRE_MAP`), falling back to the ATLAS entry `AML.T0043` for
unrecognised anomalies.

| Threat class      | Technique   | Tactic             |
| ----------------- | ----------- | ------------------ |
| DoS               | T1498       | Impact             |
| DDoS              | T1498.001   | Impact             |
| Brute Force       | T1110       | Credential Access  |
| Web Exploit       | T1190       | Initial Access     |
| SQL Injection     | T1190       | Initial Access     |
| Data Exfiltration | T1041       | Exfiltration       |
| PortScan          | T1595       | Reconnaissance     |
| C2                | T1071       | Command and Control|
| Ransomware        | T1486       | Impact             |
| Infiltration      | T1078       | Persistence        |
| MITM              | T1557       | Collection         |
| Backdoor          | T1543       | Persistence        |
| Unknown Anomaly   | AML.T0043   | ATLAS — ML Attack  |

---

## Training

The dataset is **not** in this repository (~6.5 GB). See
[`data/README.md`](data/README.md) for download instructions.

```bash
python -m acds.threat_classifier train data/cic_ids2018/*.csv
```

This fits the preprocessor, both tiers, and overwrites `acds_models/`.
Cross-validation uses `GroupKFold` on `Session_ID` to keep flows from the same
attack session out of both train and validation folds — plain `KFold` leaks and
inflates scores badly on this dataset.

Run the committed models against the built-in synthetic flow:

```bash
python -m acds.threat_classifier infer
```

---

## Known limitations

These are open items, not hidden defects — worth knowing before building on top.

1. **`"Label"` appears as a threat class.** `acds_models/meta.json` lists
   `"Label"` among `threat_classes`, which means repeated CSV header rows were
   ingested as data during the training run that produced the committed models.
   Predictions for that class are meaningless. Filter it in the UI, and drop
   rows where `Label == "Label"` in `load_dataset` before retraining.
2. **The committed models were trained on DoS and brute-force traffic only.**
   `meta.json` covers Benign, four DoS variants, FTP-BruteForce and
   SSH-Bruteforce. The `MITRE_MAP` table is broader than what the current
   models can actually predict; PortScan, C2, ransomware and exfiltration
   classes need the remaining CIC-IDS2018 days included in training.
3. **Pickle artifacts are coupled to library versions.** `preprocessor.pkl` and
   `tier1_lgbm.pkl` are joblib pickles. Stay inside the `requirements.txt`
   bounds (notably `scikit-learn>=1.3,<1.6`) or regenerate them by retraining.
4. **`Session_ID` and `Window_Index` are synthesised** when absent — fixed
   5000-row blocks and a running index. That is a reasonable stand-in for
   grouped CV, but it is not a true attack-session identifier, so grouped
   validation scores remain optimistic.
5. **Single-flow inference only.** `inspect_traffic_flow` handles one flow per
   call. Batch scoring means looping, which is fine at dashboard volumes but not
   at line rate.

---

## Project context

Final Year Project — BS Artificial Intelligence, SZABIST Islamabad.
This repository is the threat classification module of the wider ACDS system;
the user interface and remaining modules are maintained by the project team.

## License

MIT — see [LICENSE](LICENSE).
