# ACDS: AI-Based Autonomous Cyber Defense System

Final Year Project, BS Artificial Intelligence, SZABIST Islamabad.
Supervisor: Muhammad Hasaan Mujtaba.

ACDS is a modular platform in which separate machine-learning modules analyse different kinds of
security evidence and report their findings in one common format. A web console runs the
modules and shows their results together, with analyst feedback on every finding.

## Repository layout

```
dashboard/                          Web console: FastAPI backend + React UI (module 12)
modules/
  anomaly_detection/                Anomaly detection: Hammad Qureshi
  threat_classification/            Network threat classification: Muhammad Bilal Khan
  malware_classification/           Malware classification: Nair Abbas
docs/
  FYP_Midterm_Report/               LaTeX mid-term report (main.pdf)
```

Each module is self-contained, with its own README, requirements and **its own Python
environment** (`modules/<name>/.venv`). They pin conflicting library versions, so they must not share one.
The dashboard runs each module as a separate process (see `dashboard/workers/README.md`).

## Modules (from the project proposal)

| # | Module | Owner | Status |
|---|---|---|---|
| 1 | Network Monitoring | Team | Planned |
| 2 | Anomaly Detection | Hammad Qureshi | Done (prototype), runs in the dashboard |
| 3 | Threat Classification | Muhammad Bilal Khan | Done (prototype), dashboard adapter written, not yet run |
| 4 | Log Analysis | Team | In progress |
| 5 | Malware Classification | Nair Abbas | Done (prototype), dashboard adapter written, not yet run |
| 6–11 | Incident Correlation, Vulnerability Analysis, Attack-Path Analysis, Attack Prediction, Risk Analysis, Investigation Agent | Team | Planned |
| 12 | Dashboard & Feedback | Team | Working prototype (`dashboard/`) |

## Quick start

```bash
# 1. Set up the environment of each module you want to use (see each module's README)
cd modules/anomaly_detection && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && cd ../..
cd modules/threat_classification && python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt && cd ../..
cd modules/malware_classification && python3 -m venv .venv && .venv/bin/pip install catboost scikit-learn pandas joblib && cd ../..

# 2. Start the console → http://127.0.0.1:8000
./dashboard/start.sh
```

Datasets (CIC-IDS2017, NSL-KDD, CSE-CIC-IDS2018, BODMAS) are not committed. See each module's
README for download instructions.

## Adding a module

Create `modules/<name>/` with its code and models, write a worker in `dashboard/workers/`,
and register the module in `dashboard/backend/app/modules.py`. The worker contract is in
`dashboard/workers/README.md`.

## History

The threat and malware modules were imported with `git subtree`, so their original commits
and authors are preserved. Their original repositories were
[MuhmmadBilalKhan/acds-threat-classification](https://github.com/MuhmmadBilalKhan/acds-threat-classification) and
[Nair-Abbas/malwarec-classification](https://github.com/Nair-Abbas/malwarec-classification).
