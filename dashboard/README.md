# ACDS Console

Web console for the FYP **AI-Based Autonomous Cyber Defense System** (SZABIST). It is
module 12 of the proposal (Dashboard & Feedback) and the integration layer (objective O6):
one place to run every analysis module, see their findings together, and give feedback.

The workflow follows vulnerability and penetration-testing consoles such as Nessus and Metasploit Pro:
**pick a scan template (module) → choose input → run → review findings by severity and host →
mark each finding as confirmed / false positive / resolved.**

| # | Module | Owner | In console |
|---|---|---|---|
| 2 | Anomaly Detection | Hammad Qureshi | ✅ runs |
| 3 | Threat Classification | Muhammad Bilal Khan | adapter written, not yet run (needs its env, see below) |
| 5 | Malware Classification | Nair Abbas | adapter written, not yet run (needs its env, see below) |
| 12 | Dashboard & Feedback | Team | this console |
| 1, 4, 6–11 | Monitoring, logs, correlation, vuln, attack path, prediction, risk, agent | Team | listed as planned |

## Architecture

```
React UI (Vite)  ──HTTP /api──▶  FastAPI backend  ──subprocess──▶  workers/<module>_worker.py
 frontend/                        backend/app/                      runs inside modules/<name>/
                                  SQLite: var/acds.sqlite3          with that module's .venv
```

Each module keeps its own folder and Python environment, because their pinned libraries
conflict. The backend launches a small worker script inside that environment and reads back
findings in one common JSON format (`workers/README.md`). Adding a module = one worker
script + one entry in `backend/app/modules.py`.

## Run

```bash
./start.sh            # builds the UI, serves everything on http://127.0.0.1:8000
./start.sh dev        # hot-reload: UI on http://127.0.0.1:5173, API on :8000
```

API docs: http://127.0.0.1:8000/docs

**Demo inputs.** Built-in samples are generated from the local datasets (they are not committed):

```bash
../modules/anomaly_detection/.venv/bin/python samples/make_samples.py
```

## Connecting the modules

Each module in `../modules/<name>/` runs with its own Python environment at
`../modules/<name>/.venv`. The Modules page says what is missing. To use other locations,
copy `acds.config.example.json` to `acds.config.json`, or set env vars such as
`ACDS_THREAT_DIR` / `ACDS_THREAT_PYTHON`.

- **Anomaly Detection**: `cd modules/anomaly_detection && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`,
  then train the models (`bash experiments/run_all.sh`; they are not committed, about 130 MB).
- **Threat Classification**: needs **Python 3.10/3.11** (it pins `numpy<2`, `scikit-learn<1.6`):
  `cd modules/threat_classification && python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt`.
  CIC-IDS2017 column names are mapped to the CIC-IDS2018 names it was trained on.
- **Malware Classification**: `cd modules/malware_classification && python3 -m venv .venv &&
  .venv/bin/pip install catboost scikit-learn pandas joblib`. Input is a BODMAS feature CSV
  (`feature_0` … `feature_2325`).

## Scope

Recommended actions (BLOCK / ALERT / quarantine) are text for the analyst. The console never
executes them, which matches the proposal's exclusion of automatic control of production systems.
