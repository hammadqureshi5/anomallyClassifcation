# Contributing

Notes for the ACDS project team working alongside this module.

## Scope of this repository

This repository owns **threat detection and classification only** — the two
model tiers, the preprocessing pipeline, and the alert context they produce.

Out of scope here: the user interface, the API or transport layer, alert
storage, and automated response actions. Those belong to the sibling modules.
This one is a library they import.

## Getting set up

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
pip install -e .
```

Confirm nothing is broken before you start:

```bash
python -m acds.threat_classifier     # mocked smoke test, no data needed
python -m acds.threat_classifier infer   # real models, synthetic flow
```

## The contract other modules depend on

Treat these as a public API. Changing any of them breaks the UI and the
response engine, so coordinate first and bump `schema_version`.

- `ThreatClassificationSystem.load(directory)`
- `ThreatClassificationSystem.inspect_traffic_flow(flow: dict) -> dict`
- The alert context shape documented in [`docs/alert_schema.md`](docs/alert_schema.md)
- The `severity` and `action` value sets

Additive changes — a new optional field, a new MITRE mapping entry — are safe.

## Model artifacts

`acds_models/` is committed so the rest of the team can run inference without
the 6.5 GB dataset or an eight-hour training run.

- Do **not** hand-edit the artifacts.
- Replace them only by retraining, and say what changed in the commit message:
  which dataset days, which classes, and the resulting macro F1.
- Keep `scikit-learn` inside the `requirements.txt` bounds. The pickles are
  version-coupled and will fail to load outside them.

## Datasets

Never commit data. `.gitignore` already excludes `data/` and all `*.csv`, but
check `git status` before committing anyway — a stray 3.8 GB CSV in history
cannot be removed cleanly once pushed.

## Code conventions

- Python 3.10+, type hints on public functions.
- Line length 100 (`ruff` config is in `pyproject.toml`).
- Keep the numbered section banners in `threat_classifier.py`; they are the
  navigation scheme for an 800-line module.
- No `print` in library code — use the module `log`. `print` is fine in
  `examples/` and the CLI demo.

## Tests

```bash
pip install pytest
pytest
```

Add a test when you change the alert shape, the severity thresholds, or the
pickle-loading path. The last one has broken silently before.

## Commits and branches

- Branch off `main`: `feature/<short-name>`, `fix/<short-name>`.
- Imperative, scoped commit subjects: `Add PortScan class to MITRE map`.
- Open a pull request rather than pushing to `main`, so the module's consumers
  get a chance to see interface changes before they land.
