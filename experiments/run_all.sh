#!/usr/bin/env bash
# Reproduce the whole before-and-after study (about 15 minutes on a 12-core machine).
#   bash experiments/run_all.sh
# 1. tests  2. validation-only tuning -> configs/improved_<dataset>.yaml
# 3. final test-set evaluation -> reports/improvement/<dataset>/ (results, figures) and models/
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python

$PY -m pytest -q
for ds in nsl-kdd cicids2017; do
  $PY -m experiments.tune --dataset "$ds"
  $PY -m experiments.evaluate --dataset "$ds"
done
echo "Done. See reports/improvement/TECHNICAL_REPORT.md and reports/improvement/<dataset>/results.md"
