# Module workers

Each ACDS module lives in its own folder (`modules/<name>`) with its own Python environment, because the
modules pin conflicting library versions (for example, the threat classifier's pickles need
scikit-learn < 1.6, while the anomaly models were saved with scikit-learn 1.9). The platform
therefore runs every module as a separate process:

```
<module python> workers/<name>_worker.py --input IN.csv --output OUT.json --options '{"max_rows": "20000"}'
```

The working directory is the module's folder, so the worker can `import` the module's
package and open `models/...` with relative paths.

## Contract

- **stdout**: `PROGRESS 0.42` lines move the progress bar; every other line is shown in the
  scan's Log tab.
- **exit code**: non-zero marks the scan as failed (the last log lines explain why).
- **OUT.json**:

```json
{
  "rows_scanned": 5000,
  "findings": [
    {
      "severity": "critical | high | medium | low | info",
      "title": "Short, groupable title (findings with the same title are grouped)",
      "description": "One or two sentences",
      "host": "asset the finding is filed under (IP, *:port, file hash …)",
      "asset": {"src_ip": "…", "dst_ip": "…", "dst_port": 443, "file": "…"},
      "score": 0.97,
      "confidence": 0.91,
      "mitre": {"technique_id": "T1498", "technique_name": "…", "tactic": "Impact"},
      "evidence": [{"label": "Anomaly score", "value": 0.97}],
      "top_features": [{"feature": "src_bytes", "value": 23618981, "z_score": 10.06, "direction": "high"}],
      "recommendation": "What the analyst should do"
    }
  ]
}
```

`_common.py` has helpers (argument parsing, CSV reading, progress, output). It only needs
pandas, which every module environment has.

## Adding a module

1. Write `workers/<name>_worker.py` following the contract.
2. Add or update its entry in `backend/app/modules.py` (`status="active"`, `worker=…`,
   input type, options, metrics, required model files).
3. Point the platform at the module folder and its Python (see `acds.config.example.json`).
