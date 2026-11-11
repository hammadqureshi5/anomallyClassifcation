"""Alert format: the contract between this module and the response/mitigation module.

`alerts.json` is a list of objects:
{
  "id": "ALERT-000123", "row_index": 123, "timestamp": "...", "src_ip": "...",
  "dst_ip": "...", "dst_port": 22, "score": 0.98, "threshold": 0.95,
  "severity": "low|medium|high", "detector": "ensemble",
  "top_features": [{"feature": "failed_logins", "z_score": 12.3, "direction": "high", "value": 25}]
}
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pandas as pd


@dataclass
class Alert:
    id: str
    row_index: int
    timestamp: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    score: float
    threshold: float
    severity: str
    detector: str
    top_features: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def clean_value(value):
    """Convert numpy/pandas values to plain JSON-friendly Python values."""
    if value is None or (not isinstance(value, (list, dict, str)) and pd.isna(value)):
        return None
    if hasattr(value, "item"):
        value = value.item()
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    return value


def save_alerts(alerts: list[Alert], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [a.to_dict() for a in alerts]
    if path.suffix == ".csv":
        df = pd.DataFrame(records)
        df["top_features"] = df["top_features"].apply(json.dumps) if len(df) else []
        df.to_csv(path, index=False)
    else:
        path.write_text(json.dumps(records, indent=2, default=str))
    return path


def load_alerts(path: str | Path) -> list[Alert]:
    return [Alert(**record) for record in json.loads(Path(path).read_text())]
