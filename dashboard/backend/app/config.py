"""Paths and per-module settings.

Every analysis module lives in its own folder under modules/ with its own Python environment
(their pinned library versions conflict, e.g. scikit-learn <1.6 vs 1.9), so the platform
runs each one as a separate worker process. Paths default to modules/<name> and
modules/<name>/.venv and can be overridden with environment variables or `acds.config.json`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

PLATFORM_DIR = Path(__file__).resolve().parents[2]
MODULES_DIR = PLATFORM_DIR.parent / "modules"
WORKERS_DIR = PLATFORM_DIR / "workers"
DATA_DIR = Path(os.environ.get("ACDS_DATA_DIR", PLATFORM_DIR / "var"))
UPLOAD_DIR = DATA_DIR / "uploads"
RESULTS_DIR = DATA_DIR / "results"
SAMPLES_DIR = PLATFORM_DIR / "samples"
DB_PATH = DATA_DIR / "acds.sqlite3"
FRONTEND_DIST = PLATFORM_DIR / "frontend" / "dist"

for _d in (DATA_DIR, UPLOAD_DIR, RESULTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

_file_config: dict = {}
_config_path = PLATFORM_DIR / "acds.config.json"
if _config_path.exists():
    _file_config = json.loads(_config_path.read_text())


def _setting(module_id: str, key: str, default: Path) -> Path:
    env = os.environ.get(f"ACDS_{module_id.upper()}_{key.upper()}")
    if env:
        return Path(env)
    value = _file_config.get(module_id, {}).get(key)
    return Path(value) if value else default


def module_paths(module_id: str, default_dir: Path) -> tuple[Path, Path]:
    """Return (module directory, python interpreter) for a module."""
    directory = _setting(module_id, "dir", default_dir)
    python = _setting(module_id, "python", directory / ".venv" / "bin" / "python")
    return directory, python


ANOMALY_DIR, ANOMALY_PYTHON = module_paths("anomaly", MODULES_DIR / "anomaly_detection")
THREAT_DIR, THREAT_PYTHON = module_paths("threat", MODULES_DIR / "threat_classification")
MALWARE_DIR, MALWARE_PYTHON = module_paths("malware", MODULES_DIR / "malware_classification")
