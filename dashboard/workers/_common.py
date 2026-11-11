"""Shared helpers for module workers. Standard library + pandas only, because each worker
runs inside a different module's Python environment."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--options", default="{}")
    args = parser.parse_args()
    args.options = json.loads(args.options)
    # Workers run with the module folder as working directory; make its package importable.
    sys.path.insert(0, str(Path.cwd()))
    return args


def log(message: str) -> None:
    print(message, flush=True)


def progress(fraction: float) -> None:
    print(f"PROGRESS {fraction:.3f}", flush=True)


def row_limit(options: dict) -> int | None:
    value = str(options.get("max_rows", "all"))
    return None if value == "all" else int(value)


def read_csv(path: str, max_rows: int | None) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    except UnicodeDecodeError:  # CIC-IDS2017 files are latin-1
        df = pd.read_csv(path, nrows=max_rows, low_memory=False, encoding="latin-1")
    log(f"Loaded {len(df):,} rows x {df.shape[1]} columns")
    return df


def clean(value):
    """Make numpy/pandas values JSON-safe."""
    if value is None:
        return None
    if hasattr(value, "item"):
        value = value.item()
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    return value


def host_for(src_ip=None, dst_ip=None, dst_port=None, fallback: str | None = None) -> str | None:
    """The asset a network finding is filed under: destination host, else source, else service port."""
    for ip in (dst_ip, src_ip):
        if ip not in (None, "") and not (isinstance(ip, float) and math.isnan(ip)):
            return str(ip)
    if dst_port is not None:
        return f"*:{int(float(dst_port))}"
    return fallback


def write_output(path: str, rows_scanned: int, findings: list[dict]) -> None:
    Path(path).write_text(json.dumps({"rows_scanned": int(rows_scanned), "findings": findings}, default=clean))
    log(f"Wrote {len(findings):,} findings")
