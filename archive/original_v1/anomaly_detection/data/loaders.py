"""Dataset loaders.

Every loader returns a `Dataset` with the same layout, so the rest of the module does not
care where the data came from:

- X           feature columns (numeric and/or categorical)
- y           1 = attack, 0 = benign, or None when the data has no labels
- attack_type attack name per row ("benign" for normal traffic), or None
- meta        context columns used in alerts: src_ip, dst_ip, dst_port, timestamp
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

META_COLUMNS = ["src_ip", "dst_ip", "dst_port", "timestamp"]

# Column names used by common datasets/tools, mapped to our standard meta names.
META_ALIASES = {
    "src_ip": ["src_ip", "source ip", "src ip", "srcip", "source_ip"],
    "dst_ip": ["dst_ip", "destination ip", "dst ip", "dstip", "destination_ip"],
    "dst_port": ["dst_port", "destination port", "dst port", "dsport", "destination_port"],
    "timestamp": ["timestamp", "time", "stime", "ts"],
}
# Identifier columns that must never be used as features.
ID_COLUMNS = {"flow id", "flow_id", "source port", "src_port", "sport", "id"}
# dst_port carries signal (e.g. scans hit unusual ports), so it stays a feature as well.
META_KEPT_AS_FEATURE = {"dst_port"}
BENIGN_LABELS = {"benign", "normal", "0"}


@dataclass
class Dataset:
    X: pd.DataFrame
    y: np.ndarray | None = None
    attack_type: pd.Series | None = None
    meta: pd.DataFrame | None = None

    def __post_init__(self):
        self.X = self.X.reset_index(drop=True)
        if self.meta is None:
            self.meta = pd.DataFrame(index=self.X.index, columns=META_COLUMNS)
        self.meta = self.meta.reset_index(drop=True).reindex(columns=META_COLUMNS)
        if self.attack_type is not None:
            self.attack_type = self.attack_type.reset_index(drop=True)
        if self.y is not None:
            self.y = np.asarray(self.y, dtype=int)

    def __len__(self) -> int:
        return len(self.X)

    def subset(self, mask_or_idx) -> "Dataset":
        idx = np.flatnonzero(mask_or_idx) if np.asarray(mask_or_idx).dtype == bool else np.asarray(mask_or_idx)
        return Dataset(
            X=self.X.iloc[idx],
            y=None if self.y is None else self.y[idx],
            attack_type=None if self.attack_type is None else self.attack_type.iloc[idx],
            meta=self.meta.iloc[idx],
        )

    def to_frame(self) -> pd.DataFrame:
        """Flatten back to one table (meta + features + labels), e.g. to save as CSV."""
        parts = [self.meta.dropna(axis=1, how="all"), self.X.drop(columns=self.meta.columns, errors="ignore")]
        if self.y is not None:
            parts.append(pd.Series(self.y, name="label"))
        if self.attack_type is not None:
            parts.append(self.attack_type.rename("attack_type"))
        return pd.concat(parts, axis=1)


def _split_frame(df: pd.DataFrame, label_col: str | None, attack_col: str | None = None) -> Dataset:
    """Separate meta, ID, label and feature columns of a raw table."""
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    lower = {c.lower(): c for c in df.columns}

    meta = pd.DataFrame(index=df.index)
    drop = []
    for std_name, aliases in META_ALIASES.items():
        for alias in aliases:
            if alias in lower:
                col = lower[alias]
                meta[std_name] = df[col]
                if std_name not in META_KEPT_AS_FEATURE:
                    drop.append(col)
                break
    drop += [lower[c] for c in ID_COLUMNS if c in lower]

    y = attack_type = None
    if label_col is not None:
        label_col = lower.get(label_col.lower(), label_col)
        if label_col not in df.columns:
            raise ValueError(f"Label column {label_col!r} not found. Columns: {list(df.columns)}")
        labels = df[label_col].astype(str).str.strip()
        y = (~labels.str.lower().isin(BENIGN_LABELS)).astype(int).to_numpy()
        drop.append(label_col)
        if attack_col is None and "attack_type" in lower:
            attack_col = lower["attack_type"]
        if attack_col is not None and attack_col in df.columns:
            attack_type = df[attack_col].astype(str)
            drop.append(attack_col)
        else:
            attack_type = labels.where(y == 1, "benign")
    elif "attack_type" in lower:
        drop.append(lower["attack_type"])

    X = df.drop(columns=list(dict.fromkeys(drop)))
    return Dataset(X=X, y=y, attack_type=attack_type, meta=meta)


def load_csv(path: str | Path, label_col: str | None = None) -> Dataset:
    """Load any flow/event CSV. If `label_col` is given, values like BENIGN/normal/0 count as benign."""
    df = pd.read_csv(path, low_memory=False)
    if label_col is None:
        for candidate in ("label", "Label"):
            if candidate in [str(c).strip() for c in df.columns]:
                label_col = candidate
                break
    return _split_frame(df, label_col)


NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]


def load_nsl_kdd(data_dir: str | Path, split: str = "train") -> Dataset:
    """Load NSL-KDD from `data_dir` (expects KDDTrain+.txt / KDDTest+.txt).

    The test file contains attack types that never appear in training, which is a good
    check of how well the detectors handle unknown attacks.
    """
    filename = {"train": "KDDTrain+.txt", "test": "KDDTest+.txt"}[split]
    path = Path(data_dir) / filename
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Download NSL-KDD (KDDTrain+.txt, KDDTest+.txt) into {data_dir}."
        )
    df = pd.read_csv(path, header=None)
    columns = NSL_KDD_COLUMNS + ["label"]
    if df.shape[1] == len(columns) + 1:
        columns = columns + ["difficulty"]
    df.columns = columns
    df = df.drop(columns=["difficulty"], errors="ignore")
    return _split_frame(df, "label")


def load_cicids2017(data_dir: str | Path, sample_frac: float = 1.0, random_state: int = 42) -> Dataset:
    """Load CIC-IDS2017 flow CSVs (all *.csv files in `data_dir`), sampling each file."""
    files = sorted(Path(data_dir).glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files in {data_dir}. Download CIC-IDS2017 (MachineLearningCSV) into it."
        )
    frames = []
    for path in files:
        part = pd.read_csv(path, low_memory=False, encoding="latin-1")
        if sample_frac < 1.0:
            part = part.sample(frac=sample_frac, random_state=random_state)
        frames.append(part)
    df = pd.concat(frames, ignore_index=True)
    return _split_frame(df, "Label")
