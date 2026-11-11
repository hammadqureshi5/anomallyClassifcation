"""Evaluation protocol shared by every experiment, so all models see identical data.

- train / test: the data used for final fitting and the final, untouched evaluation.
  * nsl-kdd    : official KDDTrain+ / KDDTest+ files (17 test attack types are unseen in training).
  * cicids2017 : duplicates and label conflicts removed BEFORE splitting (corrected protocol),
                 10% sample, stratified 70/30 split. Fixed seed, so the test set never changes.
- fit / val: a stratified 80/20 split of TRAIN only. All tuning decisions are made on `val`;
  the test set is never used for any choice.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

from anomaly_detection.data import Dataset, load_cicids2017, load_nsl_kdd

ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = ROOT.parents[1] / "data" / "anomaly_detection"  # repository-level data/ folder
DATA_DIRS = {"nsl-kdd": DATA_ROOT / "NSL-KDD", "cicids2017": DATA_ROOT / "CIC-IDS2017"}
CACHE_DIR = DATA_ROOT / "processed"
REPORT_DIR = ROOT / "reports/improvement"
DATASETS = list(DATA_DIRS)
SPLIT_SEED = 42          # fixed: defines the test set
MODEL_SEEDS = [42, 43, 44]  # repeated runs for mean ± std
CIC_SAMPLE_FRAC = 0.1


def _stratified(ds: Dataset, test_size: float, seed: int) -> tuple[Dataset, Dataset]:
    idx = np.arange(len(ds))
    a, b = train_test_split(idx, test_size=test_size, random_state=seed, stratify=ds.y)
    return ds.subset(a), ds.subset(b)


def load_splits(dataset: str) -> tuple[Dataset, Dataset]:
    """(train, test) for a dataset under the protocol above, cached after the first load."""
    if dataset == "nsl-kdd":
        return load_nsl_kdd(DATA_DIRS[dataset], "train"), load_nsl_kdd(DATA_DIRS[dataset], "test")
    if dataset == "cicids2017":
        cache = CACHE_DIR / f"cicids2017_dedup_frac{CIC_SAMPLE_FRAC}_seed{SPLIT_SEED}.joblib"
        if cache.exists():
            return joblib.load(cache)
        ds = load_cicids2017(DATA_DIRS[dataset], CIC_SAMPLE_FRAC, SPLIT_SEED, drop_duplicates=True)
        splits = _stratified(ds, 0.3, SPLIT_SEED)
        cache.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(splits, cache)
        return splits
    raise ValueError(f"dataset must be one of {DATASETS}")


def tuning_split(train: Dataset) -> tuple[Dataset, Dataset]:
    """(fit, val) carved from TRAIN only; used for every tuning decision."""
    return _stratified(train, 0.2, SPLIT_SEED)


def describe(ds: Dataset) -> dict:
    return {"rows": len(ds), "attacks": int(ds.y.sum()), "benign": int((ds.y == 0).sum()),
            "attack_types": int(ds.attack_type[ds.y == 1].nunique())}
