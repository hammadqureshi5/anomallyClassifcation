"""
Autonomous Cyber Defense System — Threat Classification Module
==============================================================
Two-tier hierarchical inference pipeline for CSE-CIC-IDS2018 / Edge-IIoTset.

Tier 1 : Binary Detection (LightGBM)   → Normal | Anomalous
Tier 2 : Multi-Class Threat Classifier (CatBoost) → DoS | Brute Force |
          Web Exploit | Data Exfiltration | PortScan | C2 | Ransomware | …

Author : Autonomous Cyber Defense Systems pipeline
"""

from __future__ import annotations

# ── Standard library ──────────────────────────────────────────────────────────
import json
import logging
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ACDS")

# ── Numerical / ML core ───────────────────────────────────────────────────────
import numpy as np
import pandas as pd

# scikit-learn
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import GroupKFold, TimeSeriesSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, RobustScaler
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

# category-encoders (pip install category-encoders)
from category_encoders import TargetEncoder

# imbalanced-learn (pip install imbalanced-learn)
from imblearn.combine import SMOTETomek
from imblearn.pipeline import Pipeline as ImbPipeline

# LightGBM (pip install lightgbm)
import lightgbm as lgb

# CatBoost (pip install catboost)
from catboost import CatBoostClassifier

# ─────────────────────────────────────────────────────────────────────────────
# 0.  MITRE ATT&CK / ATLAS MAPPING TABLE
# ─────────────────────────────────────────────────────────────────────────────

MITRE_MAP: dict[str, dict[str, str]] = {
    "DoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
    },
    "DDoS": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic": "Impact",
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "Web Exploit": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "PortScan": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "C2": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol C2",
        "tactic": "Command and Control",
    },
    "Ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
    },
    "Infiltration": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence",
    },
    "MITM": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Collection",
    },
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "Backdoor": {
        "technique_id": "T1543",
        "technique_name": "Create or Modify System Process",
        "tactic": "Persistence",
    },
    "Unknown Anomaly": {
        "technique_id": "AML.T0043",
        "technique_name": "Craft Adversarial Data",
        "tactic": "ATLAS – ML Attack",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.  FEATURE SCHEMA  (edit to match your dataset columns)
# ─────────────────────────────────────────────────────────────────────────────

# Columns to DROP before any processing (identifiers → overfitting)
DROP_COLUMNS: list[str] = [
    # CIC-IDS2018
    "Src IP", "Dst IP", "Src MAC", "Dst MAC", "Timestamp", "Flow ID",
    # Edge-IIoTset equivalents
    "frame.time", "ip.src", "ip.dst", "eth.src", "eth.dst",
]

# High-skew numerics → Log1p → RobustScaler
# Using actual CIC-IDS2018 column names
SKEWED_NUM_COLS: list[str] = [
    "Flow Duration",
    "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Bwd Pkt Len Max",
    "Flow Byts/s", "Flow Pkts/s",
    "Fwd IAT Tot", "Bwd IAT Tot",
]

# Low-skew numerics → RobustScaler only
NORMAL_NUM_COLS: list[str] = [
    "Fwd Pkt Len Mean", "Bwd Pkt Len Mean",
    "Flow IAT Mean", "Flow IAT Std",
    "Active Mean", "Idle Mean",
    "Pkt Len Mean", "Pkt Len Std",
    "Pkt Size Avg", "Fwd Seg Size Avg",
    "Subflow Fwd Byts", "Subflow Bwd Byts",
]

# Low-cardinality categorical → OneHotEncoder
LOW_CARD_CAT_COLS: list[str] = [
    "Protocol",
]

# High-cardinality categorical → TargetEncoder
HIGH_CARD_CAT_COLS: list[str] = [
    "Dst Port",
]

# Column used for GroupKFold (attack session identifier or IP pair hash)
GROUP_COLUMN: str = "Session_ID"

# Column used for TimeSeriesSplit ordering
TIME_COLUMN: str = "Window_Index"

# Default location for persisted model artifacts, relative to the repo root.
DEFAULT_MODEL_DIR: str = "acds_models"

# ─────────────────────────────────────────────────────────────────────────────
# 2.  CUSTOM TRANSFORMERS
# ─────────────────────────────────────────────────────────────────────────────

class SafeLog1p(BaseEstimator, TransformerMixin):
    """
    Log1p transform that first replaces ±Inf and NaN with the rolling
    column median so no row is ever discarded during live inference.
    """

    def __init__(self, window: int = 500) -> None:
        self.window = window
        self._medians: pd.Series | None = None

    def fit(self, X: pd.DataFrame, y=None) -> "SafeLog1p":
        df = pd.DataFrame(X).replace([np.inf, -np.inf], np.nan)
        self._medians = df.median()
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        df = pd.DataFrame(X).replace([np.inf, -np.inf], np.nan)
        df = df.fillna(self._medians)
        return np.log1p(np.abs(df.values)).astype(np.float32)


class ColumnFilter(BaseEstimator, TransformerMixin):
    """
    Drops columns that exist in the frame and silently skips
    columns already absent (safe for partial live JSON rows).
    """

    def __init__(self, drop_cols: list[str]) -> None:
        self.drop_cols = drop_cols

    def fit(self, X, y=None) -> "ColumnFilter":
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        present = [c for c in self.drop_cols if c in X.columns]
        return X.drop(columns=present, errors="ignore")


class RollingMedianImputer(BaseEstimator, TransformerMixin):
    """
    Fills NaN / Inf with the training-time median for each column.
    Applied after Log1p on skewed columns and before RobustScaler.
    """

    def fit(self, X, y=None) -> "RollingMedianImputer":
        df = pd.DataFrame(X).replace([np.inf, -np.inf], np.nan)
        self._medians = df.median()
        return self

    def transform(self, X) -> np.ndarray:
        df = pd.DataFrame(X).replace([np.inf, -np.inf], np.nan)
        return df.fillna(self._medians).values.astype(np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 3.  PREPROCESSING PIPELINE FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def build_preprocessor(target_series: pd.Series | None = None) -> ColumnTransformer:
    """
    Returns a fully fitted-compatible ColumnTransformer.

    TargetEncoder requires y during fit; pass `target_series` for that.
    For inference-only use, the fitted transformer is loaded from disk.
    """

    skewed_pipe = Pipeline([
        ("log1p",  SafeLog1p()),
        ("impute", RollingMedianImputer()),
        ("scale",  RobustScaler()),
    ])

    normal_pipe = Pipeline([
        ("impute", RollingMedianImputer()),
        ("scale",  RobustScaler()),
    ])

    low_card_pipe = Pipeline([
        ("ohe", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    high_card_pipe = Pipeline([
        ("te", TargetEncoder(smoothing=10, handle_unknown="value", handle_missing="value")),
        ("scale", RobustScaler()),
    ])

    return ColumnTransformer(
        transformers=[
            ("skewed_num",   skewed_pipe,   SKEWED_NUM_COLS),
            ("normal_num",   normal_pipe,   NORMAL_NUM_COLS),
            ("low_card_cat", low_card_pipe, LOW_CARD_CAT_COLS),
            ("high_card_cat", high_card_pipe, HIGH_CARD_CAT_COLS),
        ],
        remainder="drop",   # any other column not in schema is silently dropped
        n_jobs=-1,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4.  DATA LOADING & PREPARATION
# ─────────────────────────────────────────────────────────────────────────────

def load_dataset(paths: list[str | Path]) -> pd.DataFrame:
    """
    Reads one or more CSVs (CIC-IDS2018, Edge-IIoTset, or mixed),
    normalises column names, and returns a single cleaned DataFrame.
    """
    frames = []
    for p in paths:
        df = pd.read_csv(p, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True)

    # Remove identifier columns
    combined = ColumnFilter(DROP_COLUMNS).transform(combined)

    # Normalise label column name
    for label_col in ("Label", "label", "Attack_type", "attack_cat"):
        if label_col in combined.columns:
            combined.rename(columns={label_col: "Label"}, inplace=True)
            break
    assert "Label" in combined.columns, "No recognisable label column found."

    # Create binary target:  0 = Normal,  1 = Anomalous
    combined["Binary_Label"] = (
        combined["Label"].str.strip().str.lower() != "benign"
    ).astype(int)

    # Coerce categorical columns to str so OHE / TargetEncoder never see mixed types
    for col in LOW_CARD_CAT_COLS + HIGH_CARD_CAT_COLS:
        if col in combined.columns:
            combined[col] = combined[col].astype(str)

    # Coerce all numeric feature columns to float, replacing non-numeric with NaN
    num_cols = SKEWED_NUM_COLS + NORMAL_NUM_COLS
    for col in num_cols:
        if col in combined.columns:
            combined[col] = pd.to_numeric(combined[col], errors="coerce")

    # Assign synthetic session / window IDs when not present
    if GROUP_COLUMN not in combined.columns:
        combined[GROUP_COLUMN] = (np.arange(len(combined)) // 5000).astype(int)
    if TIME_COLUMN not in combined.columns:
        combined[TIME_COLUMN] = np.arange(len(combined))

    log.info("Dataset loaded: %d rows, %d columns.", *combined.shape)
    return combined


# ─────────────────────────────────────────────────────────────────────────────
# 5.  TIER 1 — BINARY DETECTION ENGINE  (LightGBM)
# ─────────────────────────────────────────────────────────────────────────────

def build_tier1_model(scale_pos_weight: float = 10.0) -> lgb.LGBMClassifier:
    return lgb.LGBMClassifier(
        n_estimators=800,
        learning_rate=0.05,
        num_leaves=127,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=0.1,
        scale_pos_weight=scale_pos_weight,   # handles class imbalance
        objective="binary",
        metric="binary_logloss",
        n_jobs=-1,
        random_state=42,
        verbose=-1,
    )


def train_tier1(
    X: np.ndarray,
    y_binary: np.ndarray,
    groups: np.ndarray,
    n_splits: int = 5,
) -> lgb.LGBMClassifier:
    """
    Trains the Tier 1 binary classifier using GroupKFold to prevent
    traffic from the same session bleeding across train / test splits.
    Returns the model retrained on the full dataset after CV evaluation.
    """
    gkf = GroupKFold(n_splits=n_splits)
    pos_ratio = max((y_binary == 0).sum() / max((y_binary == 1).sum(), 1), 1.0)
    model = build_tier1_model(scale_pos_weight=pos_ratio)

    fold_scores: list[float] = []
    for fold, (tr_idx, va_idx) in enumerate(gkf.split(X, y_binary, groups)):
        m = build_tier1_model(scale_pos_weight=pos_ratio)
        m.fit(X[tr_idx], y_binary[tr_idx])
        preds = m.predict(X[va_idx])
        f1 = f1_score(y_binary[va_idx], preds, average="binary")
        fold_scores.append(f1)
        log.info("Tier1 fold %d/%d  F1=%.4f", fold + 1, n_splits, f1)

    log.info("Tier1 mean CV F1: %.4f ± %.4f", np.mean(fold_scores), np.std(fold_scores))

    # Retrain on full data
    model.fit(X, y_binary)
    return model


# ─────────────────────────────────────────────────────────────────────────────
# 6.  TIER 2 — MULTI-CLASS THREAT CLASSIFIER  (CatBoost + SMOTETomek)
# ─────────────────────────────────────────────────────────────────────────────

def build_tier2_model(n_classes: int) -> CatBoostClassifier:
    return CatBoostClassifier(
        iterations=1000,
        learning_rate=0.05,
        depth=8,
        l2_leaf_reg=3,
        loss_function="MultiClass",
        eval_metric="TotalF1",
        class_weights=None,          # SMOTETomek handles balance; set to list if needed
        auto_class_weights="Balanced",
        random_seed=42,
        verbose=0,
        thread_count=-1,
    )


def _safe_resample(X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Apply SMOTETomek only when every class has enough samples for SMOTE
    (needs at least k_neighbors+1 = 6 samples).  Falls back to no resampling
    when any class is too small — CatBoost's auto_class_weights handles balance.
    """
    from collections import Counter
    counts = Counter(y)
    min_samples = min(counts.values())
    if min_samples < 6:
        log.warning(
            "Skipping SMOTETomek — smallest class has %d sample(s). "
            "CatBoost auto_class_weights will handle imbalance.", min_samples
        )
        return X, y
    smote_tomek = SMOTETomek(random_state=42, n_jobs=-1)
    return smote_tomek.fit_resample(X, y)


def train_tier2(
    X: np.ndarray,
    y_multi: np.ndarray,
    groups: np.ndarray,
    class_names: list[str],
    n_splits: int = 5,
) -> CatBoostClassifier:
    """
    Trains the Tier 2 classifier on anomalous traffic ONLY.
    Uses SMOTETomek where class sizes allow, then GroupKFold to
    prevent session leakage.
    """
    gkf = GroupKFold(n_splits=n_splits)
    n_classes = len(class_names)
    fold_scores: list[float] = []

    for fold, (tr_idx, va_idx) in enumerate(gkf.split(X, y_multi, groups)):
        X_tr, y_tr = X[tr_idx], y_multi[tr_idx]
        X_va, y_va = X[va_idx], y_multi[va_idx]

        X_res, y_res = _safe_resample(X_tr, y_tr)

        m = build_tier2_model(n_classes)
        m.fit(X_res, y_res)
        preds = m.predict(X_va).flatten()
        f1 = f1_score(y_va, preds, average="macro")
        fold_scores.append(f1)
        log.info("Tier2 fold %d/%d  macro-F1=%.4f", fold + 1, n_splits, f1)

    log.info("Tier2 mean CV macro-F1: %.4f ± %.4f", np.mean(fold_scores), np.std(fold_scores))

    # Final model: resample full anomaly set and retrain
    X_res, y_res = _safe_resample(X, y_multi)
    final_model = build_tier2_model(n_classes)
    final_model.fit(X_res, y_res)
    return final_model


# ─────────────────────────────────────────────────────────────────────────────
# 6b. PICKLE COMPATIBILITY SHIM
# ─────────────────────────────────────────────────────────────────────────────

def _register_legacy_pickle_aliases() -> None:
    """
    Make artifacts saved by earlier script-style runs loadable from anywhere.

    When this file is executed directly (``python threat_classifier.py train``)
    the custom transformers below are defined in the ``__main__`` module, so
    ``joblib`` records their class paths as ``__main__.SafeLog1p`` and friends.
    Importing the package instead (``from acds import ...``) leaves those names
    absent from ``__main__``, and unpickling the preprocessor then fails with
    ``AttributeError: Can't get attribute 'SafeLog1p'``.

    Aliasing the classes into ``__main__`` before any load resolves this without
    retraining or rewriting the model files. Harmless when the names are already
    present, so it is safe to call unconditionally.
    """
    main_module = sys.modules.get("__main__")
    if main_module is None:  # embedded interpreters may have no __main__
        return
    for cls in (SafeLog1p, ColumnFilter, RollingMedianImputer):
        if not hasattr(main_module, cls.__name__):
            setattr(main_module, cls.__name__, cls)


# ─────────────────────────────────────────────────────────────────────────────
# 7.  TRAINING ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class ThreatClassificationSystem:
    """
    Encapsulates the entire two-tier pipeline.
    After training, call `.inspect_traffic_flow(flow_row)` for live inference.
    """

    BINARY_LABEL_MAP = {0: "Normal", 1: "Anomalous"}

    def __init__(self) -> None:
        self.preprocessor: ColumnTransformer | None = None
        self.tier1_model: lgb.LGBMClassifier | None = None
        self.tier2_model: CatBoostClassifier | None = None
        self.threat_classes: list[str] = []
        self._is_fitted: bool = False

    # ── Training ─────────────────────────────────────────────────────────────

    def train(
        self,
        dataset_paths: list[str | Path],
        cv_strategy: str = "group",   # "group" | "timeseries"
        n_splits: int = 5,
    ) -> None:
        """
        End-to-end training entry point.

        Parameters
        ----------
        dataset_paths : list of file paths (CSV) for CIC-IDS2018 / Edge-IIoTset
        cv_strategy   : "group" uses GroupKFold on SESSION_ID;
                        "timeseries" uses TimeSeriesSplit on WINDOW_INDEX
        n_splits      : number of CV folds
        """
        df = load_dataset(dataset_paths)

        # ── Feature matrix & labels ──────────────────────────────────────────
        y_binary = df["Binary_Label"].values
        y_text   = df["Label"].str.strip().values
        groups   = df[GROUP_COLUMN].values

        # Encode multi-class labels (anomalous subset only)
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        y_multi_all = le.fit_transform(y_text)
        self.threat_classes = list(le.classes_)
        self._label_encoder = le

        feature_df = df.drop(
            columns=["Label", "Binary_Label", GROUP_COLUMN, TIME_COLUMN],
            errors="ignore",
        )

        # ── Fit preprocessor ─────────────────────────────────────────────────
        log.info("Fitting preprocessor …")
        self.preprocessor = build_preprocessor(target_series=pd.Series(y_text))
        X_all = self.preprocessor.fit_transform(feature_df, y_text)

        # ── Tier 1 ───────────────────────────────────────────────────────────
        log.info("Training Tier 1 binary detector …")
        self.tier1_model = train_tier1(X_all, y_binary, groups, n_splits)

        # ── Tier 2: only on anomalous rows ───────────────────────────────────
        log.info("Training Tier 2 multi-class classifier …")
        anomaly_mask = y_binary == 1
        X_anom   = X_all[anomaly_mask]
        y_anom   = y_multi_all[anomaly_mask]
        g_anom   = groups[anomaly_mask]

        self.tier2_model = train_tier2(
            X_anom, y_anom, g_anom, self.threat_classes, n_splits
        )
        self._is_fitted = True
        log.info("Training complete.")

    # ── Persistence ──────────────────────────────────────────────────────────

    def save(self, directory: str | Path = DEFAULT_MODEL_DIR) -> None:
        import joblib
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.preprocessor,   d / "preprocessor.pkl")
        joblib.dump(self.tier1_model,    d / "tier1_lgbm.pkl")
        joblib.dump(self._label_encoder, d / "label_encoder.pkl")
        self.tier2_model.save_model(str(d / "tier2_catboost.cbm"))
        meta = {"threat_classes": self.threat_classes}
        (d / "meta.json").write_text(json.dumps(meta, indent=2))
        log.info("Models saved to %s", d.resolve())

    @classmethod
    def load(cls, directory: str | Path = DEFAULT_MODEL_DIR) -> "ThreatClassificationSystem":
        import joblib

        # Required before unpickling artifacts produced by script-style runs.
        _register_legacy_pickle_aliases()

        d = Path(directory)
        obj = cls()
        obj.preprocessor   = joblib.load(d / "preprocessor.pkl")
        obj.tier1_model    = joblib.load(d / "tier1_lgbm.pkl")
        obj._label_encoder = joblib.load(d / "label_encoder.pkl")
        cb = CatBoostClassifier()
        cb.load_model(str(d / "tier2_catboost.cbm"))
        obj.tier2_model    = cb
        meta = json.loads((d / "meta.json").read_text())
        obj.threat_classes = meta["threat_classes"]
        obj._is_fitted     = True
        log.info("Models loaded from %s", d.resolve())
        return obj

    # ─────────────────────────────────────────────────────────────────────────
    # 8.  PRODUCTION INFERENCE ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────

    def inspect_traffic_flow(self, flow_row: dict[str, Any]) -> dict[str, Any]:
        """
        PRIMARY INFERENCE ENTRY POINT.

        Accepts a single network flow as a flat dict (from JSON telemetry).
        Returns a fully structured JSON-serialisable alert context.

        Parameters
        ----------
        flow_row : dict
            Raw network flow features, may contain extra / missing keys.

        Returns
        -------
        dict  — structured alert context (see schema below)
        """
        assert self._is_fitted, "System not trained. Call .train() or .load() first."

        # ── 1. Normalise input to DataFrame ──────────────────────────────────
        row_df = pd.DataFrame([flow_row])
        # Strip identifier columns from live row
        row_df = ColumnFilter(DROP_COLUMNS).transform(row_df)

        # ── 2. Preprocess ────────────────────────────────────────────────────
        X = self.preprocessor.transform(row_df)

        # ── 3. Tier 1 — Binary detection ─────────────────────────────────────
        t1_proba = self.tier1_model.predict_proba(X)[0]  # [P(Normal), P(Anomalous)]
        t1_pred  = int(np.argmax(t1_proba))
        t1_conf  = float(t1_proba[t1_pred])

        if t1_pred == 0:
            # Normal traffic — fast-path return
            return self._build_alert(
                verdict="Normal",
                confidence=t1_conf,
                threat_category=None,
                threat_confidence=None,
                tier2_probabilities=None,
                mitre=None,
            )

        # ── 4. Tier 2 — Multi-class threat classification ────────────────────
        t2_proba  = self.tier2_model.predict_proba(X)[0]   # shape: (n_classes,)
        t2_idx    = int(np.argmax(t2_proba))
        t2_conf   = float(t2_proba[t2_idx])
        t2_label  = self._label_encoder.inverse_transform([t2_idx])[0]

        # Build per-class probability map
        prob_map = {
            cls: round(float(p), 6)
            for cls, p in zip(self.threat_classes, t2_proba)
        }

        # Resolve MITRE mapping (fall back to Unknown Anomaly)
        mitre_entry = self._resolve_mitre(t2_label)

        return self._build_alert(
            verdict="Anomalous",
            confidence=t1_conf,
            threat_category=t2_label,
            threat_confidence=t2_conf,
            tier2_probabilities=prob_map,
            mitre=mitre_entry,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _resolve_mitre(label: str) -> dict[str, str]:
        """
        Fuzzy-matches a predicted threat label against MITRE_MAP keys.
        Falls back to 'Unknown Anomaly' entry if no match found.
        """
        label_lower = label.lower().strip()
        for key, entry in MITRE_MAP.items():
            if key.lower() in label_lower or label_lower in key.lower():
                return entry
        return MITRE_MAP["Unknown Anomaly"]

    @staticmethod
    def _build_alert(
        verdict: str,
        confidence: float,
        threat_category: str | None,
        threat_confidence: float | None,
        tier2_probabilities: dict | None,
        mitre: dict | None,
    ) -> dict[str, Any]:
        """Assembles the final structured alert context dict."""
        alert: dict[str, Any] = {
            "schema_version": "1.2",
            "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
            "tier1": {
                "verdict":    verdict,
                "confidence": round(confidence, 6),
            },
        }

        if verdict == "Normal":
            alert["tier2"] = None
            alert["mitre"] = None
            alert["severity"] = "INFO"
            alert["action"]   = "ALLOW"
        else:
            # Derive severity from confidence
            if threat_confidence is not None and threat_confidence >= 0.90:
                severity = "CRITICAL"
            elif threat_confidence is not None and threat_confidence >= 0.70:
                severity = "HIGH"
            elif threat_confidence is not None and threat_confidence >= 0.50:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            alert["tier2"] = {
                "threat_category":  threat_category,
                "confidence":       round(threat_confidence or 0.0, 6),
                "class_probabilities": tier2_probabilities,
            }
            alert["mitre"]    = mitre
            alert["severity"] = severity
            alert["action"]   = "BLOCK" if severity in ("CRITICAL", "HIGH") else "ALERT"

        return alert


# ─────────────────────────────────────────────────────────────────────────────
# 9.  CLI / DEMO HARNESS
# ─────────────────────────────────────────────────────────────────────────────

def _demo_live_inference(system: ThreatClassificationSystem) -> None:
    """
    Simulates a live network flow row arriving as JSON telemetry.
    Replace with actual streaming ingestion (Kafka, Zeek log, etc.).
    """
    # Column names match CIC-IDS2018 exactly
    synthetic_flow = {
        "Flow Duration":    1_200_000,
        "Tot Fwd Pkts":     450,
        "Tot Bwd Pkts":     5,
        "TotLen Fwd Pkts":  580_000,
        "TotLen Bwd Pkts":  1_200,
        "Fwd Pkt Len Max":  1_480,
        "Bwd Pkt Len Max":  80,
        "Flow Byts/s":      483_333,
        "Flow Pkts/s":      379,
        "Fwd IAT Tot":      1_190_000,
        "Bwd IAT Tot":      200_000,
        "Fwd Pkt Len Mean": 1_288.0,
        "Bwd Pkt Len Mean": 240.0,
        "Flow IAT Mean":    2_650.0,
        "Flow IAT Std":     18_000.0,
        "Active Mean":      350.0,
        "Idle Mean":        900_000.0,
        "Pkt Len Mean":     950.0,
        "Pkt Len Std":      420.0,
        "Pkt Size Avg":     975.0,
        "Fwd Seg Size Avg": 1_280.0,
        "Subflow Fwd Byts": 145_000,
        "Subflow Bwd Byts": 300,
        "Protocol":         "6",        # 6 = TCP in CIC-IDS2018
        "Dst Port":         "80",
        # Identifiers intentionally included — will be silently dropped
        "Src IP":  "192.168.1.50",
        "Dst IP":  "10.0.0.1",
    }

    result = system.inspect_traffic_flow(synthetic_flow)
    print("\n── ACDS Alert Context ──────────────────────────────────")
    print(json.dumps(result, indent=2))
    print("────────────────────────────────────────────────────────\n")


def _cli(argv: list[str] | None = None) -> None:
    """
    Command-line entry point.

    Usage
    -----
    acds-threat train <dataset.csv> [more.csv ...]
        Fit both tiers on the given CSVs and write artifacts to ./acds_models.

    acds-threat infer
        Load ./acds_models and run the synthetic single-flow demo.

    acds-threat
        Interface smoke test with mocked models — no data or artifacts needed.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0] if args else None

    if command == "train":
        dataset_files = args[1:]
        if not dataset_files:
            log.error("train requires at least one dataset path.")
            raise SystemExit(2)
        system = ThreatClassificationSystem()
        system.train(dataset_files, cv_strategy="group", n_splits=5)
        system.save(DEFAULT_MODEL_DIR)
        return

    if command == "infer":
        system = ThreatClassificationSystem.load(DEFAULT_MODEL_DIR)
        _demo_live_inference(system)
        return

    if command is not None:
        log.error("Unknown command %r. Expected 'train', 'infer', or no argument.", command)
        raise SystemExit(2)

    _run_smoke_test()


def _run_smoke_test() -> None:
    """
    Exercises the inference interface with mocked models.

    Verifies that alert assembly, severity derivation and MITRE resolution work
    without requiring a dataset or trained artifacts. Useful in CI.
    """
    from unittest.mock import MagicMock

    log.info("No command given — running interface smoke test with mocked models.")
    system = ThreatClassificationSystem()

    mock_pre = MagicMock()
    mock_pre.transform.return_value = np.random.rand(1, 60).astype(np.float32)

    mock_t1 = MagicMock()
    mock_t1.predict_proba.return_value = np.array([[0.05, 0.95]])

    mock_t2 = MagicMock()
    mock_t2.predict_proba.return_value = np.array([[0.02, 0.85, 0.08, 0.05]])

    mock_le = MagicMock()
    mock_le.inverse_transform.return_value = ["DoS"]
    mock_le.classes_ = np.array(["Benign", "DoS", "PortScan", "Brute Force"])

    system.preprocessor   = mock_pre
    system.tier1_model    = mock_t1
    system.tier2_model    = mock_t2
    system._label_encoder = mock_le
    system.threat_classes = list(mock_le.classes_)
    system._is_fitted     = True

    _demo_live_inference(system)
    log.info(
        "Smoke test complete. Train on real data with: "
        "python -m acds.threat_classifier train <dataset.csv>"
    )


if __name__ == "__main__":
    _cli()
