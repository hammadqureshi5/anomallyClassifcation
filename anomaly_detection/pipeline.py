"""End-to-end pipeline: preprocess -> detectors -> threshold -> explain -> alerts."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .alerts import Alert, clean_value
from .config import Config
from .data.loaders import Dataset
from .detectors import EnsembleDetector, build_detector
from .explain import FeatureExplainer
from .features import Preprocessor
from .thresholding import percentile_threshold, severity, severity_cutoffs


@dataclass
class DetectionResult:
    scores: dict[str, np.ndarray]   # per detector, including "ensemble"
    is_anomaly: np.ndarray          # decisions of the primary detector
    alerts: list[Alert]


class AnomalyPipeline:
    def __init__(self, config: Config | None = None):
        self.config = config or Config()

    @property
    def primary(self) -> str:
        return self.config.primary_detector

    def fit(self, dataset: Dataset) -> "AnomalyPipeline":
        """Train on normal traffic only.

        If the dataset has labels, attack rows are removed first. Without labels all rows
        are assumed normal, so the training data should be as clean as possible.
        """
        cfg = self.config
        X_df = dataset.X if dataset.y is None else dataset.X[dataset.y == 0]
        if len(X_df) < 50:
            raise ValueError(f"Need at least 50 benign rows to train, got {len(X_df)}")

        rng = np.random.default_rng(cfg.random_state)
        order = rng.permutation(len(X_df))
        n_val = max(1, int(len(X_df) * cfg.val_fraction))
        val_df = X_df.iloc[order[:n_val]]
        train_df = X_df.iloc[order[n_val:][: cfg.max_train_samples]]

        self.preprocessor_ = Preprocessor(corr_threshold=cfg.features.get("corr_threshold")).fit(train_df)
        X_train = self.preprocessor_.transform(train_df)
        X_val = self.preprocessor_.transform(val_df)

        self.detector_ = EnsembleDetector([build_detector(n, cfg) for n in cfg.detectors],
                                          normalization=cfg.ensemble["normalization"],
                                          combine=cfg.ensemble["combine"])
        self.detector_.fit(X_train, X_ref=X_val)

        val_scores = self.detector_.score_all(X_val)
        # Kept so thresholds can be recalibrated without refitting (used by experiments/).
        self.val_scores_ = val_scores
        if self.primary not in val_scores:
            raise ValueError(f"primary_detector {self.primary!r} is not one of {list(val_scores)}")
        self.thresholds_ = {n: percentile_threshold(s, cfg.threshold_percentile) for n, s in val_scores.items()}
        self.severity_cutoffs_ = {
            n: severity_cutoffs(s, self.thresholds_[n], cfg.severity_percentiles) for n, s in val_scores.items()
        }
        self.explainer_ = FeatureExplainer(self.preprocessor_.feature_names_).fit(X_train)
        return self

    def transform(self, X_df: pd.DataFrame) -> np.ndarray:
        return self.preprocessor_.transform(X_df)

    def score(self, X_df: pd.DataFrame) -> dict[str, np.ndarray]:
        return self.detector_.score_all(self.transform(X_df))

    def detect(self, dataset: Dataset) -> DetectionResult:
        X = self.transform(dataset.X)
        scores = self.detector_.score_all(X)
        primary_scores = scores[self.primary]
        threshold = self.thresholds_[self.primary]
        is_anomaly = primary_scores > threshold

        idx = np.flatnonzero(is_anomaly)
        explanations = self.explainer_.explain(X[idx], self.config.top_k_features) if len(idx) else []
        alerts = []
        for i, reasons in zip(idx, explanations):
            row = dataset.X.iloc[i]
            meta = dataset.meta.iloc[i]
            for reason in reasons:
                # Attach the original (unscaled) value when the feature is a raw column.
                if reason["feature"] in row.index:
                    reason["value"] = clean_value(row[reason["feature"]])
            port = clean_value(meta["dst_port"])
            alerts.append(Alert(
                id=f"ALERT-{i:06d}",
                row_index=int(i),
                timestamp=None if clean_value(meta["timestamp"]) is None else str(meta["timestamp"]),
                src_ip=clean_value(meta["src_ip"]),
                dst_ip=clean_value(meta["dst_ip"]),
                dst_port=None if port is None else int(float(port)),
                score=round(float(primary_scores[i]), 6),
                threshold=round(threshold, 6),
                severity=severity(primary_scores[i], self.severity_cutoffs_[self.primary]),
                detector=self.primary,
                top_features=reasons,
            ))
        return DetectionResult(scores=scores, is_anomaly=is_anomaly, alerts=alerts)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path: str | Path) -> "AnomalyPipeline":
        return joblib.load(path)
