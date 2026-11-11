"""Hybrid detector: supervised model for KNOWN attacks + anomaly pipeline for UNKNOWN ones.

A flow is flagged if either part flags it. The supervised Random Forest is very accurate
on attack types it was trained on but cannot recognise new ones; the anomaly pipeline
needs no attack labels and covers what the classifier misses.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from .data.loaders import Dataset
from .pipeline import AnomalyPipeline


class HybridDetector:
    threshold = 0.5

    def __init__(self, pipeline: AnomalyPipeline, n_estimators: int = 100, random_state: int = 42):
        self.pipeline = pipeline
        self.n_estimators = n_estimators
        self.random_state = random_state

    def fit(self, dataset: Dataset) -> "HybridDetector":
        """Fits the anomaly pipeline (benign rows only) and the classifier (all labelled rows)."""
        if dataset.y is None or len(np.unique(dataset.y)) < 2:
            raise ValueError("HybridDetector needs labelled data with both benign and attack rows")
        if not hasattr(self.pipeline, "preprocessor_"):
            self.pipeline.fit(dataset)
        self.classifier_ = RandomForestClassifier(
            n_estimators=self.n_estimators, class_weight="balanced", n_jobs=-1, random_state=self.random_state
        ).fit(self.pipeline.transform(dataset.X), dataset.y)
        return self

    def score(self, X_df: pd.DataFrame) -> dict[str, np.ndarray]:
        """Scores per part plus the hybrid score (> 0.5 means flagged).

        The anomaly score is rescaled so its threshold maps to 0.5, which makes
        "hybrid > 0.5" exactly "classifier > 0.5 OR anomaly score > its threshold".
        """
        X = self.pipeline.transform(X_df)
        anomaly = self.pipeline.detector_.score_all(X)[self.pipeline.primary]
        threshold = self.pipeline.thresholds_[self.pipeline.primary]
        if threshold <= 0:
            raise ValueError("Hybrid rescaling needs a positive anomaly threshold")
        supervised = self.classifier_.predict_proba(X)[:, 1]
        return {"anomaly": anomaly, "supervised": supervised,
                "hybrid": np.maximum(supervised, 0.5 * anomaly / threshold)}

    def predict(self, X_df: pd.DataFrame) -> np.ndarray:
        return self.score(X_df)["hybrid"] > self.threshold
