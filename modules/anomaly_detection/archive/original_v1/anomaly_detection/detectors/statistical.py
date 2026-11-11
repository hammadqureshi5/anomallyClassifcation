from __future__ import annotations

import numpy as np

from .base import BaseDetector


class RobustZScoreDetector(BaseDetector):
    """Per-feature robust z-score (median / MAD); row score = largest |z|.

    Simple and explainable baseline: an alert means "at least one feature is far
    outside its normal range". Median/MAD are used instead of mean/std because the
    training data may still contain a few outliers.
    """

    name = "robust_z"

    def fit(self, X: np.ndarray) -> "RobustZScoreDetector":
        self.median_ = np.median(X, axis=0)
        mad = np.median(np.abs(X - self.median_), axis=0) * 1.4826
        std = X.std(axis=0)
        # Sparse features (mostly one value) have MAD = 0; fall back to std, then 1.
        self.scale_ = np.where(mad > 1e-9, mad, np.where(std > 1e-9, std, 1.0))
        return self

    def feature_z(self, X: np.ndarray) -> np.ndarray:
        return (X - self.median_) / self.scale_

    def score(self, X: np.ndarray) -> np.ndarray:
        return np.abs(self.feature_z(X)).max(axis=1)
