from __future__ import annotations

import numpy as np

from .base import BaseDetector


class RobustZScoreDetector(BaseDetector):
    """Per-feature robust z-score (median / MAD); row score = mean of the top_k largest |z|.

    Simple and explainable baseline: an alert means "some features are far outside
    their normal range". Median/MAD are used instead of mean/std because the training
    data may still contain a few outliers. top_k=1 (the default) is the plain maximum;
    a larger top_k is less sensitive to a single noisy feature.
    """

    name = "robust_z"

    def __init__(self, top_k: int = 1):
        self.top_k = top_k

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
        z = np.abs(self.feature_z(X))
        if self.top_k <= 1:
            return z.max(axis=1)
        k = min(self.top_k, z.shape[1])
        return np.partition(z, -k, axis=1)[:, -k:].mean(axis=1)
