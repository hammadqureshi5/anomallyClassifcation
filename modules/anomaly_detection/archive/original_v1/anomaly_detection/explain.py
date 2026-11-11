"""Explain alerts: which features made a flow look unusual."""
from __future__ import annotations

import numpy as np

from .detectors.statistical import RobustZScoreDetector


class FeatureExplainer:
    """Ranks features by how far they are from normal (robust z-score).

    This works no matter which detector raised the alert, so an analyst (or the
    response module) always sees a reason such as "src_bytes is 14 sigma above normal".
    """

    def __init__(self, feature_names: list[str]):
        self.feature_names = list(feature_names)

    def fit(self, X: np.ndarray) -> "FeatureExplainer":
        self.stats_ = RobustZScoreDetector().fit(X)
        return self

    def explain(self, X: np.ndarray, top_k: int = 3) -> list[list[dict]]:
        z = self.stats_.feature_z(X)
        top = np.argsort(-np.abs(z), axis=1)[:, :top_k]
        return [
            [
                {
                    "feature": self.feature_names[j],
                    "z_score": round(float(z[i, j]), 2),
                    "direction": "high" if z[i, j] > 0 else "low",
                }
                for j in row
            ]
            for i, row in enumerate(top)
        ]
