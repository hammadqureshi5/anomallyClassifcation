from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from .base import BaseDetector, subsample


class IsolationForestDetector(BaseDetector):
    """Isolation Forest: anomalies are isolated by fewer random splits than normal points."""

    name = "iforest"

    def __init__(self, n_estimators: int = 200, max_samples: int | str = "auto", max_features: float = 1.0,
                 max_train_samples: int | None = None, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.max_features = max_features
        self.max_train_samples = max_train_samples
        self.random_state = random_state

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        X = subsample(X, self.max_train_samples, self.random_state)
        max_samples = self.max_samples if self.max_samples == "auto" else min(int(self.max_samples), len(X))
        self.model_ = IsolationForest(
            n_estimators=self.n_estimators, max_samples=max_samples, max_features=self.max_features,
            random_state=self.random_state, n_jobs=-1,
        ).fit(X)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return -self.model_.score_samples(X)
