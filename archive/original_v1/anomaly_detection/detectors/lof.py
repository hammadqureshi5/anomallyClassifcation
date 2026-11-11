from __future__ import annotations

import numpy as np
from sklearn.neighbors import LocalOutlierFactor

from .base import BaseDetector, subsample


class LOFDetector(BaseDetector):
    """Local Outlier Factor: flags points in much sparser regions than their neighbours."""

    name = "lof"

    def __init__(self, n_neighbors: int = 20, max_train_samples: int | None = 10000, random_state: int = 42):
        self.n_neighbors = n_neighbors
        self.max_train_samples = max_train_samples
        self.random_state = random_state

    def fit(self, X: np.ndarray) -> "LOFDetector":
        self.model_ = LocalOutlierFactor(n_neighbors=self.n_neighbors, novelty=True, n_jobs=-1).fit(
            subsample(X, self.max_train_samples, self.random_state)
        )
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return -self.model_.score_samples(X)
