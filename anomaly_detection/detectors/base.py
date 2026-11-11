from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np


class BaseDetector(ABC):
    """Common interface: fit on (mostly) normal data, score new data.

    Scores follow one convention everywhere: higher = more anomalous. Turning scores into
    yes/no decisions is the job of `thresholding`, not the detector.
    """

    name: str = "base"

    @abstractmethod
    def fit(self, X: np.ndarray) -> "BaseDetector": ...

    @abstractmethod
    def score(self, X: np.ndarray) -> np.ndarray: ...

    def predict(self, X: np.ndarray, threshold: float) -> np.ndarray:
        return self.score(X) > threshold


def subsample(X: np.ndarray, max_samples: int | None, random_state: int) -> np.ndarray:
    if max_samples is None or len(X) <= max_samples:
        return X
    idx = np.random.default_rng(random_state).choice(len(X), max_samples, replace=False)
    return X[idx]
