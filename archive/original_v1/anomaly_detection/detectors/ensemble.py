from __future__ import annotations

import numpy as np

from .base import BaseDetector


class EnsembleDetector(BaseDetector):
    """Averages several detectors after putting their scores on a common scale.

    Raw scores are not comparable (a z-score vs. a reconstruction error), so each score
    is converted to its rank among scores on reference BENIGN traffic: 0.99 means
    "higher than 99% of normal traffic". The ensemble score is the mean rank.
    """

    name = "ensemble"

    def __init__(self, detectors: list[BaseDetector]):
        self.detectors = detectors

    def fit(self, X: np.ndarray, X_ref: np.ndarray | None = None) -> "EnsembleDetector":
        for detector in self.detectors:
            detector.fit(X)
        ref = X if X_ref is None else X_ref
        self.ref_scores_ = {d.name: np.sort(d.score(ref)) for d in self.detectors}
        return self

    def _rank(self, name: str, scores: np.ndarray) -> np.ndarray:
        ref = self.ref_scores_[name]
        return np.searchsorted(ref, scores, side="right") / len(ref)

    def score_all(self, X: np.ndarray) -> dict[str, np.ndarray]:
        """Scores of every member detector plus the ensemble, computed in one pass."""
        scores = {d.name: d.score(X) for d in self.detectors}
        scores[self.name] = np.mean([self._rank(n, s) for n, s in scores.items()], axis=0)
        return scores

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.score_all(X)[self.name]
