from __future__ import annotations

import numpy as np

from .base import BaseDetector

NORMALIZATIONS = ("rank", "tail")
COMBINERS = ("mean", "max")


def normalize_scores(scores: np.ndarray, ref_sorted: np.ndarray, method: str = "rank") -> np.ndarray:
    """Put one detector's raw scores on a scale shared by all detectors.

    rank: fraction of reference BENIGN scores below this score (0..1). Every score above
          the benign maximum becomes 1.0, so very different attacks can tie.
    tail: (score - benign median) / (benign 99th percentile - benign median). 0 = typical
          normal traffic, 1 = the 99th percentile of normal; unbounded above, so strong
          and weak anomalies stay distinguishable.
    """
    if method == "rank":
        return np.searchsorted(ref_sorted, scores, side="right") / len(ref_sorted)
    if method == "tail":
        median = np.quantile(ref_sorted, 0.5)
        spread = np.quantile(ref_sorted, 0.99) - median
        return (scores - median) / (spread if spread > 1e-12 else 1.0)
    raise ValueError(f"normalization must be one of {NORMALIZATIONS}, got {method!r}")


def combine_scores(normalized: list[np.ndarray], method: str = "mean") -> np.ndarray:
    if method == "mean":
        return np.mean(normalized, axis=0)
    if method == "max":
        return np.max(normalized, axis=0)
    raise ValueError(f"combine must be one of {COMBINERS}, got {method!r}")


class EnsembleDetector(BaseDetector):
    """Combines several detectors after putting their scores on a common scale.

    Raw scores are not comparable (a z-score vs. a reconstruction error), so each score
    is first normalised against scores on reference BENIGN traffic (see
    `normalize_scores`), then combined by mean or max. The defaults (rank + mean) are
    the original v1 behaviour.
    """

    name = "ensemble"

    def __init__(self, detectors: list[BaseDetector], normalization: str = "rank", combine: str = "mean"):
        self.detectors = detectors
        self.normalization = normalization
        self.combine = combine

    def fit(self, X: np.ndarray, X_ref: np.ndarray | None = None) -> "EnsembleDetector":
        for detector in self.detectors:
            detector.fit(X)
        ref = X if X_ref is None else X_ref
        self.ref_scores_ = {d.name: np.sort(d.score(ref)) for d in self.detectors}
        return self

    def _rank(self, name: str, scores: np.ndarray) -> np.ndarray:
        return normalize_scores(scores, self.ref_scores_[name], "rank")

    def combine_member_scores(self, scores: dict[str, np.ndarray], names: list[str] | None = None,
                              normalization: str | None = None, combine: str | None = None) -> np.ndarray:
        """Ensemble score from already-computed member scores (also used for tuning)."""
        names = names or [d.name for d in self.detectors]
        normalization = normalization or getattr(self, "normalization", "rank")
        combine = combine or getattr(self, "combine", "mean")
        normalized = [normalize_scores(scores[n], self.ref_scores_[n], normalization) for n in names]
        return combine_scores(normalized, combine)

    def score_all(self, X: np.ndarray) -> dict[str, np.ndarray]:
        """Scores of every member detector plus the ensemble, computed in one pass."""
        scores = {d.name: d.score(X) for d in self.detectors}
        scores[self.name] = self.combine_member_scores(scores)
        return scores

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.score_all(X)[self.name]
