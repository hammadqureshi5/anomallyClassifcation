"""Turn anomaly scores into decisions."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import precision_recall_curve


def percentile_threshold(benign_scores: np.ndarray, percentile: float = 99.0) -> float:
    """Flag anything above this percentile of normal-traffic scores.

    percentile=99 targets about a 1% false-positive rate. No attack labels needed.
    """
    return float(np.percentile(benign_scores, percentile))


def best_f1_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Threshold that maximises F1. Needs labels, so use it for analysis, not deployment."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-12)
    return float(thresholds[np.argmax(f1[:-1])])


def severity_cutoffs(benign_scores: np.ndarray, threshold: float, percentiles: dict) -> dict[str, float]:
    """Score cutoffs for medium/high severity, never below the alert threshold."""
    return {level: max(threshold, float(np.percentile(benign_scores, p))) for level, p in percentiles.items()}


def severity(score: float, cutoffs: dict[str, float]) -> str:
    if score > cutoffs.get("high", np.inf):
        return "high"
    if score > cutoffs.get("medium", np.inf):
        return "medium"
    return "low"
