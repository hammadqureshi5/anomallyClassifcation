"""Metrics and plots for the FYP report.

Accuracy is deliberately not the headline metric: attacks are rare, so "everything is
normal" would score very high accuracy while catching nothing.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_curve, precision_score, recall_score,
                             roc_auc_score, roc_curve)


def evaluate_scores(y_true: np.ndarray, scores: np.ndarray, threshold: float,
                    attack_type: pd.Series | None = None) -> dict:
    y_pred = (scores > threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both_classes = len(np.unique(y_true)) == 2
    metrics = {
        "threshold": float(threshold),
        "accuracy": float((tp + tn) / max(len(y_true), 1)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if both_classes else None,
        "pr_auc": float(average_precision_score(y_true, scores)) if both_classes else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if attack_type is not None:
        frame = pd.DataFrame({"type": attack_type.to_numpy(), "y": y_true, "pred": y_pred})
        attacks = frame[frame["y"] == 1].groupby("type")
        metrics["recall_per_attack"] = {
            str(k): {"recall": round(float(g["pred"].mean()), 4), "count": int(len(g))}
            for k, g in attacks
        }
    return metrics


def supervised_baseline_scores(X_train: np.ndarray, y_train: np.ndarray, X_test: np.ndarray,
                               random_state: int = 42) -> np.ndarray:
    """Random Forest trained WITH attack labels, for comparison in the report.

    It is usually very strong on attack types it has seen and weaker on new ones,
    which is the main argument for the unsupervised detectors.
    """
    model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=random_state,
                                   class_weight="balanced")
    model.fit(X_train, y_train)
    return model.predict_proba(X_test)[:, 1]


def metrics_table(results: dict[str, dict]) -> str:
    """Markdown table of the main metrics, one row per detector."""
    cols = ["accuracy", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc"]
    lines = ["| detector | " + " | ".join(cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for name, m in results.items():
        cells = ["-" if m.get(c) is None else f"{m[c]:.3f}" for c in cols]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def plot_curves(y_true: np.ndarray, scores_by_detector: dict[str, np.ndarray], out_dir: str | Path) -> list[Path]:
    """Save ROC and precision-recall curves for all detectors."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []

    fig, ax = plt.subplots(figsize=(6, 5))
    for name, scores in scores_by_detector.items():
        fpr, tpr, _ = roc_curve(y_true, scores)
        ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc_score(y_true, scores):.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey", linewidth=1)
    ax.set(xlabel="False positive rate", ylabel="True positive rate (recall)", title="ROC curve")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    paths.append(out_dir / "roc_curve.png")
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 5))
    for name, scores in scores_by_detector.items():
        precision, recall, _ = precision_recall_curve(y_true, scores)
        ax.plot(recall, precision, label=f"{name} (AP={average_precision_score(y_true, scores):.3f})")
    ax.set(xlabel="Recall", ylabel="Precision", title="Precision-recall curve")
    ax.legend(loc="lower left", fontsize=8)
    fig.tight_layout()
    paths.append(out_dir / "pr_curve.png")
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)
    return paths
