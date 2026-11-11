"""Build all report figures for a dataset from results.json and the saved models.

    python -m experiments.make_figures --dataset nsl-kdd

Called by experiments.evaluate; can be re-run alone (no retraining) to restyle figures.
"""
from __future__ import annotations

import argparse
import json

import joblib

from . import figures
from .protocol import REPORT_DIR, ROOT, load_splits

TITLES = {"nsl-kdd": "NSL-KDD", "cicids2017": "CIC-IDS2017"}
METRICS = ["accuracy", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc"]


def autoencoder_history(pipe) -> dict | None:
    for d in pipe.detector_.detectors:
        if d.name == "autoencoder":
            return {"loss": list(map(float, d.model_.loss_curve_)),
                    "val_r2": list(map(float, d.model_.validation_scores_ or []))}
    return None


def render(dataset: str, results: dict, test, models: dict) -> None:
    """models: {"baseline": AnomalyPipeline, "improved": AnomalyPipeline, "hybrid": HybridDetector} (seed 42)."""
    out = REPORT_DIR / dataset / "figures"
    t = TITLES[dataset]
    scores = {
        "baseline": models["baseline"].score(test.X)[models["baseline"].primary],
        "improved": models["improved"].score(test.X)[models["improved"].primary],
        "hybrid": models["hybrid"].score(test.X)["hybrid"],
    }
    cms = {m: results["per_seed"][0][m]["confusion_matrix"] for m in scores}
    figures.metric_comparison(results["summary"], METRICS, f"{t}: original vs improved (test set, mean ± std over 3 seeds)",
                              out / "1_metric_comparison.png")
    figures.confusion_matrices(cms, f"{t}: confusion matrices (test set, seed 42)", out / "2_confusion_matrices.png")
    figures.learning_curves(results["learning_curve"], f"{t}: learning curve (training vs validation split)",
                            out / "3_learning_curve.png")
    histories = {m: h for m in ("baseline", "improved") if (h := autoencoder_history(models[m]))}
    if histories:
        figures.autoencoder_curves(histories, f"{t}: autoencoder training", out / "3b_autoencoder_training.png")
    figures.feature_bars(results["rf_feature_importance"], f"{t}: feature importance (hybrid's classifier)",
                         "mean decrease in impurity", out / "4_feature_importance.png")
    figures.feature_bars(results["alert_top_feature_counts"], f"{t}: features that most often explain v2 alerts",
                         "alerts where this feature was the top reason", out / "4b_alert_reasons.png")
    figures.curves(test.y, scores, f"{t} (test set, seed 42)", out / "5_roc_pr_curves.png")
    figures.per_attack_recall(results["per_attack_recall"], f"{t}: recall per attack type (test set, seed 42)",
                              out / "6_per_attack_recall.png")
    figures.ablation(results["ablation"], ["f1", "recall", "precision", "pr_auc"],
                     f"{t}: contribution of each change (test set, seed 42)", out / "7_ablation.png")


def main(dataset: str) -> None:
    results = json.loads((REPORT_DIR / dataset / "results.json").read_text())
    _, test = load_splits(dataset)
    models = {m: joblib.load(ROOT / path) for m, path in results["model_files"].items()}
    render(dataset, results, test, models)
    print(f"figures written to {REPORT_DIR / dataset / 'figures'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=list(TITLES), required=True)
    main(parser.parse_args().dataset)
