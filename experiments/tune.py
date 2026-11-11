"""Stage-wise, validation-only search for the improved (v2) configuration.

    python -m experiments.tune --dataset nsl-kdd

Every decision is made on the `val` split carved from TRAIN (see protocol.py); the test
set is not loaded here at all. A change is adopted only if it beats the current choice
by more than MARGIN on validation, so the original (v1) setting wins ties.

Stages
  0  feature selection   : drop highly correlated features?        (metric: mean member PR-AUC)
  1  detector settings   : small grid per detector                 (metric: that detector's PR-AUC)
  2  ensemble design     : member subset x normalisation x combiner (metric: ensemble PR-AUC)
  3  alert threshold     : percentile of benign scores             (metric: F1)
  4  hybrid              : add a supervised classifier for known attacks? (metric: F1)
"""
from __future__ import annotations

import argparse
import itertools
import json
import time
from copy import deepcopy
from dataclasses import asdict

import numpy as np
import yaml
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

from anomaly_detection import AnomalyPipeline, Config
from anomaly_detection.hybrid import HybridDetector
from anomaly_detection.thresholding import percentile_threshold

from .protocol import REPORT_DIR, ROOT, describe, load_splits, tuning_split

MARGIN = 0.002
BASELINE_CONFIG = ROOT / "configs/baseline.yaml"
DETECTORS = ["robust_z", "iforest", "lof", "autoencoder"]

# First entry of every grid is the v1 setting.
FEATURE_GRID = [None, 0.99, 0.95]
DETECTOR_GRIDS = {
    "robust_z": [{"top_k": k} for k in (1, 3, 10)],
    "iforest": [{"n_estimators": 200, "max_samples": ms, "max_features": mf}
                for ms in ("auto", 1024, 4096) for mf in (1.0, 0.5)],
    "lof": [{"n_neighbors": k, "max_train_samples": n} for n in (10000, 30000) for k in (20, 10, 50)],
    "autoencoder": [
        {"hidden_layer_sizes": None, "max_iter": 60, "alpha": 1e-4, "bottleneck_ratio": 0.25},
        {"hidden_layer_sizes": None, "max_iter": 200, "alpha": 1e-4, "bottleneck_ratio": 0.25},
        {"hidden_layer_sizes": None, "max_iter": 200, "alpha": 1e-3, "bottleneck_ratio": 0.25},
        {"hidden_layer_sizes": None, "max_iter": 200, "alpha": 1e-4, "bottleneck_ratio": 0.5},
    ],
}
NORMALIZATIONS = ["rank", "tail"]
COMBINERS = ["mean", "max"]
THRESHOLD_PERCENTILES = [99.0, 99.5, 98.0, 97.0, 95.0, 90.0]


def with_changes(cfg: Config, **changes) -> Config:
    cfg = deepcopy(cfg)
    for key, value in changes.items():
        setattr(cfg, key, value)
    return cfg


def fit_and_score(cfg: Config, fit, val):
    start = time.perf_counter()
    pipe = AnomalyPipeline(cfg).fit(fit)
    fit_seconds = time.perf_counter() - start
    return pipe, pipe.score(val.X), fit_seconds


def choose(candidates: list[dict], metric: str) -> dict:
    """Keep the first (v1) candidate unless another beats it by more than MARGIN."""
    best = max(candidates, key=lambda c: c[metric])
    return best if best[metric] > candidates[0][metric] + MARGIN else candidates[0]


def threshold_metrics(y, scores, benign_ref, percentile) -> dict:
    thr = percentile_threshold(benign_ref, percentile)
    pred = scores > thr
    return {"percentile": percentile, "threshold": float(thr), "f1": float(f1_score(y, pred)),
            "recall": float(pred[y == 1].mean()), "false_positive_rate": float(pred[y == 0].mean())}


def log(msg: str) -> None:
    print(msg, flush=True)


def tune(dataset: str) -> dict:
    train, _ = load_splits(dataset)
    fit, val = tuning_split(train)
    y = val.y
    log(f"[{dataset}] fit split {describe(fit)} | val split {describe(val)}")
    base = Config.from_yaml(BASELINE_CONFIG)
    record = {"dataset": dataset, "margin": MARGIN, "fit_split": describe(fit), "val_split": describe(val)}

    # Stage 0: feature selection, judged by the average PR-AUC of the four v1 detectors.
    stage0 = []
    for corr in FEATURE_GRID:
        cfg = with_changes(base, features={"corr_threshold": corr})
        pipe, scores, secs = fit_and_score(cfg, fit, val)
        member = {n: float(average_precision_score(y, scores[n])) for n in DETECTORS}
        cand = {"corr_threshold": corr, "n_features": len(pipe.preprocessor_.feature_names_),
                "member_pr_auc": member, "mean_member_pr_auc": float(np.mean(list(member.values()))),
                "ensemble_pr_auc": float(average_precision_score(y, scores["ensemble"])), "fit_seconds": secs}
        if corr is None:  # this run IS the baseline model fitted on the fit split
            ens = scores["ensemble"]
            pred = ens > pipe.thresholds_["ensemble"]
            record["baseline_val"] = {
                "pr_auc": cand["ensemble_pr_auc"], "roc_auc": float(roc_auc_score(y, ens)),
                "f1": float(f1_score(y, pred)), "recall": float(pred[y == 1].mean()),
                "false_positive_rate": float(pred[y == 0].mean()), "member_pr_auc": member}
        stage0.append(cand)
        log(f"  stage0 corr={corr}: features={cand['n_features']} mean member PR-AUC={cand['mean_member_pr_auc']:.4f}")
    chosen0 = choose(stage0, "mean_member_pr_auc")
    record["stage0_features"] = {"candidates": stage0, "chosen": chosen0["corr_threshold"]}
    cfg = with_changes(base, features={"corr_threshold": chosen0["corr_threshold"]})

    # Stage 1: settings per detector, each judged on its own PR-AUC.
    record["stage1_detectors"] = {}
    tuned = {}
    for name in DETECTORS:
        cands = []
        for params in DETECTOR_GRIDS[name]:
            c = with_changes(cfg, detectors=[name], **{name: params})
            _, scores, secs = fit_and_score(c, fit, val)
            cands.append({"params": params, "pr_auc": float(average_precision_score(y, scores[name])),
                          "roc_auc": float(roc_auc_score(y, scores[name])), "fit_seconds": secs})
            log(f"  stage1 {name} {params}: PR-AUC={cands[-1]['pr_auc']:.4f} ({secs:.0f}s)")
        best = choose(cands, "pr_auc")
        tuned[name] = best["params"]
        record["stage1_detectors"][name] = {"candidates": cands, "chosen": best["params"]}
    cfg = with_changes(cfg, detectors=list(DETECTORS), **tuned)

    # Stage 2: which members, and how to normalise and combine them.
    pipe, scores, _ = fit_and_score(cfg, fit, val)
    ens = pipe.detector_
    cands = []
    for norm, comb in [("rank", "mean")] + [nc for nc in itertools.product(NORMALIZATIONS, COMBINERS)
                                              if nc != ("rank", "mean")]:
        for r in range(len(DETECTORS), 0, -1):
            for subset in itertools.combinations(DETECTORS, r):
                s = ens.combine_member_scores(scores, list(subset), norm, comb)
                cands.append({"detectors": list(subset), "normalization": norm, "combine": comb,
                              "pr_auc": float(average_precision_score(y, s)), "roc_auc": float(roc_auc_score(y, s))})
    best = max(cands, key=lambda c: c["pr_auc"])
    if best["pr_auc"] > cands[0]["pr_auc"] + MARGIN:
        # Among candidates within MARGIN of the best, prefer the simplest (fewest detectors).
        near = [c for c in cands if c["pr_auc"] >= best["pr_auc"] - MARGIN]
        best = min(near, key=lambda c: (len(c["detectors"]), -c["pr_auc"]))
    else:
        best = cands[0]
    log(f"  stage2 chosen: {best}")
    record["stage2_ensemble"] = {"candidates": sorted(cands, key=lambda c: -c["pr_auc"]), "chosen": best}
    cfg = with_changes(cfg, detectors=best["detectors"],
                       ensemble={"normalization": best["normalization"], "combine": best["combine"]})

    # Stage 3: alert threshold. Benign reference = the pipeline's internal benign hold-out.
    names, norm, comb = best["detectors"], best["normalization"], best["combine"]
    benign_ref = ens.combine_member_scores(pipe.val_scores_, names, norm, comb)
    val_scores = ens.combine_member_scores(scores, names, norm, comb)
    cands = [threshold_metrics(y, val_scores, benign_ref, p) for p in THRESHOLD_PERCENTILES]
    best_thr = choose(cands, "f1")
    for c in cands:
        log(f"  stage3 p={c['percentile']}: F1={c['f1']:.4f} recall={c['recall']:.3f} FPR={c['false_positive_rate']:.4f}")
    record["stage3_threshold"] = {"candidates": cands, "chosen": best_thr["percentile"]}
    cfg = with_changes(cfg, threshold_percentile=best_thr["percentile"])

    # Final improved config, refitted on the fit split: its validation performance.
    pipe, scores, secs = fit_and_score(cfg, fit, val)
    s = scores["ensemble"]
    pred = s > pipe.thresholds_["ensemble"]
    record["improved_val"] = {"pr_auc": float(average_precision_score(y, s)), "roc_auc": float(roc_auc_score(y, s)),
                              "f1": float(f1_score(y, pred)), "recall": float(pred[y == 1].mean()),
                              "false_positive_rate": float(pred[y == 0].mean()), "fit_seconds": secs}

    # Stage 4: hybrid (classifier for known attacks OR improved anomaly pipeline).
    hybrid = HybridDetector(pipe, random_state=cfg.random_state).fit(fit)
    h = hybrid.score(val.X)["hybrid"]
    hp = h > hybrid.threshold
    record["hybrid_val"] = {"pr_auc": float(average_precision_score(y, h)), "roc_auc": float(roc_auc_score(y, h)),
                            "f1": float(f1_score(y, hp)), "recall": float(hp[y == 1].mean()),
                            "false_positive_rate": float(hp[y == 0].mean())}
    record["best_model"] = "hybrid" if record["hybrid_val"]["f1"] > record["improved_val"]["f1"] + MARGIN else "improved"
    log(f"  validation: baseline {record['baseline_val']}\n              improved {record['improved_val']}\n"
        f"              hybrid {record['hybrid_val']}\n  best model on validation: {record['best_model']}")

    if dataset == "cicids2017":  # so the CLI uses the same corrected (deduplicated) data as the experiments
        cfg.data = {**cfg.data, "cicids_drop_duplicates": True}
    config_path = ROOT / f"configs/improved_{dataset}.yaml"
    header = (f"# IMPROVED (v2) configuration for {dataset}, generated by `python -m experiments.tune "
              f"--dataset {dataset}`.\n# Every value was chosen on the validation split of the training data "
              f"(never the test set).\n# See reports/improvement/{dataset}/tuning.json for all candidates.\n")
    config_path.write_text(header + yaml.safe_dump(asdict(cfg), sort_keys=False))
    out = REPORT_DIR / dataset
    out.mkdir(parents=True, exist_ok=True)
    (out / "tuning.json").write_text(json.dumps(record, indent=2, default=str))
    log(f"  wrote {config_path} and {out / 'tuning.json'}")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["nsl-kdd", "cicids2017"], required=True)
    tune(parser.parse_args().dataset)
