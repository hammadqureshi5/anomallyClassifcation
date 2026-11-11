"""Final before-and-after evaluation on the untouched TEST set.

    python -m experiments.evaluate --dataset nsl-kdd

Requires configs/improved_<dataset>.yaml from `experiments.tune`. All models are fitted on
the same TRAIN data and evaluated on the same TEST data, for every seed in MODEL_SEEDS.
The test set is only used here, after every design decision has been fixed.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from copy import deepcopy

import joblib
import numpy as np
from sklearn.metrics import average_precision_score
from sklearn.model_selection import train_test_split

from anomaly_detection import AnomalyPipeline, Config
from anomaly_detection.evaluation import evaluate_scores
from anomaly_detection.hybrid import HybridDetector

from . import make_figures
from .figures import clean_label
from .protocol import MODEL_SEEDS, REPORT_DIR, ROOT, describe, load_splits, tuning_split

METRICS = ["accuracy", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc"]
COST = ["fit_seconds", "inference_ms_per_1k_flows"]
LEARNING_CURVE_SIZES = [1000, 3000, 10000, 30000, 50000]


def log(msg: str) -> None:
    print(msg, flush=True)


def load_config(path, seed: int) -> Config:
    cfg = Config.from_yaml(path)
    cfg.random_state = seed
    return cfg


def timed_metrics(score_fn, X_df, y, threshold, attack_type, fit_seconds) -> tuple[np.ndarray, dict]:
    start = time.perf_counter()
    scores = score_fn(X_df)
    seconds = time.perf_counter() - start
    m = evaluate_scores(y, scores, threshold, attack_type)
    m["fit_seconds"] = fit_seconds
    m["inference_ms_per_1k_flows"] = seconds / len(X_df) * 1e6
    return scores, m


def fit_anomaly(cfg: Config, train):
    start = time.perf_counter()
    pipe = AnomalyPipeline(cfg).fit(train)
    return pipe, time.perf_counter() - start


def run_seed(dataset: str, seed: int, train, test, keep: bool) -> dict:
    out = {}
    for model, path in [("baseline", ROOT / "configs/baseline.yaml"), ("improved", ROOT / f"configs/improved_{dataset}.yaml")]:
        pipe, fit_s = fit_anomaly(load_config(path, seed), train)
        score_fn = lambda X, p=pipe: p.score(X)[p.primary]
        scores, m = timed_metrics(score_fn, test.X, test.y, pipe.thresholds_[pipe.primary], test.attack_type, fit_s)
        out[model] = {"pipe": pipe, "scores": scores, "metrics": m}

    pipe = out["improved"]["pipe"]
    start = time.perf_counter()
    hybrid = HybridDetector(pipe, random_state=seed).fit(train)  # pipe already fitted: only the classifier trains
    fit_s = out["improved"]["metrics"]["fit_seconds"] + time.perf_counter() - start
    score_fn = lambda X: hybrid.score(X)["hybrid"]
    scores, m = timed_metrics(score_fn, test.X, test.y, hybrid.threshold, test.attack_type, fit_s)
    out["hybrid"] = {"pipe": hybrid, "scores": scores, "metrics": m}

    for model, r in out.items():
        log(f"  seed {seed} {model:<9} " + " ".join(f"{k}={r['metrics'][k]:.3f}" for k in METRICS)
            + f" fit={r['metrics']['fit_seconds']:.1f}s")
    if not keep:
        for r in out.values():
            r.pop("pipe"), r.pop("scores")
    return out


def summarize(per_seed: list[dict]) -> dict:
    summary = {}
    for model in per_seed[0]:
        summary[model] = {}
        for k in METRICS + COST:
            vals = np.array([run[model]["metrics"][k] for run in per_seed], dtype=float)
            summary[model][k] = {"mean": float(vals.mean()), "std": float(vals.std(ddof=1)) if len(vals) > 1 else 0.0,
                                 "values": vals.round(6).tolist()}
    return summary


def train_vs_test(kept: dict, train, test) -> dict:
    """Generalisation check: the same fitted models scored on TRAIN and on TEST."""
    rows = {}
    for model, r in kept.items():
        obj = r["pipe"]
        if model == "hybrid":
            fn, thr = (lambda X: obj.score(X)["hybrid"]), obj.threshold
        else:
            fn, thr = (lambda X, p=obj: p.score(X)[p.primary]), obj.thresholds_[obj.primary]
        tr = evaluate_scores(train.y, fn(train.X), thr)
        te = r["metrics"]
        rows[model] = {split: {k: m[k] for k in ["f1", "recall", "false_positive_rate", "pr_auc"]}
                       for split, m in [("train", tr), ("test", te)]}
    return rows


def ablation(dataset: str, tuning: dict, train, test) -> list[dict]:
    """Cumulative contribution of each tuned change (seed 42). Choices come from tuning.json;
    the test set only measures them."""
    base = load_config(ROOT / "configs/baseline.yaml", MODEL_SEEDS[0])
    steps = [("Original (v1)", deepcopy(base))]
    cfg = deepcopy(base)
    cfg.features = {"corr_threshold": tuning["stage0_features"]["chosen"]}
    steps.append(("+ feature selection", deepcopy(cfg)))
    for name, d in tuning["stage1_detectors"].items():
        setattr(cfg, name, d["chosen"])
    steps.append(("+ tuned detector settings", deepcopy(cfg)))
    ens = tuning["stage2_ensemble"]["chosen"]
    cfg.detectors = ens["detectors"]
    cfg.ensemble = {"normalization": ens["normalization"], "combine": ens["combine"]}
    steps.append(("+ ensemble redesign", deepcopy(cfg)))
    cfg.threshold_percentile = tuning["stage3_threshold"]["chosen"]
    steps.append(("+ tuned threshold (= v2)", deepcopy(cfg)))

    results = []
    for label, c in steps:
        pipe, _ = fit_anomaly(c, train)
        s = pipe.score(test.X)[pipe.primary]
        m = evaluate_scores(test.y, s, pipe.thresholds_[pipe.primary])
        results.append({"step": label, "metrics": {k: m[k] for k in METRICS}})
        log(f"  ablation {label:<28} " + " ".join(f"{k}={m[k]:.3f}" for k in METRICS))
    return results


def learning_curve(dataset: str, train) -> dict:
    """PR-AUC on the training split vs the validation split as benign training data grows."""
    fit, val = tuning_split(train)
    rng_idx = np.arange(len(fit))
    if len(fit) > 20000:  # score a fixed stratified subsample of the training split to keep this fast
        rng_idx, _ = train_test_split(rng_idx, train_size=20000, random_state=0, stratify=fit.y)
    fit_eval = fit.subset(rng_idx)
    n_benign = int((fit.y == 0).sum() * 0.8)  # the pipeline holds 20% of benign rows out for thresholds
    curves = {}
    for model, path in [("baseline", ROOT / "configs/baseline.yaml"), ("improved", ROOT / f"configs/improved_{dataset}.yaml")]:
        curves[model] = []
        for n in [s for s in LEARNING_CURVE_SIZES if s <= n_benign] or [n_benign]:
            cfg = load_config(path, MODEL_SEEDS[0])
            cfg.max_train_samples = n
            pipe = AnomalyPipeline(cfg).fit(fit)
            curves[model].append({
                "train_rows": n,
                "train_pr_auc": float(average_precision_score(fit_eval.y, pipe.score(fit_eval.X)[pipe.primary])),
                "val_pr_auc": float(average_precision_score(val.y, pipe.score(val.X)[pipe.primary])),
            })
            log(f"  learning curve {model} n={n}: {curves[model][-1]}")
    return curves


def fmt(v: float, k: str) -> str:
    return f"{v:.1f}" if k in COST else f"{v:.4f}"


def markdown(dataset: str, results: dict) -> str:
    s, lines = results["summary"], []
    lines.append(f"# Before-and-after results: {dataset}\n")
    lines.append(f"Train: {results['train']} | Test: {results['test']}  \n"
                 f"Seeds: {MODEL_SEEDS} (mean ± std). Test set never used for tuning.\n")
    lines.append("| Metric | Original (v1) | Improved (v2) | Change v2 − v1 | Hybrid | Change hybrid − v1 |")
    lines.append("|---|---|---|---|---|---|")
    for k in METRICS + COST:
        b, i, h = s["baseline"][k], s["improved"][k], s["hybrid"][k]
        lines.append(f"| {k} | {fmt(b['mean'], k)} ± {fmt(b['std'], k)} | {fmt(i['mean'], k)} ± {fmt(i['std'], k)} | "
                     f"{i['mean'] - b['mean']:+.4f} | {fmt(h['mean'], k)} ± {fmt(h['std'], k)} | {h['mean'] - b['mean']:+.4f} |")
    lines.append("\nLower is better for false_positive_rate, fit_seconds and inference time.\n")
    lines.append("## Train vs test (seed 42)\n\n| Model | Split | F1 | Recall | FPR | PR-AUC |\n|---|---|---|---|---|---|")
    for model, splits in results["train_vs_test"].items():
        for split, m in splits.items():
            lines.append(f"| {model} | {split} | {m['f1']:.4f} | {m['recall']:.4f} | {m['false_positive_rate']:.4f} | {m['pr_auc']:.4f} |")
    lines.append("\n## Ablation (seed 42, cumulative)\n\n| Step | " + " | ".join(METRICS) + " |\n|---|" + "---|" * len(METRICS))
    for step in results["ablation"]:
        lines.append(f"| {step['step']} | " + " | ".join(f"{step['metrics'][k]:.4f}" for k in METRICS) + " |")
    lines.append("\n## Recall per attack type (seed 42)\n\n| Attack | n | Original | Improved | Hybrid |\n|---|---|---|---|---|")
    pa = results["per_attack_recall"]
    for t, v in sorted(pa["baseline"].items(), key=lambda kv: -kv[1]["count"]):
        lines.append(f"| {clean_label(t)} | {v['count']} | {v['recall']:.3f} | {pa['improved'][t]['recall']:.3f} | {pa['hybrid'][t]['recall']:.3f} |")
    return "\n".join(lines) + "\n"


def evaluate(dataset: str) -> dict:
    out_dir = REPORT_DIR / dataset
    tuning = json.loads((out_dir / "tuning.json").read_text())
    train, test = load_splits(dataset)
    log(f"[{dataset}] train {describe(train)} | test {describe(test)}")

    per_seed = [run_seed(dataset, seed, train, test, keep=(seed == MODEL_SEEDS[0])) for seed in MODEL_SEEDS]
    kept = per_seed[0]
    results = {
        "dataset": dataset, "train": describe(train), "test": describe(test), "seeds": MODEL_SEEDS,
        "summary": summarize(per_seed),
        "per_seed": [{m: r["metrics"] for m, r in run.items()} for run in per_seed],
        "best_model_by_validation": tuning["best_model"],
        "validation": {"baseline": tuning["baseline_val"], "improved": tuning["improved_val"], "hybrid": tuning["hybrid_val"]},
    }
    results["per_attack_recall"] = {m: r["metrics"]["recall_per_attack"] for m, r in kept.items()}
    results["train_vs_test"] = train_vs_test(kept, train, test)
    results["ablation"] = ablation(dataset, tuning, train, test)
    results["learning_curve"] = learning_curve(dataset, train)

    # Feature importance: classifier part of the hybrid, and which features explain v2 alerts.
    hybrid, pipe = kept["hybrid"]["pipe"], kept["improved"]["pipe"]
    names = pipe.preprocessor_.feature_names_
    results["rf_feature_importance"] = dict(zip(names, map(float, hybrid.classifier_.feature_importances_)))
    alerts = pipe.detect(test).alerts
    results["alert_top_feature_counts"] = dict(Counter(a.top_features[0]["feature"] for a in alerts if a.top_features))
    results["dropped_correlated_features"] = pipe.preprocessor_.dropped_correlated_

    # Save models (seed 42).
    models_dir = ROOT / "models"
    paths = {m: models_dir / f"{m}_{dataset}.joblib" for m in kept}
    for m, path in paths.items():
        joblib.dump(kept[m]["pipe"], path)
    results["model_files"] = {m: str(p.relative_to(ROOT)) for m, p in paths.items()}

    (out_dir / "results.json").write_text(json.dumps(results, indent=2, default=str))
    (out_dir / "results.md").write_text(markdown(dataset, results))
    make_figures.render(dataset, results, test, {m: r["pipe"] for m, r in kept.items()})
    log(f"  wrote {out_dir / 'results.json'}, results.md and figures/")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["nsl-kdd", "cicids2017"], required=True)
    evaluate(parser.parse_args().dataset)
