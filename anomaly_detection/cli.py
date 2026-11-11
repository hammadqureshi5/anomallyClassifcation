"""Command-line interface.

    python -m anomaly_detection.cli generate --out data/processed/sample_traffic.csv
    python -m anomaly_detection.cli evaluate --dataset synthetic
    python -m anomaly_detection.cli evaluate --dataset nsl-kdd --supervised
    python -m anomaly_detection.cli train    --dataset nsl-kdd --model models/pipeline.joblib
    python -m anomaly_detection.cli detect   --model models/pipeline.joblib --input traffic.csv
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

from .alerts import save_alerts
from .config import Config
from .data import Dataset, generate_synthetic, load_cicids2017, load_csv, load_nsl_kdd
from .evaluation import evaluate_scores, metrics_table, plot_curves, supervised_baseline_scores
from .pipeline import AnomalyPipeline

DATASETS = ["synthetic", "nsl-kdd", "cicids2017", "csv"]
DEFAULT_DIRS = {"nsl-kdd": "data/raw/NSL-KDD", "cicids2017": "data/raw/CIC-IDS- 2017"}


def _random_split(ds: Dataset, cfg: Config) -> tuple[Dataset, Dataset]:
    idx = np.arange(len(ds))
    stratify = ds.y if ds.y is not None and len(np.unique(ds.y)) == 2 else None
    train_idx, test_idx = train_test_split(idx, test_size=cfg.data["test_size"],
                                           random_state=cfg.random_state, stratify=stratify)
    return ds.subset(train_idx), ds.subset(test_idx)


def load_train_test(args, cfg: Config) -> tuple[Dataset, Dataset]:
    data_dir = args.data_dir or DEFAULT_DIRS.get(args.dataset)
    if args.dataset == "synthetic":
        return generate_synthetic(8000, 800, seed=cfg.random_state), generate_synthetic(4000, 800, seed=cfg.random_state + 1)
    if args.dataset == "nsl-kdd":
        return load_nsl_kdd(data_dir, "train"), load_nsl_kdd(data_dir, "test")
    if args.dataset == "cicids2017":
        ds = load_cicids2017(data_dir, cfg.data["cicids_sample_frac"], cfg.random_state,
                             drop_duplicates=cfg.data.get("cicids_drop_duplicates", False))
        return _random_split(ds, cfg)
    if not args.input:
        raise SystemExit("--input is required with --dataset csv")
    return _random_split(load_csv(args.input, args.label_col), cfg)


def cmd_generate(args, cfg: Config) -> None:
    ds = generate_synthetic(args.n_benign, args.n_attack, seed=args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    ds.to_frame().to_csv(out, index=False)
    print(f"Wrote {len(ds)} flows ({int(ds.y.sum())} attacks) to {out}")


def cmd_train(args, cfg: Config) -> None:
    if args.dataset == "csv":
        if not args.input:
            raise SystemExit("--input is required with --dataset csv")
        train = load_csv(args.input, args.label_col)
    else:
        train, _ = load_train_test(args, cfg)
    pipe = AnomalyPipeline(cfg).fit(train)
    path = pipe.save(args.model)
    print(f"Trained on {len(train)} rows ({len(pipe.preprocessor_.feature_names_)} features). Model saved to {path}")
    for name, thr in pipe.thresholds_.items():
        print(f"  threshold[{name}] = {thr:.4f}")


def cmd_evaluate(args, cfg: Config) -> None:
    train, test = load_train_test(args, cfg)
    if test.y is None:
        raise SystemExit("Evaluation needs labelled test data (use --label-col).")
    print(f"Train: {len(train)} rows | Test: {len(test)} rows ({int(test.y.sum())} attacks)")

    pipe = AnomalyPipeline(cfg).fit(train)
    scores = pipe.score(test.X)
    results = {n: evaluate_scores(test.y, s, pipe.thresholds_[n], test.attack_type) for n, s in scores.items()}

    if args.supervised and train.y is not None and len(np.unique(train.y)) == 2:
        rf_scores = supervised_baseline_scores(pipe.transform(train.X), train.y, pipe.transform(test.X), cfg.random_state)
        scores["random_forest (supervised)"] = rf_scores
        results["random_forest (supervised)"] = evaluate_scores(test.y, rf_scores, 0.5, test.attack_type)

    reports = Path(args.reports_dir)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "metrics.json").write_text(json.dumps(results, indent=2))
    table = metrics_table(results)
    (reports / "metrics.md").write_text(table + "\n")
    plots = plot_curves(test.y, scores, reports)
    pipe.save(args.model)

    print("\n" + table)
    primary = results[pipe.primary]
    if "recall_per_attack" in primary:
        print(f"\nRecall per attack type ({pipe.primary}):")
        for kind, r in sorted(primary["recall_per_attack"].items(), key=lambda kv: -kv[1]["count"]):
            print(f"  {kind:<30} {r['recall']:.3f}  (n={r['count']})")
    print(f"\nSaved {reports / 'metrics.json'}, {reports / 'metrics.md'}, " + ", ".join(map(str, plots)))
    print(f"Model saved to {args.model}")


def cmd_detect(args, cfg: Config) -> None:
    pipe = AnomalyPipeline.load(args.model)
    ds = load_csv(args.input, args.label_col)
    result = pipe.detect(ds)
    out = save_alerts(result.alerts, args.output)

    by_severity = Counter(a.severity for a in result.alerts)
    print(f"Scored {len(ds)} rows -> {len(result.alerts)} alerts "
          f"(high={by_severity['high']}, medium={by_severity['medium']}, low={by_severity['low']}). Saved to {out}")
    top_sources = Counter(a.src_ip for a in result.alerts if a.src_ip).most_common(5)
    if top_sources:
        print("Top alerting source IPs: " + ", ".join(f"{ip} ({n})" for ip, n in top_sources))
    if ds.y is not None:
        m = evaluate_scores(ds.y, result.scores[pipe.primary], pipe.thresholds_[pipe.primary])
        print(f"Labels found: precision={m['precision']:.3f} recall={m['recall']:.3f} "
              f"false_positive_rate={m['false_positive_rate']:.4f}")
    if args.scores_out:
        frame = ds.to_frame()
        for name, s in result.scores.items():
            frame[f"score_{name}"] = s
        frame["is_anomaly"] = result.is_anomaly
        frame.to_csv(args.scores_out, index=False)
        print(f"Per-row scores saved to {args.scores_out}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="anomaly_detection", description="Network anomaly detection module")
    parser.add_argument("--config", default="configs/config.yaml", help="YAML config file")
    sub = parser.add_subparsers(dest="command", required=True)

    def data_args(p):
        p.add_argument("--dataset", choices=DATASETS, default="synthetic")
        p.add_argument("--data-dir", help="folder with dataset files (defaults under data/raw/)")
        p.add_argument("--input", help="CSV file when --dataset csv")
        p.add_argument("--label-col", help="label column of a CSV (benign values: BENIGN/normal/0)")
        p.add_argument("--model", default="models/pipeline.joblib")

    p = sub.add_parser("generate", help="write a synthetic traffic CSV for demos")
    p.add_argument("--out", default="data/processed/sample_traffic.csv")
    p.add_argument("--n-benign", type=int, default=2000)
    p.add_argument("--n-attack", type=int, default=200)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("train", help="train on normal traffic and save the model")
    data_args(p)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("evaluate", help="train, test on labelled data, write metrics and plots")
    data_args(p)
    p.add_argument("--supervised", action="store_true", help="also train a supervised Random Forest baseline")
    p.add_argument("--reports-dir", default="reports")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("detect", help="score a CSV with a trained model and write alerts")
    p.add_argument("--model", default="models/pipeline.joblib")
    p.add_argument("--input", required=True)
    p.add_argument("--label-col")
    p.add_argument("--output", default="reports/alerts.json", help=".json or .csv")
    p.add_argument("--scores-out", help="optional CSV with per-row scores")
    p.set_defaults(func=cmd_detect)

    args = parser.parse_args(argv)
    cfg = Config.from_yaml(args.config) if Path(args.config).exists() else Config()
    args.func(args, cfg)


if __name__ == "__main__":
    main()
