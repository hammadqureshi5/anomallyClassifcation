"""Worker for the Anomaly Detection module (anomally_detection repo)."""

from __future__ import annotations

from _common import clean, host_for, log, parse_args, progress, read_csv, row_limit, write_output

MODEL_INFO = {
    "improved_cicids2017": "v2 model trained on CIC-IDS2017 benign traffic",
    "improved_nsl-kdd": "v2 model trained on NSL-KDD normal traffic",
    "pipeline": "demo model trained on synthetic traffic",
}

RECOMMENDATION = ("Review this flow against the host's normal behaviour. If the activity is not expected, "
                  "check the threat-classification result for the same traffic and isolate or rate-limit "
                  "the source. Mark the finding as a false positive if it is legitimate, so the "
                  "threshold can be re-tuned.")


def pick_model(columns: list[str]) -> str:
    cols = {c.strip().lower() for c in columns}
    if "flow duration" in cols:
        return "improved_cicids2017"
    if {"protocol_type", "service"} <= cols:
        return "improved_nsl-kdd"
    return "pipeline"


def main() -> None:
    args = parse_args()
    from anomaly_detection.data.loaders import _split_frame
    from anomaly_detection.pipeline import AnomalyPipeline

    progress(0.05)
    df = read_csv(args.input, row_limit(args.options))
    model = args.options.get("model", "auto")
    if model == "auto":
        model = pick_model(list(df.columns))
        log(f"Auto-selected model: {model}")
    log(f"Model: {MODEL_INFO.get(model, model)}")
    progress(0.2)

    label_col = next((c for c in df.columns if str(c).strip().lower() == "label"), None)
    dataset = _split_frame(df, label_col)
    pipe = AnomalyPipeline.load(f"models/{model}.joblib")
    for detector in getattr(pipe.detector_, "detectors", []):
        # Models saved by v1 predate RobustZScoreDetector.top_k; top_k=1 is the v1 behaviour.
        if detector.name == "robust_z" and not hasattr(detector, "top_k"):
            detector.top_k = 1
    log("Model loaded; scoring flows with detector(s): " + ", ".join(pipe.config.detectors))
    progress(0.4)

    result = pipe.detect(dataset)
    progress(0.9)
    log(f"{int(result.is_anomaly.sum()):,} of {len(dataset):,} flows above threshold "
        f"({100 * result.is_anomaly.mean():.1f}%)")
    if dataset.y is not None:
        caught = int((result.is_anomaly & (dataset.y == 1)).sum())
        log(f"Ground truth in file: {int(dataset.y.sum()):,} attack rows; {caught:,} flagged "
            f"(recall {caught / max(int(dataset.y.sum()), 1):.1%})")

    findings = []
    for alert in result.alerts:
        top = alert.top_features[0] if alert.top_features else None
        title = (f"Anomalous flow: unusually {top['direction']} {top['feature']}" if top
                 else "Anomalous network flow")
        reasons = "; ".join(f"{f['feature']} is {f['direction']} (z = {f['z_score']})"
                            for f in alert.top_features)
        evidence = [
            {"label": "Anomaly score", "value": alert.score},
            {"label": "Threshold", "value": alert.threshold},
            {"label": "Detector", "value": alert.detector},
            {"label": "Model", "value": model},
            {"label": "Row in input", "value": alert.row_index},
        ]
        if alert.timestamp:
            evidence.append({"label": "Timestamp", "value": alert.timestamp})
        if dataset.attack_type is not None:
            evidence.append({"label": "Label in input file",
                             "value": clean(dataset.attack_type.iloc[alert.row_index])})
        findings.append({
            "severity": alert.severity,
            "title": title,
            "description": f"This flow deviates from the learned profile of normal traffic. {reasons}.",
            "host": host_for(alert.src_ip, alert.dst_ip, alert.dst_port, fallback=f"row {alert.row_index}"),
            "asset": {"src_ip": alert.src_ip, "dst_ip": alert.dst_ip, "dst_port": alert.dst_port},
            "score": alert.score,
            "confidence": None,
            "mitre": None,
            "evidence": evidence,
            "top_features": alert.top_features,
            "recommendation": RECOMMENDATION,
        })
    write_output(args.output, len(dataset), findings)


if __name__ == "__main__":
    main()
