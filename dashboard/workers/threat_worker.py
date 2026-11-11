"""Worker for the Threat Classification module (acds-threat-classification repo).

Runs the same two tiers as ThreatClassificationSystem.inspect_traffic_flow, but on the
whole batch at once. Accepts CIC-IDS2018 column names and maps CIC-IDS2017 names to them.
"""

from __future__ import annotations

import numpy as np

from _common import clean, host_for, log, parse_args, progress, read_csv, row_limit, write_output

# CIC-IDS2017 (CICFlowMeter v3) name -> CIC-IDS2018 name used by the trained preprocessor.
CIC2017_TO_2018 = {
    "Destination Port": "Dst Port", "Source IP": "Src IP", "Destination IP": "Dst IP",
    "Total Fwd Packets": "Tot Fwd Pkts", "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts", "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max", "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean", "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Flow Bytes/s": "Flow Byts/s", "Flow Packets/s": "Flow Pkts/s",
    "Fwd IAT Total": "Fwd IAT Tot", "Bwd IAT Total": "Bwd IAT Tot",
    "Packet Length Mean": "Pkt Len Mean", "Packet Length Std": "Pkt Len Std",
    "Average Packet Size": "Pkt Size Avg", "Avg Fwd Segment Size": "Fwd Seg Size Avg",
    "Subflow Fwd Bytes": "Subflow Fwd Byts", "Subflow Bwd Bytes": "Subflow Bwd Byts",
}

ACTION_TEXT = {
    "BLOCK": "Recommended action: BLOCK the source at the perimeter firewall and investigate the target "
             "host. This is a recommendation for analyst review; ACDS never executes it automatically.",
    "ALERT": "Recommended action: ALERT. Monitor the source and correlate with other findings before "
             "taking action.",
}


def main() -> None:
    args = parse_args()
    from acds import threat_classifier as tc
    from acds.threat_classifier import ColumnFilter, ThreatClassificationSystem

    progress(0.05)
    df = read_csv(args.input, row_limit(args.options))
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns={k: v for k, v in CIC2017_TO_2018.items() if k in df.columns})
    labels = df["Label"].astype(str).str.strip() if "Label" in df.columns else None

    required = (tc.SKEWED_NUM_COLS + tc.NORMAL_NUM_COLS + tc.LOW_CARD_CAT_COLS + tc.HIGH_CARD_CAT_COLS)
    missing = [c for c in required if c not in df.columns]
    if missing:
        log(f"{len(missing)} expected feature(s) not in file, imputed from training medians: "
            + ", ".join(missing))
    features = ColumnFilter(tc.DROP_COLUMNS).transform(df.drop(columns=["Label"], errors="ignore"))
    for col in missing:
        features[col] = "6" if col == "Protocol" else np.nan
    for col in tc.LOW_CARD_CAT_COLS + tc.HIGH_CARD_CAT_COLS:
        features[col] = features[col].astype(str)
    progress(0.15)

    system = ThreatClassificationSystem.load("acds_models")
    progress(0.3)
    X = system.preprocessor.transform(features)
    t1 = system.tier1_model.predict_proba(X)
    anomalous = np.flatnonzero(t1[:, 1] > t1[:, 0])
    log(f"Tier 1 (LightGBM): {len(anomalous):,} of {len(df):,} flows anomalous")
    progress(0.6)

    findings = []
    if len(anomalous):
        t2 = system.tier2_model.predict_proba(X[anomalous])
        for k, i in enumerate(anomalous):
            idx = int(np.argmax(t2[k]))
            label = system._label_encoder.inverse_transform([idx])[0]
            probs = {c: round(float(p), 6) for c, p in zip(system.threat_classes, t2[k])}
            alert = system._build_alert("Anomalous", float(t1[i, 1]), label, float(t2[k][idx]), probs,
                                        system._resolve_mitre(label))
            row = df.iloc[i]
            src, dst = clean(row.get("Src IP")), clean(row.get("Dst IP"))
            port = clean(row.get("Dst Port"))
            top_probs = sorted(probs.items(), key=lambda kv: -kv[1])[:3]
            evidence = [
                {"label": "Tier 1 verdict", "value": f"Anomalous ({alert['tier1']['confidence']:.1%})"},
                {"label": "Tier 2 class", "value": f"{label} ({alert['tier2']['confidence']:.1%})"},
                {"label": "Other candidates", "value": ", ".join(f"{c} {p:.1%}" for c, p in top_probs[1:])},
                {"label": "Recommended action", "value": alert["action"]},
                {"label": "Row in input", "value": int(i)},
            ]
            if labels is not None:
                evidence.append({"label": "Label in input file", "value": labels.iloc[i]})
            findings.append({
                "severity": alert["severity"].lower(),
                "title": f"{label} detected",
                "description": f"The two-tier classifier identified this flow as {label}, mapped to "
                               f"MITRE ATT&CK {alert['mitre']['technique_id']} "
                               f"({alert['mitre']['technique_name']}, tactic: {alert['mitre']['tactic']}).",
                "host": host_for(src, dst, port, fallback=f"row {i}"),
                "asset": {"src_ip": src, "dst_ip": dst, "dst_port": None if port is None else int(float(port))},
                "score": alert["tier2"]["confidence"],
                "confidence": alert["tier2"]["confidence"],
                "mitre": alert["mitre"],
                "evidence": evidence,
                "top_features": [],
                "recommendation": ACTION_TEXT[alert["action"]],
            })
    progress(0.95)
    write_output(args.output, len(df), findings)


if __name__ == "__main__":
    main()
