"""
Integration example — how another ACDS component consumes this module.

Run from the repository root:

    python examples/integration_demo.py

Mirrors the intended production shape: load the models once at startup, then
score flows as they arrive.
"""

from __future__ import annotations

import json

from acds import ThreatClassificationSystem

MODEL_DIR = "acds_models"

# A DoS-shaped flow: long duration, heavily forward-skewed, high byte rate.
DOS_LIKE_FLOW: dict[str, object] = {
    "Flow Duration":    1_200_000,
    "Tot Fwd Pkts":     450,
    "Tot Bwd Pkts":     5,
    "TotLen Fwd Pkts":  580_000,
    "TotLen Bwd Pkts":  1_200,
    "Fwd Pkt Len Max":  1_480,
    "Bwd Pkt Len Max":  80,
    "Flow Byts/s":      483_333,
    "Flow Pkts/s":      379,
    "Fwd IAT Tot":      1_190_000,
    "Bwd IAT Tot":      200_000,
    "Fwd Pkt Len Mean": 1_288.0,
    "Bwd Pkt Len Mean": 240.0,
    "Flow IAT Mean":    2_650.0,
    "Flow IAT Std":     18_000.0,
    "Active Mean":      350.0,
    "Idle Mean":        900_000.0,
    "Pkt Len Mean":     950.0,
    "Pkt Len Std":      420.0,
    "Pkt Size Avg":     975.0,
    "Fwd Seg Size Avg": 1_280.0,
    "Subflow Fwd Byts": 145_000,
    "Subflow Bwd Byts": 300,
    "Protocol":         "6",
    "Dst Port":         "80",
    # Identifiers are dropped inside the pipeline — pass them through freely.
    "Src IP":           "192.168.1.50",
    "Dst IP":           "10.0.0.1",
}

# A sparse row, to show that missing features are imputed rather than fatal.
PARTIAL_FLOW: dict[str, object] = {
    "Flow Duration": 8_000,
    "Tot Fwd Pkts":  4,
    "Tot Bwd Pkts":  3,
    "Protocol":      "6",
    "Dst Port":      "443",
}


def main() -> None:
    # Load once. Roughly 29 MB off disk — never do this per request.
    system = ThreatClassificationSystem.load(MODEL_DIR)

    for name, flow in (("DoS-like flow", DOS_LIKE_FLOW), ("Partial flow", PARTIAL_FLOW)):
        alert = system.inspect_traffic_flow(flow)

        print(f"\n── {name} " + "─" * (46 - len(name)))
        print(f"   verdict  : {alert['tier1']['verdict']} "
              f"({alert['tier1']['confidence']:.4f})")
        if alert["tier2"] is not None:
            print(f"   category : {alert['tier2']['threat_category']} "
                  f"({alert['tier2']['confidence']:.4f})")
            print(f"   mitre    : {alert['mitre']['technique_id']} — "
                  f"{alert['mitre']['technique_name']}")
        print(f"   severity : {alert['severity']}  ->  {alert['action']}")

    print("\n── Full alert payload " + "─" * 33)
    print(json.dumps(system.inspect_traffic_flow(DOS_LIKE_FLOW), indent=2))


if __name__ == "__main__":
    main()
