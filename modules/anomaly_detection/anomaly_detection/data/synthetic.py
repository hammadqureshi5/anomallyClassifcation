"""Synthetic network-flow generator for tests and demos (no dataset download needed).

Benign flows look like ordinary web/DNS/SSH traffic. Attack flows imitate common
patterns: DoS floods, port scans, SSH brute force, and data exfiltration.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .loaders import Dataset

ATTACK_TYPES = ["dos", "portscan", "bruteforce", "exfiltration"]


def _flows(n: int, rng: np.random.Generator, **overrides) -> pd.DataFrame:
    df = pd.DataFrame({
        "duration": rng.lognormal(0.0, 1.0, n),
        "src_bytes": rng.lognormal(7.0, 1.0, n),
        "dst_bytes": rng.lognormal(8.0, 1.2, n),
        "packets": rng.poisson(20, n) + 1.0,
        "distinct_dst_ports": rng.poisson(0.5, n) + 1.0,
        "failed_logins": rng.poisson(0.02, n).astype(float),
        "syn_ratio": rng.beta(2, 20, n),
        "protocol": rng.choice(["tcp", "udp", "icmp"], n, p=[0.8, 0.18, 0.02]),
        "dst_port": rng.choice([80, 443, 53, 22, 25], n, p=[0.3, 0.45, 0.15, 0.05, 0.05]),
    })
    for col, values in overrides.items():
        df[col] = values
    df["packet_rate"] = df["packets"] / (df["duration"] + 0.1)
    return df


def _attack(kind: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    if kind == "dos":
        return _flows(n, rng, duration=rng.uniform(0.01, 0.5, n), packets=rng.poisson(3000, n) + 1.0,
                      dst_bytes=rng.lognormal(3, 0.5, n), syn_ratio=rng.beta(20, 2, n), dst_port=80)
    if kind == "portscan":
        return _flows(n, rng, duration=rng.uniform(0.01, 0.2, n), packets=rng.integers(1, 4, n).astype(float),
                      src_bytes=rng.lognormal(3, 0.3, n), dst_bytes=rng.lognormal(2, 0.3, n),
                      distinct_dst_ports=rng.poisson(300, n) + 1.0, syn_ratio=rng.beta(20, 2, n),
                      dst_port=rng.integers(1, 65535, n))
    if kind == "bruteforce":
        return _flows(n, rng, duration=rng.uniform(0.5, 3, n), failed_logins=rng.poisson(20, n) + 3.0,
                      src_bytes=rng.lognormal(6, 0.3, n), protocol="tcp", dst_port=22)
    if kind == "exfiltration":
        return _flows(n, rng, duration=rng.lognormal(4, 0.5, n), src_bytes=rng.lognormal(17, 0.7, n),
                      dst_bytes=rng.lognormal(5, 0.5, n), protocol="tcp", dst_port=443)
    raise ValueError(f"Unknown attack type {kind!r}; choose from {ATTACK_TYPES}")


def generate_synthetic(
    n_benign: int = 5000,
    n_attack: int = 500,
    attack_types: list[str] | None = None,
    seed: int = 0,
) -> Dataset:
    rng = np.random.default_rng(seed)
    attack_types = attack_types or ATTACK_TYPES

    parts, kinds = [_flows(n_benign, rng)], ["benign"] * n_benign
    per_type = np.array_split(np.arange(n_attack), len(attack_types))
    for kind, idx in zip(attack_types, per_type):
        parts.append(_attack(kind, len(idx), rng))
        kinds += [kind] * len(idx)

    df = pd.concat(parts, ignore_index=True)
    attack_type = pd.Series(kinds, name="attack_type")
    n = len(df)

    attacker_ips = [f"10.0.0.{i}" for i in range(1, 6)]
    src_ip = np.where(attack_type == "benign",
                      [f"192.168.1.{i}" for i in rng.integers(2, 250, n)],
                      rng.choice(attacker_ips, n))
    meta = pd.DataFrame({
        "src_ip": src_ip,
        "dst_ip": [f"172.16.0.{i}" for i in rng.integers(2, 20, n)],
        "dst_port": df.pop("dst_port"),
        "timestamp": pd.Timestamp("2026-01-01") + pd.to_timedelta(rng.uniform(0, 86400, n), unit="s"),
    })

    order = rng.permutation(n)
    ds = Dataset(X=df, y=(attack_type != "benign").astype(int).to_numpy(),
                 attack_type=attack_type, meta=meta)
    return ds.subset(order)
