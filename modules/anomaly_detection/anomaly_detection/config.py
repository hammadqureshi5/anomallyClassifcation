"""Configuration for the anomaly detection module."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml


@dataclass
class Config:
    detectors: list[str] = field(default_factory=lambda: ["robust_z", "iforest", "lof", "autoencoder"])
    primary_detector: str = "ensemble"
    threshold_percentile: float = 99.0
    severity_percentiles: dict = field(default_factory=lambda: {"medium": 99.7, "high": 99.95})
    val_fraction: float = 0.2
    max_train_samples: int = 50000
    random_state: int = 42
    top_k_features: int = 3
    # Options added in v2; the defaults reproduce the original (v1) behaviour exactly.
    features: dict = field(default_factory=lambda: {"corr_threshold": None})
    ensemble: dict = field(default_factory=lambda: {"normalization": "rank", "combine": "mean"})
    robust_z: dict = field(default_factory=lambda: {"top_k": 1})
    iforest: dict = field(default_factory=lambda: {"n_estimators": 200})
    lof: dict = field(default_factory=lambda: {"n_neighbors": 20, "max_train_samples": 10000})
    autoencoder: dict = field(default_factory=lambda: {"hidden_layer_sizes": None, "max_iter": 60})
    data: dict = field(default_factory=lambda: {"cicids_sample_frac": 0.1, "test_size": 0.3,
                                                 "cicids_drop_duplicates": False})

    @classmethod
    def from_dict(cls, values: dict) -> "Config":
        known = {f.name for f in fields(cls)}
        unknown = set(values) - known
        if unknown:
            raise ValueError(f"Unknown config keys: {sorted(unknown)}")
        cfg = cls()
        for key, value in values.items():
            default = getattr(cfg, key)
            # Merge nested sections so a partial override keeps the other defaults.
            if isinstance(default, dict) and isinstance(value, dict):
                value = {**default, **value}
            setattr(cfg, key, value)
        return cfg

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Config":
        with open(path) as f:
            return cls.from_dict(yaml.safe_load(f) or {})
