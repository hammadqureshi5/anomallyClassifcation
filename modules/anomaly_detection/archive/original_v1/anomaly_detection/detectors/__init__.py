from __future__ import annotations

from ..config import Config
from .autoencoder import AutoencoderDetector
from .base import BaseDetector
from .ensemble import EnsembleDetector
from .iforest import IsolationForestDetector
from .lof import LOFDetector
from .statistical import RobustZScoreDetector

DETECTORS = {
    RobustZScoreDetector.name: RobustZScoreDetector,
    IsolationForestDetector.name: IsolationForestDetector,
    LOFDetector.name: LOFDetector,
    AutoencoderDetector.name: AutoencoderDetector,
}


def build_detector(name: str, config: Config) -> BaseDetector:
    if name not in DETECTORS:
        raise ValueError(f"Unknown detector {name!r}; choose from {sorted(DETECTORS)}")
    if name == RobustZScoreDetector.name:
        return RobustZScoreDetector()
    params = dict(getattr(config, name))
    return DETECTORS[name](random_state=config.random_state, **params)


__all__ = [
    "BaseDetector", "EnsembleDetector", "RobustZScoreDetector", "IsolationForestDetector",
    "LOFDetector", "AutoencoderDetector", "DETECTORS", "build_detector",
]
