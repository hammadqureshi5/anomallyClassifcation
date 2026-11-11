"""
Autonomous Cyber Defense System (ACDS) — Threat Classification Module
=====================================================================

Public interface for the two-tier network threat classification pipeline.

Typical use from another module (for example a dashboard or API layer)::

    from acds import ThreatClassificationSystem

    system = ThreatClassificationSystem.load("acds_models")
    alert = system.inspect_traffic_flow(flow_dict)

``inspect_traffic_flow`` returns a JSON-serialisable alert context. See the
project README for the full response schema.
"""

from .threat_classifier import (
    MITRE_MAP,
    ColumnFilter,
    RollingMedianImputer,
    SafeLog1p,
    ThreatClassificationSystem,
    build_preprocessor,
    load_dataset,
)

__all__ = [
    "ThreatClassificationSystem",
    "MITRE_MAP",
    "SafeLog1p",
    "ColumnFilter",
    "RollingMedianImputer",
    "build_preprocessor",
    "load_dataset",
]

__version__ = "0.1.0"
