"""
Regression test for the __main__ pickle-compatibility shim.

Artifacts produced by running the module as a script
(`python -m acds.threat_classifier train ...`) pickle the custom transformers
under the `__main__` module. Loading them from a normal package import then
fails with `AttributeError: Can't get attribute 'SafeLog1p'`.

`_register_legacy_pickle_aliases` aliases the classes into `__main__` before any
load. This test pins that behaviour so the shim is not removed as dead code.
"""

from __future__ import annotations

import pickle
import sys

from acds.threat_classifier import (
    ColumnFilter,
    RollingMedianImputer,
    SafeLog1p,
    _register_legacy_pickle_aliases,
)

LEGACY_CLASSES = (SafeLog1p, ColumnFilter, RollingMedianImputer)


def test_shim_registers_all_transformers_into_main() -> None:
    main_module = sys.modules["__main__"]
    for cls in LEGACY_CLASSES:
        if hasattr(main_module, cls.__name__):
            delattr(main_module, cls.__name__)

    _register_legacy_pickle_aliases()

    for cls in LEGACY_CLASSES:
        assert getattr(main_module, cls.__name__) is cls


def test_shim_is_idempotent_and_non_destructive() -> None:
    main_module = sys.modules["__main__"]
    sentinel = object()
    setattr(main_module, "SafeLog1p", sentinel)
    try:
        _register_legacy_pickle_aliases()
        # An existing binding must not be overwritten.
        assert getattr(main_module, "SafeLog1p") is sentinel
    finally:
        delattr(main_module, "SafeLog1p")


def test_main_pickled_payload_loads_after_shim() -> None:
    """Round-trips a payload whose class path points at __main__."""
    main_module = sys.modules["__main__"]
    for cls in LEGACY_CLASSES:
        if hasattr(main_module, cls.__name__):
            delattr(main_module, cls.__name__)

    # Forge a pickle that references __main__.SafeLog1p, as joblib would have.
    setattr(main_module, "SafeLog1p", SafeLog1p)
    instance = SafeLog1p(window=42)
    instance.__class__.__module__ = "__main__"
    try:
        payload = pickle.dumps(instance)
    finally:
        instance.__class__.__module__ = SafeLog1p.__module__
        delattr(main_module, "SafeLog1p")

    _register_legacy_pickle_aliases()
    restored = pickle.loads(payload)
    assert restored.window == 42
