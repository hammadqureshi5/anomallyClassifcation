"""Tests for the v2 options. Defaults must keep v1 behaviour."""
import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import roc_auc_score

from anomaly_detection import AnomalyPipeline, Config
from anomaly_detection.detectors import RobustZScoreDetector
from anomaly_detection.detectors.ensemble import combine_scores, normalize_scores
from anomaly_detection.features import Preprocessor
from anomaly_detection.hybrid import HybridDetector


def test_tail_normalization_does_not_saturate():
    ref = np.sort(np.random.default_rng(0).normal(size=1000))
    scores = np.array([10.0, 100.0])
    assert normalize_scores(scores, ref, "rank").tolist() == [1.0, 1.0]   # v1: tie
    tail = normalize_scores(scores, ref, "tail")
    assert tail[1] > tail[0] > 1.0                                        # v2: ordered
    assert combine_scores([np.array([1.0, 0.0]), np.array([0.0, 3.0])], "max").tolist() == [1.0, 3.0]


def test_robust_z_top_k_default_is_max():
    X = np.random.default_rng(1).normal(size=(200, 5))
    det = RobustZScoreDetector().fit(X)
    np.testing.assert_allclose(det.score(X), np.abs(det.feature_z(X)).max(axis=1))
    assert (RobustZScoreDetector(top_k=3).fit(X).score(X) <= det.score(X) + 1e-12).all()


def test_correlated_features_are_dropped_only_when_asked():
    rng = np.random.default_rng(2)
    a = rng.lognormal(size=500)
    df = pd.DataFrame({"a": a, "a_copy": a * 2, "b": rng.lognormal(size=500)})
    assert Preprocessor().fit(df).feature_names_ == ["a", "a_copy", "b"]
    pre = Preprocessor(corr_threshold=0.99).fit(df)
    assert pre.feature_names_ == ["a", "b"] and pre.dropped_correlated_ == {"a_copy": "a"}


@pytest.fixture(scope="module")
def v2_config(fast_config):
    cfg = Config.from_dict({**fast_config.__dict__, "detectors": ["iforest", "autoencoder"],
                            "ensemble": {"normalization": "tail", "combine": "max"},
                            "features": {"corr_threshold": 0.99}, "threshold_percentile": 97.0})
    return cfg


def test_v2_pipeline_and_hybrid(train_ds, test_ds, v2_config):
    pipe = AnomalyPipeline(v2_config).fit(train_ds)
    assert roc_auc_score(test_ds.y, pipe.score(test_ds.X)["ensemble"]) > 0.95
    hybrid = HybridDetector(pipe, n_estimators=50).fit(train_ds)
    s = hybrid.score(test_ds.X)
    # hybrid flag == classifier flag OR anomaly flag
    expected = (s["supervised"] > 0.5) | (s["anomaly"] > pipe.thresholds_["ensemble"])
    np.testing.assert_array_equal(hybrid.predict(test_ds.X), expected)
    assert hybrid.predict(test_ds.X)[test_ds.y == 1].mean() > 0.95
