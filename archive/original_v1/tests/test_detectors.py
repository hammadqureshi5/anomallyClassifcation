import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from anomaly_detection.detectors import DETECTORS, EnsembleDetector, build_detector
from anomaly_detection.features import Preprocessor


@pytest.fixture(scope="module")
def matrices(train_ds, test_ds):
    benign = train_ds.X[train_ds.y == 0]
    pre = Preprocessor().fit(benign)
    return pre.transform(benign), pre.transform(test_ds.X), test_ds.y


@pytest.mark.parametrize("name", sorted(DETECTORS))
def test_detector_separates_attacks(name, matrices, fast_config):
    X_train, X_test, y_test = matrices
    detector = build_detector(name, fast_config).fit(X_train)
    scores = detector.score(X_test)
    assert scores.shape == (len(X_test),)
    assert np.isfinite(scores).all()
    assert roc_auc_score(y_test, scores) > 0.9


def test_ensemble_scores_are_ranks(matrices, fast_config):
    X_train, X_test, y_test = matrices
    members = [build_detector(n, fast_config) for n in ("robust_z", "iforest")]
    ensemble = EnsembleDetector(members).fit(X_train[:1500], X_ref=X_train[1500:])
    scores = ensemble.score_all(X_test)
    assert set(scores) == {"robust_z", "iforest", "ensemble"}
    assert scores["ensemble"].min() >= 0 and scores["ensemble"].max() <= 1
    assert roc_auc_score(y_test, scores["ensemble"]) > 0.9
