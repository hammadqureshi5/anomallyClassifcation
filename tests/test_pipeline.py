import json

import numpy as np
import pytest

from anomaly_detection import AnomalyPipeline, load_alerts, load_csv, save_alerts
from anomaly_detection.evaluation import evaluate_scores

ALERT_KEYS = {"id", "row_index", "timestamp", "src_ip", "dst_ip", "dst_port", "score",
              "threshold", "severity", "detector", "top_features"}


@pytest.fixture(scope="module")
def pipeline(train_ds, fast_config):
    return AnomalyPipeline(fast_config).fit(train_ds)


def test_detects_attacks_with_low_false_positives(pipeline, test_ds):
    result = pipeline.detect(test_ds)
    m = evaluate_scores(test_ds.y, result.scores["ensemble"], pipeline.thresholds_["ensemble"], test_ds.attack_type)
    assert m["roc_auc"] > 0.95
    assert m["recall"] > 0.8
    assert m["false_positive_rate"] < 0.05
    assert set(m["recall_per_attack"]) == {"dos", "portscan", "bruteforce", "exfiltration"}


def test_alert_schema_and_json_round_trip(pipeline, test_ds, tmp_path):
    result = pipeline.detect(test_ds)
    assert len(result.alerts) == int(result.is_anomaly.sum()) > 0
    alert = result.alerts[0]
    assert set(alert.to_dict()) == ALERT_KEYS
    assert alert.severity in {"low", "medium", "high"}
    assert len(alert.top_features) == 3 and "z_score" in alert.top_features[0]

    path = save_alerts(result.alerts, tmp_path / "alerts.json")
    json.loads(path.read_text())
    assert load_alerts(path)[0] == alert


def test_save_load_gives_same_scores(pipeline, test_ds, tmp_path):
    path = pipeline.save(tmp_path / "model.joblib")
    loaded = AnomalyPipeline.load(path)
    np.testing.assert_allclose(loaded.score(test_ds.X)["ensemble"], pipeline.score(test_ds.X)["ensemble"])


def test_detect_from_csv(pipeline, test_ds, tmp_path):
    csv = tmp_path / "traffic.csv"
    test_ds.to_frame().to_csv(csv, index=False)
    ds = load_csv(csv)
    assert ds.y is not None and "attack_type" not in ds.X.columns and "src_ip" not in ds.X.columns
    result = pipeline.detect(ds)
    assert result.alerts and result.alerts[0].src_ip is not None
