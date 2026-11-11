import json

from anomaly_detection.cli import main


def test_generate_evaluate_detect(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no config file here, so defaults are used
    main(["generate", "--out", "sample.csv", "--n-benign", "500", "--n-attack", "50"])
    main(["evaluate", "--dataset", "synthetic", "--supervised", "--reports-dir", "reports", "--model", "model.joblib"])
    metrics = json.loads((tmp_path / "reports" / "metrics.json").read_text())
    assert "ensemble" in metrics and "random_forest (supervised)" in metrics
    assert (tmp_path / "reports" / "roc_curve.png").exists()

    main(["detect", "--model", "model.joblib", "--input", "sample.csv", "--output", "alerts.json",
          "--scores-out", "scores.csv"])
    assert json.loads((tmp_path / "alerts.json").read_text())
    assert (tmp_path / "scores.csv").exists()
