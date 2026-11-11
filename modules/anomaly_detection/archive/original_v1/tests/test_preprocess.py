import numpy as np
import pandas as pd

from anomaly_detection.features import Preprocessor


def test_handles_inf_nan_unseen_categories_and_missing_columns():
    train = pd.DataFrame({
        "bytes": [10.0, 20.0, 30.0, 40.0, np.inf],
        "packets": [1, 2, 3, 4, 5],
        "protocol": ["tcp", "udp", "tcp", "tcp", "udp"],
        "constant": [1, 1, 1, 1, 1],
    })
    pre = Preprocessor().fit(train)
    assert "constant" not in pre.feature_names_
    assert {"protocol=tcp", "protocol=udp"} <= set(pre.feature_names_)

    new = pd.DataFrame({"bytes": [np.nan, -np.inf], "protocol": ["icmp", "tcp"], "extra": [1, 2]})
    X = pre.transform(new)  # "packets" missing, "extra" unknown, "icmp" unseen
    assert X.shape == (2, len(pre.feature_names_))
    assert np.isfinite(X).all()
