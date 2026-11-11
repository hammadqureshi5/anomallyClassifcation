import pytest

from anomaly_detection import Config, generate_synthetic


@pytest.fixture(scope="session")
def fast_config():
    return Config.from_dict({
        "iforest": {"n_estimators": 50},
        "lof": {"n_neighbors": 20, "max_train_samples": 2000},
        "autoencoder": {"max_iter": 30},
    })


@pytest.fixture(scope="session")
def train_ds():
    return generate_synthetic(n_benign=2000, n_attack=200, seed=1)


@pytest.fixture(scope="session")
def test_ds():
    return generate_synthetic(n_benign=1000, n_attack=200, seed=2)
