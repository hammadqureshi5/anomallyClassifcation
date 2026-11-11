from __future__ import annotations

import warnings

import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor

from .base import BaseDetector, subsample


class AutoencoderDetector(BaseDetector):
    """Autoencoder: learns to compress and rebuild normal traffic; the reconstruction
    error is high for traffic unlike anything seen in training.

    Built on sklearn's MLPRegressor (input -> bottleneck -> input) so PyTorch is not needed.
    """

    name = "autoencoder"

    def __init__(self, hidden_layer_sizes: list[int] | None = None, max_iter: int = 60,
                 max_train_samples: int | None = None, random_state: int = 42):
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter
        self.max_train_samples = max_train_samples
        self.random_state = random_state

    def _layers(self, n_features: int) -> tuple[int, ...]:
        if self.hidden_layer_sizes:
            return tuple(self.hidden_layer_sizes)
        bottleneck = max(2, n_features // 4)
        outer = max(bottleneck * 2, n_features // 2)
        return (outer, bottleneck, outer)

    def fit(self, X: np.ndarray) -> "AutoencoderDetector":
        X = subsample(X, self.max_train_samples, self.random_state)
        self.model_ = MLPRegressor(
            hidden_layer_sizes=self._layers(X.shape[1]),
            max_iter=self.max_iter,
            early_stopping=True,
            random_state=self.random_state,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.model_.fit(X, X)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return np.mean((X - self.model_.predict(X)) ** 2, axis=1)
