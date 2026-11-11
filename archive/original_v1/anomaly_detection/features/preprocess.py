"""Turn raw flow tables into numeric matrices the detectors can use.

Steps (fit only on benign training traffic, then reused unchanged at detection time):
1. inf -> NaN, then NaN -> training median
2. signed log1p on numeric columns (byte/packet counts are very heavy-tailed)
3. one-hot encode categoricals (top categories only; unseen values become all zeros)
4. drop constant columns
5. RobustScaler (median/IQR), then clip extreme values
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler


class Preprocessor:
    def __init__(self, log_transform: bool = True, max_categories: int = 50, clip: float = 50.0):
        self.log_transform = log_transform
        self.max_categories = max_categories
        self.clip = clip

    def fit(self, df: pd.DataFrame) -> "Preprocessor":
        df = df.replace([np.inf, -np.inf], np.nan)
        self.numeric_ = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
        self.categorical_ = [c for c in df.columns if c not in self.numeric_]
        self.medians_ = df[self.numeric_].median().fillna(0.0)
        self.categories_ = {
            c: df[c].astype(str).value_counts().index[: self.max_categories].tolist()
            for c in self.categorical_
        }
        encoded = self._encode(df)
        self.feature_names_ = [c for c in encoded.columns if encoded[c].nunique() > 1]
        self.scaler_ = RobustScaler().fit(encoded[self.feature_names_].to_numpy())
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        encoded = self._encode(df.replace([np.inf, -np.inf], np.nan))
        encoded = encoded.reindex(columns=self.feature_names_, fill_value=0.0)
        X = self.scaler_.transform(encoded.to_numpy())
        return np.clip(X, -self.clip, self.clip)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)

    def _encode(self, df: pd.DataFrame) -> pd.DataFrame:
        num = df.reindex(columns=self.numeric_).apply(pd.to_numeric, errors="coerce")
        num = num.fillna(self.medians_).astype(float)
        if self.log_transform:
            num = np.sign(num) * np.log1p(num.abs())
        dummies = {}
        for col, cats in self.categories_.items():
            values = df[col].astype(str) if col in df.columns else pd.Series("", index=df.index)
            for cat in cats:
                dummies[f"{col}={cat}"] = (values == cat).astype(float).to_numpy()
        return pd.concat([num, pd.DataFrame(dummies, index=df.index)], axis=1)
