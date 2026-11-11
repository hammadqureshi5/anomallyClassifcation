import gc
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
import joblib


# --------------------------------------------------
# 1. Paths and settings
# --------------------------------------------------

DATA_PATH = Path(
    r"C:\Users\Dell\.cache\huggingface\datasets\bodmas_category_joined.csv"
)

PROJECT_DIR = Path(__file__).resolve().parent
MODEL_DIR = PROJECT_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

RANDOM_STATE = 42
TEST_SIZE = 0.20

MALWARE_CATEGORIES = [
    "trojan",
    "worm",
    "backdoor",
    "downloader",
    "ransomware",
    "dropper",
    "informationstealer",
    "virus",
]


# --------------------------------------------------
# 2. Find feature columns
# --------------------------------------------------

print("\nFinding feature columns...")

# Read only the CSV header, not the full dataset
columns = pd.read_csv(DATA_PATH, nrows=0).columns.tolist()

feature_columns = [
    col for col in columns
    if re.fullmatch(r"feature_\d+", col)
]

feature_columns.sort(key=lambda col: int(col.split("_")[1]))

if len(feature_columns) == 0:
    raise ValueError("No feature columns were found.")

print(f"Found {len(feature_columns)} feature columns.")
print("First 5:", feature_columns[:5])
print("Last 5:", feature_columns[-5:])

required_columns = ["label", "category"]

for col in required_columns:
    if col not in columns:
        raise ValueError(f"Required column '{col}' was not found in the CSV.")

print(f"Found {len(feature_columns)} feature columns.")


# --------------------------------------------------
# 3. Load only features and required labels
# --------------------------------------------------

print("\nLoading dataset. This may take a few minutes...")

data = pd.read_csv(
    DATA_PATH,
    usecols=feature_columns + required_columns,
    low_memory=False,
)

print(f"Dataset loaded: {data.shape[0]:,} rows")

# Ensure labels are numeric
data["label"] = pd.to_numeric(data["label"], errors="coerce")
data = data.dropna(subset=["label"])
data["label"] = data["label"].astype("int8")

# Keep only valid binary labels
data = data[data["label"].isin([0, 1])].copy()

# Convert features to numeric and replace invalid values
X = data[feature_columns].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(0).astype("float32")

y_binary = data["label"].astype("int8")

print("\nBinary label distribution:")
print(y_binary.value_counts().rename(index={0: "Benign", 1: "Malware"}))

# Save feature names for the Gradio app
with open(MODEL_DIR / "feature_columns.json", "w", encoding="utf-8") as file:
    json.dump(feature_columns, file, indent=2)


# --------------------------------------------------
# 4. Train CatBoost binary classifier
# --------------------------------------------------

print("\n" + "=" * 60)
print("TRAINING CATBOOST: BENIGN VS MALWARE")
print("=" * 60)

X_train_bin, X_test_bin, y_train_bin, y_test_bin = train_test_split(
    X,
    y_binary,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_binary,
)

catboost_model = CatBoostClassifier(
    iterations=300,
    depth=6,
    learning_rate=0.1,
    loss_function="Logloss",
    eval_metric="AUC",
    thread_count=2,
    random_seed=RANDOM_STATE,
    verbose=50,
)

catboost_model.fit(X_train_bin, y_train_bin)

# Predictions
binary_predictions = catboost_model.predict(X_test_bin).astype(int).flatten()
binary_probabilities = catboost_model.predict_proba(X_test_bin)[:, 1]

binary_accuracy = accuracy_score(y_test_bin, binary_predictions)
binary_f1 = f1_score(y_test_bin, binary_predictions)
binary_auc = roc_auc_score(y_test_bin, binary_probabilities)
binary_cm = confusion_matrix(y_test_bin, binary_predictions)

print("\nCatBoost Results")
print(f"Accuracy:  {binary_accuracy:.4f}")
print(f"Malware F1: {binary_f1:.4f}")
print(f"ROC-AUC:   {binary_auc:.4f}")

print("\nConfusion Matrix:")
print(binary_cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test_bin,
        binary_predictions,
        target_names=["Benign", "Malware"],
        digits=4,
    )
)

catboost_path = MODEL_DIR / "catboost_binary.cbm"
catboost_model.save_model(str(catboost_path))

print(f"\nCatBoost model saved to: {catboost_path}")


# Release binary split memory before training the second model
del X_train_bin, X_test_bin, y_train_bin, y_test_bin
del binary_predictions, binary_probabilities
del catboost_model
gc.collect()


# --------------------------------------------------
# 5. Prepare data for 8-category Random Forest
# --------------------------------------------------

print("\n" + "=" * 60)
print("PREPARING DATA FOR RANDOM FOREST")
print("=" * 60)

# Only malware samples belonging to the selected 8 categories
category_mask = (
    (data["label"] == 1)
    & (data["category"].isin(MALWARE_CATEGORIES))
)

category_data = data.loc[category_mask, ["category"]].copy()

# Use the same feature columns, but only selected malware rows
X_category = X.loc[category_mask].copy()
y_category = category_data["category"].astype(str)

print(f"Selected malware samples: {len(y_category):,}")
print("\nCategory distribution:")
print(y_category.value_counts())


# --------------------------------------------------
# 6. Train Random Forest 8-category classifier
# --------------------------------------------------

print("\n" + "=" * 60)
print("TRAINING RANDOM FOREST: 8 MALWARE CATEGORIES")
print("=" * 60)

X_train_cat, X_test_cat, y_train_cat, y_test_cat = train_test_split(
    X_category,
    y_category,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_category,
)

random_forest_model = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced_subsample",
    max_features="sqrt",
    min_samples_leaf=2,
    random_state=RANDOM_STATE,
    n_jobs=2,
)

random_forest_model.fit(X_train_cat, y_train_cat)

category_predictions = random_forest_model.predict(X_test_cat)

category_accuracy = accuracy_score(y_test_cat, category_predictions)
category_macro_f1 = f1_score(
    y_test_cat,
    category_predictions,
    average="macro",
    zero_division=0,
)
category_weighted_f1 = f1_score(
    y_test_cat,
    category_predictions,
    average="weighted",
    zero_division=0,
)

category_labels = random_forest_model.classes_

category_cm = confusion_matrix(
    y_test_cat,
    category_predictions,
    labels=category_labels,
)

print("\nRandom Forest Results")
print(f"Accuracy:    {category_accuracy:.4f}")
print(f"Macro-F1:    {category_macro_f1:.4f}")
print(f"Weighted-F1: {category_weighted_f1:.4f}")

print("\nConfusion Matrix:")
print(category_cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test_cat,
        category_predictions,
        labels=category_labels,
        digits=4,
        zero_division=0,
    )
)

rf_path = MODEL_DIR / "random_forest_8category.joblib"
joblib.dump(random_forest_model, rf_path)

print(f"\nRandom Forest model saved to: {rf_path}")


# --------------------------------------------------
# 7. Save evaluation metrics
# --------------------------------------------------

metrics = {
    "dataset": str(DATA_PATH),
    "total_rows": int(len(data)),
    "feature_count": int(len(feature_columns)),
    "binary_classifier": {
        "model": "CatBoost",
        "classes": ["Benign", "Malware"],
        "accuracy": float(binary_accuracy),
        "malware_f1": float(binary_f1),
        "roc_auc": float(binary_auc),
        "confusion_matrix": binary_cm.tolist(),
    },
    "category_classifier": {
        "model": "Random Forest",
        "categories": [str(category) for category in category_labels],
        "accuracy": float(category_accuracy),
        "macro_f1": float(category_macro_f1),
        "weighted_f1": float(category_weighted_f1),
        "confusion_matrix": category_cm.tolist(),
    },
}

metrics_path = MODEL_DIR / "model_metrics.json"

with open(metrics_path, "w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=2)

print(f"\nMetrics saved to: {metrics_path}")


# --------------------------------------------------
# 8. Finish
# --------------------------------------------------

print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)
print(f"Models and metrics are saved in:\n{MODEL_DIR}")