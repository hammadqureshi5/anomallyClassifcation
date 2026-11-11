
import os
import json
from datetime import datetime

import gradio as gr
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

from catboost import CatBoostClassifier


# ============================================================
# 1. PATHS AND MODEL LOADING
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

BINARY_MODEL_PATH = os.path.join(MODEL_DIR, "catboost_binary.cbm")
CATEGORY_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_8category.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_columns.json")
METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")

binary_model = CatBoostClassifier()
binary_model.load_model(BINARY_MODEL_PATH)

category_model = joblib.load(CATEGORY_MODEL_PATH)

with open(FEATURES_PATH, "r") as f:
    feature_columns = json.load(f)

if isinstance(feature_columns, dict):
    feature_columns = feature_columns.get("features", [])

with open(METRICS_PATH, "r") as f:
    saved_metrics = json.load(f)


# ============================================================
# 2. MODEL EVALUATION METRICS
# ============================================================

# Values from the completed model evaluation.
# Precision and recall for CatBoost are calculated from its
# saved confusion matrix.

catboost_cm = np.array([
    [15366, 62],
    [71, 11387]
])

catboost_accuracy = 99.51
catboost_precision = (11387 / (11387 + 62)) * 100
catboost_recall = (11387 / (11387 + 71)) * 100
catboost_f1 = 99.42
catboost_auc = 99.97

rf_accuracy = 94.34
rf_macro_f1 = 87.66
rf_weighted_f1 = 94.32

# Random Forest confusion matrix from saved evaluation.
rf_cm = np.array([
    [1425, 0, 2, 0, 1, 38, 0, 0],
    [0, 178, 0, 1, 0, 27, 0, 0],
    [2, 0, 111, 0, 0, 23, 0, 7],
    [0, 0, 3, 74, 0, 13, 0, 0],
    [1, 0, 0, 0, 139, 24, 0, 0],
    [96, 12, 30, 5, 12, 5627, 1, 212],
    [0, 0, 0, 0, 0, 14, 24, 0],
    [4, 0, 6, 0, 0, 114, 0, 3215]
])

category_names = [
    "backdoor",
    "downloader",
    "dropper",
    "informationstealer",
    "ransomware",
    "trojan",
    "virus",
    "worm"
]


# ============================================================
# 3. VISUAL DESIGN
# ============================================================

custom_css = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

.gradio-container {
    background: #0b1120 !important;
    font-family: 'Inter', sans-serif !important;
    max-width: 1500px !important;
}

body {
    background: #0b1120 !important;
}

#main-header {
    background: #111c30;
    border: 1px solid #253752;
    border-radius: 12px;
    padding: 25px 30px;
    margin-bottom: 20px;
}

.brand {
    color: #e8f0fc;
    font-size: 29px;
    font-weight: 800;
    letter-spacing: 1px;
}

.brand span {
    color: #25c4d2;
}

.header-description {
    color: #94a6bf;
    font-size: 13px;
    margin-top: 8px;
}

.section-heading {
    color: #e8f0fc;
    font-size: 18px;
    font-weight: 700;
    margin: 20px 0 12px;
    border-left: 3px solid #25c4d2;
    padding-left: 10px;
}

.model-card {
    background: #111c30;
    border: 1px solid #263a57;
    border-radius: 12px;
    padding: 20px;
    height: 100%;
}

.model-name {
    color: #f0f5ff;
    font-size: 19px;
    font-weight: 700;
}

.model-type {
    color: #25c4d2;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    margin-bottom: 12px;
}

.metric-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    margin-top: 15px;
}

.metric {
    background: #192943;
    border-radius: 8px;
    padding: 12px;
}

.metric-label {
    color: #8fa3c0;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .7px;
}

.metric-value {
    color: #f1f6ff;
    font-size: 21px;
    font-weight: 700;
    margin-top: 5px;
}

.metric-note {
    color: #91a3bd;
    font-size: 10px;
    margin-top: 3px;
}

.workspace {
    background: #111c30;
    border: 1px solid #263a57;
    border-radius: 12px;
    padding: 20px;
}

.stat-card {
    background: #111c30;
    border: 1px solid #263a57;
    border-radius: 10px;
    padding: 17px;
    min-height: 95px;
}

.stat-label {
    color: #93a8c4;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .8px;
}

.stat-value {
    color: #f2f6ff;
    font-size: 27px;
    font-weight: 800;
    margin-top: 8px;
}

.stat-card.safe {
    border-top: 3px solid #22b99b;
}

.stat-card.danger {
    border-top: 3px solid #ed6577;
}

.stat-card.info {
    border-top: 3px solid #25c4d2;
}

button.primary {
    background: #087fbd !important;
    border: none !important;
    color: white !important;
    font-weight: 700 !important;
}

button.primary:hover {
    background: #079bb7 !important;
}

footer {
    display: none !important;
}
"""


# ============================================================
# 4. HTML COMPONENT HELPERS
# ============================================================

def metric_html(label, value, note=""):
    return f"""
    <div class="metric">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-note">{note}</div>
    </div>
    """


def model_card(title, subtitle, metrics):
    metric_content = "".join(
        metric_html(label, value, note)
        for label, value, note in metrics
    )

    return f"""
    <div class="model-card">
        <div class="model-type">{subtitle}</div>
        <div class="model-name">{title}</div>
        <div class="metric-grid">
            {metric_content}
        </div>
    </div>
    """


def stat_card(label, value, card_type):
    return f"""
    <div class="stat-card {card_type}">
        <div class="stat-label">{label}</div>
        <div class="stat-value">{value}</div>
    </div>
    """


# ============================================================
# 5. CONFUSION MATRIX VISUALIZATION
# ============================================================

def create_confusion_matrix(matrix, labels, title):

    fig, ax = plt.subplots(figsize=(6, 4))
    fig.patch.set_facecolor("#111c30")
    ax.set_facecolor("#111c30")

    image = ax.imshow(matrix, cmap="Blues")

    ax.set_title(
        title,
        color="white",
        fontsize=13,
        fontweight="bold",
        pad=15
    )

    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))

    ax.set_xticklabels(
        labels,
        rotation=35,
        ha="right",
        color="#c2d0e3",
        fontsize=8
    )

    ax.set_yticklabels(
        labels,
        color="#c2d0e3",
        fontsize=8
    )

    ax.set_xlabel("Predicted Label", color="#aabbd0")
    ax.set_ylabel("Actual Label", color="#aabbd0")

    threshold = matrix.max() / 2

    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            ax.text(
                j, i, str(matrix[i, j]),
                ha="center",
                va="center",
                color="white" if matrix[i, j] > threshold else "#d8e7f7",
                fontsize=7
            )

    ax.tick_params(length=0)
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)

    fig.tight_layout()
    return fig


# ============================================================
# 6. ANALYSIS CHARTS
# ============================================================

def create_detection_chart(results):

    counts = results["Prediction"].value_counts().reindex(
        ["Benign", "Malware"],
        fill_value=0
    )

    fig, ax = plt.subplots(figsize=(6, 3.3))
    fig.patch.set_facecolor("#111c30")
    ax.set_facecolor("#111c30")

    bars = ax.bar(
        counts.index,
        counts.values,
        color=["#22b99b", "#ed6577"],
        width=0.5
    )

    ax.set_title(
        "Detection Distribution",
        color="white",
        fontsize=13,
        fontweight="bold"
    )

    ax.set_ylabel("Samples", color="#aabbd0")
    ax.tick_params(colors="#b8c8dd")

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#34445b")
    ax.spines["left"].set_color("#34445b")

    for bar in bars:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            str(int(bar.get_height())),
            ha="center",
            color="white",
            fontsize=10
        )

    fig.tight_layout()
    return fig


def create_category_chart(results):

    malware = results[
        results["Prediction"] == "Malware"
    ]

    fig, ax = plt.subplots(figsize=(7, 3.3))
    fig.patch.set_facecolor("#111c30")
    ax.set_facecolor("#111c30")

    if malware.empty:
        ax.text(
            0.5, 0.5,
            "No malware detected",
            color="white",
            ha="center",
            va="center",
            transform=ax.transAxes
        )
        ax.set_axis_off()

    else:
        counts = malware["Predicted Category"].value_counts()

        ax.barh(
            counts.index,
            counts.values,
            color="#25c4d2"
        )

        ax.set_title(
            "Malware Category Distribution",
            color="white",
            fontsize=13,
            fontweight="bold"
        )

        ax.set_xlabel("Samples", color="#aabbd0")
        ax.tick_params(colors="#b8c8dd")

        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["bottom"].set_color("#34445b")
        ax.spines["left"].set_color("#34445b")

    fig.tight_layout()
    return fig


# ============================================================
# 7. TWO-STAGE MALWARE DETECTION
# ============================================================

def analyze_csv(file):

    if file is None:
        raise gr.Error("Please upload a CSV file.")

    try:
        data = pd.read_csv(file)

        if data.empty:
            raise gr.Error("The uploaded CSV is empty.")

        missing = [
            col for col in feature_columns
            if col not in data.columns
        ]

        if missing:
            raise gr.Error(
                f"Missing {len(missing)} required features. "
                f"Example: {', '.join(missing[:5])}"
            )

        X = data[feature_columns].copy()

        X = X.apply(pd.to_numeric, errors="coerce")
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Stage 1: CatBoost binary detection
        binary_predictions = binary_model.predict(X).ravel().astype(int)

        binary_probabilities = binary_model.predict_proba(X)

        malware_index = list(binary_model.classes_).index(1)

        malware_probabilities = binary_probabilities[
            :, malware_index
        ]

        # Stage 2: Random Forest category prediction
        malware_indices = np.where(binary_predictions == 1)[0]

        category_predictions = {}
        category_confidences = {}

        if len(malware_indices) > 0:

            malware_data = X.iloc[malware_indices]

            rf_predictions = category_model.predict(
                malware_data
            ).ravel()

            rf_probabilities = category_model.predict_proba(
                malware_data
            )

            for i, original_index in enumerate(malware_indices):

                category_predictions[original_index] = str(
                    rf_predictions[i]
                )

                category_confidences[original_index] = (
                    float(np.max(rf_probabilities[i])) * 100
                )

        # Build result table
        predictions = []
        categories = []
        category_confidence_values = []

        for i, prediction in enumerate(binary_predictions):

            if prediction == 0:
                predictions.append("Benign")
                categories.append("N/A")
                category_confidence_values.append(0)

            else:
                predictions.append("Malware")
                categories.append(category_predictions[i])
                category_confidence_values.append(
                    category_confidences[i]
                )

        results = pd.DataFrame({
            "Sample ID": range(1, len(data) + 1),
            "Prediction": predictions,
            "Malware Probability (%)": np.round(
                malware_probabilities * 100, 2
            ),
            "Predicted Category": categories,
            "Category Confidence (%)": np.round(
                category_confidence_values, 2
            )
        })

        # Summary statistics
        total = len(results)
        benign_count = predictions.count("Benign")
        malware_count = predictions.count("Malware")
        detection_rate = malware_count / total * 100

        summary = f"""
        <div class="section-heading">Analysis Overview</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;">
            {stat_card("Total Samples", f"{total:,}", "info")}
            {stat_card("Benign Samples", f"{benign_count:,}", "safe")}
            {stat_card("Malware Detected", f"{malware_count:,}", "danger")}
            {stat_card("Malware Rate", f"{detection_rate:.2f}%", "info")}
        </div>
        """

        detection_chart = create_detection_chart(results)
        category_chart = create_category_chart(results)

        status = (
            f"Analysis completed successfully. "
            f"{total:,} samples processed using "
            f"{len(feature_columns):,} features."
        )

        return (
            results,
            summary,
            detection_chart,
            category_chart,
            status
        )

    except gr.Error:
        raise

    except Exception as e:
        raise gr.Error(f"Analysis error: {str(e)}")


# ============================================================
# 8. DASHBOARD
# ============================================================

with gr.Blocks(
    theme=gr.themes.Base(
        primary_hue="cyan",
        neutral_hue="slate"
    ),
    css=custom_css,
    title="Malware Intelligence System"
) as demo:

    # Header
    gr.HTML("""
        <div id="main-header">
            <div class="brand">MALWARE<span>INTELLIGENCE</span></div>
            <div class="header-description">
                AI-Based Autonomous Cyber Defense System |
                Malware Detection and Classification
            </div>
        </div>
    """)

    # Model performance
    gr.HTML('<div class="section-heading">Model Performance</div>')

    with gr.Row():

        with gr.Column():
            gr.HTML(model_card(
                "CatBoost Classifier",
                "STAGE 01 | BINARY CLASSIFICATION",
                [
                    ("Accuracy", "99.51%", "Overall accuracy"),
                    ("Precision", f"{catboost_precision:.2f}%", "Malware class"),
                    ("Recall", f"{catboost_recall:.2f}%", "Malware class"),
                    ("F1-score", "99.42%", "Malware class"),
                    ("ROC-AUC", "99.97%", "Binary classification"),
                    ("Test Samples", "26,886", "Held-out test set")
                ]
            ))

        with gr.Column():
            gr.HTML(model_card(
                "Random Forest Classifier",
                "STAGE 02 | EIGHT-CLASS CLASSIFICATION",
                [
                    ("Accuracy", "94.34%", "Overall accuracy"),
                    ("Macro F1", "87.66%", "Equal class weighting"),
                    ("Weighted F1", "94.32%", "Support-weighted"),
                    ("Precision", "See evaluation JSON", "Not hardcoded"),
                    ("Recall", "See evaluation JSON", "Not hardcoded"),
                    ("Classes", "8", "Malware categories")
                ]
            ))

    # Confusion matrices
    gr.HTML('<div class="section-heading">Model Evaluation</div>')

    with gr.Row():
        gr.Plot(
            value=create_confusion_matrix(
                catboost_cm,
                ["Benign", "Malware"],
                "CatBoost Confusion Matrix"
            ),
            label="CatBoost Confusion Matrix"
        )

        gr.Plot(
            value=create_confusion_matrix(
                rf_cm,
                category_names,
                "Random Forest Confusion Matrix"
            ),
            label="Random Forest Confusion Matrix"
        )

    # Workflow
    gr.HTML('<div class="section-heading">Detection Architecture</div>')

    gr.HTML("""
        <div style="background:#111c30;border:1px solid #263a57;
                    border-radius:10px;padding:20px;text-align:center;">

            <div style="color:#25c4d2;font-weight:700;">
                INPUT: EXTRACTED FEATURE DATA
            </div>

            <div style="color:#91a3bd;margin:12px;">↓</div>

            <div style="background:#192943;padding:14px;border-radius:8px;">
                <b style="color:white;">CATBOOST</b>
                <div style="color:#91a3bd;font-size:12px;">
                    Binary Classification
                </div>
                <div style="color:#25c4d2;font-size:12px;">
                    Benign / Malware
                </div>
            </div>

            <div style="color:#91a3bd;margin:12px;">↓</div>

            <div style="background:#192943;padding:14px;border-radius:8px;">
                <b style="color:white;">RANDOM FOREST</b>
                <div style="color:#91a3bd;font-size:12px;">
                    Malware Category Classification
                </div>
                <div style="color:#25c4d2;font-size:12px;">
                    Trojan | Worm | Backdoor | Downloader |
                    Ransomware | Dropper | Information Stealer | Virus
                </div>
            </div>
        </div>
    """)

    # Upload workspace
    gr.HTML('<div class="section-heading">Malware Analysis Workspace</div>')

    with gr.Group(elem_classes=["workspace"]):

        gr.Markdown("### Upload Feature Dataset")

        file_input = gr.File(
            label="Select CSV file",
            file_types=[".csv"],
            type="filepath"
        )

        gr.Markdown(
            f"""
            **Required features:** {len(feature_columns):,}

            Upload a CSV containing the extracted numerical features
            (`feature_0` to `feature_{len(feature_columns)-1}`).

            Raw `.exe` files are not supported by this interface.
            """
        )

        analyze_button = gr.Button(
            "ANALYZE DATASET",
            variant="primary"
        )

        status_output = gr.Markdown()

    # Live analysis
    gr.HTML('<div class="section-heading">Live Detection Results</div>')

    summary_output = gr.HTML()

    with gr.Row():
        detection_plot = gr.Plot(label="Detection Distribution")
        category_plot = gr.Plot(label="Malware Category Distribution")

    gr.HTML('<div class="section-heading">Sample-Level Classification</div>')

    results_output = gr.Dataframe(
        label="Prediction Results",
        interactive=False,
        wrap=True
    )

    # Footer
    gr.HTML("""
        <div style="text-align:center;padding:25px;color:#71839e;
                    font-size:11px;border-top:1px solid #253752;margin-top:25px;">
            AI-BASED MALWARE DETECTION AND CLASSIFICATION
            <br>
            TWO-STAGE MACHINE LEARNING PIPELINE
        </div>
    """)

    analyze_button.click(
        fn=analyze_csv,
        inputs=[file_input],
        outputs=[
            results_output,
            summary_output,
            detection_plot,
            category_plot,
            status_output
        ]
    )


# ============================================================
# 9. LAUNCH
# ============================================================

if __name__ == "__main__":
    demo.launch()
