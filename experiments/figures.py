"""Report figures (static PNGs). Colours: fixed categorical order, neutral text ink."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

SURFACE, INK, INK_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
MODEL_COLORS = {"baseline": "#2a78d6", "improved": "#eb6834", "hybrid": "#1baf7a"}
MODEL_LABELS = {"baseline": "Original (v1)", "improved": "Improved (v2)", "hybrid": "Hybrid (v2 + classifier)"}

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK_2,
    "text.color": INK, "axes.titlecolor": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 9, "axes.titlesize": 11,
    "legend.frameon": False, "axes.axisbelow": True,
})


def clean_label(text: str) -> str:
    """CIC-IDS2017 labels contain a mis-decoded dash (e.g. 'Web Attack \ufffd XSS')."""
    return str(text).replace("\u00ef\u00bf\u00bd", "-").replace("\ufffd", "-")


def _save(fig, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=160, bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    return path


def metric_comparison(summary: dict, metrics: list[str], title: str, path: Path) -> Path:
    """Grouped bars: mean over seeds with ±1 std error bars, value labelled on each bar."""
    models = [m for m in MODEL_COLORS if m in summary]
    x = np.arange(len(metrics))
    width = 0.8 / len(models)
    fig, ax = plt.subplots(figsize=(1.3 * len(metrics) + 2, 4))
    for i, model in enumerate(models):
        means = [summary[model][m]["mean"] for m in metrics]
        stds = [summary[model][m]["std"] for m in metrics]
        pos = x + (i - (len(models) - 1) / 2) * width
        ax.bar(pos, means, width * 0.92, yerr=stds, color=MODEL_COLORS[model], label=MODEL_LABELS[model],
               error_kw={"ecolor": INK_2, "elinewidth": 0.8, "capsize": 2})
        for p, v, sd in zip(pos, means, stds):
            ax.text(p, v + sd + 0.015, f"{v:.2f}", ha="center", va="bottom", fontsize=6.5, color=INK_2)
    ax.set_xticks(x, [m.replace("_", " ") for m in metrics])
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("score (test set)")
    ax.set_title(title, loc="left")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=len(models))
    ax.grid(axis="x", visible=False)
    return _save(fig, path)


def confusion_matrices(cms: dict[str, dict], title: str, path: Path) -> Path:
    models = [m for m in MODEL_COLORS if m in cms]
    fig, axes = plt.subplots(1, len(models), figsize=(3.4 * len(models), 3.3))
    axes = np.atleast_1d(axes)
    for ax, model in zip(axes, models):
        cm = cms[model]
        mat = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
        row_share = mat / mat.sum(axis=1, keepdims=True)
        ax.imshow(row_share, cmap="Blues", vmin=0, vmax=1)
        for (r, c), v in np.ndenumerate(mat):
            ax.text(c, r, f"{v:,}\n({row_share[r, c]:.1%})", ha="center", va="center", fontsize=8,
                    color="white" if row_share[r, c] > 0.6 else INK)
        ax.set_xticks([0, 1], ["benign", "attack"])
        ax.set_yticks([0, 1], ["benign", "attack"])
        ax.set_xlabel("predicted")
        ax.set_ylabel("actual")
        ax.set_title(MODEL_LABELS[model], fontsize=9, loc="left")
        ax.grid(False)
    fig.suptitle(title, x=0.01, ha="left", fontsize=11)
    return _save(fig, path)


def curves(y: np.ndarray, scores: dict[str, np.ndarray], title: str, path: Path) -> Path:
    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4))
    for model in [m for m in MODEL_COLORS if m in scores]:
        s = scores[model]
        fpr, tpr, _ = roc_curve(y, s)
        a1.plot(fpr, tpr, color=MODEL_COLORS[model], lw=2, label=f"{MODEL_LABELS[model]} (AUC {roc_auc_score(y, s):.3f})")
        p, r, _ = precision_recall_curve(y, s)
        a2.plot(r, p, color=MODEL_COLORS[model], lw=2,
                label=f"{MODEL_LABELS[model]} (AP {average_precision_score(y, s):.3f})")
    a1.plot([0, 1], [0, 1], ls="--", color=GRID, lw=1)
    a1.set(xlabel="false positive rate", ylabel="true positive rate (recall)", title="ROC curve")
    a2.set(xlabel="recall", ylabel="precision", title="Precision-recall curve")
    a1.legend(loc="lower right", fontsize=7.5)
    a2.legend(loc="lower left", fontsize=7.5)
    fig.suptitle(title, x=0.01, ha="left", fontsize=11)
    return _save(fig, path)


def per_attack_recall(recalls: dict[str, dict], title: str, path: Path, top: int = 15) -> Path:
    """Horizontal grouped bars for the most frequent attack types in the test set."""
    models = [m for m in MODEL_COLORS if m in recalls]
    first = recalls[models[0]]
    types = sorted(first, key=lambda t: -first[t]["count"])[:top][::-1]
    y = np.arange(len(types))
    h = 0.8 / len(models)
    fig, ax = plt.subplots(figsize=(7.5, 0.42 * len(types) + 1.4))
    for i, model in enumerate(models):
        vals = [recalls[model].get(t, {"recall": 0})["recall"] for t in types]
        ax.barh(y + ((len(models) - 1) / 2 - i) * h, vals, h * 0.9, color=MODEL_COLORS[model], label=MODEL_LABELS[model])
    ax.set_yticks(y, [f"{clean_label(t)}  (n={first[t]['count']:,})" for t in types])
    ax.set_xlim(0, 1)
    ax.set_xlabel("share of attacks detected (recall, test set)")
    ax.set_title(title, loc="left")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), ncol=len(models))
    return _save(fig, path)


def learning_curves(lc: dict[str, list[dict]], title: str, path: Path) -> Path:
    """Training vs validation PR-AUC as the amount of benign training data grows."""
    fig, ax = plt.subplots(figsize=(6.5, 4))
    for model in [m for m in MODEL_COLORS if m in lc]:
        n = [p["train_rows"] for p in lc[model]]
        ax.plot(n, [p["train_pr_auc"] for p in lc[model]], color=MODEL_COLORS[model], lw=2, ls="--", marker="o", ms=4,
                label=f"{MODEL_LABELS[model]}: training split")
        ax.plot(n, [p["val_pr_auc"] for p in lc[model]], color=MODEL_COLORS[model], lw=2, marker="o", ms=4,
                label=f"{MODEL_LABELS[model]}: validation split")
    ax.set_xscale("log")
    ax.set(xlabel="benign training flows (log scale)", ylabel="PR-AUC", title=title)
    ax.title.set_ha("left")
    ax.title.set_position((0, 1))
    ax.legend(fontsize=7.5)
    return _save(fig, path)


def autoencoder_curves(histories: dict[str, dict], title: str, path: Path) -> Path:
    """Autoencoder training loss and early-stopping validation score per epoch."""
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.6))
    for model, h in histories.items():
        a1.plot(np.arange(1, len(h["loss"]) + 1), h["loss"], color=MODEL_COLORS[model], lw=2, label=MODEL_LABELS[model])
        a2.plot(np.arange(1, len(h["val_r2"]) + 1), h["val_r2"], color=MODEL_COLORS[model], lw=2, label=MODEL_LABELS[model])
    a1.set(xlabel="epoch", ylabel="training loss (MSE / 2)", title="Training loss")
    a1.set_yscale("log")
    a2.set(xlabel="epoch", ylabel="R² on held-out 10% of benign training data", title="Validation score")
    a1.legend(fontsize=7.5)
    fig.suptitle(title, x=0.01, ha="left", fontsize=11)
    return _save(fig, path)


def feature_bars(values: dict[str, float], title: str, xlabel: str, path: Path, top: int = 15) -> Path:
    items = sorted(values.items(), key=lambda kv: -kv[1])[:top][::-1]
    fig, ax = plt.subplots(figsize=(7, 0.32 * len(items) + 1.2))
    ax.barh([k for k, _ in items], [v for _, v in items], 0.7, color=MODEL_COLORS["baseline"])
    for i, (_, v) in enumerate(items):
        ax.text(v, i, f" {v:.3f}" if v < 1 else f" {v:.0f}", va="center", fontsize=7, color=INK_2)
    ax.set_xlabel(xlabel)
    ax.set_title(title, loc="left")
    ax.grid(axis="y", visible=False)
    return _save(fig, path)


def ablation(steps: list[dict], metrics: list[str], title: str, path: Path) -> Path:
    """One line per metric across cumulative improvement steps (test set, seed 42)."""
    colors = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
    fig, ax = plt.subplots(figsize=(8, 4))
    x = np.arange(len(steps))
    for metric, color in zip(metrics, colors):
        vals = [s["metrics"][metric] for s in steps]
        ax.plot(x, vals, color=color, lw=2, marker="o", ms=5, label=metric.replace("_", " "))
    ax.set_xticks(x, [s["step"] for s in steps], rotation=15, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("score (test set)")
    ax.set_title(title, loc="left")
    ax.legend(fontsize=7.5, loc="lower right")
    return _save(fig, path)
