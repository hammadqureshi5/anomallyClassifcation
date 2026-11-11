"""Registry of the twelve ACDS modules from the project proposal.

A module with a `worker` can be used as a scan template. Adding a new module means:
write `workers/<name>_worker.py` (see workers/README.md for the contract) and add an
entry below with status "active".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import config

NETWORK_CSV = {"kind": "network_flows_csv", "label": "Network flow records (CSV)", "accept": ".csv"}
PE_CSV = {"kind": "pe_features_csv", "label": "PE feature vectors, BODMAS format (CSV)", "accept": ".csv"}


@dataclass
class Module:
    id: str
    number: int
    name: str
    owner: str
    category: str
    status: str  # active | in_progress | planned
    description: str
    repo: str | None = None
    input: dict | None = None
    options: list[dict] = field(default_factory=list)
    metrics: list[dict] = field(default_factory=list)
    # Worker process settings (active modules only).
    worker: str | None = None
    directory: Path | None = None
    python: Path | None = None
    required_files: list[str] = field(default_factory=list)

    def readiness(self) -> tuple[bool, str]:
        if self.status == "active" and not self.worker:
            return True, "Built into this console"
        if self.status != "active":
            return False, "Not implemented yet"
        if not self.directory or not self.directory.is_dir():
            return False, f"Module folder not found: {self.directory}"
        missing = [f for f in self.required_files if not (self.directory / f).exists()]
        if missing:
            return False, f"Missing model files: {', '.join(missing)}"
        if not self.python or not self.python.exists():
            return False, f"Python environment not set up: {self.python}"
        return True, "Ready"

    def to_dict(self) -> dict:
        ready, reason = self.readiness()
        return {
            "id": self.id, "number": self.number, "name": self.name, "owner": self.owner,
            "category": self.category, "status": self.status, "ready": ready,
            "ready_reason": reason, "description": self.description, "repo": self.repo,
            "input": self.input, "options": self.options, "metrics": self.metrics,
        }


def _select(key: str, label: str, choices: list[tuple[str, str]], default: str) -> dict:
    return {"key": key, "label": label, "type": "select",
            "choices": [{"value": v, "label": l} for v, l in choices], "default": default}


ROW_LIMIT = _select("max_rows", "Rows to scan", [
    ("5000", "First 5,000 rows"), ("20000", "First 20,000 rows"),
    ("100000", "First 100,000 rows"), ("all", "All rows"),
], "20000")

MODULES: list[Module] = [
    Module(
        id="network_monitoring", number=1, name="Network Monitoring", owner="Team",
        category="Collection", status="planned",
        description="Collects live network activity (e.g. via CICFlowMeter) and feeds flow records to the analysis modules.",
    ),
    Module(
        id="anomaly", number=2, name="Anomaly Detection", owner="Hammad Qureshi",
        category="Network", status="active",
        description="Learns normal traffic only (LOF, Isolation Forest, autoencoder, robust z-score ensemble) "
                    "and flags flows that deviate from it, including attacks never seen in training. "
                    "Each alert lists the features that made the flow look unusual.",
        repo="https://github.com/hammadqureshi5/anomallyClassifcation/tree/main/modules/anomaly_detection",
        input=NETWORK_CSV,
        options=[
            _select("model", "Model", [
                ("auto", "Auto-detect from CSV columns"),
                ("improved_cicids2017", "v2: CIC-IDS2017 (LOF + autoencoder)"),
                ("improved_nsl-kdd", "v2: NSL-KDD"),
                ("pipeline", "Demo: synthetic traffic"),
            ], "auto"),
            ROW_LIMIT,
        ],
        metrics=[
            {"label": "F1 (CIC-IDS2017, v2)", "value": "0.83"},
            {"label": "F1 (NSL-KDD, v2)", "value": "0.90"},
            {"label": "Unseen attack types caught", "value": "85%"},
            {"label": "False-positive rate (CIC)", "value": "2.9%"},
        ],
        worker="anomaly_worker.py", directory=config.ANOMALY_DIR, python=config.ANOMALY_PYTHON,
        required_files=["anomaly_detection/pipeline.py", "models/improved_cicids2017.joblib"],
    ),
    Module(
        id="threat", number=3, name="Threat Classification", owner="Muhammad Bilal Khan",
        category="Network", status="active",
        description="Two-tier cascade: LightGBM decides benign vs. anomalous, then CatBoost names the attack "
                    "family. Each detection is mapped to MITRE ATT&CK with a recommended (non-executed) action.",
        repo="https://github.com/hammadqureshi5/anomallyClassifcation/tree/main/modules/threat_classification",
        input=NETWORK_CSV,
        options=[ROW_LIMIT],
        metrics=[
            {"label": "Holdout accuracy", "value": "99.91%"},
            {"label": "Macro F1", "value": "0.958"},
        ],
        worker="threat_worker.py", directory=config.THREAT_DIR, python=config.THREAT_PYTHON,
        required_files=["acds/threat_classifier.py", "acds_models/tier1_lgbm.pkl", "acds_models/tier2_catboost.cbm"],
    ),
    Module(
        id="log_analysis", number=4, name="Log Analysis", owner="Team",
        category="Host", status="in_progress",
        description="Examines system and application logs for errors and suspicious events.",
    ),
    Module(
        id="malware", number=5, name="Malware Classification", owner="Nair Abbas",
        category="Endpoint", status="active",
        description="CatBoost separates benign and malicious Windows executables (BODMAS feature vectors); "
                    "a Random Forest then assigns one of eight malware categories.",
        repo="https://github.com/hammadqureshi5/anomallyClassifcation/tree/main/modules/malware_classification",
        input=PE_CSV,
        options=[ROW_LIMIT],
        metrics=[
            {"label": "Detection accuracy", "value": "99.51%"},
            {"label": "Malware F1", "value": "0.994"},
            {"label": "ROC-AUC", "value": "0.9997"},
            {"label": "Category accuracy", "value": "94.34%"},
        ],
        worker="malware_worker.py", directory=config.MALWARE_DIR, python=config.MALWARE_PYTHON,
        required_files=["models/catboost_binary.cbm", "models/random_forest_8category.joblib",
                        "models/feature_columns.json"],
    ),
    Module(id="incident_correlation", number=6, name="Incident Correlation", owner="Team",
           category="Analysis", status="planned",
           description="Groups related alerts and events from all modules into incidents."),
    Module(id="vulnerability", number=7, name="Vulnerability Analysis", owner="Team",
           category="Assessment", status="planned",
           description="Identifies known weaknesses in systems and applications."),
    Module(id="attack_path", number=8, name="Attack-Path Analysis", owner="Team",
           category="Assessment", status="planned",
           description="Studies how an attacker could move through a system, using MITRE ATT&CK as reference."),
    Module(id="attack_prediction", number=9, name="Attack Prediction", owner="Team",
           category="Analysis", status="planned",
           description="Estimates likely future attack activity from available evidence."),
    Module(id="risk", number=10, name="Risk Analysis", owner="Team",
           category="Analysis", status="planned",
           description="Prioritises threats and vulnerabilities by estimated risk."),
    Module(id="investigation_agent", number=11, name="Investigation Agent", owner="Team",
           category="AI", status="planned",
           description="AI agent that combines module results and explains incidents in plain language."),
    Module(id="dashboard", number=12, name="Dashboard & Feedback", owner="Team",
           category="Platform", status="active",
           description="This web console: unified results from all modules plus analyst feedback "
                       "(confirm / false positive) on every finding.",
           metrics=[{"label": "Version", "value": "0.1"}]),
]

BY_ID = {m.id: m for m in MODULES}
