"""Build the small demo CSVs offered as built-in scan inputs.

Usage: <python with pandas> samples/make_samples.py [path/to/modules/anomaly_detection]
The datasets themselves are not committed; this samples rows from the local copies.
"""

import json
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
src = Path(sys.argv[1] if len(sys.argv) > 1 else HERE.parents[1] / "modules" / "anomaly_detection")
cic = src / "data" / "raw" / "CIC-IDS- 2017"
NETWORK = ["anomaly", "threat"]
samples = []


def add(sample_id, name, description, df, module_ids):
    path = HERE / f"{sample_id}.csv"
    df.to_csv(path, index=False)
    samples.append({"id": sample_id, "name": name, "description": description,
                    "module_ids": module_ids, "rows": len(df), "file": path.name})
    print(f"{path.name}: {len(df):,} rows")


def cic_sample(filename, n, seed=7):
    df = pd.read_csv(cic / filename, low_memory=False, encoding="latin-1")
    df.columns = [c.strip() for c in df.columns]
    return df.sample(n=min(n, len(df)), random_state=seed).reset_index(drop=True)


synthetic = src / "data" / "processed" / "sample_traffic.csv"
if synthetic.exists():
    add("synthetic_traffic", "Synthetic lab traffic (with IPs)",
        "Generated flows with source/destination IPs and injected exfiltration, scan and brute-force "
        "behaviour. Best demo of per-host results.", pd.read_csv(synthetic), ["anomaly"])

if cic.exists():
    add("cicids2017_portscan", "CIC-IDS2017 Friday: PortScan",
        "5,000 random flows from Friday afternoon (benign + port scanning).",
        cic_sample("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", 5000), NETWORK)
    add("cicids2017_ddos", "CIC-IDS2017 Friday: DDoS",
        "5,000 random flows from Friday afternoon (benign + LOIC DDoS).",
        cic_sample("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", 5000), NETWORK)
    add("cicids2017_dos", "CIC-IDS2017 Wednesday: DoS",
        "5,000 random flows from Wednesday (benign + Hulk, GoldenEye, Slowloris, Slowhttptest).",
        cic_sample("Wednesday-workingHours.pcap_ISCX.csv", 5000), NETWORK)

nsl = src / "data" / "raw" / "NSL-KDD" / "KDDTest+.txt"
if nsl.exists():
    sys.path.insert(0, str(src))
    from anomaly_detection.data.loaders import NSL_KDD_COLUMNS
    df = pd.read_csv(nsl, header=None)
    df.columns = NSL_KDD_COLUMNS + ["label", "difficulty"]
    df = df.drop(columns="difficulty").sample(n=5000, random_state=7).reset_index(drop=True)
    add("nsl_kdd_test", "NSL-KDD test set",
        "5,000 records from KDDTest+, which contains attack types never seen in training.",
        df, ["anomaly"])

(HERE / "samples.json").write_text(json.dumps(samples, indent=2))
