# Datasets

Dataset files are **not committed** — the CSE-CIC-IDS2018 CSVs used here total
roughly 6.5 GB. Everything in this directory except this file is git-ignored.

## CSE-CIC-IDS2018

Published by the Canadian Institute for Cybersecurity, University of New
Brunswick: <https://www.unb.ca/cic/datasets/ids-2018.html>

The processed CSVs (`*_TrafficForML_CICFlowMeter.csv`) are distributed through
the registry described on that page. Place them here:

```
data/
└── cic_ids2018/
    ├── Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv   # sic — typo is in the original dataset
    ├── Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
    └── Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
```

Then train:

```bash
python -m acds.threat_classifier train data/cic_ids2018/*.csv
```

### Known data-quality issue

Several of these CSVs repeat their header row partway through the file. Left
unfiltered, `"Label"` is ingested as a literal class value — which is why it
appears in `acds_models/meta.json`. Drop those rows before retraining:

```python
df = df[df["Label"].str.strip() != "Label"]
```

## Edge-IIoTset

The pipeline also accepts Edge-IIoTset column naming (`ip.src`, `frame.time`,
`Attack_type`); `load_dataset` normalises the label column automatically.
Source: <https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications>
