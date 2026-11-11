# Data

All datasets for the project, one folder per module. Each module uses its own datasets.
Nothing here is committed except the READMEs: the files are large and publicly downloadable.

```
data/
├── anomaly_detection/          Hammad Qureshi
│   ├── CIC-IDS2017/            *.pcap_ISCX.csv (MachineLearningCSV)
│   ├── NSL-KDD/                KDDTrain+.txt, KDDTest+.txt
│   └── processed/              cached splits, generated synthetic traffic
├── threat_classification/      Muhammad Bilal Khan
│   └── CSE-CIC-IDS2018/        *_TrafficForML_CICFlowMeter.csv
├── malware_classification/     Nair Abbas
│   └── BODMAS/                 bodmas_category_joined.csv
└── dashboard/
    └── samples/                demo CSVs for the console (built by dashboard/make_samples.py)
```

Each module folder has a README with the download source and the exact files expected.
