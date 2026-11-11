# Anomaly detection datasets

Used by `modules/anomaly_detection`. Everything in this folder except this README is git-ignored.

```
data/anomaly_detection/
├── CIC-IDS2017/        the 8 MachineLearningCSV files (*.pcap_ISCX.csv)
├── NSL-KDD/            KDDTrain+.txt, KDDTest+.txt
└── processed/          cached splits and generated synthetic traffic (created by the code)
```

## CIC-IDS2017

Canadian Institute for Cybersecurity, University of New Brunswick:
<https://www.unb.ca/cic/datasets/ids-2017.html>. Download **MachineLearningCSV.zip** and
extract the CSV files into `CIC-IDS2017/`.

## NSL-KDD

<https://www.unb.ca/cic/datasets/nsl.html>. Put `KDDTrain+.txt` and `KDDTest+.txt` in `NSL-KDD/`.
Its test file contains 17 attack types that never appear in training, which is why it is used
to measure detection of unseen attacks.
