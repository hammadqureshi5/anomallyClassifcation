# Before-and-after results: cicids2017

Train: {'rows': 176467, 'attacks': 29850, 'benign': 146617, 'attack_types': 13} | Test: {'rows': 75630, 'attacks': 12793, 'benign': 62837, 'attack_types': 13}  
Seeds: [42, 43, 44] (mean ± std). Test set never used for tuning.

| Metric | Original (v1) | Improved (v2) | Change v2 − v1 | Hybrid | Change hybrid − v1 |
|---|---|---|---|---|---|
| accuracy | 0.8297 ± 0.0061 | 0.9455 ± 0.0147 | +0.1158 | 0.9749 ± 0.0004 | +0.1452 |
| precision | 0.4034 ± 0.2041 | 0.8501 ± 0.0152 | +0.4467 | 0.8726 ± 0.0019 | +0.4691 |
| recall | 0.0394 ± 0.0357 | 0.8217 ± 0.0856 | +0.7824 | 0.9973 ± 0.0000 | +0.9579 |
| f1 | 0.0712 ± 0.0623 | 0.8346 ± 0.0524 | +0.7634 | 0.9308 ± 0.0011 | +0.8596 |
| false_positive_rate | 0.0094 ± 0.0003 | 0.0293 ± 0.0004 | +0.0199 | 0.0297 ± 0.0005 | +0.0202 |
| roc_auc | 0.9126 ± 0.0070 | 0.9777 ± 0.0074 | +0.0651 | 0.9991 ± 0.0001 | +0.0865 |
| pr_auc | 0.5338 ± 0.0486 | 0.8913 ± 0.0180 | +0.3574 | 0.9980 ± 0.0000 | +0.4641 |
| fit_seconds | 16.4 ± 1.2 | 31.2 ± 6.1 | +14.7458 | 35.8 ± 6.3 | +19.3487 |
| inference_ms_per_1k_flows | 26.3 ± 1.1 | 34.9 ± 1.4 | +8.6294 | 37.9 ± 1.0 | +11.6244 |

Lower is better for false_positive_rate, fit_seconds and inference time.

## Train vs test (seed 42)

| Model | Split | F1 | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|
| baseline | train | 0.1371 | 0.0771 | 0.0095 | 0.5901 |
| baseline | test | 0.1429 | 0.0805 | 0.0094 | 0.5897 |
| improved | train | 0.8759 | 0.8891 | 0.0287 | 0.9072 |
| improved | test | 0.8758 | 0.8911 | 0.0293 | 0.9046 |
| hybrid | train | 0.9339 | 1.0000 | 0.0288 | 1.0000 |
| hybrid | test | 0.9309 | 0.9973 | 0.0296 | 0.9979 |

## Ablation (seed 42, cumulative)

| Step | accuracy | precision | recall | f1 | false_positive_rate | roc_auc | pr_auc |
|---|---|---|---|---|---|---|---|
| Original (v1) | 0.8367 | 0.6358 | 0.0805 | 0.1429 | 0.0094 | 0.9191 | 0.5897 |
| + feature selection | 0.8296 | 0.4534 | 0.0365 | 0.0676 | 0.0090 | 0.9320 | 0.6052 |
| + tuned detector settings | 0.8470 | 0.7491 | 0.1440 | 0.2415 | 0.0098 | 0.9538 | 0.7215 |
| + ensemble redesign | 0.9258 | 0.9296 | 0.6071 | 0.7345 | 0.0094 | 0.9819 | 0.9046 |
| + tuned threshold (= v2) | 0.9573 | 0.8611 | 0.8911 | 0.8758 | 0.0293 | 0.9819 | 0.9046 |

## Recall per attack type (seed 42)

| Attack | n | Original | Improved | Hybrid |
|---|---|---|---|---|
| DoS Hulk | 5214 | 0.155 | 0.920 | 0.998 |
| DDoS | 3851 | 0.000 | 0.951 | 1.000 |
| PortScan | 2677 | 0.000 | 0.861 | 1.000 |
| DoS GoldenEye | 282 | 0.220 | 0.787 | 0.993 |
| FTP-Patator | 197 | 0.000 | 0.716 | 1.000 |
| DoS slowloris | 194 | 0.325 | 0.985 | 0.995 |
| DoS Slowhttptest | 156 | 0.622 | 0.462 | 0.994 |
| SSH-Patator | 87 | 0.000 | 0.011 | 0.989 |
| Bot | 63 | 0.000 | 0.064 | 0.730 |
| Web Attack - Brute Force | 41 | 0.000 | 0.024 | 1.000 |
| Web Attack - XSS | 28 | 0.000 | 0.000 | 0.964 |
| Infiltration | 2 | 0.000 | 0.500 | 0.500 |
| Heartbleed | 1 | 1.000 | 1.000 | 1.000 |
