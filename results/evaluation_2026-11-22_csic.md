# Evaluation Results — AI-Sentinel (CSIC 2010 Real-World Dataset)
# Date: 2026-11-22
# Dataset: CSIC 2010 HTTP Dataset (28,000 normal samples) + Local Shop normal traffic (5,000 samples)
# Test set: 138 attack requests + 414 legitimate requests (including 14 hand-crafted tricky requests)
# Training seed: 42
# Evaluation seed: 7
# Python: 3.14, scikit-learn 1.9.1, numpy 2.4.4

## Summary Table

| Config         | Precision | Recall (alert+block) | Recall (block only) | FPR   | FP count | Latency mean | Latency p95 |
|----------------|-----------|----------------------|---------------------|-------|----------|--------------|-------------|
| A: rules only  | 99.2%     | 91.3%                | 87.0%               | 0.2%  | 1        | 0.02 ms      | 0.03 ms     |
| B: rules + ML  | 84.8%     | 97.1%                | 89.1%               | 5.8%  | 24       | 3.64 ms      | 4.02 ms     |

## Recall by Attack Type (A → B)

| Type  | Variant     | Rules only | Rules + ML | n   |
|-------|-------------|------------|------------|-----|
| Cmd   | obfuscated  | 50%        | 67%        | 6   |
| Cmd   | plain       | 100%       | 100%       | 18  |
| Path  | obfuscated  | 100%       | 100%       | 9   |
| Path  | plain       | 100%       | 100%       | 9   |
| SQLi  | obfuscated  | 62%        | 92%        | 24  |
| SQLi  | plain       | 100%       | 100%       | 33  |
| XSS   | obfuscated  | 100%       | 100%       | 18  |
| XSS   | plain       | 100%       | 100%       | 21  |

## Missed Attacks (Config B)

- `' or 2>1 --`
- `127.0.0.1%0Acat%20/etc/hosts`

## False Positives Detail

### Config A (1 FP)
- alert: "select your size from the size chart" — low-severity rule match (sqli-select-from)

### Config B (24 FPs)
- 23x alert: normal traffic — ML anomaly only (ML alone never blocks)
- 1x alert: "select your size from the size chart" — low-severity rule match

**Important:** No false positive resulted in a BLOCK — all were ALERTS in accordance with policy design (ML alone never blocks).

## Scientific Analysis & Viva Context

1. **Realistic Anomaly Distribution:** Unlike the synthetic-only model which showed an overly optimistic 100% recall, the model trained on the authentic CSIC 2010 dataset exhibits a realistic 5.8% false-positive rate and 97.1% recall.
2. **Obfuscation Detection:** The addition of ML increased detection of obfuscated SQL injection from 62% to 92%, and obfuscated command injection from 50% to 67%.
