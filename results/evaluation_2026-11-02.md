# Evaluation Results — AI-Sentinel
# Date: 2026-11-02
# Git commit: (not yet under git)
# Dataset: built-in synthetic (138 attack + 414 legit, of which 14 hand-made tricky)
# Training seed: 42 (5000 samples)
# Evaluation seed: 7 (400 normal samples)
# Python: 3.x, scikit-learn 1.9.1, numpy 2.4.4

## Summary Table

| Config         | Precision | Recall (alert+block) | Recall (block only) | FPR   | FP count | Latency mean | Latency p95 |
|----------------|-----------|----------------------|---------------------|-------|----------|--------------|-------------|
| A: rules only  | 99.2%     | 91.3%                | 84.8%               | 0.2%  | 1        | 0.01 ms      | 0.02 ms     |
| B: rules + ML  | 94.5%     | 100.0%               | 88.4%               | 1.9%  | 8        | 3.76 ms      | 4.17 ms     |

## Recall by Attack Type (A → B)

| Type  | Variant     | Rules only | Rules + ML | n   |
|-------|-------------|------------|------------|-----|
| Cmd   | obfuscated  | 50%        | 100%       | 6   |
| Cmd   | plain       | 100%       | 100%       | 18  |
| Path  | obfuscated  | 100%       | 100%       | 9   |
| Path  | plain       | 100%       | 100%       | 9   |
| SQLi  | obfuscated  | 62%        | 100%       | 24  |
| SQLi  | plain       | 100%       | 100%       | 33  |
| XSS   | obfuscated  | 100%       | 100%       | 18  |
| XSS   | plain       | 100%       | 100%       | 21  |

## Missed Attacks (Config B)

None (0 payloads fully missed).

## False Positives Detail

### Config A (1 FP)
- alert: "select your size from the size chart" — low-severity rule match (sqli-select-from)

### Config B (8 FPs)
- 4x alert: generated normal traffic — ML anomaly only
- alert: "select your size from the size chart" — low-severity rule match
- alert: "women's shoes (size 7) - black" — ML anomaly only
- alert: "rahul.sharma@example.com / P@ssw0rd!#2024" — ML anomaly only
- alert: "o'neil / it's-a-secret!" — ML anomaly only

**Important:** No false positive was a BLOCK — all were ALERTS (policy ensures ML alone never blocks).

## Caveats

- Data is synthetic. See docs/LIMITATIONS.md for full discussion.
- Both attacks and rules were authored by the same person (optimistic results).
- Real-world FPR will be higher due to diverse user behaviour.
