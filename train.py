"""
ML model train karo:  python train.py

CSIC 2010 real-world HTTP normal traffic (~28,000 requests) + target app normal traffic
se Isolation Forest train hota hai, aur data/model.joblib me save hota hai.
"""
import os
import random
import time

import numpy as np

from sentinel import config, features, ml
from sentinel.normal_traffic import make_normal_request

if __name__ == "__main__":
    has_csic = os.path.exists(config.CSIC_NORMAL_TRAIN)
    print("=" * 60)
    print("Training AI-Sentinel Anomaly Detector (Isolation Forest)")
    print(f"Dataset: {'CSIC 2010 (Real-world HTTP) + Local Shop' if has_csic else 'Synthetic Normal Only'}")
    print("=" * 60)

    t0 = time.time()
    model = ml.train(n_samples=5000, seed=42, use_csic=True)
    duration = time.time() - t0
    print(f"[OK] Model successfully trained & saved: {config.MODEL_PATH} ({duration:.2f}s)")

    # Validation check on hold-out data
    rng = random.Random(7)
    X_val = np.array([features.to_vector(features.extract(**make_normal_request(rng))) for _ in range(2000)])
    flagged = float((model.decision_function(X_val) < 0).mean() * 100)
    print(f"[Validation] Normal test traffic false-alarm rate: {flagged:.2f}% (expected ~1%)")
    print("=" * 60)
