"""
ML model dobara train karo:  python train.py

Naqli normal traffic se Isolation Forest sikhta hai, phir hum nayi (alag seed wali) normal
traffic par check karte hain ki kitni galti se 'ajeeb' maani gayi.
"""
import random

import numpy as np

from sentinel import config, features, ml
from sentinel.normal_traffic import make_normal_request

if __name__ == "__main__":
    model = ml.train(n_samples=5000, seed=42)
    print(f"Model save hua: {config.MODEL_PATH}")

    rng = random.Random(7)
    X = np.array([features.to_vector(features.extract(**make_normal_request(rng))) for _ in range(2000)])
    flagged = float((model.decision_function(X) < 0).mean() * 100)
    print(f"Nayi normal traffic me se {flagged:.1f}% 'ajeeb' flag hui (ye false-alarm rate hai; ~1% ke aas-paas hona chahiye).")
    print("Ye numbers NAKLI data par hain -- paper me real data (CSIC 2010 / apna lab traffic) ke numbers do.")
