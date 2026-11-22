"""
ml.py -- AI wala hissa: guard ki "gut feeling".

Isolation Forest kya karta hai (ek line me):
  Ye data me random cut lagata hai. "Ajeeb" (anomaly) points jaldi alag ho jaate hain
  (kam cuts me), normal points bheed me hote hain (zyada cuts lagte hain).
  Jitni jaldi alag = utna ajeeb.

Hum model ko SIRF normal traffic dikhate hain (fit). Baad me jo request "ajeeb" lage,
decision_function usko NEGATIVE score deta hai.
"""
import os
import random

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from . import config, features
from .normal_traffic import make_normal_request


def train(n_samples: int = 5000, seed: int = 42, save: bool = True, use_csic: bool = True) -> IsolationForest:
    """
    Model train karo aur save karo.
    Agar CSIC 2010 dataset (normalTrafficTraining.txt) maujood hai to actual real-world
    HTTP traffic se train karta hai, warna synthetic normal traffic se.
    """
    rows = []

    # 1. Actual CSIC 2010 dataset traffic (agar available ho)
    if use_csic and os.path.exists(config.CSIC_NORMAL_TRAIN):
        from .csic_parser import iter_csic_requests
        for req in iter_csic_requests(config.CSIC_NORMAL_TRAIN):
            rows.append(features.to_vector(features.extract(**req)))

    # 2. Local target app normal traffic
    rng = random.Random(seed)
    for _ in range(n_samples):
        req = make_normal_request(rng)
        rows.append(features.to_vector(features.extract(**req)))

    X = np.array(rows, dtype=float)
    # contamination=0.01 -> training ke ~1% normal ko bhi "ajeeb" maan lo (threshold set karta hai)
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=seed)
    model.fit(X)
    if save:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        joblib.dump(model, config.MODEL_PATH)
    return model


class Detector:
    """Saved model load karta hai; ek vector ko score deta hai."""

    def __init__(self, train_if_missing: bool = True) -> None:
        self.model = None
        if not os.path.exists(config.MODEL_PATH) and train_if_missing:
            train()
        if os.path.exists(config.MODEL_PATH):
            self.model = joblib.load(config.MODEL_PATH)

    @property
    def ready(self):
        return self.model is not None

    def score(self, vector: list[float | int]) -> tuple[float, bool]:
        """Return (score, is_anomaly). Score negative = ajeeb."""
        s = float(self.model.decision_function(np.array([vector], dtype=float))[0])
        return round(s, 4), s < 0
