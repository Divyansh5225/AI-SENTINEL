"""
features.py -- request ko NUMBERS me badalna.

ML text nahi samajhta, sirf numbers samajhta hai. To har request ke liye hum 12 numbers
nikalte hain (jaise: kitne special characters hain, kitni lambi hai, kitni requests aa chuki hain).
Normal request ke numbers "chhote aur saaf" hote hain; attack ke numbers ajeeb hote hain.
"""
import math
import re
from collections import Counter

from .rules import decode

SPECIAL = set("'\"<>;()=\\/-#*|&$`{}[]!")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")

FEATURE_NAMES = [
    "path_len", "n_params", "payload_len", "max_value_len",
    "special_ratio", "digit_ratio", "upper_ratio", "entropy",
    "pct_count", "is_post", "rate_10s", "failed_logins_60s",
]


def entropy(text: str) -> float:
    """Shannon entropy: string kitni 'random/mixed' dikhti hai (0 = ek hi char baar baar)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract(method: str, path: str, raw_values: list[str], rate: int, fails: int) -> dict[str, float | int]:
    """Ek request -> features ka dict."""
    raw_joined = "".join(str(v) for v in raw_values)
    decoded = [decode(v) for v in raw_values]
    joined = "".join(decoded)
    n = len(joined)
    special = sum(1 for ch in joined if ch in SPECIAL)
    digits = sum(1 for ch in joined if ch.isdigit())
    upper = sum(1 for ch in joined if ch.isupper())
    return {
        "path_len": len(path),
        "n_params": len(raw_values),
        "payload_len": n,
        "max_value_len": max((len(v) for v in decoded), default=0),
        "special_ratio": special / n if n else 0.0,
        "digit_ratio": digits / n if n else 0.0,
        "upper_ratio": upper / n if n else 0.0,
        "entropy": entropy(joined),
        "pct_count": len(_PCT.findall(raw_joined)),
        "is_post": 1 if str(method).upper() == "POST" else 0,
        "rate_10s": rate,
        "failed_logins_60s": fails,
    }


def to_vector(feature_dict: dict[str, float | int]) -> list[float | int]:
    """Dict -> list (fixed order), jo model ko diya jaata hai."""
    return [feature_dict[name] for name in FEATURE_NAMES]
