"""
policy.py -- "Manager" ka faisla.

Guard (rules) aur gut feeling (ML) ki report aati hai. Manager decide karta hai:
  allow       -> jaane do
  alert       -> jaane do, par register me "suspicious" likh do
  rate_limit  -> bahut zyada requests, 429 do
  block       -> 403 do

Zaroori niyam (paper ke section 5.3 se): ML AKELA kabhi block nahi karta, sirf alert deta hai.
Block tab hota hai jab rule pakka bole, ya rule + ML dono sahmat hon.
"""
from collections import namedtuple

from . import config

Decision = namedtuple("Decision", "action reason ban category")


def decide(rule_score: int, top_category: str, ml_flag: bool, rate: int, fails: int) -> Decision:
    if fails >= config.MAX_FAILED_LOGINS:
        return Decision("block", "brute force: too many failed logins", True, "Brute Force")
    if rule_score >= config.BLOCK_SCORE:
        return Decision("block", "high-severity rule match", False, top_category)
    if rule_score > 0 and ml_flag:
        return Decision("block", "rule match + ML anomaly agree", False, top_category)
    if rate > config.RATE_LIMIT:
        return Decision("rate_limit", "too many requests in a short time", False, "Rate Limit")
    if rule_score > 0:
        return Decision("alert", "low-severity rule match", False, top_category)
    if ml_flag:
        return Decision("alert", "ML anomaly only (ML alone never blocks)", False, "Anomaly (ML)")
    return Decision("allow", "clean", False, "")
