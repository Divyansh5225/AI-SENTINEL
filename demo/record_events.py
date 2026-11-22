import sys
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sentinel.db import recent_events, stats

events = recent_events(100)
print(f"Total recorded events: {len(events)}")
print("Stats:", stats())
print("-" * 120)
for e in reversed(events):
    print(f"#{e['id']:02d} | ReqID: {e['request_id']} | {e['method']} {e['path'][:30]:<30} | {e['action']:<10} | {e['category']:<18} | Rule: {e['rule_score']} | ML: {e['ml_score']} | {e['reason']}")
