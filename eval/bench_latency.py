"""
eval/bench_latency.py -- Task A: Latency Benchmark for AI-Sentinel WAF

Measures:
  (a) End-to-end request time through WAF
  (b) Engine inspection time only
  (c) ML predict time only
  (d) Baseline with WAF bypassed (no code modifications to sentinel/)

Methodology:
  - 50 warmup requests followed by 1,000 diverse benign requests.
  - Rate limiting (30 req/min) & brute-force protection avoidance:
    Each request uses a unique client IP (10.0.x.y) via environ_overrides['REMOTE_ADDR'].
    This accurately simulates a realistic multi-user environment without polluting
    per-IP rate/fail deques or triggering false rate-limit/ban cascades.
  - Safe isolation: Uses a temporary SQLite DB path and temporary model copy;
    never writes to production data/sentinel.db or data/model.joblib.
"""
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from collections import defaultdict
import numpy as np

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sentinel import config

# Step 1: Safe isolation (never touch production DB or model)
temp_dir = tempfile.mkdtemp(prefix="sentinel_bench_")
temp_db = os.path.join(temp_dir, "temp_bench.db")
config.DB_PATH = temp_db

temp_model = os.path.join(temp_dir, "temp_model.joblib")
if os.path.exists(config.MODEL_PATH):
    shutil.copyfile(config.MODEL_PATH, temp_model)
    config.MODEL_PATH = temp_model

from sentinel import db
db.init_db()

from sentinel.app import app, guard, sentinel
import sentinel.features as feat_mod

def generate_request_pool():
    """Generate 20 distinct realistic benign request templates."""
    templates = [
        ("GET", "/", None, None, {}),
        ("GET", "/about", None, None, {}),
        ("GET", "/product", {"id": 1}, None, {}),
        ("GET", "/product", {"id": 2}, None, {}),
        ("GET", "/product", {"id": 3}, None, {}),
        ("GET", "/product", {"id": 4}, None, {}),
        ("GET", "/product", {"id": 5}, None, {}),
        ("GET", "/product", {"id": 6}, None, {}),
        ("GET", "/search", {"q": "cloud"}, None, {}),
        ("GET", "/search", {"q": "ledger"}, None, {}),
        ("GET", "/search", {"q": "logistics"}, None, {}),
        ("GET", "/search", {"q": "telematics"}, None, {}),
        ("GET", "/search", {"q": "analytics"}, None, {}),
        ("GET", "/search", {"q": "cybersecurity"}, None, {}),
        ("GET", "/search", {"category": "infrastructure", "limit": "20"}, None, {}),
        ("GET", "/search", {"filter": "active", "sort": "asc", "page": "1"}, None, {}),
        ("POST", "/login", None, {"username": "demo", "password": "demo123"}, {}),
        ("POST", "/login", None, {"username": "demo", "password": "demo123", "org": "nexuscorp"}, {}),
        ("POST", "/search", None, json.dumps({"query": "kubernetes", "max_results": 10}), {"content_type": "application/json"}),
        ("POST", "/product", None, json.dumps({"id": 1, "view": "detailed"}), {"content_type": "application/json"}),
    ]
    return templates

def run_benchmark():
    client = app.test_client()
    templates = generate_request_pool()
    num_templates = len(templates)
    
    # Trackers for inspection-only and ml-only
    last_engine_time = [0.0]
    last_ml_time = [0.0]
    
    # Instrument engine.inspect and detector.score cleanly without modifying files
    orig_inspect = sentinel.inspect
    def timed_inspect(*args, **kwargs):
        t0 = time.perf_counter()
        res = orig_inspect(*args, **kwargs)
        last_engine_time[0] = (time.perf_counter() - t0) * 1000.0
        return res
    sentinel.inspect = timed_inspect
    
    if sentinel.detector is not None and sentinel.detector.ready:
        orig_score = sentinel.detector.score
        def timed_score(*args, **kwargs):
            t0 = time.perf_counter()
            res = orig_score(*args, **kwargs)
            last_ml_time[0] = (time.perf_counter() - t0) * 1000.0
            return res
        sentinel.detector.score = timed_score

    print("=" * 70)
    print("TASK A: LATENCY BENCHMARK (1,000 Benign Requests)")
    print("=" * 70)

    # ----------------------------------------------------
    # Phase 1: Baseline (WAF Bypassed)
    # Temporarily remove guard from app.before_request_funcs[None]
    # ----------------------------------------------------
    orig_hooks = list(app.before_request_funcs[None])
    app.before_request_funcs[None] = [h for h in orig_hooks if h != guard]
    
    # Warmup baseline
    for i in range(50):
        method, path, q_params, data, extra = templates[i % num_templates]
        ip = f"10.0.{i // 256}.{i % 256}"
        env = {"REMOTE_ADDR": ip}
        if method == "GET":
            client.get(path, query_string=q_params, environ_overrides=env, **extra)
        else:
            client.post(path, data=data, environ_overrides=env, **extra)
            
    baseline_latencies = []
    for i in range(1000):
        method, path, q_params, data, extra = templates[i % num_templates]
        ip = f"10.0.{(i + 100) // 256}.{(i + 100) % 256}"
        env = {"REMOTE_ADDR": ip}
        t0 = time.perf_counter()
        if method == "GET":
            r = client.get(path, query_string=q_params, environ_overrides=env, **extra)
        else:
            r = client.post(path, data=data, environ_overrides=env, **extra)
        dt = (time.perf_counter() - t0) * 1000.0
        baseline_latencies.append(dt)

    # Restore guard hook
    app.before_request_funcs[None] = orig_hooks

    # ----------------------------------------------------
    # Phase 2: WAF Enabled (End-to-End, Engine Only, ML Only)
    # ----------------------------------------------------
    # Warmup WAF
    for i in range(50):
        method, path, q_params, data, extra = templates[i % num_templates]
        ip = f"10.0.{(i + 2000) // 256}.{(i + 2000) % 256}"
        env = {"REMOTE_ADDR": ip}
        if method == "GET":
            client.get(path, query_string=q_params, environ_overrides=env, **extra)
        else:
            client.post(path, data=data, environ_overrides=env, **extra)

    e2e_latencies = []
    engine_latencies = []
    ml_latencies = []

    for i in range(1000):
        method, path, q_params, data, extra = templates[i % num_templates]
        ip = f"10.0.{(i + 5000) // 256}.{(i + 5000) % 256}"
        env = {"REMOTE_ADDR": ip}
        last_engine_time[0] = 0.0
        last_ml_time[0] = 0.0
        
        t0 = time.perf_counter()
        if method == "GET":
            r = client.get(path, query_string=q_params, environ_overrides=env, **extra)
        else:
            r = client.post(path, data=data, environ_overrides=env, **extra)
        dt = (time.perf_counter() - t0) * 1000.0

        e2e_latencies.append(dt)
        engine_latencies.append(last_engine_time[0])
        ml_latencies.append(last_ml_time[0])

    def stats(arr):
        a = np.array(arr)
        return {
            "mean": float(np.mean(a)),
            "median": float(np.median(a)),
            "p95": float(np.percentile(a, 95)),
            "p99": float(np.percentile(a, 99)),
            "min": float(np.min(a)),
            "max": float(np.max(a)),
        }

    res_baseline = stats(baseline_latencies)
    res_e2e = stats(e2e_latencies)
    res_engine = stats(engine_latencies)
    res_ml = stats(ml_latencies)

    # Overhead
    overhead_mean = res_e2e["mean"] - res_baseline["mean"]
    overhead_median = res_e2e["median"] - res_baseline["median"]

    specs = {
        "python_version": sys.version.split()[0],
        "os": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
    }

    results = {
        "machine_specs": specs,
        "n_requests": 1000,
        "warmup_requests": 50,
        "ip_strategy": "unique_ip_per_request (10.0.x.y) to prevent rate-limit and brute-force state interference",
        "baseline_waf_bypassed_ms": res_baseline,
        "e2e_waf_enabled_ms": res_e2e,
        "engine_inspection_only_ms": res_engine,
        "ml_predict_only_ms": res_ml,
        "waf_overhead_mean_ms": overhead_mean,
        "waf_overhead_median_ms": overhead_median,
    }

    print("\n--- MACHINE SPECS ---")
    for k, v in specs.items():
        print(f"  {k}: {v}")

    print("\n--- LATENCY SUMMARY (ms) ---")
    print(f"{'Component':<28} | {'Mean':<8} | {'Median':<8} | {'p95':<8} | {'p99':<8}")
    print("-" * 70)
    print(f"{'1. Baseline (WAF Bypassed)':<28} | {res_baseline['mean']:<8.3f} | {res_baseline['median']:<8.3f} | {res_baseline['p95']:<8.3f} | {res_baseline['p99']:<8.3f}")
    print(f"{'2. End-to-End (WAF Active)':<28} | {res_e2e['mean']:<8.3f} | {res_e2e['median']:<8.3f} | {res_e2e['p95']:<8.3f} | {res_e2e['p99']:<8.3f}")
    print(f"{'3. Engine Inspection Only':<28} | {res_engine['mean']:<8.3f} | {res_engine['median']:<8.3f} | {res_engine['p95']:<8.3f} | {res_engine['p99']:<8.3f}")
    print(f"{'4. ML Predict Only':<28} | {res_ml['mean']:<8.3f} | {res_ml['median']:<8.3f} | {res_ml['p95']:<8.3f} | {res_ml['p99']:<8.3f}")
    print("-" * 70)
    print(f"WAF Net Overhead: Mean = {overhead_mean:.3f} ms, Median = {overhead_median:.3f} ms")

    # Cleanup temp files
    try:
        shutil.rmtree(temp_dir)
    except Exception:
        pass

    return results

if __name__ == "__main__":
    res = run_benchmark()
    out_path = os.path.join(os.path.dirname(__file__), "latency_results.json")
    with open(out_path, "w") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved raw latency metrics to {out_path}")
