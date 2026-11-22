"""
config.py -- saari settings ek hi jagah.
Kuch badalna ho (jaise rate limit) to sirf yahin badlo.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Database aur trained model kahan save honge
if os.environ.get("VERCEL"):
    DB_PATH = os.environ.get("SENTINEL_DB", "/tmp/sentinel.db")
else:
    DB_PATH = os.environ.get("SENTINEL_DB", os.path.join(DATA_DIR, "sentinel.db"))
MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")

# Actual CSIC 2010 Dataset paths
CSIC_DIR = os.path.join(DATA_DIR, "csic_2010")
CSIC_NORMAL_TRAIN = os.path.join(CSIC_DIR, "normalTrafficTraining.txt")
CSIC_ANOMALOUS_TEST = os.path.join(CSIC_DIR, "anomalousTrafficTest.txt")

# Mode switches (environment variable se bhi set kar sakte ho)
DRY_RUN = os.environ.get("SENTINEL_DRY_RUN", "0") == "1"   # 1 = sirf dikhao ki kya block hota, asal me block mat karo
USE_ML = os.environ.get("SENTINEL_USE_ML", "1") == "1"     # 0 = sirf rules (baseline comparison ke liye)

# Policy ke numbers
BLOCK_SCORE = 5          # rule score itna ya zyada -> seedha block
RATE_LIMIT = 20          # itni requests ...
RATE_WINDOW = 10         # ... itne seconds me -> 429 Too Many Requests
MAX_FAILED_LOGINS = 5    # itne galat login ...
LOGIN_WINDOW = 60        # ... itne seconds me -> brute force, IP ban
BAN_AFTER_BLOCKS = 5     # itne blocks ...
BAN_WINDOW = 60          # ... itne seconds me -> IP ban
BAN_SECONDS = 60         # ban kitni der ka

# Jin IPs ko kabhi block nahi karna (khali rakho; apne server/monitoring IP yahan daalo)
ALLOWLIST = set()

# Optional: API Key for /sentinel/api/* endpoints (agar set ho to remote clients bhi connect kar sakte hain)
API_KEY = os.environ.get("SENTINEL_API_KEY", "")

# Optional: Webhook URL for incident alerts (Slack, Discord, SIEM, custom HTTP webhook)
WEBHOOK_URL = os.environ.get("SENTINEL_WEBHOOK_URL", "")

# Itne characters se zyada hum inspect nahi karte (bahut lambi body se server dheema na ho)
MAX_INSPECT_CHARS = 5000
