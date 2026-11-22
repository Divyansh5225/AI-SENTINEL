#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "======================================================================"
echo "          AI-SENTINEL: LIVE DEMONSTRATION LAUNCHER"
echo "======================================================================"
echo ""

echo "[1/4] Checking if port 5000 is free..."
if command -v lsof >/dev/null 2>&1; then
    PID=$(lsof -ti:5000 || true)
    if [ -n "$PID" ]; then
        echo "[!] Killing process on port 5000 (PID: $PID)..."
        kill -9 "$PID" || true
        sleep 1
    fi
fi
echo "[OK] Port 5000 is ready."
echo ""

echo "[2/4] Starting AI-Sentinel Server on http://127.0.0.1:5000 ..."
python run.py > server.log 2>&1 &
SERVER_PID=$!

cleanup() {
    echo ""
    echo "Stopping AI-Sentinel server (PID: $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    echo "Server stopped."
}
trap cleanup EXIT INT TERM

echo "[3/4] Waiting for health endpoint to respond..."
ATTEMPTS=0
until python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/sentinel/health?format=json', timeout=1)" >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS+1))
    if [ "$ATTEMPTS" -gt 15 ]; then
        echo "[ERROR] Server failed to start within 15 seconds. Check server.log."
        exit 1
    fi
    sleep 1
done
echo "[OK] AI-Sentinel is online!"
echo ""

echo "[4/4] Executing automated endpoint healthcheck suite..."
python demo/healthcheck.py
echo ""

echo "======================================================================"
echo "              DEMO SYSTEM READY! OPEN THESE TABS IN BROWSER"
echo "======================================================================"
echo ""
echo "  1. Enterprise Portal (Target App):"
echo "     http://127.0.0.1:5000/"
echo ""
echo "  2. SOC Real-Time Monitoring Dashboard:"
echo "     http://127.0.0.1:5000/sentinel/dashboard"
echo ""
echo "  3. System Health Check UI:"
echo "     http://127.0.0.1:5000/sentinel/health"
echo ""
echo "  4. To send live attack traffic, open a new terminal and run:"
echo "     python demo.py"
echo ""
echo "======================================================================"
echo "Press Ctrl+C to stop server..."
wait "$SERVER_PID"
