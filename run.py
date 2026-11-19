"""Server chalao:  python run.py   -> http://127.0.0.1:5000"""
from sentinel.app import app

if __name__ == "__main__":
    # 127.0.0.1 = sirf tumhare computer se khulega (safe). Internet par expose mat karna.
    app.run(host="127.0.0.1", port=5000, debug=False)
