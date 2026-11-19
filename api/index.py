import os
import sys

# Project root directory ko python path me add karo
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sentinel.app import app

# Vercel WSGI entry point
# Vercel looks for the `app` variable
