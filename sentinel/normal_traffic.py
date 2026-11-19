"""
normal_traffic.py -- NAKLI (synthetic) normal traffic banane wala.

Isolation Forest ko "normal kaisa dikhta hai" sikhana padta hai. Real dataset (jaise CSIC 2010)
ya apne lab ka asli traffic best hai; shuru karne ke liye hum random normal requests bana lete hain:
home page, product page, search, category, login.
"""
import random
import string
from urllib.parse import quote_plus

WORDS = ["shoes", "laptop", "phone", "book", "pen", "notebook", "bag", "watch", "camera",
         "headphones", "charger", "mouse", "keyboard", "monitor", "table", "chair", "lamp",
         "bottle", "jacket", "tshirt", "wireless", "blue", "black", "red", "cheap", "best",
         "new", "gaming", "office", "student", "backpack", "cotton", "usb-c", "4k", "15",
         "5000", "xl", "2024", "1tb"]
CATEGORIES = ["books", "electronics", "fashion", "home", "sports", "toys"]
SORTS = ["price", "rating", "newest"]
NAMES = ["rahul", "priya", "amit", "neha", "divya", "karan", "anita", "vikas", "sara", "ravi"]

KINDS = ["home", "about", "product", "search", "category", "login"]
WEIGHTS = [15, 5, 25, 25, 15, 15]


def _search_text(rng):
    words = [rng.choice(WORDS) for _ in range(rng.randint(1, 4))]
    text = " ".join(words)
    roll = rng.random()
    if roll < 0.05:
        text += "'s"                      # jaise "men's shoes"
    elif roll < 0.08:
        text = text.replace(" ", " & ", 1)  # jaise "bag & wallet"
    return text


def _password(rng):
    chars = string.ascii_letters + string.digits + "@#$!_-."
    return "".join(rng.choice(chars) for _ in range(rng.randint(6, 14)))


def make_normal_request(rng):
    """Ek normal request banao. Return dict (features.extract ke arguments jaisa)."""
    kind = rng.choices(KINDS, weights=WEIGHTS)[0]
    method, values = "GET", []
    if kind == "home":
        path = "/"
    elif kind == "about":
        path = "/about"
    elif kind == "product":
        path, values = "/product", [str(rng.randint(1, 500))]
    elif kind == "search":
        path, values = "/search", [_search_text(rng)]
        if rng.random() < 0.3:
            values.append(str(rng.randint(1, 5)))
    elif kind == "category":
        path = "/products"
        values = [rng.choice(CATEGORIES), str(rng.randint(1, 10))]
        if rng.random() < 0.4:
            values.append(rng.choice(SORTS))
    else:
        method, path = "POST", "/login"
        values = [rng.choice(NAMES) + str(rng.randint(1, 999)), _password(rng)]
    return {
        "method": method,
        "path": path,
        "raw_values": [quote_plus(v) for v in values],   # browser jaisa URL-encoding
        "rate": rng.randint(1, 6),
        "fails": rng.choices([0, 1, 2], weights=[80, 15, 5])[0],
    }
