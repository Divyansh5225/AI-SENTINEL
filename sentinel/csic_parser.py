"""
sentinel/csic_parser.py -- CSIC 2010 HTTP Dataset Parser.

Ye module CSIC 2010 HTTP Dataset (real-world normal aur attack requests) ko parse karke
features extraction ke liye structured requests dicts me convert karta hai.
"""
import os
import urllib.parse
from typing import Generator, List, Dict, Any


def iter_csic_requests(filepath: str, max_requests: int | None = None) -> Generator[Dict[str, Any], None, None]:
    """
    CSIC 2010 raw HTTP file ko stream karke parse karo.
    Har request -> {'method': str, 'path': str, 'raw_values': list[str], 'rate': int, 'fails': int}
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"CSIC 2010 file not found at: {filepath}")

    with open(filepath, "r", encoding="latin1") as f:
        content = f.read()

    # CSIC 2010 requests are delimited by 2-3 newlines between blocks
    blocks = content.split("\n\n\n")
    if len(blocks) < 2:
        blocks = content.split("\r\n\r\n\r\n")

    count = 0
    for block in blocks:
        block = block.strip()
        if not block:
            continue

        lines = [l.strip() for l in block.splitlines() if l.strip()]
        if not lines:
            continue

        # First line: METHOD URL HTTP/1.1
        req_line = lines[0]
        parts = req_line.split()
        if len(parts) < 2:
            continue

        method = parts[0].upper()
        url = parts[1]

        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"

        raw_values: List[str] = []

        # 1. Query parameters
        if parsed.query:
            q_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for vals in q_params.values():
                raw_values.extend(vals)

        # 2. POST / PUT Body parameters
        if method in ("POST", "PUT") and len(lines) > 1:
            body = lines[-1]
            # Ignore headers if no actual body line
            if "=" in body and not body.startswith(("Content-", "User-Agent", "Host:", "Accept", "Cookie:", "Connection:")):
                b_params = urllib.parse.parse_qs(body, keep_blank_values=True)
                for vals in b_params.values():
                    raw_values.extend(vals)

        yield {
            "method": method,
            "path": path,
            "raw_values": raw_values,
            "rate": 1,
            "fails": 0,
        }

        count += 1
        if max_requests and count >= max_requests:
            break


def load_csic_requests(filepath: str, max_requests: int | None = None) -> List[Dict[str, Any]]:
    """Helper jo parsed requests ki list return karta hai."""
    return list(iter_csic_requests(filepath, max_requests=max_requests))
