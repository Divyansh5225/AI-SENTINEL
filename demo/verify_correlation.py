import sys
import os
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sentinel.db import recent_events

url = "http://127.0.0.1:5000/search?q=%3Cscript%3Ealert(%27viva_match%27)%3C/script%3E"
req = urllib.request.Request(url)

try:
    urllib.request.urlopen(req)
    print("Error: Request was not blocked!")
except urllib.error.HTTPError as e:
    resp_body = e.read().decode().strip()
    resp_req_id = e.headers.get("X-Request-ID")
    print(f"HTTP Status:        {e.code}")
    print(f"Response Body:      {resp_body}")
    print(f"X-Request-ID Hdr:   {resp_req_id}")

    # Fetch top row from DB
    db_event = recent_events(1)[0]
    print(f"SOC DB Incident #:  {db_event['id']}")
    print(f"SOC DB Request ID:  {db_event['request_id']}")
    print(f"SOC DB Rule Match:  {db_event['rules']}")
    print(f"SOC DB Category:    {db_event['category']}")
    print(f"SOC DB Action:      {db_event['action']}")

    # Correlation verification
    matches = (resp_req_id == db_event['request_id']) and (f"incident #{db_event['id']}" in resp_body)
    print(f"Correlation Verified: {matches}")
