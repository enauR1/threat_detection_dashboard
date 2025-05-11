# src/log_streamer.py
"""
JSON‑Array Log Streamer
-------------------------------------------------
Appends one synthetic log entry every 15 s to:
    data/simulated_output.json   (JSON array)
Run in a separate terminal:
    python src/log_streamer.py
"""

import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------- target file
DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "simulated_output.json"
DATA_PATH.parent.mkdir(exist_ok=True)   # ensure /data exists

# ------------------------------------------------- sample library
SAMPLE_TYPES = [
    ("unauthorized FTP access", 6),
    ("brute-force attack (SSH)", 8),
    ("reconnaissance (SNMP scan)", 5),
    ("benign HTTP traffic", 0),
    ("internal reconnaissance (SMB)", 7),
]

# ------------------------------------------------- log generator
def make_log() -> dict:
    threat, sev = random.choice(SAMPLE_TYPES)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
    text = f"[{ts}] SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22 ACTION=DROP MSG={threat}"
    return {
        "log": text,
        "suspicious": sev > 0,
        "threat_type": threat,
        "severity": sev,
        "recommended_action": "Investigate" if sev > 0 else "No action needed",
    }

# ------------------------------------------------- main loop
print("=== JSON‑array streamer started ===")
print("Writing to:", DATA_PATH.resolve())

while True:
    # Load existing array (or start new)
    if DATA_PATH.exists():
        try:
            data = json.loads(DATA_PATH.read_text())
        except json.JSONDecodeError:
            print("Corrupt JSON detected — starting fresh file.")
            data = []
    else:
        data = []

    # Append new entry and save
    data.append(make_log())
    DATA_PATH.write_text(json.dumps(data, indent=2))
    print(f"• appended (total logs: {len(data)})")

    time.sleep(15)  # add one log every 15 s
