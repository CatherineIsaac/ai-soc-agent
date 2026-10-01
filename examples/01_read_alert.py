"""Stage 1: read the latest Suricata alert from eve.json. No AI involved."""

import json
import os

EVE_FILE = os.getenv("SURICATA_EVE_FILE", "/var/log/suricata/eve.json")

with open(EVE_FILE, "r") as file:
    lines = file.readlines()

for line in reversed(lines):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue

    if event.get("event_type") == "alert":
        print("Latest Suricata alert:")
        print(json.dumps(event, indent=2))
        break
else:
    print("No Suricata alerts found.")
