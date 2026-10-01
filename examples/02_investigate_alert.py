"""Stage 2: send the latest Suricata alert to a model for analysis. No tools."""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI()

EVE_FILE = os.getenv("SURICATA_EVE_FILE", "/var/log/suricata/eve.json")
MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-luna")

with open(EVE_FILE, "r") as file:
    lines = file.readlines()

latest_alert = None

for line in reversed(lines):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue

    if event.get("event_type") == "alert":
        latest_alert = event
        break

if latest_alert:
    response = client.responses.create(
        model=MODEL,
        input=f"""
You are a SOC analyst investigating a Suricata security alert.

Analyze this alert:

{json.dumps(latest_alert, indent=2)}

Explain:
1. What happened?
2. Is this likely malicious or benign?
3. What evidence supports your conclusion?
4. What should the analyst do next?

Do not invent information that is not present in the alert.
"""
    )

    print("\n=== AI SOC INVESTIGATION ===\n")
    print(response.output_text)
else:
    print("No Suricata alerts found.")
