#!/usr/bin/env python3
import sys
import json
import requests

webhook_url = "YOUR_WEBHOOK_URL_HERE"

alert = json.loads(sys.stdin.read())

rule = alert.get("rule", {})
level = alert.get("level", "N/A")
agent = alert.get("agent", {}).get("name", "Unknown")
description = rule.get("description", "No description")
timestamp = alert.get("timestamp", "N/A")

message = {
    "title": "Wazuh Alert",
    "text": f"**Level**: {level}\n**Host**: {agent}\n**Time**: {timestamp}\n**Description**: {description}"
}

payload = {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "summary": "Wazuh Alert",
    "themeColor": "0076D7",
    "title": message["title"],
    "text": message["text"]
}

try:
    requests.post(webhook_url, json=payload)
except Exception as e:
    print(f"Failed to send alert: {e}")
