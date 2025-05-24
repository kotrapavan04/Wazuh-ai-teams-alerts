# Wazuh + AI + Microsoft Teams Integration

This project demonstrates how to integrate Wazuh (open-source SIEM) with an AI model and Microsoft Teams to automate security alert investigation and reporting.

---

## 🔍 What This Project Does

- Detects alerts from the Wazuh security platform.
- Sends alert data to an AI model for basic investigation/analysis.
- Automatically sends summarized insights to a Microsoft Teams channel.

This reduces manual effort in triaging alerts and provides faster threat visibility for SOC teams.

---

## ⚙️ How to Set It Up

### 1. Prerequisites

- A working Wazuh Docker environment
- Python 3 installed inside the Wazuh Manager container
- Access to an AI API (e.g., [aimlapi.com](https://aimlapi.com/))
- A Microsoft Teams webhook URL

### 2. Create AI Integration Script

Inside the Wazuh manager container, create:

```bash
/var/ossec/integrations/ai_alert_handler.py`  

#!/usr/bin/env python3
import sys
import json
import requests

API_KEY = 'your_actual_api_key_here'
API_URL = 'https://api.aimlapi.com/v1/chat/completions'

# Read Wazuh alert JSON from stdin
alert = json.load(sys.stdin)

prompt = f"Investigate this Wazuh alert:\n{json.dumps(alert, indent=2)}"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}
data = {
    "model": "gpt-3.5-turbo",
    "messages": [
        {"role": "user", "content": prompt}
    ]
}

response = requests.post(API_URL, headers=headers, json=data)

if response.status_code == 200:
    result = response.json()
    reply = result['choices'][0]['message']['content']
    print("AI Response:", reply)
else:
    print("Error:", response.status_code, response.text)
```
###3 Create Teams Notifer Script

Create this file:
nano var/ossec/integrations/wazuh_teams_notifier.py

Add below code in the above location:

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
-----------

And make it executable:
chmod +x wazuh_teams_notifier.py

then exit from the bash.

Note: need to install nano in the bash before creating the file if you have already installed ignore this step.


###4. Define the command in /var/ossec/etc/ossec.conf inside <ossec_config>:
<integration>
  <name>custom</name>
  <hook_url>none</hook_url>
  <command>/var/ossec/integrations/ai_alert_handler.py</command>
  <alert_format>json</alert_format>
  <rules_id>100010</rules_id>
</integration>

then edit Local_rules.xml and few rules in it 
<group name="teams-alerts">
  <rule id="100001" level="10">
    <decoded_as>json</decoded_as>
    <description>Send alert to Microsoft Teams</description>
    <options>no_full_log</options>
    <command>teams_notify</command>
  </rule>
</group>

then restart the docker:
docker restart single-node-wazuh.manager-1

###5. Test it:
1.Create a test alert:
echo '{ "rule": { "level": 10, "description": "Test alert" }, "agent": { "name": "TestAgent" }, "full_log": "Suspicious login attempt detected." }' > /tmp/test_alert.json
this will create a .json file.

2.Run the integration script:
cat /tmp/test_alert.json | docker exec -i <wazuh_manager_container_id_or_name> python3 /var/ossec/integrations/wazuh_teams_notifier.py

Now you should get a alert in your teams which is Analyzed by AI.

🧠 What the AI Component Does
-Accepts raw alert data from Wazuh.
-Sends it to an AI API for initial analysis.
-Receives a summarized explanation or recommendation (e.g., potential cause, next action).
-Embeds that summary in the Teams message.

💬 How Teams Integration Works
-A Microsoft Teams webhook URL is used to post messages to a specific channel.
The script formats a message including:
-Alert description
-Agent name
-AI-generated summary (if enabled)
-Sends it via an HTTP POST request to the Teams webhook.

📁 File Structure
wazuh-ai-teams-alert/
├── ai_alert_handler.py
├── wazuh_teams_notifier.py
├── test_alert.json
└── README.md

🙌 Contributing
Pull requests and ideas to improve this workflow are welcome!



