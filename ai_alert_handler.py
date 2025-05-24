
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
