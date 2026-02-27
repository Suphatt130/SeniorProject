import time
import requests
import json
import os
import config
from database.db_manager import save_log
from alerting.alert_func import send_line_alert, send_email_alert
import logging

# Configure logging to save errors to a file and show them in the console
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("spade_errors.log"), logging.StreamHandler()]
)

def load_rules():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(current_dir, '../resources/splunk_rules.json')
    try:
        with open(json_path, 'r') as f: return json.load(f)
    except: return {}

RULES = load_rules()
QUERY_BRUTEFORCE = RULES.get('bruteforce', {}).get('query', '')
SEVERITY_SCORE = RULES.get('bruteforce', {}).get('severity', 5)

def run_bruteforce_check(last_alert_time):
    payload = {
        "search": QUERY_BRUTEFORCE,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "-5m",
        "latest_time": "now"
    }
    
    try:
        response = requests.post(config.SPLUNK_URL, data=payload, verify=False)
        if response.status_code == 200:
            events = []
            for line in response.text.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        if "result" in data: events.append(data["result"])
                    except: continue

            if events:
                print(f"[Brute Force] Detected {len(events)} attacks.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                severity_label = config.get_severity_label(SEVERITY_SCORE)
                for event in events:
                    save_log(
                        attack_type="Brute Force", 
                        event=event, 
                        alert_sent=ready_to_alert,
                        severity=severity_label
                    )

                if ready_to_alert:
                    latest = events[0]
                    msg = (
                        f"🚨 **Brute Force Alert!**\n💻 Host: {latest.get('dest')}\n👤 Target: {latest.get('user')}\n🌍 Attacker IP: {latest.get('src_ip')}\n🔢 Attempts: {latest.get('count')}")
                    print("   >> Sending Brute Force Alert")
                    send_email_alert("Brute Force Alert!", msg)
                    return current_time
        return last_alert_time
    except Exception as e:
        print(f"[BruteForce] Error: {e}")
        return last_alert_time