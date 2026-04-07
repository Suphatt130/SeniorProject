import time
import requests
import json
import os
import config
from database.db_manager import save_log
from alerting.alert_func import send_line_alert, send_email_alert
import logging
import builtins
import datetime

_original_print = builtins.print
def print(*args, **kwargs):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    _original_print(f"[{ts}]", *args, **kwargs)

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
QUERY_DOS = RULES.get('dos', {}).get('query', '')
SEVERITY_SCORE = RULES.get('dos', {}).get('severity', 7)

def run_dos_check(last_alert_time):
    payload = {
        "search": QUERY_DOS,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "-30s",
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
                        if "result" in data:
                            events.append(data["result"])
                    except: continue

            if events:
                print(f"[DoS] Detected {len(events)} Large ICMP traffic streams.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                severity_label = config.get_severity_label(SEVERITY_SCORE)

                for event in events:
                    save_log(
                        attack_type="DoS", 
                        event=event, 
                        alert_sent=ready_to_alert, 
                        severity=severity_label,
                    )

                if ready_to_alert:
                    latest = events[0]
                    msg = (
                        f"🚨 **DoS Alert! (ICMP Flood)**\nTarget: {latest.get('dest_ip')}\nAttacker: {latest.get('src_ip')}\nSize: {latest.get('size')} bytes\nPackets: {latest.get('count')}/10s")
                    print("   >> Sending DoS Alert")
                    send_line_alert(msg)
                    send_email_alert("DoS Alert!", msg)
                    return current_time
                    
        return last_alert_time

    except Exception as e:
        print(f"[DoS] Error: {e}")
        return last_alert_time