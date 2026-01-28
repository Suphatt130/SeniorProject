import time
import requests
import json
import os
import config
from database.db_manager import save_log
from alerting.alert_func import send_line_alert

def load_rules():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(current_dir, '../resources/splunk_rules.json')
    try:
        with open(json_path, 'r') as f: return json.load(f)
    except: return {}

RULES = load_rules()
QUERY_CRYPTO = RULES.get('crypto', {}).get('query', '')
SEVERITY_CRYPTO = RULES.get('crypto', {}).get('severity', 'Critical')

def run_crypto_check(last_alert_time):
    payload = {
        "search": QUERY_CRYPTO,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "-5m", "latest_time": "now"
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
                print(f"[Crypto] Malicious Driver Detected: {len(events)} events.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                for event in events:
                    host = event.get('Computer', 'Unknown')
                    driver = event.get('ImageLoaded', 'Unknown')
                    md5 = event.get('MD5', 'N/A')
                    sha1 = event.get('SHA1', 'N/A')
                    end_time = event.get('EndTime', 'N/A')
                    
                    details = f"End: {end_time} | SHA1: {sha1}"
                    
                    save_log(
                        attack_type="Cryptojacking", 
                        event=event, 
                        alert_sent=ready_to_alert, 
                        details_str=details,
                        severity=SEVERITY_CRYPTO,
                        source_app=driver
                    )

                if ready_to_alert:
                    latest = events[0]
                    msg = (
                        f"🚨 **Cryptojacking Alert!**\n💻 Host: {latest.get('dvc')}\n📂 Driver: {latest.get('Driver_Image')}\n🔑 MD5: {latest.get('MD5')}\n📝 Activity: {latest.get('Activity')}")
                    print("   >> Sending Crypto Alert")
                    send_line_alert(msg)
                    return current_time
                    
        return last_alert_time
    except Exception as e:
        print(f"[Crypto] Error: {e}")
        return last_alert_time