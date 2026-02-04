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
QUERY_DDOS = RULES.get('ddos', {}).get('query', '')
SEVERITY_SCORE = RULES.get('ddos', {}).get('severity', 7)

def run_ddos_check(last_alert_time):
    payload = {
        "search": QUERY_DDOS,
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
                print(f"[DDoS] Detected {len(events)} high-volume SYN streams.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                severity_label = config.get_severity_label(SEVERITY_SCORE)

                for event in events:

                    save_log(
                        attack_type="DDoS", 
                        event=event, 
                        alert_sent=ready_to_alert, 
                        severity=severity_label
                    )

                if ready_to_alert:
                    latest = events[0]
                    msg = (
                        f"🚨 **DDoS / DoS Alert!**\n💻 Target: {latest.get('dest_ip')}\n🌍 Attacker: {latest.get('src_ip')}\n Port: {latest.get('dest_port')}\n🔥 Packets: {latest.get('count')}/10s")
                    print("   >> Sending DDoS Alert")
                    send_line_alert(msg)
                    return current_time
                    
        return last_alert_time

    except Exception as e:
        print(f"[DDoS] Error: {e}")
        return last_alert_time