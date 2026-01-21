import time
import requests
import json
import config
from database.db_manager import save_log
from resources.splunk_rules import QUERY_DDOS
from alerting.alert_func import send_line_alert, send_email_alert

def run_ddos_check(last_alert_time):
    payload = {
        "search": QUERY_DDOS,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "-30s", "latest_time": "now"
    }
    
    try:
        response = requests.post(config.SPLUNK_URL, data=payload, verify=False)
        if response.status_code == 200:
            events = []
            for line in response.text.strip().split("\n"):
                if line:
                    try:
                        d = json.loads(line)
                        if "result" in d:
                            events.append(d["result"])
                    except: continue

            if events:
                print(f"[DDoS] High Traffic Detected: {len(events)} sources.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                for event in events:
                    target = event.get('DestinationIp', 'N/A')
                    count = event.get('count', '0')
                    # Save to DB (details column)
                    save_log("DDoS", event, ready_to_alert, f"Target: {target} | Count: {count}")

                if ready_to_alert:
                    latest = events[0]
                    msg = (f"🚨 **DDoS/Flood Alert!**\nHost: {latest.get('Computer')}\nTraffic Count: {latest.get('count')} connections in 30s")
                    print("   >> Sending DDoS Alert")
                    send_email_alert("DDoS/Flood Alert",msg)
                    return current_time
                    
        return last_alert_time
    except Exception as e:
        print(f"[DDoS] Error: {e}")
        return last_alert_time