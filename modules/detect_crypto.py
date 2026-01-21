import time
import requests
import json
import config
from database.db_manager import save_log
from resources.splunk_rules import QUERY_CRYPTO
from alerting.alert_func import send_line_alert, send_email_alert

def run_crypto_check(last_alert_time):
    payload = {
        "search": QUERY_CRYPTO,
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
                print(f"[Crypto] Miner Detected.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                for event in events:
                    cmd = event.get('CommandLine', 'N/A')
                    # Save to DB
                    save_log("Cryptojacking", event, ready_to_alert, f"Cmd: {cmd}")

                if ready_to_alert:
                    latest = events[0]
                    msg = (f"🚨 **Cryptojacking Alert!**\nHost: {latest.get('Computer')}\nProcess: {latest.get('Process_Name')}")
                    print("   >> Sending Crypto Alert")
                    send_email_alert("Cryptojacking Alert!",msg)
                    return current_time
                    
        return last_alert_time
    except Exception as e:
        print(f"[Crypto] Error: {e}")
        return last_alert_time