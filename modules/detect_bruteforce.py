import time
import requests
import json
import config
from database.db_manager import save_log
from resources.splunk_rules import QUERY_BRUTEFORCE
from alerting.alert_func import send_line_alert

def run_bruteforce_check(last_alert_time):
    
    payload = {
        "search": QUERY_BRUTEFORCE,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "-30s", "latest_time": "now"
    }
    
    try:
        # Request to Splunk
        response = requests.post(config.SPLUNK_URL, data=payload, verify=False)
        
        if response.status_code == 200:
            events = []
            for line in response.text.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        # Strict Check for valid results
                        if "result" in data:
                            events.append(data["result"])
                    except: continue

            if events:
                print(f"[BruteForce] Detected {len(events)} targets under attack.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                for event in events:
                    user = event.get('User', 'Unknown')
                    ip = event.get('IpAddress', '-')
                    count = event.get('count', 0)
                    
                    details = f"User: {user} | Source IP: {ip} | Failures: {count}"
                    
                    # Save to DB
                    save_log(
                        attack_type="Brute Force", 
                        event=event, 
                        alert_sent=ready_to_alert, 
                        details_str=details,
                        source_app="Windows Logon", # Static value for this type
                        browser=None,
                        technique_id="T1110" # MITRE ID for Brute Force
                    )
                
                if ready_to_alert:
                    latest = events[0]
                    msg = (
                        f"🚨 **Brute Force Alert!**\n"
                        f"💻 Host: {latest.get('Computer')}\n"
                        f"👤 Target User: {latest.get('User')}\n"
                        f"🛑 Source IP: {latest.get('IpAddress')}\n"
                        f"🔢 Failures: {latest.get('count')} (in last 30s)\n"
                        f"🛠 Technique: T1110"
                    )
                    print("   >> Sending Brute Force Alert")
                    send_line_alert(msg)
                    return current_time
                    
        return last_alert_time

    except Exception as e:
        print(f"[BruteForce] Error: {e}")
        return last_alert_time