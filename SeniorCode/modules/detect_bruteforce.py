import time
import requests
import json
import config
from database.db_manager import save_log
from resources.splunk_rules import QUERY_BRUTEFORCE
from alerting.alert_func import send_line_alert, send_email_alert

def run_bruteforce_check(last_alert_time):
    
    payload = {
        "search": QUERY_BRUTEFORCE,
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
                        data = json.loads(line)
                        if "result" in data:
                            events.append(data["result"])
                    except: continue

            if events:
                print(f"[BruteForce] Detected {len(events)} MySQL attacks.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                for event in events:
                    user = event.get('target_user', 'Unknown')
                    ip = event.get('attacker_ip', 'Unknown')
                    count = event.get('count', 0)
                    
                    details = f"User: {user} | IP: {ip} | Fails: {count}"
                    
                    save_log(
                        attack_type="Brute Force", 
                        event=event, 
                        alert_sent=ready_to_alert, 
                        details_str=details,
                        source_app="MySQL Server",
                        browser=None,
                        technique_id="T1110" 
                    )
                
                if ready_to_alert:
                    latest = events[0]
                    # Format the Alert for Line/Console as well
                    user = latest.get('target_user', 'Unknown')
                    ip = latest.get('attacker_ip', 'Unknown')
                    count = latest.get('count', 0)
                    
                    msg = (f"🚨 **MySQL Brute Force Alert!**\nWARNING: Brute Force Detected! IP {ip} tried to guess password for user {user} {count} times.")

                    print("   >> Sending Brute Force Alert")
                    send_email_alert("Brute Force Alert!",msg)
                    return current_time
                    
        return last_alert_time

    except Exception as e:
        print(f"[BruteForce] Error: {e}")
        return last_alert_time