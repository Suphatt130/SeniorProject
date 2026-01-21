import requests
import json
import socket
import datetime 
import config
from alerting.alert_func import send_line_alert,send_email_alert
from resources.splunk_rules import QUERY_LICENSE
from database.db_manager import save_log

# Global variable to track the last alert date
LAST_ALERT_DATE = None

def run_license_check():
    global LAST_ALERT_DATE
    
    # 1. Get Hostname & IP
    hostname = socket.gethostname()
    try:
        ip_addr = socket.gethostbyname(hostname)
    except:
        ip_addr = "Unknown IP"

    try:
        # Request to Splunk
        response = requests.post(
            f"{config.SPLUNK_BASE_URL}/services/search/jobs/export",
            data={"search": QUERY_LICENSE, "output_mode": "json"},
            verify=False
        )
        
        if response.text:
            result_text = response.text.strip()
            if not result_text: return

            try:
                # Parse Splunk JSON
                data = json.loads(result_text.split('\n')[0])
                
                # Extract percentage
                if "result" in data:
                    pct = float(data["result"].get("pctused", 0))
                else:
                    pct = float(data.get("pctused", 0))
                
                # Calculate MB Usage (Based on 500MB Limit)
                used_mb = int(pct * 5)
                
                print(f"[License] Usage since: {pct}% ({used_mb}/500 MB)")
                
                # 3. Alert Logic (Once Per Day)
                if pct >= 80.0:
                    today = datetime.date.today()
                    
                    # Check if we already alerted today
                    if LAST_ALERT_DATE != today:
                        msg = (f"⚠️ [CRITICAL] Splunk License Alert\nHost: {hostname} ({ip_addr})\nUsage (Since Midnight): {pct}%\nData Volume: {used_mb}/500 MB")
                        send_email_alert("License Alert!",msg)
                        
                        # --- SAVE TO DATABASE ---
                        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        
                        dummy_event = {
                            '_time': timestamp_now,
                            'Computer': hostname,
                            'User': 'Splunk System'
                        }
                        
                        save_log(
                            attack_type="License Alert",
                            event=dummy_event,
                            alert_sent=True,
                            details_str=f"Usage: {pct}% ({used_mb}MB)",
                            source_app="Splunk Enterprise",
                            technique_id="Quota Exceeded"
                        )

                        # Update the tracker
                        LAST_ALERT_DATE = today
                        print(f"   >> License Alert Sent for {today}")
                    else:
                        print(f"   [SKIP] Threshold exceeded, but alert already sent today ({today}).")
                        
            except Exception as e:
                # Ignore metadata lines
                pass

    except Exception as e:
        print(f"[License] Error: {e}")