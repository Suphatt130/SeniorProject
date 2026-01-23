import requests
import json
import socket
import datetime 
import config
from alerting.alert_func import send_line_alert, send_email_alert
from resources.splunk_rules import QUERY_LICENSE
from database.db_manager import save_log

# Global variables to track state
LAST_CHECK_DATE = None
TRIGGERED_LEVELS = set() # Stores levels (e.g., {60, 70}) alerted today

def run_license_check():
    global LAST_CHECK_DATE, TRIGGERED_LEVELS
    
    hostname = socket.gethostname()
    
    today = datetime.date.today()
    if LAST_CHECK_DATE != today:
        LAST_CHECK_DATE = today
        TRIGGERED_LEVELS = set() # Clear the alerts for the new day
        print(f"[License] New day detected ({today}). Resetting alert thresholds.")

    try:
        response = requests.post(
            f"{config.SPLUNK_BASE_URL}/services/search/jobs/export",
            data={"search": QUERY_LICENSE, "output_mode": "json"},
            verify=False
        )
        
        if response.text:
            result_text = response.text.strip()
            if not result_text: return

            try:
                data = json.loads(result_text.split('\n')[0])
                
                if "result" in data:
                    pct = float(data["result"].get("pctused", 0))
                else:
                    pct = float(data.get("pctused", 0))
                
                used_mb = int(pct * 5)
                
                # print(f"[License] Usage: {pct}% ({used_mb}/500 MB)")
                
                # 2. Check 3 Specific Levels: 60, 70, 80
                alert_thresholds = [60, 70, 80]
                
                for threshold in alert_thresholds:
                    # If usage exceeds threshold AND we haven't alerted this level today
                    if pct >= threshold and threshold not in TRIGGERED_LEVELS:
                        
                        msg = (f"⚠️ [LICENSE WARNING] Threshold Reached\nHost: {hostname}\nCurrent Usage: {pct}% (>{threshold}%)\nVolume: {used_mb}/500 MB")
                        send_email_alert("LICENSE WARNING!",msg)
                        
                        # Save to Database
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
                            details_str=f"Usage hit {threshold}% threshold",
                            usage_percent=pct,
                            usage_mb=used_mb
                        )

                        # Mark this level as triggered for today
                        TRIGGERED_LEVELS.add(threshold)
                        print(f"   >> License Alert Sent for {threshold}% threshold.")

            except Exception as e:
                pass

    except Exception as e:
        print(f"[License] Error: {e}")