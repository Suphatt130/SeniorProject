import requests
import json
import socket
import datetime 
import config
from alerting.alert_func import send_line_alert, send_email_alert
from resources.splunk_rules import QUERY_LICENSE
from database.db_manager import save_log

# Global variable to track the last alert date
LAST_ALERT_DATE = None

def run_license_check():
    global LAST_ALERT_DATE
    
    hostname = socket.gethostname()
    
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
                
                if pct >= 80.0:
                    today = datetime.date.today()
                    
                    if LAST_ALERT_DATE != today:
                        msg = (
                            f"⚠️ [CRITICAL] Splunk License Alert\n"
                            f"Host: {hostname}\n"
                            f"Usage: {pct}%\n"
                            f"Volume: {used_mb}/500 MB"
                        )
                        send_email_alert("License Alert", msg)
                        
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
                            details_str=f"Usage: {pct}%",
                            usage_percent=pct,
                            usage_mb=used_mb
                        )
                        # --------------------------------

                        LAST_ALERT_DATE = today
                        print(f"   >> License Alert Sent & Saved.")
                        
            except Exception as e:
                pass

    except Exception as e:
        print(f"[License] Error: {e}")