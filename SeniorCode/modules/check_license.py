import requests
import json
import socket
import datetime
import config
from alerting.alert_func import send_line_alert, send_email_alert
from database.db_manager import save_log

# API Endpoint
LICENSE_API_ENDPOINT = f"{config.SPLUNK_BASE_URL}/services/licenser/pools"
STATUS_FILE = config.LICENSE_STATUS_FILE

# Settings
SEVERITY_SCORE = 2
LICENSE_QUOTA_MB = 500
LAST_CHECK_DATE = None
TRIGGERED_LEVELS = set()

def run_license_check():
    global LAST_CHECK_DATE, TRIGGERED_LEVELS
    
    hostname = socket.gethostname()
    
    # Daily Reset
    today = datetime.date.today()
    if LAST_CHECK_DATE != today:
        LAST_CHECK_DATE = today
        TRIGGERED_LEVELS = set() 
        print(f"[License] New day detected ({today}). Resetting alert thresholds.")

    try:
        response = requests.get(
            LICENSE_API_ENDPOINT,
            params={"output_mode": "json"},
            verify=False
        )
        
        if response.status_code == 200:
            data = json.loads(response.text)
            
            used_bytes = 0
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                used_bytes += int(content.get("used_bytes", 0))

            used_mb = round(used_bytes / 1024 / 1024, 2)
            pct = round((used_mb / LICENSE_QUOTA_MB) * 100, 2)

            try:
                with open(STATUS_FILE, "w") as f:
                    json.dump({"mb": used_mb, "pct": pct}, f)
            except Exception as e:
                print(f"[License] Failed to write status file: {e}")
            
            print(f"[License] Live Update: {pct}% ({used_mb} MB)")

            alert_thresholds = [60, 70, 80]
            alert_triggered = False 

            for threshold in alert_thresholds:
                if pct >= threshold and threshold not in TRIGGERED_LEVELS:
                    msg = (f"⚠️ [LICENSE WARNING] Threshold Reached\nHost: {hostname}\nCurrent Usage: {pct}% (>{threshold}%)\nVolume: {used_mb}/500 MB")
                    send_email_alert("LICENSE WARNING!", msg)
                    TRIGGERED_LEVELS.add(threshold)
                    alert_triggered = True

            if alert_triggered:
                timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                dummy_event = {'_time': timestamp_now, 'Computer': hostname, 'User': 'Splunk System'}
                severity_label = config.get_severity_label(SEVERITY_SCORE)

                save_log(
                    attack_type="License Alert", 
                    event=dummy_event,
                    alert_sent=True,
                    details_str=f"Usage hit {pct}%", 
                    usage_percent=pct,
                    usage_mb=used_mb,              
                    severity=severity_label
                )

        else:
            print(f"[License] API Error {response.status_code}")

    except Exception as e:
        print(f"[License] Connection Error: {e}")