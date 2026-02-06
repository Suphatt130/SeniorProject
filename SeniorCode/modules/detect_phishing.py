import time
import requests
import json
import os
import base64
import config
from database.db_manager import save_log
from alerting.alert_func import send_line_alert, send_email_alert

def load_rules():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(current_dir, '../resources/splunk_rules.json')
    try:
        with open(json_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load rules: {e}")
        return {}

RULES_CONFIG = load_rules()
QUERY_PHISHING = RULES_CONFIG.get('phishing', {}).get('query', '')
SEVERITY_SCORE = RULES_CONFIG.get('phishing', {}).get('severity', 5)

def check_url_reputation(url):
    """
    Checks URL against VirusTotal API.
    Returns: True if malicious, False if safe/unknown/error.
    """
    if "127.0.0.1" in url or "localhost" in url: return False

    if not config.VIRUSTOTAL_API_KEY or "YOUR_" in config.VIRUSTOTAL_API_KEY:
        print("[VT] API Key not set. Skipping check.")
        return False

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"{config.VIRUSTOTAL_URL}/{url_id}"
        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                print(f"[VT] ⚠️ MALICIOUS: {url}")
                return True
    except: pass
    return False

def run_phishing_check(last_alert_time):
    payload = {
        "search": QUERY_PHISHING,
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
                        if "result" in data: events.append(data["result"])
                    except: continue

            if events:
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                malicious_found = False

                for event in events:
                    link = event.get('Clicked_Link', 'N/A')
                    
                    if check_url_reputation(link):
                        malicious_found = True
                        severity_label = config.get_severity_label(SEVERITY_SCORE)

                        save_log(
                            attack_type="Phishing", 
                            event=event, 
                            alert_sent=ready_to_alert, 
                            severity=severity_label
                        )
                        
                        if ready_to_alert:
                            latest = event
                            msg = (
                                f"🚨 **Phishing Alert!** (Confirmed Malicious)\n💻 Host: {latest.get('Computer')}\n👤 User: {latest.get('User')}\n🔗 Link: {link}\n🛠 App: {latest.get('Parent_App')}")
                            print("   >> Sending Phishing Alert")
                            send_email_alert("Phishing Alert!", msg)

                if malicious_found and ready_to_alert: return current_time
        return last_alert_time
    except Exception as e:
        print(f"[Phishing] Error: {e}")
        return last_alert_time