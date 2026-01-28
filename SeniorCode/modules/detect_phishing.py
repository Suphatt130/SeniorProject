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
SEVERITY_PHISHING = RULES_CONFIG.get('phishing', {}).get('severity', 'Unknown')

def check_url_reputation(url):
    """
    Checks URL against VirusTotal API.
    Returns: True if malicious, False if safe/unknown/error.
    """
    # 1. Skip Localhost/Private IPs immediately
    if "127.0.0.1" in url or "localhost" in url:
        return False

    if not config.VT_API_KEY or "YOUR_" in config.VT_API_KEY:
        print("[VT] API Key not set. Skipping check.")
        return False

    try:
        # 2. Encode URL to Base64 (Required by VirusTotal API)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # 3. Send Request
        api_url = f"{config.VT_URL}/{url_id}"
        headers = {"x-apikey": config.VT_API_KEY}
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # 4. Check Stats
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            
            if malicious_count > 0:
                print(f"[VT] ⚠️ MALICIOUS LINK CONFIRMED: {url} (Score: {malicious_count})")
                return True
            else:
                return False
        elif response.status_code == 404:
            return False
        elif response.status_code == 429:
            print("[VT] ⚠️ Quota Exceeded!")
            return False
            
    except Exception as e:
        print(f"[VT] Error checking URL: {e}")
        return False

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
                        if "result" in data:
                            events.append(data["result"])
                    except: continue

            if events:
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                malicious_event_found = False

                for event in events:
                    if 'Time' in event:
                        event['_time'] = event['Time']
                    
                    link = event.get('Clicked_Link', 'N/A')
                    is_malicious = check_url_reputation(link)
                    
                    if is_malicious:
                        malicious_event_found = True
                        
                        browser = event.get('Browser_Name', 'Unknown')
                        parent = event.get('Parent_App', 'Unknown')
                        tech_id = event.get('Technique_ID', 'T1027')
                        
                        event['Client_IP'] = "N/A"

                        details = f"Link: {link}"
                        
                        save_log(
                            attack_type="Phishing", 
                            event=event, 
                            alert_sent=ready_to_alert, 
                            details_str=details,
                            browser=browser,
                            source_app=parent,
                            technique_id=tech_id,
                            severity=SEVERITY_PHISHING
                        )
                        
                        if ready_to_alert:
                            latest = event
                            msg = (
                                f"🚨 **Phishing Alert!** (Confirmed Malicious)\n💻 Host: {latest.get('Computer')}\n👤 User: {latest.get('User')}\n🔗 Link: {link}\n🛠 App: {latest.get('Parent_App')}")
                            print("   >> Sending Phishing Alert")
                            send_email_alert("Phishing Alert!", msg)

                if malicious_event_found and ready_to_alert:
                    return current_time
                    
        return last_alert_time

    except Exception as e:
        print(f"[Phishing] Error: {e}")
        return last_alert_time