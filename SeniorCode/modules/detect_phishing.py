import time
import requests
import json
import base64
import config
from database.db_manager import save_log
from resources.splunk_rules import QUERY_PHISHING
from alerting.alert_func import send_line_alert, send_email_alert

def check_url_reputation(url):
    """
    Checks URL against VirusTotal API.
    Returns: True if malicious, False if safe/unknown/error.
    """
    if not config.VIRUSTOTAL_API_KEY or "YOUR_" in config.VIRUSTOTAL_API_KEY:
        print("[VT] API Key not set. Skipping check (Assuming Safe).")
        return False

    try:
        # 1. Encode URL to Base64 (Required by VirusTotal API)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # 2. Send Request
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # 3. Check Stats
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            
            if malicious_count > 0:
                print(f"[VT] ⚠️ MALICIOUS LINK CONFIRMED: {url} (Score: {malicious_count})")
                return True
            else:
                # print(f"[VT] Link is clean: {url}")
                return False
        elif response.status_code == 404:
            # URL not found in VT database (New URL) - Treat as unknown/safe for now
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
        "earliest_time": "-30s", "latest_time": "now"
    }
    
    try:
        response = requests.post(config.SPLUNK_URL, data=payload, verify=False)
        
        if response.status_code == 200:
            events = []
            
            # Strict JSON Parsing
            for line in response.text.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        if "result" in data:
                            result_data = data["result"]
                            if result_data.get('Clicked_Link'):
                                events.append(result_data)
                    except: continue

            if events:
                # print(f"[Phishing] Splunk found {len(events)} clicks. Verifying with VirusTotal...")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                confirmed_threats = []

                for event in events:
                    link = event.get('Clicked_Link', 'N/A')
                    
                    # --- STEP 1: VIRUSTOTAL CHECK ---
                    is_malicious = check_url_reputation(link)
                    
                    # --- STEP 2: STORE & ALERT ONLY IF MALICIOUS ---
                    if is_malicious:
                        technique = event.get('Technique_ID', 'N/A')
                        parent_app = event.get('Parent_App', 'Unknown')
                        browser_name = event.get('Browser_Name', 'Unknown')
                        
                        # Save to DB
                        save_log(
                            attack_type="Phishing", 
                            event=event, 
                            alert_sent=ready_to_alert, 
                            details_str=link,
                            source_app=parent_app,
                            browser=browser_name,
                            technique_id=technique
                        )
                        confirmed_threats.append(event)
                
                # --- STEP 3: SEND ALERT IF THREATS CONFIRMED ---
                if confirmed_threats and ready_to_alert:
                    latest = confirmed_threats[0]
                    msg = (f"🚨 **Malicious Phishing Link Detected!**\n✅ **Verified by VirusTotal**\n⏰ Time: {latest.get('_time')}\n💻 Host: {latest.get('Computer')}\n🌐 Browser: {latest.get('Browser_Name')}\n🔗 Link: {latest.get('Clicked_Link')}")
                    print("   >> Sending Confirmed Phishing Alert")
                    send_email_alert("Phishing Link Detected!",msg)
                    return current_time
                    
        return last_alert_time

    except Exception as e:
        print(f"[Phishing] Error: {e}")
        return last_alert_time