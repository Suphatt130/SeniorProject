import time
import requests
import json
import config
from database.db_manager import save_log
from resources.splunk_rules import QUERY_CRYPTO
from alerting.alert_func import send_line_alert,send_email_alert

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
                        data = json.loads(line)
                        if "result" in data:
                            events.append(data["result"])
                    except: continue

            if events:
                print(f"[Crypto] Malicious Driver Detected: {len(events)} events.")
                current_time = time.time()
                ready_to_alert = (current_time - last_alert_time) >= config.ALERT_COOLDOWN
                
                for event in events:
                    image = event.get('ImageLoaded', 'Unknown')
                    md5 = event.get('MD5', 'N/A')
                    sha1 = event.get('SHA1', 'N/A')
                    sha256 = event.get('SHA256', 'N/A')
                    imphash = event.get('IMPHASH', 'N/A')
                    signature = event.get('Signature', 'Unsigned')
                    event['SHA1'] = sha1
                    event['SHA256'] = sha256
                    event['IMPHASH'] = imphash

                    details = f"Hash: {md5} | Sign: {signature}"
                    
                    save_log(
                        attack_type="Cryptojacking", 
                        event=event, 
                        alert_sent=ready_to_alert, 
                        details_str=details,
                        source_app=image,
                        browser=None
                    )

                if ready_to_alert:
                    latest = events[0]
                    msg = (
                        f"🚨 **Cryptojacking Driver Alert!**\n💻 Host: {latest.get('Computer')}\n📂 Driver: {latest.get('ImageLoaded')}\n🔑 SHA1: {latest.get('SHA1')}\n📝 Signature: {latest.get('Signature')}")
                    print("   >> Sending Crypto Alert")
                    send_email_alert(msg)
                    return current_time
                    
        return last_alert_time
    except Exception as e:
        print(f"[Crypto] Error: {e}")
        return last_alert_time