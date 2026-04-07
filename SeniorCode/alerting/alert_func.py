import os
import requests
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load the .env file
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
env_path = os.path.join(parent_dir, '.env')
load_dotenv(env_path)

# Get the variables
LINE_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")

#################################

def send_line_alert(message_text):
    now_ms = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    if LINE_TOKEN:
        print(f"DEBUG: Loaded LINE Token starts with: {LINE_TOKEN[:5]}...")
    else:
        print("DEBUG: LINE Token is EMPTY or NOT FOUND in .env")
        return
    
    """Sends a broadcast message using LINE Messaging API"""
    url = "https://api.line.me/v2/bot/message/broadcast"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LINE_TOKEN}"
    }
    
    payload = {
        "messages": [
            {
                "type": "text",
                "text": message_text
            }
        ]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            print(f"[{now_ms}] >> LINE Messaging API Alert Sent Successfully.")
        else:
            print(f"[{now_ms}] >> Failed to send LINE Alert: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[{now_ms}] >> Error sending LINE: {e}")

def send_email_alert(subject, body):
    now_ms = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    """Sends an email alert"""
    if not RECEIVER_EMAIL:
        print(f"[{now_ms}] >> [Email] Aborted: Receiver email is missing or None.")
        return

    if isinstance(RECEIVER_EMAIL, list):
        to_header = ", ".join(RECEIVER_EMAIL)
        to_addrs = RECEIVER_EMAIL
    else:
        to_header = RECEIVER_EMAIL
        to_addrs = [RECEIVER_EMAIL]

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_header
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_addrs, msg.as_string())
        server.quit()
        print(f"[{now_ms}] >> Email Alert Sent Successfully.")
    except Exception as e:
        print(f"[{now_ms}] >> Error sending Email: {e}")