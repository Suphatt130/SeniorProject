# config.py
#import os
import urllib3
from dotenv import load_dotenv

# Load .env from the root directory
load_dotenv()

# Disable SSL Warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SPLUNK SETTINGS
SPLUNK_URL = "https://127.0.0.1:8089/services/search/jobs/export"
SPLUNK_BASE_URL = "https://127.0.0.1:8089" # For License check
SPLUNK_AUTH = None 

# VIRUSTOTAL SETTINGS
VIRUSTOTAL_API_KEY = "7d96c0dabd2a535c44feca13c9ad28690377db5f313cdd32ac9018dbd02270a7"

# DATABASE
DB_NAME = "security_events.db"

# THRESHOLDS & TIMERS
CHECK_INTERVAL = 30             # Check for attacks every 30s
LICENSE_CHECK_INTERVAL = 60     # Check license every 60s
ALERT_COOLDOWN = 1800           # 30 Minutes between alerts per type
LICENSE_LIMIT_MB = 500          # 500 MB Free License