# config.py
import os
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SPLUNK SETTINGS
SPLUNK_URL = "https://127.0.0.1:8089/services/search/jobs/export"
SPLUNK_BASE_URL = "https://127.0.0.1:8089" 
SPLUNK_AUTH = None 

# VIRUSTOTAL SETTINGS
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# DATABASE
DB_NAME = "security_events.db"

# THRESHOLDS & TIMERS
CHECK_INTERVAL = 30             
LICENSE_CHECK_INTERVAL = 60     
ALERT_COOLDOWN = 0
LICENSE_LIMIT_MB = 500