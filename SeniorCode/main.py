import time
import threading
from database.db_manager import init_db
from modules.detect_phishing import run_phishing_check
from modules.detect_ddos import run_ddos_check
from modules.detect_crypto import run_crypto_check
from modules.check_license import run_license_check
from modules.detect_bruteforce import run_bruteforce_check
import config

def worker_phishing():
    last_alert = 0
    while True:
        last_alert = run_phishing_check(last_alert)
        time.sleep(config.CHECK_INTERVAL)

def worker_ddos():
    last_alert = 0
    while True:
        last_alert = run_ddos_check(last_alert)
        time.sleep(config.CHECK_INTERVAL)

def worker_crypto():
    last_alert = 0
    while True:
        last_alert = run_crypto_check(last_alert)
        time.sleep(config.CHECK_INTERVAL)

def worker_license():
    while True:
        run_license_check()
        time.sleep(config.LICENSE_CHECK_INTERVAL)

def worker_bruteforce():
    last_alert = 0
    while True:
        last_alert = run_bruteforce_check(last_alert)
        time.sleep(config.CHECK_INTERVAL)

if __name__ == "__main__":
    print("=== SECURITY MONITOR STARTED ===")
    print("   [+] Database Initialized")
    print("   [+] Starting 5 Detection Threads...")
    
    init_db()

    # Create Threads
    t1 = threading.Thread(target=worker_phishing, daemon=True)
    t2 = threading.Thread(target=worker_ddos, daemon=True)
    t3 = threading.Thread(target=worker_crypto, daemon=True)
    t4 = threading.Thread(target=worker_license, daemon=True)
    t5 = threading.Thread(target=worker_bruteforce, daemon=True)

    # Start Threads
    t1.start()
    #t2.start()
    t3.start()
    t4.start()
    t5.start()

    # Keep Main Thread Alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping all monitors.")