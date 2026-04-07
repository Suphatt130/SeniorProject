import sqlite3
import config
from datetime import datetime
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string

def get_db_connection():
    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;") # WAL (Write-Ahead Log) is a feature to make sure that all logs are write and read simutaniously with out dropping anything
    return conn

def generate_secure_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for i in range(15))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd) 
            and any(c in "!@#$%^&*" for c in pwd)):
            return pwd
        
def init_db():
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        # 1. PHISHING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_phishing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                attack_type TEXT,
                timestamp TEXT,
                computer TEXT,
                user TEXT,
                parent_app TEXT,
                browser_name TEXT,
                clicked_link TEXT,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN,
                status TEXT DEFAULT 'Awaiting Action',
                verdict TEXT DEFAULT 'None',
                assignee TEXT DEFAULT 'None',
                comment TEXT DEFAULT ''
            )
        ''')

        # 2. DOS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_dos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                attack_type TEXT,
                first_time TEXT,
                last_time TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                size INTEGER,
                count INTEGER,
                action TEXT,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN,
                status TEXT DEFAULT 'Awaiting Action',
                verdict TEXT DEFAULT 'None',
                assignee TEXT DEFAULT 'Unassigned',
                comment TEXT DEFAULT ''
            )
        ''')

        # 3. CRYPTOJACKING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_crypto (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                attack_type TEXT,
                timestamp TEXT,
                image_loaded TEXT,
                dest TEXT,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                imphash TEXT,
                process_path TEXT,
                signature TEXT,
                signature_id TEXT,
                user_id TEXT,
                vendor_product TEXT,
                first_time TEXT,
                last_time TEXT,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN,
                status TEXT DEFAULT 'Awaiting Action',
                verdict TEXT DEFAULT 'None',
                assignee TEXT DEFAULT 'None',
                comment TEXT DEFAULT ''
            )
        ''')

        # 4. BRUTE FORCE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_bruteforce (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                attack_type TEXT,
                first_time TEXT,
                last_time TEXT,
                src_ip TEXT,
                user TEXT,
                dest TEXT,
                count INTEGER,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN,
                status TEXT DEFAULT 'Awaiting Action',
                verdict TEXT DEFAULT 'None',
                assignee TEXT DEFAULT 'None',
                comment TEXT DEFAULT ''
            )
        ''')

        # 5. LICENSE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_license (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                pct_used REAL,
                usage_mb INTEGER,
                severity TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 6. USERS TABLE (For Login and Assignees)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT
            )
        ''')

        admin_check = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not admin_check:
            admin_pwd = generate_secure_password()
            admin_hash = generate_password_hash(admin_pwd)
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                        ("admin", admin_hash, "SOC Admin"))
            print("\n" + "="*50)
            print("🚨 INITIAL ADMIN ACCOUNT CREATED 🚨")
            print("Username: admin")
            print(f"Password: {admin_pwd}")
            print("SAVE THIS PASSWORD! IT WILL ONLY BE SHOWN ONCE!")
            print("="*50 + "\n")

        conn.commit()
        conn.close()
        print("[+] Database Initialized with New Schema")
    except Exception as e:
        print(f"[DB] Init Error: {e}")

def save_log(attack_type, event, alert_sent, details_str=None, **kwargs):
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timestamp = event.get('Time') or event.get('_time') or event.get('firstTime') or now_str
        severity = kwargs.get('severity', 'Unknown')
        risk = kwargs.get('risk_score', 0)

        if attack_type == "Phishing":
            cursor.execute('''
                INSERT INTO logs_phishing (
                    rule_name, attack_type, timestamp, computer, user, parent_app, 
                    browser_name, clicked_link, technique_id, 
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                "Windows Phishing Executes URL Link",
                "Phishing",
                event.get('_time', timestamp),
                event.get('Computer', 'Unknown'),
                event.get('User', 'Unknown'),
                event.get('Parent_App', 'Unknown'),
                event.get('Browser_Name', 'Unknown'),
                event.get('Clicked_Link', 'N/A'),
                event.get('Technique_ID', 'T1566.001'),
                severity,
                alert_sent
            ))

        elif attack_type == "DoS":
            cursor.execute('''
                INSERT INTO logs_dos (
                    rule_name, attack_type, first_time, last_time, src_ip, dest_ip, 
                    protocol, size, count, action, technique_id, risk_score,
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                "Detect Large ICMP Traffic",
                "DoS",
                event.get('firstTime', timestamp),
                event.get('lastTime', timestamp),
                event.get('src_ip', 'Unknown'),
                event.get('dest_ip', 'Unknown'),
                event.get('protocol', 'ICMP'),
                event.get('size', 0),
                event.get('count', 0),
                event.get('action', 'Unknown'),
                "T1095",
                severity,
                alert_sent
            ))

        elif attack_type == "Cryptojacking":
            cursor.execute('''
                INSERT INTO logs_crypto (
                    rule_name, attack_type, timestamp, image_loaded, dest, md5, sha1, 
                    sha256, imphash, process_path, signature, 
                    signature_id, user_id, vendor_product, 
                    first_time, last_time, technique_id,
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                "XMRIG Driver Loaded",
                "Cryptojacking",
                event.get('_time', timestamp),
                event.get('ImageLoaded', 'Unknown'),
                event.get('dest', 'Unknown'),
                event.get('MD5', 'N/A'),
                event.get('SHA1', 'N/A'),
                event.get('SHA256', 'N/A'),
                event.get('IMPHASH', 'N/A'),
                event.get('process_path', 'Unknown'),
                event.get('signature', 'Unknown'),
                event.get('signature_id', 'Unknown'),
                event.get('user_id', 'Unknown'),
                event.get('vendor_product', 'Sysmon'),
                event.get('firstTime', timestamp),
                event.get('lastTime', timestamp),
                "T1543.003",
                severity,
                alert_sent
            ))

        elif attack_type == "Brute Force":
            cursor.execute('''
                INSERT INTO logs_bruteforce (
                    rule_name, attack_type, first_time, last_time, src_ip, user, 
                    dest, count, technique_id,
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                "MySQL Brute Force",
                "Brute Force",
                event.get('firstTime', timestamp),
                event.get('lastTime', timestamp),
                event.get('src_ip', 'Unknown'),
                event.get('user', 'Unknown'),
                event.get('dest', 'Unknown'),
                event.get('count', 0),
                "T1110",
                severity,
                alert_sent
            ))

        elif attack_type == "License Alert" or attack_type == "License Warning":
            cursor.execute('''
                INSERT INTO logs_license (
                    timestamp, pct_used, usage_mb, 
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                timestamp,
                kwargs.get('usage_percent', 0.0),
                kwargs.get('usage_mb', 0),
                severity,
                alert_sent
            ))

        conn.commit()
        conn.close()
        
        try:
            requests.post("http://127.0.0.1:5000/internal/trigger_update", timeout=1)
        except Exception:
            pass

    except Exception as e:
        print(f"[DB] Save Error ({attack_type}): {e}")