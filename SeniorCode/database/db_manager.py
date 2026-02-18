import sqlite3
import config
from datetime import datetime

def get_db_connection():
    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        # 1. PHISHING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_phishing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,      -- Time
                computer TEXT,       -- Computer
                user TEXT,           -- User
                parent_app TEXT,     -- Parent_App
                browser_name TEXT,   -- Browser_Name
                clicked_link TEXT,   -- Clicked_Link
                technique_id TEXT,   -- Technique_ID
                severity TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 2. DOS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_dos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                host TEXT,
                dest_port TEXT,
                tcp_flags TEXT,
                count INTEGER,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 3. CRYPTOJACKING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_crypto (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                alert_sent BOOLEAN
            )
        ''')

        # 4. BRUTE FORCE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_bruteforce (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_time TEXT,
                last_time TEXT,
                src_ip TEXT,
                user TEXT,
                dest TEXT,
                count INTEGER,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN
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

        if attack_type == "Phishing":
            cursor.execute('''
                INSERT INTO logs_phishing (
                    timestamp, computer, user, parent_app, 
                    browser_name, clicked_link, technique_id, 
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('_time', timestamp),
                event.get('Computer', 'Unknown'),
                event.get('User', 'Unknown'),
                event.get('Parent_App', 'Unknown'),
                event.get('Browser_Name', 'Unknown'),
                event.get('Clicked_Link', 'N/A'),
                event.get('Technique_ID', 'T1027'),
                severity,
                alert_sent
            ))

        elif attack_type == "DoS":
            cursor.execute('''
                INSERT INTO logs_dos (
                    timestamp, src_ip, dest_ip, host, 
                    dest_port, tcp_flags, count, technique_id,
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('_time', timestamp),
                event.get('src_ip', 'Unknown'),
                event.get('dest_ip', 'Unknown'),
                event.get('host', 'Unknown'),
                event.get('dest_port', 'Unknown'),
                event.get('tcp_flags', 'S'),
                event.get('count', 0),
                "T1498.001",
                severity,
                alert_sent
            ))

        elif attack_type == "Cryptojacking":
            cursor.execute('''
                INSERT INTO logs_crypto (
                    timestamp, image_loaded, dest, md5, sha1, 
                    sha256, imphash, process_path, signature, 
                    signature_id, user_id, vendor_product, 
                    first_time, last_time, technique_id,
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
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
                    first_time, last_time, src_ip, user, 
                    dest, count, technique_id,
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
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
    except Exception as e:
        print(f"[DB] Save Error ({attack_type}): {e}")