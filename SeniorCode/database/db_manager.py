import sqlite3
import config

def init_db():
    """Initializes 5 separate tables for different attack types."""
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        # 1. PHISHING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_phishing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                user TEXT,
                browser TEXT,
                source_app TEXT,
                link TEXT,
                technique_id TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 2. DDOS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_ddos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                target_ip TEXT,
                connection_count INTEGER,
                alert_sent BOOLEAN
            )
        ''')

        # 3. CRYPTOJACKING
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_crypto (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                driver_image TEXT,
                md5_hash TEXT,
                signature TEXT,
                technique_id TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 4. BRUTE FORCE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_bruteforce (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                target_user TEXT,
                source_ip TEXT,
                failure_count INTEGER,
                technique_id TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 5. LICENSE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_license (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                usage_percent REAL,
                usage_mb INTEGER,
                alert_sent BOOLEAN
            )
        ''')

        conn.commit()
        conn.close()
        # print("[DB] Database initialized.")
    except Exception as e:
        print(f"[DB] Init Error: {e}")


def save_log(attack_type, event, alert_sent, details_str=None, **kwargs):
    """
    Routes data to specific tables. 
    FIXED: Now correctly saves License Usage data.
    """
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        timestamp = event.get('_time', 'N/A')
        computer = event.get('Computer', 'Unknown')
        user = event.get('User', 'Unknown')

        if attack_type == "Phishing":
            cursor.execute('''
                INSERT INTO logs_phishing (timestamp, computer, user, browser, source_app, link, technique_id, alert_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, computer, user,
                kwargs.get('browser', 'Unknown'),
                kwargs.get('source_app', 'Unknown'),
                event.get('Clicked_Link', 'N/A'),
                kwargs.get('technique_id', 'N/A'),
                alert_sent
            ))

        elif attack_type == "DDoS":
            cursor.execute('''
                INSERT INTO logs_ddos (timestamp, computer, target_ip, connection_count, alert_sent)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                timestamp, computer,
                event.get('DestinationIp', 'Unknown'),
                event.get('count', 0),
                alert_sent
            ))

        elif attack_type == "Cryptojacking":
            cursor.execute('''
                INSERT INTO logs_crypto (timestamp, computer, driver_image, md5_hash, signature, technique_id, alert_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, computer,
                kwargs.get('source_app', 'Unknown'),
                event.get('MD5', 'N/A'),
                event.get('Signature', 'N/A'),
                kwargs.get('technique_id', 'T1068'),
                alert_sent
            ))

        elif attack_type == "Brute Force":
            cursor.execute('''
                INSERT INTO logs_bruteforce (timestamp, computer, target_user, source_ip, failure_count, technique_id, alert_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, computer,
                event.get('User', 'Unknown'),
                event.get('IpAddress', 'Unknown'),
                event.get('count', 0),
                "T1110",
                alert_sent
            ))

        elif attack_type == "License Alert":
            u_pct = kwargs.get('usage_percent', 0.0)
            u_mb = kwargs.get('usage_mb', 0)
            
            cursor.execute('''
                INSERT INTO logs_license (timestamp, computer, usage_percent, usage_mb, alert_sent)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                timestamp, computer, u_pct, u_mb, alert_sent
            ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Save Error ({attack_type}): {e}")