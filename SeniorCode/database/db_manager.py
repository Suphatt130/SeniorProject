import sqlite3
import config

def init_db():
    """Initializes 5 separate tables for different attack types."""
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        # 1. PHISHING TABLE
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

        # 2. DDOS TABLE
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

        # 3. CRYPTOJACKING TABLE
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

        # 4. BRUTE FORCE TABLE
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

        # 5. LICENSE TABLE
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_license (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                computer TEXT,
                usage_percent DECIMAL(5, 2),
                usage_mb INTEGER,
                alert_sent BOOLEAN
            )
        ''')

        conn.commit()
        conn.close()
        print("[DB] Database initialized with 5 separate tables.")
    except Exception as e:
        print(f"[DB] Init Error: {e}")


def save_log(attack_type, event, alert_sent, details_str=None, **kwargs):
    """
    Routes the log data to the specific table based on attack_type.
    Extracts data directly from the 'event' dictionary or kwargs.
    """
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        timestamp = event.get('_time', 'N/A')
        computer = event.get('Computer', 'Unknown')
        user = event.get('User', 'Unknown')

        # --- ROUTING LOGIC ---
        
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
            # DDoS events pass 'DestinationIp' and 'count'
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
                kwargs.get('source_app', 'Unknown'), # We used source_app to pass ImageLoaded
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
            cursor.execute('''
                INSERT INTO logs_license (timestamp, computer, usage_percent, usage_mb, alert_sent)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                timestamp, computer,
                0.0, # Placeholder, strictly we'd parse this from details_str if needed
                0,   # Placeholder
                alert_sent
            ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Save Error ({attack_type}): {e}")