import sqlite3
import config

def init_db():
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
                client_ip TEXT,
                parent_app TEXT,
                browser_name TEXT,
                clicked_link TEXT,
                technique_id TEXT,
                severity TEXT,
                alert_sent BOOLEAN
            )
        ''')

        # 2. DDOS
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs_ddos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                computer TEXT,
                dest_port TEXT,
                tcp_flags TEXT,
                packet_count INTEGER,
                severity TEXT,
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
                sha1_hash TEXT,
                sha256_hash TEXT,
                imphash TEXT,
                signature TEXT,
                severity TEXT,
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
                severity TEXT,
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
                severity TEXT,
                alert_sent BOOLEAN
            )
        ''')

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Init Error: {e}")

def save_log(attack_type, event, alert_sent, details_str=None, **kwargs):
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()

        timestamp = event.get('Time') or event.get('firstTime') or event.get('_time', 'N/A')
        computer = event.get('Computer', 'Unknown')
        user = event.get('User', 'Unknown')
        severity = kwargs.get('severity', 'Unknown') 

        if attack_type == "Phishing":
            cursor.execute('''
                INSERT INTO logs_phishing (
                    timestamp, computer, user, 
                    client_ip, parent_app, browser_name, clicked_link, 
                    technique_id, severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, computer, user,
                event.get('Client_IP', 'N/A'),
                event.get('Parent_App', 'Unknown'),
                event.get('Browser_Name', 'Unknown'),
                event.get('Clicked_Link', 'N/A'),
                event.get('Technique_ID', 'N/A'),
                kwargs.get('severity', 'High'),
                alert_sent
            ))

        elif attack_type == "DDoS":
            cursor.execute('''
                INSERT INTO logs_ddos (
                    timestamp, src_ip, dest_ip, computer, 
                    dest_port, tcp_flags, packet_count, 
                    severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('_time', timestamp),
                event.get('src_ip', 'Unknown'),
                event.get('dest_ip', 'Unknown'),
                event.get('host', 'Unknown'),
                event.get('dest_port', 'Unknown'),
                event.get('tcp_flags', 'S'),
                event.get('count', 0),
                kwargs.get('severity', 'High'),
                alert_sent
            ))

        elif attack_type == "Cryptojacking":
            cursor.execute('''
                INSERT INTO logs_crypto (
                    timestamp, computer, driver_image, md5_hash, sha1_hash, 
                    sha256_hash, imphash, signature, severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('Time', timestamp),
                event.get('Computer', 'Unknown'),
                event.get('ImageLoaded', 'Unknown'),
                event.get('MD5', 'N/A'),
                event.get('SHA1', 'N/A'),
                event.get('SHA256', 'N/A'),
                event.get('IMPHASH', 'N/A'),
                event.get('Signature', 'N/A'),
                severity,
                alert_sent
            ))

        elif attack_type == "Brute Force":
            cursor.execute('''
                INSERT INTO logs_bruteforce (
                    timestamp, computer, target_user, source_ip, 
                    failure_count, technique_id, severity, alert_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                event.get('dest', 'Unknown'),
                event.get('user', 'Unknown'),
                event.get('src_ip', 'Unknown'),
                event.get('count', 0),
                "T1110",
                severity,
                alert_sent
            ))

        elif attack_type == "License Alert":
            cursor.execute('''
                INSERT INTO logs_license (timestamp, computer, usage_percent, usage_mb, severity, alert_sent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, computer,
                kwargs.get('usage_percent', 0.0),
                kwargs.get('usage_mb', 0),
                severity,
                alert_sent
            ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Save Error ({attack_type}): {e}")