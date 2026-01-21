import sqlite3
import config

def init_db():
    """Initializes the master security table with specific columns."""
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        # Updated Schema: Added columns for Phishing specifics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attack_type TEXT,
                computer TEXT,
                user TEXT,
                source_app TEXT,
                browser TEXT,
                technique_id TEXT,
                details TEXT,         -- Stores Link, Command, or Target IP
                alert_sent BOOLEAN)
        ''')
        conn.commit()
        conn.close()
        print("[DB] Database initialized with extended schema.")
    except Exception as e:
        print(f"[DB] Init Error: {e}")

def save_log(attack_type, event, alert_sent, details_str, source_app=None, browser=None, technique_id=None):
    try:
        conn = sqlite3.connect(config.DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_logs (
                timestamp, attack_type, computer, user, 
                source_app, browser, technique_id, 
                details, alert_sent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.get('_time', 'N/A'),
            attack_type,
            event.get('Computer', 'Unknown'),
            event.get('User', 'Unknown'),
            source_app,
            browser,
            technique_id,
            details_str,
            alert_sent
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Save Error: {e}")