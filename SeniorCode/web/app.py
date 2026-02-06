import sqlite3
from flask import Flask, render_template, jsonify
import config
import os

app = Flask(__name__)

# Ensure we use the absolute path to the database
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../security_events.db')

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"[Web] DB Connection Error: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"error": "DB Connection Failed"})
        
        stats = {}
        
        # 1. Get Counts
        try: p = conn.execute("SELECT COUNT(*) FROM logs_phishing").fetchone()[0]
        except: p = 0
        try: d = conn.execute("SELECT COUNT(*) FROM logs_ddos").fetchone()[0]
        except: d = 0
        try: c = conn.execute("SELECT COUNT(*) FROM logs_crypto").fetchone()[0]
        except: c = 0
        try: b = conn.execute("SELECT COUNT(*) FROM logs_bruteforce").fetchone()[0]
        except: b = 0
        
        # 2. Get License Data
        license_text = "0 / 500 MB"
        try:
            import json
            if os.path.exists(config.LICENSE_STATUS_FILE):
                with open(config.LICENSE_STATUS_FILE, "r") as f:
                    data = json.load(f)
                    used = data.get("mb", 0)
                    license_text = f"{int(used)} / 500 MB"
            else:
                row = conn.execute("SELECT usage_mb FROM logs_license ORDER BY id DESC LIMIT 1").fetchone()
                if row:
                    license_text = f"{int(row['usage_mb'])} / 500 MB"
        except: pass

        stats['phishing'] = p
        stats['ddos'] = d
        stats['crypto'] = c
        stats['bruteforce'] = b
        stats['license_text'] = license_text
        stats['total'] = p + d + c + b
        
        conn.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/logs')
def api_logs():
    conn = get_db_connection()
    if not conn: return jsonify([])

    all_logs = []
    
    # --- 1. PHISHING ---
    try:
        rows = conn.execute("SELECT * FROM logs_phishing ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'],
                "type": "Phishing",
                "host": r['computer'],
                "source": r['parent_app'], 
                "severity": r['severity'],
                "extra": r['technique_id'], 
                "details": f"Link: {r['clicked_link']} | Browser: {r['browser_name']}",
                "alert": r['alert_sent']
            })
    except Exception: pass

    # --- 2. DDOS ---
    try:
        rows = conn.execute("SELECT * FROM logs_ddos ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'],
                "type": "DoS / Flood",
                "host": r['host'],
                "source": r['src_ip'], 
                "severity": r['severity'],
                "extra": r['technique_id'], 
                "details": f"Target: {r['dest_ip']}:{r['dest_port']} | Flags: {r['tcp_flags']} | Pkts: {r['count']}",
                "alert": r['alert_sent']
            })
    except Exception: pass

    # --- 3. CRYPTOJACKING ---
    try:
        rows = conn.execute("SELECT * FROM logs_crypto ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            det = f"File: {r['image_loaded']}"
            if r['md5']: det += f" | MD5: {r['md5']}"
            
            all_logs.append({
                "time": r['timestamp'],
                "type": "Cryptojacking",
                "host": r['dest'], 
                "source": r['process_path'] or "Unknown",
                "severity": r['severity'],
                "extra": r['technique_id'],
                "details": det,
                "alert": r['alert_sent']
            })
    except Exception: pass

    # --- 4. BRUTE FORCE ---
    try:
        rows = conn.execute("SELECT * FROM logs_bruteforce ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['first_time'], 
                "type": "Brute Force",
                "host": r['dest'],
                "source": r['src_ip'],
                "severity": r['severity'],
                "extra": r['technique_id'],
                "details": f"Target User: {r['user']} | Failures: {r['count']}",
                "alert": r['alert_sent']
            })
    except Exception: pass

    conn.close()

    all_logs.sort(key=lambda x: x['time'], reverse=True)
    
    return jsonify(all_logs)

if __name__ == '__main__':
    app.run(debug=True, port=5000)