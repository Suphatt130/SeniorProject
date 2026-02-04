from flask import Flask, render_template, jsonify
import sqlite3
import os
import sys
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import config

app = Flask(__name__)
DB_PATH = os.path.join(parent_dir, config.DB_NAME)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    try:
        conn = get_db_connection()
        stats = {}
        
        # 1. Get Counts for other cards
        try: p = conn.execute("SELECT COUNT(*) FROM logs_phishing").fetchone()[0]
        except: p = 0
        try: d = conn.execute("SELECT COUNT(*) FROM logs_ddos").fetchone()[0]
        except: d = 0
        try: c = conn.execute("SELECT COUNT(*) FROM logs_crypto").fetchone()[0]
        except: c = 0
        try: b = conn.execute("SELECT COUNT(*) FROM logs_bruteforce").fetchone()[0]
        except: b = 0
        
        # 2. Get SPECIAL License Data
        license_text = "0 / 500 MB" 
        try:
            file_path = config.LICENSE_STATUS_FILE
            
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    data = json.load(f)
                    used = data.get("mb", 0)
                    license_text = f"{int(used)} / 500 MB"
            else:
                print(f"[API] File not found at: {file_path}")
        except Exception as e: 
            print(f"[API] License Read Error: {e}")

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
    try:
        conn = get_db_connection()
        all_logs = []

        # 1. Phishing
        try:
            rows = conn.execute("SELECT * FROM logs_phishing ORDER BY id DESC LIMIT 10").fetchall()
            for r in rows:
                all_logs.append({
                    "time": r['timestamp'], 
                    "type": "Phishing", 
                    "host": r['computer'],
                    "source": r['parent_app'] if 'parent_app' in r.keys() else 'Unknown',
                    "severity": r['severity'] if 'severity' in r.keys() else 'High',
                    "extra": r['technique_id'],
                    "details": f"Link: {r['clicked_link']}", 
                    "alert": r['alert_sent']
                })
        except Exception as e:
            print(f"[API ERROR] Phishing: {e}")

        # 2. DDoS
        try:
            rows = conn.execute("SELECT * FROM logs_ddos ORDER BY id DESC LIMIT 10").fetchall()
            for r in rows:
                all_logs.append({
                    "time": r['timestamp'], 
                    "type": "DoS / Flood", 
                    "host": r['computer'],
                    "source": r['src_ip'],
                    "severity": r['severity'],
                    "extra": "T1498.001",
                    "details": f"Dest: {r['dest_ip']}:{r['dest_port']} | Flag: {r['tcp_flags']} | Pkts: {r['packet_count']}", 
                    "alert": r['alert_sent']
                })
        except Exception: pass

        # 3. Crypto
        try:
            rows = conn.execute("SELECT * FROM logs_crypto ORDER BY id DESC LIMIT 10").fetchall()
            for r in rows:
                all_logs.append({
                    "time": r['timestamp'], 
                    "type": "Cryptojacking", 
                    "host": r['computer'],
                    "source": r['driver_image'],
                    "severity": r['severity'] if 'severity' in r.keys() else 'Critical',
                    "extra": "T1543.003",
                    "details": f"MD5: {r['md5_hash']}", 
                    "alert": r['alert_sent']
                })
        except Exception: pass

        # 4. Brute Force
        try:
            rows = conn.execute("SELECT * FROM logs_bruteforce ORDER BY id DESC LIMIT 10").fetchall()
            for r in rows:
                all_logs.append({
                    "time": r['timestamp'], 
                    "type": "Brute Force", 
                    "host": r['computer'],
                    "source": r['source_ip'],      # Frontend "source" = DB "source_ip"
                    "severity": r['severity'] if 'severity' in r.keys() else 'Medium',
                    "extra": "T1110", 
                    "details": f"User: {r['target_user']} ({r['failure_count']} fails)", 
                    "alert": r['alert_sent']
                })
        except Exception: pass

        # 5. License
        try:
            rows = conn.execute("SELECT * FROM logs_license ORDER BY id DESC LIMIT 10").fetchall()
            for r in rows:
                all_logs.append({
                    "time": r['timestamp'], 
                    "type": "License Warning", 
                    "host": r['computer'],
                    "source": "Splunk",
                    "severity": r['severity'],
                    "extra": "Quota", 
                    "details": f"{r['usage_percent']}% used", 
                    "alert": r['alert_sent']
                })
        except Exception: pass

        conn.close()
        
        all_logs.sort(key=lambda x: x['time'], reverse=True)
        
        return jsonify(all_logs)
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)