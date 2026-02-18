from flask import Flask, render_template, jsonify
import sqlite3
import requests
import os
import sys
import json
from datetime import datetime

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import config

app = Flask(__name__)
DB_PATH = os.path.join(parent_dir, config.DB_NAME)

##--------------- Dont Touch above ---------------##

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"[Web] DB Connection Error: {e}")
        return None

def get_splunk_realtime_stats():
    try:
        query_endpoints = "| metadata type=hosts index=* | eval age=now()-lastTime | stats count(eval(age < 300)) as online, count as total"
        
        query_volume = "| tstats count where index=* earliest=-30s"

        headers = {'Authorization': f'Bearer {config.SPLUNK_AUTH}'} if config.SPLUNK_AUTH else {}
        
        resp_ep = requests.post(
            f"{config.SPLUNK_BASE_URL}/services/search/jobs/export",
            data={"search": query_endpoints, "output_mode": "json", "exec_mode": "oneshot"},
            headers=headers, verify=False, timeout=5
        )
        
        resp_vol = requests.post(
            f"{config.SPLUNK_BASE_URL}/services/search/jobs/export",
            data={"search": query_volume, "output_mode": "json", "exec_mode": "oneshot"},
            headers=headers, verify=False, timeout=5
        )

        online = 0
        total_hosts = 0
        volume_30s = 0

        if resp_ep.status_code == 200 and resp_ep.text:
            try:
                data = json.loads(resp_ep.text)
                result = data.get("result", {})
                online = int(result.get("online", 0))
                total_hosts = int(result.get("total", 0))
            except: pass

        if resp_vol.status_code == 200 and resp_vol.text:
            try:
                data = json.loads(resp_vol.text)
                result = data.get("result", {})
                volume_30s = int(result.get("count", 0))
            except: pass

        return online, total_hosts, volume_30s

    except Exception as e:
        print(f"[Splunk API Error] {e}")
        return 0, 0, 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/stats')
def api_stats():
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"error": "DB Connection Failed"})
        
        stats = {}
        today_str = datetime.now().strftime('%Y-%m-%d')
        date_filter = f"{today_str}%"
        
        try: p = conn.execute("SELECT COUNT(*) FROM logs_phishing WHERE timestamp LIKE ?", (date_filter,)).fetchone()[0]
        except: p = 0
        try: d = conn.execute("SELECT COUNT(*) FROM logs_dos WHERE timestamp LIKE ?", (date_filter,)).fetchone()[0]
        except: d = 0
        try: c = conn.execute("SELECT COUNT(*) FROM logs_crypto WHERE timestamp LIKE ?", (date_filter,)).fetchone()[0]
        except: c = 0
        try: b = conn.execute("SELECT COUNT(*) FROM logs_bruteforce WHERE first_time LIKE ?", (date_filter,)).fetchone()[0]
        except: b = 0
        
        license_mb_raw = 0 
        try:
            if os.path.exists(config.LICENSE_STATUS_FILE):
                with open(config.LICENSE_STATUS_FILE, "r") as f:
                    data = json.load(f)
                    license_mb_raw = float(data.get("mb", 0))
            else:
                row = conn.execute("SELECT usage_mb FROM logs_license ORDER BY id DESC LIMIT 1").fetchone()
                if row: license_mb_raw = float(row['usage_mb'])
        except: pass

        online_eps, total_eps, logs_30s = get_splunk_realtime_stats()

        stats['phishing'] = p
        stats['dos'] = d
        stats['crypto'] = c
        stats['bruteforce'] = b
        stats['total'] = p + d + c + b
        
        stats['license_mb_raw'] = int(license_mb_raw)
        stats['license_text'] = f"{int(license_mb_raw)} / 500 MB"

        # REAL DATA MAPPED HERE
        stats['endpoints_online'] = online_eps
        stats['endpoints_total'] = total_eps
        stats['logs_last_30s'] = logs_30s
        
        conn.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/logs')
def api_logs():
    conn = get_db_connection()
    if not conn: return jsonify([])

    all_logs = []
    
    today_str = datetime.now().strftime('%Y-%m-%d')
    date_filter = f"{today_str}%"

    # --- 1. PHISHING ---
    try:
        rows = conn.execute("SELECT * FROM logs_phishing WHERE timestamp LIKE ? ORDER BY id DESC", (date_filter,)).fetchall()
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

    # --- 2. DOS ---
    try:
        rows = conn.execute("SELECT * FROM logs_dos WHERE timestamp LIKE ? ORDER BY id DESC", (date_filter,)).fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'],
                "type": "DoS",
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
        rows = conn.execute("SELECT * FROM logs_crypto WHERE timestamp LIKE ? ORDER BY id DESC", (date_filter,)).fetchall()
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
        rows = conn.execute("SELECT * FROM logs_bruteforce WHERE first_time LIKE ? ORDER BY id DESC", (date_filter,)).fetchall()
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
    app.run(host='0.0.0.0', port=5000, debug=True)