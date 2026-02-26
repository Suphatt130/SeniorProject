from flask import Flask, render_template, jsonify, request
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
        query_warnings = "| rest /services/licenser/messages | stats values(description) as warnings"

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

        resp_warn = requests.post(
            f"{config.SPLUNK_BASE_URL}/services/search/jobs/export",
            data={"search": query_warnings, "output_mode": "json", "exec_mode": "oneshot"},
            headers=headers, verify=False, timeout=5
        )

        online = 0
        total_hosts = 0
        volume_30s = 0
        warnings_list = []

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

        if resp_warn.status_code == 200 and resp_warn.text:
            try:
                for line in resp_warn.text.strip().split('\n'):
                    if line:
                        data = json.loads(line)
                        warn_val = data.get("result", {}).get("warnings")
                        if warn_val:
                            if isinstance(warn_val, list):
                                warnings_list.extend(warn_val)
                            else:
                                warnings_list.append(warn_val)
            except: pass

        return online, total_hosts, volume_30s, warnings_list

    except Exception as e:
        print(f"[Splunk API Error] {e}")
        return 0, 0, 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

def get_time_query(column_name="timestamp"):
    start = request.args.get('start')
    end = request.args.get('end')
    
    if start and end:
        s = start.replace('T', ' ')
        e = end.replace('T', ' ')
        return f" {column_name} BETWEEN ? AND ?", (s, e)
    
    today = datetime.now().strftime('%Y-%m-%d') + "%"
    return f" {column_name} LIKE ?", (today,)

@app.route('/api/stats')
def api_stats():
    stats = {}
    conn = get_db_connection()
    cond, params = get_time_query("timestamp")
    cond_bf, params_bf = get_time_query("first_time")

    p = conn.execute(f"SELECT COUNT(*) FROM logs_phishing WHERE{cond}", params).fetchone()[0]
    d = conn.execute(f"SELECT COUNT(*) FROM logs_dos WHERE{cond}", params).fetchone()[0]
    c = conn.execute(f"SELECT COUNT(*) FROM logs_crypto WHERE{cond}", params).fetchone()[0]
    b = conn.execute(f"SELECT COUNT(*) FROM logs_bruteforce WHERE{cond_bf}", params_bf).fetchone()[0]

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

    online_eps, total_eps, logs_30s, license_warnings = get_splunk_realtime_stats()

    stats['phishing'] = p
    stats['dos'] = d
    stats['crypto'] = c
    stats['bruteforce'] = b
    stats['total'] = p + d + c + b
    
    stats['license_mb_raw'] = int(license_mb_raw)
    stats['license_text'] = f"{int(license_mb_raw)} / 500 MB"

    stats['endpoints_online'] = online_eps
    stats['endpoints_total'] = total_eps
    stats['logs_last_30s'] = logs_30s
    stats['license_warnings'] = license_warnings

    conn.close()
    return jsonify(stats)

@app.route('/api/logs')
def api_logs():
    conn = get_db_connection()
    if not conn: return jsonify([])

    cond, params = get_time_query("timestamp")
    cond_bf, params_bf = get_time_query("first_time")

    all_logs = []
    
    try:
        # PHISHING
        rows = conn.execute(f"SELECT * FROM logs_phishing WHERE{cond} ORDER BY id DESC", params).fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "Phishing", "host": r['computer'],
                "source": r['parent_app'], "severity": r['severity'],
                "extra": r['technique_id'], "details": f"Link: {r['clicked_link']}",
                "alert": r['alert_sent']
            })

        # DOS
        rows = conn.execute(f"SELECT * FROM logs_dos WHERE{cond} ORDER BY id DESC", params).fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "DoS", "host": r['host'],
                "source": r['src_ip'], "severity": r['severity'],
                "extra": r['technique_id'], "details": f"Target: {r['dest_ip']}",
                "alert": r['alert_sent']
            })

        # BRUTE FORCE
        rows = conn.execute(f"SELECT * FROM logs_bruteforce WHERE{cond_bf} ORDER BY id DESC", params_bf).fetchall()
        for r in rows:
            all_logs.append({
                "time": r['first_time'], "type": "Brute Force", "host": r['dest'],
                "source": r['src_ip'], "severity": r['severity'],
                "extra": r['technique_id'], "details": f"User: {r['user']}",
                "alert": r['alert_sent']
            })
            
        # CRYPTOJACKING
        rows = conn.execute(f"SELECT * FROM logs_crypto WHERE{cond} ORDER BY id DESC", params).fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "Cryptojacking", "host": r['dest'],
                "source": r['process_path'], "severity": r['severity'],
                "extra": r['technique_id'], "details": f"File: {r['image_loaded']}",
                "alert": r['alert_sent']
            })

    except Exception as e:
        print(f"API Logs Error: {e}")

    conn.close()
    all_logs.sort(key=lambda x: x['time'], reverse=True)
    return jsonify(all_logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)