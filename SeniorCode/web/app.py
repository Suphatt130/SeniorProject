from flask import Flask, render_template, jsonify
import sqlite3
import os
import sys

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
    """Returns counts including License Warnings in the Total"""
    try:
        conn = get_db_connection()
        stats = {}
        
        # 1. Count all tables
        p_count = conn.execute("SELECT COUNT(*) FROM logs_phishing").fetchone()[0]
        d_count = conn.execute("SELECT COUNT(*) FROM logs_ddos").fetchone()[0]
        c_count = conn.execute("SELECT COUNT(*) FROM logs_crypto").fetchone()[0]
        b_count = conn.execute("SELECT COUNT(*) FROM logs_bruteforce").fetchone()[0]
        l_count = conn.execute("SELECT COUNT(*) FROM logs_license").fetchone()[0] # <--- Added License Count
        
        stats['phishing'] = p_count
        stats['ddos'] = d_count
        stats['crypto'] = c_count
        stats['bruteforce'] = b_count
        stats['license'] = l_count
        
        # 2. Add License count to Total
        stats['total'] = p_count + d_count + c_count + b_count + l_count 
        
        conn.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"total":0, "phishing":0, "ddos":0, "crypto":0, "bruteforce":0, "license":0})

@app.route('/api/logs')
def api_logs():
    """Fetches logs and ensures 7 columns of data for the frontend"""
    try:
        conn = get_db_connection()
        all_logs = []

        # 1. Phishing
        rows = conn.execute("SELECT * FROM logs_phishing ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], 
                "type": "Phishing", 
                "host": r['computer'],
                "source": r['source_app'],
                "extra": r['technique_id'], 
                "details": r['link'], 
                "alert": r['alert_sent']
            })

        # 2. DDoS
        rows = conn.execute("SELECT * FROM logs_ddos ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], 
                "type": "DDoS", 
                "host": r['computer'],
                "source": "Network",
                "extra": "-", 
                "details": f"Target: {r['target_ip']} ({r['connection_count']} reqs)", 
                "alert": r['alert_sent']
            })

        # 3. Crypto
        rows = conn.execute("SELECT * FROM logs_crypto ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], 
                "type": "Cryptojacking", 
                "host": r['computer'],
                "source": r['driver_image'],
                "extra": r['technique_id'], 
                "details": f"MD5: {r['md5_hash'][:10]}...", 
                "alert": r['alert_sent']
            })

        # 4. Brute Force
        rows = conn.execute("SELECT * FROM logs_bruteforce ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], 
                "type": "Brute Force", 
                "host": r['computer'],
                "source": "winlogon.exe",
                "extra": r['technique_id'], 
                "details": f"User: {r['target_user']} ({r['failure_count']} fails)", 
                "alert": r['alert_sent']
            })

        # 5. License Logs
        rows = conn.execute("SELECT * FROM logs_license ORDER BY id DESC LIMIT 5").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], 
                "type": "License Warning",
                "host": r['computer'],
                "source": "Splunk",
                "extra": "-",
                "details": f"Usage: {r['usage_percent']}% ({r['usage_mb']} MB)", 
                "alert": r['alert_sent']
            })
            
        conn.close()
        all_logs.sort(key=lambda x: x['time'], reverse=True)
        return jsonify(all_logs)
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)