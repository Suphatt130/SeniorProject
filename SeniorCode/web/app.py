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
    """Returns counts from all 5 separate tables"""
    try:
        conn = get_db_connection()
        stats = {}
        
        # Count individually
        p_count = conn.execute("SELECT COUNT(*) FROM logs_phishing").fetchone()[0]
        d_count = conn.execute("SELECT COUNT(*) FROM logs_ddos").fetchone()[0]
        c_count = conn.execute("SELECT COUNT(*) FROM logs_crypto").fetchone()[0]
        b_count = conn.execute("SELECT COUNT(*) FROM logs_bruteforce").fetchone()[0]
        l_count = conn.execute("SELECT COUNT(*) FROM logs_license").fetchone()[0]
        
        stats['phishing'] = p_count
        stats['ddos'] = d_count
        stats['crypto'] = c_count
        stats['bruteforce'] = b_count
        stats['license'] = l_count
        stats['total'] = p_count + d_count + c_count + b_count + l_count
        
        conn.close()
        return jsonify(stats)
    except Exception as e:
        # If tables don't exist yet (first run), return 0
        return jsonify({"total":0, "phishing":0, "ddos":0, "crypto":0, "bruteforce":0})

@app.route('/api/logs')
def api_logs():
    """Fetches latest logs from all tables and merges them sorted by time."""
    try:
        conn = get_db_connection()
        all_logs = []

        # 1. Fetch Phishing
        rows = conn.execute("SELECT * FROM logs_phishing ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "Phishing", "host": r['computer'],
                "details": f"Link: {r['link']}", "extra": r['technique_id'], "alert": r['alert_sent']
            })

        # 2. Fetch DDoS
        rows = conn.execute("SELECT * FROM logs_ddos ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "DDoS", "host": r['computer'],
                "details": f"Target: {r['target_ip']} ({r['connection_count']} reqs)", "extra": "-", "alert": r['alert_sent']
            })

        # 3. Fetch Crypto
        rows = conn.execute("SELECT * FROM logs_crypto ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "Cryptojacking", "host": r['computer'],
                "details": f"Driver: {r['driver_image']} (MD5: {r['md5_hash'][:10]}...)", 
                "extra": r['technique_id'], "alert": r['alert_sent']
            })

        # 4. Fetch Brute Force
        rows = conn.execute("SELECT * FROM logs_bruteforce ORDER BY id DESC LIMIT 10").fetchall()
        for r in rows:
            all_logs.append({
                "time": r['timestamp'], "type": "Brute Force", "host": r['computer'],
                "details": f"User: {r['target_user']} (Failures: {r['failure_count']})",
                "extra": r['technique_id'], "alert": r['alert_sent']
            })
            
        conn.close()

        # Sort combined list by Time (descending)
        all_logs.sort(key=lambda x: x['time'], reverse=True)
        
        return jsonify(all_logs)
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)