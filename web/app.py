from flask import Flask, render_template, jsonify
import sqlite3
import os
import sys

# Allow importing config from parent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import config  # Import config to get DB name

app = Flask(__name__)
DB_PATH = os.path.join(parent_dir, config.DB_NAME)

def get_db_connection():
    """Connects to the SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

@app.route('/')
def index():
    """Serves the dashboard HTML page"""
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    """API: Returns counts for the summary cards"""
    try:
        conn = get_db_connection()
        stats = {}
        
        # Count total attacks
        stats['total'] = conn.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
        
        # Count by specific types
        stats['phishing'] = conn.execute("SELECT COUNT(*) FROM security_logs WHERE attack_type='Phishing'").fetchone()[0]
        stats['ddos'] = conn.execute("SELECT COUNT(*) FROM security_logs WHERE attack_type='DDoS'").fetchone()[0]
        stats['crypto'] = conn.execute("SELECT COUNT(*) FROM security_logs WHERE attack_type='Cryptojacking'").fetchone()[0]
        stats['bruteforce'] = conn.execute("SELECT COUNT(*) FROM security_logs WHERE attack_type='Brute Force'").fetchone()[0]
        
        conn.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/logs')
def api_logs():
    """API: Returns the latest 50 logs for the table"""
    try:
        conn = get_db_connection()
        # Fetch latest 50 logs, ordered by newest first
        logs = conn.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 50").fetchall()
        conn.close()
        
        # Convert SQLite rows to a list of dictionaries so JS can read it
        logs_list = [dict(row) for row in logs]
        return jsonify(logs_list)
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    print(f"[*] Dashboard running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)