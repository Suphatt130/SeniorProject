from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
import sqlite3
import requests
import os
import sys
import json
from datetime import datetime
import string, secrets, re

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import config

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY 
socketio = SocketIO(app, cors_allowed_origins="*")

DB_PATH = os.path.join(parent_dir, config.DB_NAME)
socketio = SocketIO(app, cors_allowed_origins="*")
##--------------- Dont Touch above ---------------##

import logging

# Configure logging to save errors to a file and show them in the console
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("spade_errors.log"), logging.StreamHandler()]
)

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
        query_volume = "| tstats count where index=* earliest=-10s"
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
    if 'username' not in session:
        return redirect(url_for('login'))

    if session.get('role') == 'SOC Admin':
        return redirect(url_for('register'))
        
    return render_template('index.html', current_user=session['username'])

@app.route('/about')
def about():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        
        # Verify user exists and password is correct
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'SOC Admin':
                return redirect(url_for('register'))
            else:
                return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
            
    return render_template('login.html')

def generate_secure_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for i in range(15))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*" for c in pwd)):
            return pwd

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('role') != 'SOC Admin':
        flash("Unauthorized. Only Admins can create new users.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')

        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()

        if existing:
            flash("Username already exists.", "warning")
        else:
            new_pwd = generate_secure_password() # Auto-generate password
            pass_hash = generate_password_hash(new_pwd)
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, pass_hash, role))
            conn.commit()
            flash(f"User created! Give them this password: {new_pwd}", "success")
        conn.close()

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear() # Destroy the session cookie
    return redirect(url_for('login'))

def get_time_query(column_name="timestamp"):
    start = request.args.get('start')
    end = request.args.get('end')
    
    if start and end:
        s = start.replace('T', ' ')
        e = end.replace('T', ' ')
        return f" {column_name} BETWEEN ? AND ?", (s, e)
    
    today = datetime.now().strftime('%Y-%m-%d') + "%"
    return f" {column_name} LIKE ?", (today,)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
        else:
            pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{15,}$"
            if not re.match(pattern, new_password):
                flash("Password must be 15+ characters with uppercase, lowercase, number, and special character (!@#$%^&*).", "danger")
            else:
                conn = get_db_connection()
                conn.execute("UPDATE users SET password_hash=? WHERE username=?", 
                             (generate_password_hash(new_password), session['username']))
                conn.commit()
                conn.close()
                flash("Password successfully updated!", "success")
                
    return render_template('profile.html', current_user=session['username'], role=session['role'])

@app.route('/api/stats')
def api_stats():
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"error": "DB Connection Failed"})
        
        start_dt = request.args.get('start')
        end_dt = request.args.get('end')
        
        if start_dt and end_dt:
            start_str = start_dt.replace('T', ' ') + ':00'
            end_str = end_dt.replace('T', ' ') + ':59'
        else:
            today_str = datetime.now().strftime('%Y-%m-%d')
            start_str = f"{today_str} 00:00:00"
            end_str = f"{today_str} 23:59:59"
            
        stats = {}
        
        try: p = conn.execute("SELECT COUNT(*) FROM logs_phishing WHERE REPLACE(timestamp, 'T', ' ') >= ? AND REPLACE(timestamp, 'T', ' ') <= ?", (start_str, end_str)).fetchone()[0]
        except: p = 0
        try: d = conn.execute("SELECT COUNT(*) FROM logs_dos WHERE REPLACE(first_time, 'T', ' ') >= ? AND REPLACE(first_time, 'T', ' ') <= ?", (start_str, end_str)).fetchone()[0]
        except: d = 0
        try: c = conn.execute("SELECT COUNT(*) FROM logs_crypto WHERE REPLACE(timestamp, 'T', ' ') >= ? AND REPLACE(timestamp, 'T', ' ') <= ?", (start_str, end_str)).fetchone()[0]
        except: c = 0
        try: b = conn.execute("SELECT COUNT(*) FROM logs_bruteforce WHERE REPLACE(first_time, 'T', ' ') >= ? AND REPLACE(first_time, 'T', ' ') <= ?", (start_str, end_str)).fetchone()[0]
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
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/logs')
def api_logs():
    conn = get_db_connection()
    if not conn: return jsonify([])

    all_logs = []
    
    start_dt = request.args.get('start')
    end_dt = request.args.get('end')
    
    if start_dt and end_dt:
        start_str = start_dt.replace('T', ' ') + ':00'
        end_str = end_dt.replace('T', ' ') + ':59'
        assignee_filter = request.args.get('assignee')
    else:
        today_str = datetime.now().strftime('%Y-%m-%d')
        start_str = f"{today_str} 00:00:00"
        end_str = f"{today_str} 23:59:59"
        assignee_filter = request.args.get('assignee')

    # --- 1. PHISHING ---
    try:
        query = "SELECT * FROM logs_phishing WHERE REPLACE(timestamp, 'T', ' ') >= ? AND REPLACE(timestamp, 'T', ' ') <= ?"
        params = [start_str, end_str]

        if assignee_filter:
            query += " AND assignee = ?"
            params.append(assignee_filter)

        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()

        for r in rows:
            all_logs.append({
                "time": r['timestamp'], 
                "name": r['rule_name'],
                "type": r['attack_type'],
                "host": r['computer'], 
                "source": r['parent_app'], 
                "severity": r['severity'], 
                "extra": r['technique_id'], 
                "details": f"Link: {r['clicked_link']} | Browser: {r['browser_name']}",
                "status": r['status'],
                "verdict": r['verdict'], 
                "assignee": r['assignee'], 
                "comment": r['comment']
            })
    except Exception as e: 
        logging.error(f"Failed to fetch Phishing logs: {e}")

    # --- 2. DOS ---
    try:
        query = "SELECT * FROM logs_dos WHERE REPLACE(first_time, 'T', ' ') >= ? AND REPLACE(first_time, 'T', ' ') <= ?"
        params = [start_str, end_str]

        if assignee_filter:
            query += " AND assignee = ?"
            params.append(assignee_filter)

        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()

        for r in rows:
            all_logs.append({
                "time": r['first_time'], 
                "name": r['rule_name'],
                "type": r['attack_type'],
                "host": r['dest_ip'], 
                "source": r['src_ip'], 
                "severity": r['severity'], 
                "extra": r['technique_id'], 
                "details": f"Proto: {r['protocol']} | Size: {r['size']} bytes | Action: {r['action']} | Pkts: {r['count']}",
                "status": r['status'], 
                "verdict": r['verdict'], 
                "assignee": r['assignee'], 
                "comment": r['comment']
            })
    except Exception as e: 
        logging.error(f"Failed to fetch DoS logs: {e}")

    # --- 3. CRYPTOJACKING ---
    try:
        query = "SELECT * FROM logs_crypto WHERE REPLACE(timestamp, 'T', ' ') >= ? AND REPLACE(timestamp, 'T', ' ') <= ?"
        params = [start_str, end_str]

        if assignee_filter:
            query += " AND assignee = ?"
            params.append(assignee_filter)

        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()

        for r in rows:
            det = f"File: {r['image_loaded']}"
            if r['md5']: det += f" | MD5: {r['md5']}"
            all_logs.append({
                "time": r['timestamp'], 
                "name": r['rule_name'],
                "type": r['attack_type'], 
                "host": r['dest'], 
                "source": r['process_path'] or "Unknown",
                "severity": r['severity'], 
                "extra": r['technique_id'], 
                "details": det,
                "status": r['status'], 
                "verdict": r['verdict'], 
                "assignee": r['assignee'], 
                "comment": r['comment']
            })
    except Exception as e: 
        logging.error(f"Failed to fetch Cryptojacking logs: {e}")

    # --- 4. BRUTE FORCE ---
    try:
        query = "SELECT * FROM logs_bruteforce WHERE REPLACE(first_time, 'T', ' ') >= ? AND REPLACE(first_time, 'T', ' ') <= ?"
        params = [start_str, end_str]

        if assignee_filter:
            query += " AND assignee = ?"
            params.append(assignee_filter)

        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()
        
        for r in rows:
            all_logs.append({
                "time": r['first_time'], 
                "name": r['rule_name'],
                "type": r['attack_type'],
                "host": r['dest'], 
                "source": r['src_ip'],
                "severity": r['severity'], 
                "extra": r['technique_id'],
                "details": f"Target User: {r['user']} | Failures: {r['count']}",
                "status": r['status'], 
                "verdict": r['verdict'], 
                "assignee": r['assignee'], 
                "comment": r['comment']
            })
    except Exception as e: 
        logging.error(f"Failed to fetch Brute Force logs: {e}")

    conn.close()
    all_logs.sort(key=lambda x: x['time'], reverse=True)
    return jsonify(all_logs)

@app.route('/internal/trigger_update', methods=['POST'])
def trigger_update():
    # Broadcast a message named 'refresh_data' to all connected browsers
    socketio.emit('refresh_data') 
    return jsonify({"status": "success"}), 200

@app.route('/api/users')
def api_users():
    try:
        conn = get_db_connection()
        # Fetch all usernames and roles from the database
        rows = conn.execute("SELECT username, role FROM users ORDER BY username ASC").fetchall()
        conn.close()
        
        # Package them into a list of dictionaries
        users = [{"username": r["username"], "role": r["role"]} for r in rows]
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/update_incident', methods=['POST'])
def update_incident():
    data = request.get_json()
    incident_time = data.get('time')
    attack_type = data.get('type')
    new_status = data.get('status')
    new_verdict = data.get('verdict')
    new_assignee = data.get('assignee')
    new_comment = data.get('comment')
    incident_host = data.get('host')
    
    if attack_type == 'Windows Phishing Executes URL Link' or attack_type == 'Phishing':
        target_table = 'logs_phishing'
        time_col = 'timestamp'
        host_col = 'computer'
    elif attack_type == 'Detect Large ICMP Traffic' or attack_type == 'DoS':
        target_table = 'logs_dos'
        time_col = 'first_time'
        host_col = 'dest_ip'
    elif attack_type == 'XMRIG Driver Loaded' or attack_type == 'Cryptojacking':
        target_table = 'logs_crypto'
        time_col = 'timestamp'
        host_col = 'dest'
    elif attack_type == 'MySQL Brute Force' or attack_type == 'Brute Force':
        target_table = 'logs_bruteforce'
        time_col = 'first_time'
        host_col = 'dest'
    else:
        return jsonify({"status": "error", "message": f"Invalid attack type: {attack_type}"}), 400

    user_role = session.get('role', 'L1 Analyst')

    if new_status == 'Closed' and user_role == 'L1 Analyst':
        return jsonify({"status": "error", "message": "Access Denied: L1 Analysts cannot close incidents. Please change status to 'Escalated' and assign to an L2 Analyst."}), 403
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = f"""
            UPDATE {target_table} 
            SET status = ?, verdict = ?, assignee = ?, comment = ?
            WHERE {time_col} = ? AND {host_col} = ?
        """
        cursor.execute(query, (new_status, new_verdict, new_assignee, new_comment, incident_time, incident_host))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/my_cases')
def my_cases():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('my_cases.html', current_user=session['username'])

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)