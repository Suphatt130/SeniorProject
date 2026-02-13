SPADE Security Monitor Project
Project Name: Anomaly Detection and Alerting System utilizing Splunk Free License
Program Name: SPADE (Splunk Anomaly Detection Extension)
Developed by: ICT SP2025-53
Faculty: ICT, Mahidol University
----------------------------------------------------------------------------------------------------

Project Overview
SPADE is a real-time security monitoring dashboard that integrates with Splunk to detect and visualize network threats. It uses a Python backend to query Splunk logs and a Flask-based web interface to display alerts.

Key Features:
    - Real-time Detection: Phishing, DDoS, Cryptojacking, and Brute Force attacks.
    - License Monitoring: Tracks Splunk bandwidth usage to prevent overages.
    - Alerting System: Sends notifications via LINE and Email.
    - Interactive Dashboard: Live charts, sortable tables, and status indicators.
----------------------------------------------------------------------------------------------------

Prerequisites
Before running the project, ensure you have the following installed:
    1. Python 3.10 or higher
    2. Splunk Free License (Running locally on https://127.0.0.1:8089)
    3. Sysmon (Installed on the target Windows machine for log collection)
----------------------------------------------------------------------------------------------------

Installation & Setup
1. Clone or Extract the Project
    Ensure your project folder has the following structure:
        SeniorCode/
        ├── alerting/          # Alert sending logic (LINE/Email)
        ├── database/          # DB management scripts
        ├── modules/           # Detection logic (Phishing, DDoS, etc.)
        ├── resources/         # Splunk queries (json files)
        ├── web/               # Flask Web App (static/, templates/, app.py)
        ├── .env               # Secrets file (YOU MUST CREATE THIS)
        ├── config.py          # Configuration settings
        ├── main.py            # Backend detection service
        └── security_events.db # SQLite Database

2. Install Python Dependencies
    Open your terminal (Command Prompt or PowerShell) in the SeniorCode folder and run:
        pip install flask requests python-dotenv urllib3 chart.js
----------------------------------------------------------------------------------------------------

Configuration (.env)
You must create a file named .env in the root folder (SeniorCode/) to store your private keys. Create a file named .env and paste the following inside:
    # --- VirusTotal API (For Phishing Detection) ---
    VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

    # --- LINE Alert Settings ---
    LINE_CHANNEL_ACCESS_TOKEN=your_line_channel_token_here

    # --- Email Alert Settings ---
    SENDER_EMAIL=your_email@gmail.com
    SENDER_PASSWORD=your_app_password_here
    RECEIVER_EMAIL=recipient_email@gmail.com
    SMTP_SERVER=smtp.gmail.com
    SMTP_PORT=587
----------------------------------------------------------------------------------------------------

Usage Guide
    Step 1: Start the Backend Monitor
    This script runs in the background. It queries Splunk, detects attacks, saves them to the database, and sends alerts.
        1. Open a terminal in the SeniorCode folder.
        2. Run the following command:
            python3 main.py
    Step 2: Start the Web Dashboard
    This launches the visual website. 
        1. Open a second terminal window in the SeniorCode folder.
        2. Navigate to the web folder:
            cd web
        3. Run the Flask app:
            python3 app.py
    Step 3: Access the Dashboard
        Open your web browser (Chrome, Edge, etc.) and go to: http://localhost:5000 or http://127.0.0.1:5000
----------------------------------------------------------------------------------------------------

Contact
If you encounter any issues, please contact the developer:
    Email: RatChng@hotmail.com
    Call: +66 65 951 9065