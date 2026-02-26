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

Launch the Program
    1. Double-click the start_spade.bat file.
    2. The launcher will automatically:
        - Detect your Python installation.
        - Install required libraries (Flask, requests, python-dotenv, etc.) to your user profile.
        - Open two command windows: one for the Backend Monitor and one for the Web Dashboard.
    3. Open your web browser and go to: http://localhost:5000

(Note: Keep the two black command windows open while using the dashboard. To stop the program, simply close the command windows.)
----------------------------------------------------------------------------------------------------

Contact
If you encounter any issues, please contact the developer:
    Email: RatChng@hotmail.com
    Call: +66 65 951 9065