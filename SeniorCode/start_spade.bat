@echo off
title SPADE Security Monitor Launcher
color 0A

echo ======================================================
echo    SPADE SECURITY MONITOR - AUTOMATED LAUNCHER
echo ======================================================

:: 1. Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python is not installed or not in PATH.
    echo     Please install Python 3.10+ and check "Add to PATH" during installation.
    pause
    exit
)

:: 2. Create Virtual Environment (if it doesn't exist)
if not exist "venv" (
    echo [+] Creating Python Virtual Environment (First run only)...
    python -m venv venv
)

:: 3. Activate Virtual Environment
call venv\Scripts\activate

:: 4. Install Dependencies
if not exist "venv\installed.flag" (
    echo [+] Installing required libraries...
    pip install -r requirements.txt
    echo done > venv\installed.flag
)

:: 5. Launch the Programs
echo.
echo [+] Starting Backend Monitor...
start "SPADE Backend" cmd /k "venv\Scripts\python main.py"

echo [+] Starting Web Dashboard...
start "SPADE Web Dashboard" cmd /k "venv\Scripts\python web/app.py"

echo.
echo [V] All systems running!
echo     Backend and Web Server opened in new windows.
echo     You can close this window now.
echo.
timeout /t 5