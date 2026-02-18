@echo off
title SPADE Security Monitor Launcher
color 0A

:: 1. FORCE CORRECT DIRECTORY
cd /d "%~dp0"

echo ======================================================
echo    SPADE SECURITY MONITOR - AUTOMATED LAUNCHER
echo ======================================================

:: 2. Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python is not found! 
    echo     Please make sure Python is installed and added to PATH.
    pause
    exit
)

:: 3. Create Virtual Environment (if missing)
if not exist "venv" (
    echo [+] Creating new Python Virtual Environment...
    python -m venv venv
)

:: 4. Install Dependencies
echo [+] Activating environment and checking libraries...
call venv\Scripts\activate
pip install -r requirements.txt

:: 5. Launch Programs (THE FIX IS HERE)
:: We point directly to "venv\Scripts\python.exe" so it works 100% of the time.

echo.
echo [+] Starting Backend Monitor...
start "SPADE Backend" cmd /k "venv\Scripts\python.exe main.py"

echo [+] Starting Web Dashboard...
start "SPADE Web Dashboard" cmd /k "venv\Scripts\python.exe web/app.py"

echo.
echo [V] All systems launched.
echo     If a window closes, check the error message inside it.
echo.
timeout /t 5