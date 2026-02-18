@echo off
title SPADE Security Monitor Launcher
color 0A

:: 1. FORCE CORRECT DIRECTORY (Fixes path issues)
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

:: 3. Create/Check Virtual Environment
if not exist "venv" (
    echo [+] Creating new Python Virtual Environment...
    python -m venv venv
)

:: 4. Activate & Install Dependencies
echo [+] Activating environment...
call venv\Scripts\activate

:: Force install requirements every time to be safe (it's fast if already installed)
echo [+] Checking/Installing libraries...
pip install -r requirements.txt

:: 5. Launch Programs (With /k to keep window open on error)
echo.
echo [+] Starting Backend Monitor...
start "SPADE Backend" cmd /k "python main.py"

echo [+] Starting Web Dashboard...
start "SPADE Web Dashboard" cmd /k "python web/app.py"

echo.
echo [V] All systems launched.
echo     If a window closes, check the error message inside it.
echo.
pause