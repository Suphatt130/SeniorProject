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

:: 3. Install Dependencies (To User Path)
echo [+] Installing/Checking libraries...
:: We use --user to ensure it works even without Admin rights
python -m pip install --user -r requirements.txt

:: 4. Launch Programs (USING GLOBAL PYTHON)
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