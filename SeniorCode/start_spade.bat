@echo off
title SPADE Security Monitor Launcher
color 0A

:: 1. FORCE CORRECT DIRECTORY (Robust Method)
pushd "%~dp0"

echo ======================================================
echo    SPADE SECURITY MONITOR - AUTOMATED LAUNCHER
echo ======================================================

:: 2. DETECT THE CORRECT PYTHON
:: We prefer 'py' because your 'python' command points to a broken MinGW version.
set PYTHON_CMD=python

:: Check if 'py' launcher is available (Standard with Python 3.10+)
py --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [V] Found Python Launcher 'py'. Using it to bypass broken system Python...
    set PYTHON_CMD=py
) else (
    echo [!] 'py' launcher not found. Trying standard 'python'...
)

:: 3. Verify Python works
%PYTHON_CMD% --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python is not found! 
    echo     Please install Python 3.10+ from python.org and check "Add to PATH".
    pause
    exit
)

:: 4. Install Dependencies
echo [+] Installing/Checking libraries using %PYTHON_CMD%...
%PYTHON_CMD% -m pip install --user -r requirements.txt

:: Check if install failed
if %errorlevel% neq 0 (
    echo.
    echo [X] INSTALLATION FAILED!
    echo     Your computer is pointing to a broken Python installation (likely MinGW).
    echo     Please install the official Python from python.org.
    pause
    exit
)

:: 5. Launch Programs
echo.
echo [+] Starting Backend Monitor...
start "SPADE Backend" cmd /k "%PYTHON_CMD% main.py"

echo [+] Starting Web Dashboard...
start "SPADE Web Dashboard" cmd /k "%PYTHON_CMD% web/app.py"

echo.
echo [V] All systems launched.
echo     If a window closes, check the error message inside it.
echo.
timeout /t 20