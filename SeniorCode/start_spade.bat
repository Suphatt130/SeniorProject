@echo off
title SPADE Security Monitor (VENV Launcher)
color 0B

:: 1. SET CURRENT DIRECTORY
cd /d "%~dp0"
set "PROJECT_DIR=%~dp0"

echo ======================================================
echo    SPADE SECURITY MONITOR - VIRTUAL ENV MODE
echo ======================================================

:: 2. DETECT GLOBAL PYTHON
set PYTHON_CMD=python
py --version >nul 2>&1
if %errorlevel% equ 0 set PYTHON_CMD=py
for /f "tokens=*" %%i in ('where %PYTHON_CMD%') do set "FULL_PYTHON_PATH=%%i"

if "%FULL_PYTHON_PATH%"=="" (
    echo [X] Could not find Python path!
    pause
    exit
)
echo [V] Found Base Python at: "%FULL_PYTHON_PATH%"

:: 3. CREATE VIRTUAL ENVIRONMENT (If missing)
if not exist "venv\Scripts\python.exe" (
    echo.
    echo [+] No 'venv' found. Creating an isolated Virtual Environment now...
    echo     (This might take 10-20 seconds)
    "%FULL_PYTHON_PATH%" -m venv venv
)

:: 4. INSTALL DEPENDENCIES (Directly inside the VENV)
echo.
echo [+] Installing/Verifying libraries inside VENV...
"%PROJECT_DIR%venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
"%PROJECT_DIR%venv\Scripts\python.exe" -m pip install -r requirements.txt

:: 5. LAUNCH PROGRAMS (Using the VENV Python directly!)
echo.
echo [+] Starting Backend Monitor...
start "SPADE Backend" /D "%PROJECT_DIR%" cmd /k ""%PROJECT_DIR%venv\Scripts\python.exe" main.py"

echo [+] Starting Web Dashboard...
start "SPADE Web Dashboard" /D "%PROJECT_DIR%" cmd /k ""%PROJECT_DIR%venv\Scripts\python.exe" web/app.py"

echo.
echo [V] All systems launched in Virtual Environment.
echo.
pause