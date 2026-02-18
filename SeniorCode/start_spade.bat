@echo off
title SPADE Security Monitor Launcher
color 0A

:: 1. SET CURRENT DIRECTORY (Saved as variable)
cd /d "%~dp0"
set "PROJECT_DIR=%~dp0"

echo ======================================================
echo    SPADE SECURITY MONITOR - AUTOMATED LAUNCHER
echo ======================================================

:: 2. DETECT PYTHON (Find the full path to the executable)
set PYTHON_CMD=python

:: Check for 'py' launcher first
py --version >nul 2>&1
if %errorlevel% equ 0 set PYTHON_CMD=py

:: Get the ABSOLUTE PATH to the python executable
for /f "tokens=*" %%i in ('where %PYTHON_CMD%') do set "FULL_PYTHON_PATH=%%i"

:: Verify we found it
if "%FULL_PYTHON_PATH%"=="" (
    echo [X] Could not find Python path!
    echo     Please reinstall Python and check "Add to PATH".
    pause
    exit
)
echo [V] Found Python at: "%FULL_PYTHON_PATH%"

:: 3. INSTALL DEPENDENCIES (Using the full path)
echo.
echo [+] Installing libraries...
"%FULL_PYTHON_PATH%" -m pip install --user -r requirements.txt

if %errorlevel% neq 0 (
    echo.
    echo [X] INSTALL FAILED.
    echo     Please try running this file as Administrator.
    pause
    exit
)

:: 4. LAUNCH PROGRAMS (The Robust Way)
:: We use /D to force the starting directory.
:: We use the full path to python to avoid "command not found".

echo.
echo [+] Starting Backend Monitor...
:: Syntax: start "Title" /D "WorkingFolder" cmd /k "Command"
start "SPADE Backend" /D "%PROJECT_DIR%" cmd /k ""%FULL_PYTHON_PATH%" main.py"

echo [+] Starting Web Dashboard...
start "SPADE Web Dashboard" /D "%PROJECT_DIR%" cmd /k ""%FULL_PYTHON_PATH%" web/app.py"

echo.
echo [V] All systems launched.
echo     Windows should now stay open.
echo.
pause