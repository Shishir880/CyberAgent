@echo off
title CyberAgent - Autonomous AI Penetration Testing Platform
cd /d "%~dp0"
echo ========================================================
echo   Starting CyberAgent Autonomous AI Platform
echo ========================================================
echo.

:: Check if virtual environment exists, if not create and install dependencies
if not exist ".venv" (
    echo [*] Setting up virtual environment (.venv)...
    python -m venv .venv
    echo [*] Installing dependencies from requirements.txt...
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

:: Launch CLI
python cli.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] CyberAgent exited with an error. Press any key to close.
    pause >nul
)
