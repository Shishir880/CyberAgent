@echo off
title CyberAgent - Autonomous AI Penetration Testing Platform
cd /d "%~dp0"

echo ========================================================
echo   Starting CyberAgent Autonomous AI Platform
echo ========================================================
echo.

if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    call ".venv\Scripts\activate.bat"
    python -m pip install --upgrade pip
    pip install -r requirements.txt
)

python cli.py

if errorlevel 1 (
    echo.
    echo [!] CyberAgent exited. Press any key to close.
    pause >nul
)
