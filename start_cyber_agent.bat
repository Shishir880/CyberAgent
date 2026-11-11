@echo off
title CyberAgent - Autonomous AI Penetration Testing Platform
cd /d "%~dp0"

echo ========================================================
echo   Starting CyberAgent Autonomous AI Platform
echo ========================================================
echo.

if exist "%~dp0.venv\Scripts\python.exe" (
    echo [*] Running CyberAgent with virtual environment...
    "%~dp0.venv\Scripts\python.exe" "%~dp0cli.py"
) else (
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    "%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip
    "%~dp0.venv\Scripts\pip.exe" install -r requirements.txt
    "%~dp0.venv\Scripts\python.exe" "%~dp0cli.py"
)

echo.
echo ========================================================
echo [*] CyberAgent process ended. Press any key to close.
echo ========================================================
pause >nul
