@echo off
title CyberAgent - Autonomous AI Software Engineer
cd /d "%~dp0"
echo ========================================================
echo   Starting CyberAgent Autonomous AI Platform
echo ========================================================
echo.
python cli.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] CyberAgent exited with an error. Press any key to close.
    pause >nul
)
