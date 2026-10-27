@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Install the server dependencies first; see docs/PAIRING.md.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m src.pairing %*
if errorlevel 1 pause
