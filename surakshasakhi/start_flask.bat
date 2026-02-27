@echo off
REM Start Flask server using venv Python
cd /d "%~dp0"
.\..\\.venv\Scripts\python.exe -m flask run --host=127.0.0.1 --port=5000
pause
