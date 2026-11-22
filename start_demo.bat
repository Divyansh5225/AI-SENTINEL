@echo off
setlocal enabledelayedexpansion

echo ======================================================================
echo           AI-SENTINEL: LIVE DEMONSTRATION LAUNCHER
echo ======================================================================
echo.

cd /d "%~dp0"

echo [1/4] Checking if port 5000 is free...
netstat -ano | findstr :5000 | findstr LISTENING >nul
if %ERRORLEVEL% equ 0 (
    echo [!] Port 5000 is already in use. Attempting to free port...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
        echo Killing process PID: %%a
        taskkill /PID %%a /F >nul 2>&1
    )
    timeout /t 1 /nobreak >nul
)
echo [OK] Port 5000 is ready.
echo.

echo [2/4] Starting AI-Sentinel Server on http://127.0.0.1:5000 ...
start "" /b python run.py > server.log 2>&1

echo [3/4] Waiting for server to initialize and health endpoint to respond...
set /a attempts=0
:wait_loop
set /a attempts+=1
if !attempts! gtr 15 (
    echo [ERROR] Server failed to start within 15 seconds. Check server.log.
    exit /b 1
)
python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/sentinel/health?format=json', timeout=1)" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    timeout /t 1 /nobreak >nul
    goto wait_loop
)
echo [OK] AI-Sentinel is online!
echo.

echo [4/4] Executing automated endpoint healthcheck suite...
python demo/healthcheck.py
echo.

echo ======================================================================
echo               DEMO SYSTEM READY! OPEN THESE TABS IN BROWSER
echo ======================================================================
echo.
echo   1. Enterprise Portal (Target App):
echo      http://127.0.0.1:5000/
echo.
echo   2. SOC Real-Time Monitoring Dashboard:
echo      http://127.0.0.1:5000/sentinel/dashboard
echo.
echo   3. System Health Check UI:
echo      http://127.0.0.1:5000/sentinel/health
echo.
echo   4. To send live attack traffic, open a new terminal and run:
echo      python demo.py
echo.
echo ======================================================================
echo Press any key to stop server and exit launcher...
pause >nul
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)
echo Server stopped.
