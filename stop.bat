@echo off
title WebScan - Stopping Server
echo ===================================================
echo   WebScan - Stopping Application Server
echo ===================================================
echo.

cd /d "%~dp0"

echo [INFO] Searching for WebScan processes listening on port 5173...

set FOUND=0
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5173 ^| findstr LISTENING') do (
    set FOUND=1
    echo [INFO] Terminating server process PID %%a...
    taskkill /F /PID %%a >nul 2>&1
)

if "%FOUND%"=="1" (
    echo [SUCCESS] WebScan server stopped successfully.
) else (
    echo [INFO] No active WebScan process found listening on port 5173.
)

echo.
timeout /t 3 >nul
