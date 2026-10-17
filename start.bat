@echo off
title WebScan - Defensive Security Suite
echo ===================================================
echo   WebScan - Defensive Security Auditing & Compliance
echo ===================================================
echo.

cd /d "%~dp0"

:: Check for node_modules and install if missing
if not exist node_modules (
    echo [INFO] Node modules not found. Installing dependencies...
    call npm install
    if %errorlevel% neq 0 (
        echo [ERROR] npm install failed. Please check your Node.js installation.
        pause
        exit /b 1
    )
)

:: Wait 1.5 seconds then open the browser
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5173"

echo [INFO] Starting WebScan Vite server on port 5173...
echo [INFO] Press Ctrl+C in this window or run stop.bat to terminate.
echo.

call npm run dev
