@echo off
title FINDER_IO Launcher
color 0A
echo.
echo   ╔══════════════════════════════════════════╗
echo   ║          FINDER_IO v2.1 LAUNCHER         ║
echo   ║    OSINT Email → Phone Recon Engine       ║
echo   ╚══════════════════════════════════════════╝
echo.
echo   [*] Starting server...
echo.

cd /d "%~dp0"

:: Check if node is available
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] Node.js not found. Install from https://nodejs.org
    pause
    exit /b 1
)

:: Install dependencies if needed
if not exist "node_modules" (
    echo   [*] Installing dependencies...
    npm install --silent
    echo   [*] Dependencies installed.
    echo.
)

:: Kill any existing instance on port 3700
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3700 ^| findstr LISTENING 2^>nul') do (
    echo   [*] Killing existing process on port 3700 (PID: %%a)
    taskkill /PID %%a /F >nul 2>&1
)

echo   [*] Launching FINDER_IO on http://localhost:3700
echo   [*] Opening browser...
echo.
echo   Press Ctrl+C to stop the server.
echo   ═══════════════════════════════════════════
echo.

:: Open browser after a short delay
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:3700"

:: Start server
node server.js
