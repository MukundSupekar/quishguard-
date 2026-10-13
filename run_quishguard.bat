@echo off
title QuishGuard - Cybersecurity QR Scanner
cd /d "C:\Users\Admin\Documents\Project"

echo =========================================================
echo    QUISHGUARD CYBERSOC DEFENSE PLATFORM
echo    Starting Server on http://127.0.0.1:5000...
echo =========================================================

:: Wait 1.5 seconds then open the default browser automatically
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:5000"

:: Start the Flask web application
python app.py

echo.
echo Server stopped.
pause
