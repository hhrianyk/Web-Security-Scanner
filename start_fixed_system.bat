@echo off
echo ===================================================
echo Starting the Security System with All Fixes Applied
echo ===================================================
echo.

:: Step 1: Check if MongoDB is running and start it if needed
echo Step 1: Checking MongoDB status...
python check_mongodb.py >nul 2>&1
if %errorlevel% neq 0 (
    echo MongoDB is not running, starting it now...
    start "MongoDB Server" python run_mongodb.py
    timeout /t 5 /nobreak >nul
) else (
    echo MongoDB is already running.
)

:: Step 2: Verify all fixes are applied
echo.
echo Step 2: Verifying system fixes...
python fix_issues.py
if %errorlevel% neq 0 (
    echo.
    echo Warning: Some issues may still exist in the system.
    echo Review the output above before continuing.
    echo.
    pause
)

:: Step 3: Start the main application
echo.
echo Step 3: Starting the main application...
echo.
python app.py

:: End
echo.
echo System shutdown.
pause 