@echo off
echo === MongoDB and Application Starter ===

echo Checking MongoDB connection...
python check_mongodb.py > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Starting MongoDB server...
    start "" "C:\Program Files\MongoDB\mongodb-win32-x86_64-windows-6.0.8\bin\mongod.exe" --dbpath="C:\data\db"
    echo Waiting for MongoDB to start...
    timeout /t 5 > nul
)

echo Starting application...
python app.py 