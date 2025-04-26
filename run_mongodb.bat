@echo off
echo Creating MongoDB data directory...
md C:\data\db 2>nul

echo Starting MongoDB...
start "" mongod.exe --dbpath="C:\data\db"

echo MongoDB should be running in a separate window.
echo To verify, run: python check_mongodb.py 