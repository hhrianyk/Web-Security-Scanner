@echo off
echo Creating MongoDB data directory...
md C:\data\db 2>nul

echo Starting MongoDB as a service...
sc create MongoDB binPath= "\"mongod\" --service --dbpath=\"C:\data\db\"" displayname= "MongoDB" start= auto

echo Starting MongoDB service...
net start MongoDB

echo MongoDB service should now be running.
echo To verify, run: python check_mongodb.py 