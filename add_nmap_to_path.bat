@echo off
echo Adding Nmap to PATH temporarily for this session...
set PATH=%PATH%;C:\Program Files (x86)\Nmap
echo.

echo Adding Nmap to PATH permanently...
setx PATH "%PATH%;C:\Program Files (x86)\Nmap" /M
echo.

echo PATH updated. Changes will be fully applied after system restart.
echo You can test if Nmap is in PATH by running: nmap -V
echo.
pause
