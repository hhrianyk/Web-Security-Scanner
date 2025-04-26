@echo off
timeout /t 5
taskkill /f /im python.exe /fi "WINDOWTITLE eq VulnerabilityScanner"
start "VulnerabilityScanner" python app.py
exit