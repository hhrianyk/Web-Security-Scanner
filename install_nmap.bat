@echo off
echo ==========================================
echo NMAP Installer for Windows
echo ==========================================
echo.

:: Set download URL for the latest Nmap stable version
set NMAP_URL=https://nmap.org/dist/nmap-7.94-setup.exe
set DOWNLOAD_PATH=%TEMP%\nmap-setup.exe

echo Downloading Nmap installer...
powershell -Command "Invoke-WebRequest -Uri '%NMAP_URL%' -OutFile '%DOWNLOAD_PATH%'"

if not exist "%DOWNLOAD_PATH%" (
    echo Failed to download Nmap installer.
    echo Please download manually from https://nmap.org/download.html
    goto :ERROR
)

echo.
echo Download complete. Installing Nmap...
echo.
echo Please follow the installation instructions in the Nmap setup window.
echo It is recommended to install with default settings including WinPcap.
echo.
echo Running installer now...

start /wait "" "%DOWNLOAD_PATH%" /S

echo.
echo Cleaning up temporary files...
del "%DOWNLOAD_PATH%"

echo.
echo Installation complete! 
echo Testing if Nmap is properly installed...

:: Test if nmap is accessible
nmap -V > nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo SUCCESS: Nmap has been successfully installed and is ready to use!
    echo The security script should now be able to use Nmap for port scanning.
) else (
    echo.
    echo NOTE: Nmap might be installed but not in your PATH.
    echo You may need to restart your computer for the PATH changes to take effect.
    echo After restarting, try running "nmap -V" in a command prompt.
)

echo.
echo Press any key to exit...
pause > nul
exit /b 0

:ERROR
echo.
echo Installation failed. Please try installing Nmap manually from:
echo https://nmap.org/download.html
echo.
echo Press any key to exit...
pause > nul
exit /b 1 