@echo off
echo Security Tools Installation Script
echo ================================

:: Check Python installation
python --version 2>NUL
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in the PATH
    echo Please install Python 3.8 or higher and try again
    exit /b 1
)

:: Install Python dependencies
echo Installing Python dependencies...
pip install -r new_requirements_security_tools.txt
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install Python dependencies
    exit /b 1
)

:: Create tools directory
echo Creating tools directory...
mkdir %USERPROFILE%\.security_tools 2>NUL

:: Install security tools
echo Installing security tools...
python integrate_security_tools.py --install-all

echo.
echo Installation complete!
echo Run 'python integrate_security_tools.py --test' to verify the installation
echo Run 'python integrate_security_tools.py --list' to see available tools

pause 