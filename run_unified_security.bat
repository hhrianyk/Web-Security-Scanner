@echo off
REM Unified Security Interface Runner
REM This script runs the unified security interface with different modes

setlocal enabledelayedexpansion

echo Unified Security Interface
echo =========================
echo.

REM Check if Python is installed
python --version > nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Python is not installed or not in PATH.
    echo Please install Python 3.8 or higher and try again.
    goto :EOF
)

REM Check if target is provided
if "%~1"=="" (
    echo Usage: %0 [target] [options]
    echo.
    echo Examples:
    echo   %0 example.com               (Comprehensive automated testing)
    echo   %0 example.com --mode 1      (Comprehensive automated testing)
    echo   %0 example.com --mode 2      (AI-powered testing)
    echo   %0 example.com --mode 3      (AI-simulated manual testing)
    echo   %0 example.com --mode 4      (Individual tool testing)
    echo   %0 example.com --mode 4 --tool vulnerability_scanner  (Test specific tool)
    echo   %0 example.com --all-modes   (Run all testing modes)
    echo   %0 --list-tools              (List available security tools)
    goto :EOF
)

REM Main menu if no specific mode is provided
if "%~2"=="" (
    echo Select testing mode:
    echo 1. Comprehensive automated testing
    echo 2. AI-powered testing
    echo 3. AI-simulated manual testing
    echo 4. Individual tool testing
    echo 5. All modes (comprehensive assessment)
    echo.
    
    set /p mode="Enter mode number (default: 1): "
    
    if "!mode!"=="" set mode=1
    if "!mode!"=="1" (
        python unified_security_interface.py %1 --mode 1
        goto :EOF
    )
    if "!mode!"=="2" (
        python unified_security_interface.py %1 --mode 2
        goto :EOF
    )
    if "!mode!"=="3" (
        python unified_security_interface.py %1 --mode 3
        goto :EOF
    )
    if "!mode!"=="4" (
        call :tool_selection %1
        goto :EOF
    )
    if "!mode!"=="5" (
        python unified_security_interface.py %1 --all-modes
        goto :EOF
    )
    
    echo Invalid mode. Please enter a number between 1 and 5.
    goto :EOF
)

REM Pass all arguments to the Python script
python unified_security_interface.py %*
goto :EOF

:tool_selection
echo.
echo Individual Tool Testing
echo ======================
echo.
python unified_security_interface.py --list-tools
echo.
set /p tool="Enter tool name (or leave empty for all tools): "

if "!tool!"=="" (
    python unified_security_interface.py %1 --mode 4
) else (
    python unified_security_interface.py %1 --mode 4 --tool !tool!
)
goto :EOF 