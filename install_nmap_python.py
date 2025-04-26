#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NMAP Installation Helper
------------------------
This script helps install the Python nmap library and checks for the nmap binary.
If the nmap binary is not found, it provides instructions on how to install it.
"""

import os
import sys
import subprocess
import platform
import webbrowser
from pathlib import Path
import time

def check_pip():
    """Check if pip is installed and install if necessary."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print("pip не установлен. Установка pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"],
                                stdout=subprocess.DEVNULL)
            return True
        except:
            print("Не удалось установить pip. Пожалуйста, установите pip вручную.")
            return False

def install_python_nmap():
    """Install python-nmap library."""
    print("Установка библиотеки python-nmap...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap"], 
                             stdout=subprocess.DEVNULL)
        print("Библиотека python-nmap успешно установлена!")
        return True
    except subprocess.CalledProcessError:
        print("Ошибка при установке библиотеки python-nmap.")
        return False

def check_nmap_installed():
    """Check if nmap is installed."""
    try:
        result = subprocess.run(["nmap", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            version = result.stdout.decode('utf-8', errors='ignore').strip().split('\n')[0]
            return True, version
        else:
            return False, None
    except FileNotFoundError:
        return False, None

def install_nmap_windows():
    """Launch the nmap installation batch file for Windows."""
    install_script = Path('install_nmap.bat')
    
    if not install_script.exists():
        print("Файл install_nmap.bat не найден в текущей директории.")
        print("Создание файла install_nmap.bat...")
        
        with open(install_script, 'w') as f:
            f.write("""@echo off
echo ==========================================
echo NMAP Installer for Windows
echo ==========================================
echo.

:: Set download URL for the latest Nmap stable version
set NMAP_URL=https://nmap.org/dist/nmap-7.94-setup.exe
set DOWNLOAD_PATH=%TEMP%\\nmap-setup.exe

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
exit /b 1""")
    
    print("Запуск установки Nmap с помощью install_nmap.bat...")
    subprocess.run(["cmd.exe", "/c", str(install_script)])

def show_install_instructions(system):
    """Show installation instructions for the current OS."""
    print("\nИнструкции по установке Nmap:")
    
    if system == "Windows":
        print("1. Загрузите установщик Nmap с https://nmap.org/download.html")
        print("2. Запустите установщик и следуйте инструкциям")
        print("3. Убедитесь, что установлен WinPcap/Npcap для полной функциональности")
        print("\nХотите открыть страницу загрузки Nmap в браузере? (д/н)")
        choice = input().lower()
        if choice.startswith('д'):
            webbrowser.open("https://nmap.org/download.html")
    
    elif system == "Darwin":  # macOS
        print("Выполните следующую команду в Terminal:")
        print("  brew install nmap")
        print("\nЕсли Homebrew не установлен, сначала установите его:")
        print("  /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
    
    elif system == "Linux":
        print("Для Debian/Ubuntu выполните следующие команды:")
        print("  sudo apt-get update")
        print("  sudo apt-get install nmap")
        print("\nДля RHEL/CentOS/Fedora выполните:")
        print("  sudo yum install nmap")
        print("\nДля Arch Linux выполните:")
        print("  sudo pacman -S nmap")

def main():
    print("="*50)
    print("Установка и проверка Nmap")
    print("="*50)
    
    system = platform.system()
    
    # Check if nmap is installed
    nmap_installed, nmap_version = check_nmap_installed()
    
    if nmap_installed:
        print(f"Nmap уже установлен: {nmap_version}")
    else:
        print("Nmap не обнаружен в системе.")
        
        if system == "Windows":
            print("Хотите автоматически установить Nmap для Windows? (д/н)")
            choice = input().lower()
            if choice.startswith('д'):
                install_nmap_windows()
            else:
                show_install_instructions(system)
        else:
            show_install_instructions(system)
    
    # Install python-nmap library
    if check_pip():
        install_python_nmap()
    
    # Final check after installation attempts
    nmap_installed, nmap_version = check_nmap_installed()
    
    print("\nИтоги установки:")
    print("-" * 20)
    print(f"Nmap: {'Установлен - ' + nmap_version if nmap_installed else 'Не установлен'}")
    
    try:
        import nmap
        print("Библиотека python-nmap: Установлена")
    except ImportError:
        print("Библиотека python-nmap: Не установлена")
    
    print("\nРабота скрипта завершена.")
    if not nmap_installed:
        print("РЕКОМЕНДАЦИЯ: После установки Nmap может потребоваться перезагрузка системы.")
    
    # Wait before exit on Windows
    if system == "Windows":
        time.sleep(3)

if __name__ == "__main__":
    main() 