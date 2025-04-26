@echo off
echo ==========================================
echo Установка и тестирование Nmap
echo ==========================================
echo.

echo Что вы хотите сделать?
echo 1. Установить Nmap
echo 2. Установить python-nmap библиотеку
echo 3. Протестировать установку Nmap
echo 4. Выполнить все действия (1-3)
echo 5. Выход
echo.

set /p choice="Введите номер (1-5): "

if "%choice%"=="1" (
    call :install_nmap
) else if "%choice%"=="2" (
    call :install_python_nmap
) else if "%choice%"=="3" (
    call :test_nmap
) else if "%choice%"=="4" (
    call :install_nmap
    call :install_python_nmap
    call :test_nmap
) else if "%choice%"=="5" (
    exit /b 0
) else (
    echo Неверный выбор!
    exit /b 1
)

echo.
echo Все операции завершены.
echo После установки Nmap может потребоваться перезагрузка компьютера.
echo.
pause
exit /b 0

:install_nmap
echo.
echo Установка Nmap...
echo.
if exist install_nmap.bat (
    call install_nmap.bat
) else (
    echo Файл install_nmap.bat не найден.
    echo Создание файла...
    
    (
        echo @echo off
        echo echo ==========================================
        echo echo NMAP Installer for Windows
        echo echo ==========================================
        echo echo.
        echo.
        echo :: Set download URL for the latest Nmap stable version
        echo set NMAP_URL=https://nmap.org/dist/nmap-7.94-setup.exe
        echo set DOWNLOAD_PATH=%%TEMP%%\nmap-setup.exe
        echo.
        echo echo Downloading Nmap installer...
        echo powershell -Command "Invoke-WebRequest -Uri '%%NMAP_URL%%' -OutFile '%%DOWNLOAD_PATH%%'"
        echo.
        echo if not exist "%%DOWNLOAD_PATH%%" (
        echo     echo Failed to download Nmap installer.
        echo     echo Please download manually from https://nmap.org/download.html
        echo     goto :ERROR
        echo ^)
        echo.
        echo echo.
        echo echo Download complete. Installing Nmap...
        echo echo.
        echo echo Please follow the installation instructions in the Nmap setup window.
        echo echo It is recommended to install with default settings including WinPcap.
        echo echo.
        echo echo Running installer now...
        echo.
        echo start /wait "" "%%DOWNLOAD_PATH%%" /S
        echo.
        echo echo.
        echo echo Cleaning up temporary files...
        echo del "%%DOWNLOAD_PATH%%"
        echo.
        echo echo.
        echo echo Installation complete! 
        echo echo Testing if Nmap is properly installed...
        echo.
        echo :: Test if nmap is accessible
        echo nmap -V ^> nul 2^>^&1
        echo if %%errorlevel%% equ 0 (
        echo     echo.
        echo     echo SUCCESS: Nmap has been successfully installed and is ready to use!
        echo     echo The security script should now be able to use Nmap for port scanning.
        echo ^) else (
        echo     echo.
        echo     echo NOTE: Nmap might be installed but not in your PATH.
        echo     echo You may need to restart your computer for the PATH changes to take effect.
        echo     echo After restarting, try running "nmap -V" in a command prompt.
        echo ^)
        echo.
        echo echo.
        echo echo Press any key to exit...
        echo pause ^> nul
        echo exit /b 0
        echo.
        echo :ERROR
        echo echo.
        echo echo Installation failed. Please try installing Nmap manually from:
        echo echo https://nmap.org/download.html
        echo echo.
        echo echo Press any key to exit...
        echo pause ^> nul
        echo exit /b 1
    ) > install_nmap.bat
    
    call install_nmap.bat
)
exit /b 0

:install_python_nmap
echo.
echo Установка python-nmap библиотеки...
echo.
python -m pip install python-nmap
if %errorlevel% equ 0 (
    echo Python-nmap успешно установлен!
) else (
    echo Ошибка установки python-nmap.
)
exit /b 0

:test_nmap
echo.
echo Тестирование установки Nmap...
echo.
if exist test_nmap.py (
    python test_nmap.py
) else (
    echo Файл test_nmap.py не найден.
    echo Проверка Nmap вручную...
    
    nmap -V > nul 2>&1
    if %errorlevel% equ 0 (
        echo Nmap установлен и работает правильно!
        nmap -V
    ) else (
        echo Nmap не найден или не добавлен в PATH.
        echo Возможно, требуется перезагрузка компьютера после установки.
    )
    
    python -c "import nmap; print('Python-nmap установлен и импортируется успешно!')" 2>nul
    if %errorlevel% equ 0 (
        echo Python-nmap установлен и работает правильно!
    ) else (
        echo Python-nmap не установлен или возникла ошибка при импорте.
    )
)
exit /b 0 