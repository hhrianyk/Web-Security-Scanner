@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo     ГЕНЕРАЦИЯ ПОДРОБНЫХ ОТЧЕТОВ ОБ УЯЗВИМОСТЯХ И ЭКСПЛОЙТАХ
echo ===================================================================

set TARGET=%1
set OUTPUT_DIR=detailed_reports_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%
set OUTPUT_DIR=%OUTPUT_DIR: =0%

if "%TARGET%"=="" (
    echo ОШИБКА: Целевой хост не указан.
    echo Использование: %~nx0 [целевой_хост]
    echo Пример: %~nx0 192.168.1.1
    exit /b 1
)

echo.
echo [+] Целевой хост: %TARGET%
echo [+] Директория для отчетов: %OUTPUT_DIR%
echo.

REM Создаем директорию для отчетов
mkdir %OUTPUT_DIR% 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ОШИБКА: Не удалось создать директорию для отчетов.
    exit /b 1
)

echo [*] Запуск комплексного сканирования уязвимостей...
python unified_security_interface.py --target %TARGET% --output-dir %OUTPUT_DIR% --mode 1 --scan-type comprehensive
if %ERRORLEVEL% NEQ 0 (
    echo ОШИБКА: Не удалось выполнить сканирование уязвимостей.
    exit /b 1
)

echo.
echo [*] Генерация детального отчета об уязвимых компонентах...
python unified_security_interface.py --target %TARGET% --output-dir %OUTPUT_DIR% --mode 5 --report-type component
if %ERRORLEVEL% NEQ 0 (
    echo ПРЕДУПРЕЖДЕНИЕ: Не удалось сгенерировать отчет об уязвимых компонентах.
)

echo.
echo [*] Поиск эксплойтов для обнаруженных сервисов...
python unified_security_interface.py --target %TARGET% --output-dir %OUTPUT_DIR% --mode 6 --scan-type comprehensive
if %ERRORLEVEL% NEQ 0 (
    echo ПРЕДУПРЕЖДЕНИЕ: Не удалось выполнить поиск эксплойтов.
)

echo.
echo [*] Генерация детального отчета об эксплойтах...
python unified_security_interface.py --output-dir %OUTPUT_DIR% --mode 5 --report-type exploit
if %ERRORLEVEL% NEQ 0 (
    echo ПРЕДУПРЕЖДЕНИЕ: Не удалось сгенерировать отчет об эксплойтах.
)

echo.
echo ===================================================================
echo     ОТЧЕТЫ УСПЕШНО СГЕНЕРИРОВАНЫ
echo ===================================================================
echo.
echo Отчеты доступны в директории: %OUTPUT_DIR%
echo.
echo Список отчетов:
echo   - vulnerable_components_report.md - Детальный отчет об уязвимых компонентах
echo   - exploits_report.md - Детальная информация об эксплойтах
echo   - comprehensive_exploit_report.md - Подробный отчет по эксплойтам
echo   - documented_exploits.json - Полная информация об эксплойтах в формате JSON
echo.

echo Открыть отчет об уязвимых компонентах? [Y/N]
set /p open_report=
if /i "%open_report%"=="Y" (
    start notepad %OUTPUT_DIR%\vulnerable_components_report.md
)

echo Открыть отчет об эксплойтах? [Y/N]
set /p open_exploits=
if /i "%open_exploits%"=="Y" (
    start notepad %OUTPUT_DIR%\exploits_report.md
)

endlocal 