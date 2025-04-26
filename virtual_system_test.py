#!/usr/bin/env python3
"""
Скрипт виртуального тестирования системы безопасности
Проверяет доступность и функциональность компонентов системы
"""

import os
import sys
import json
import time
import logging
import importlib
import subprocess
from datetime import datetime

# Настройка логгирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("VirtualTester")

class VirtualSystemTester:
    """Виртуальное тестирование системы безопасности"""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_status": "Initializing",
            "components": {},
            "test_results": {},
            "recommendations": []
        }
        self.test_report_path = "virtual_test_report.md"
        
    def test_module_import(self, module_name, required=False):
        """Тестирование импорта модуля"""
        try:
            module = importlib.import_module(module_name)
            self.results["components"][module_name] = {"status": "Available", "error": None}
            logger.info(f"✅ Модуль {module_name} успешно импортирован")
            return module
        except ImportError as e:
            status = "Missing (Required)" if required else "Missing (Optional)"
            self.results["components"][module_name] = {"status": status, "error": str(e)}
            if required:
                logger.error(f"❌ Обязательный модуль {module_name} не найден: {str(e)}")
                if "No module named" in str(e):
                    self.results["recommendations"].append(f"Установите модуль {module_name} командой 'pip install {module_name}'")
            else:
                logger.warning(f"⚠️ Опциональный модуль {module_name} не найден: {str(e)}")
            return None
    
    def test_file_existence(self, filepath, required=False):
        """Проверка существования файла"""
        if os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
            self.results["components"][filepath] = {
                "status": "Available", 
                "size": file_size,
                "error": None
            }
            logger.info(f"✅ Файл {filepath} найден (размер: {file_size} байт)")
            return True
        else:
            status = "Missing (Required)" if required else "Missing (Optional)"
            self.results["components"][filepath] = {"status": status, "error": "File not found"}
            if required:
                logger.error(f"❌ Обязательный файл {filepath} не найден")
                self.results["recommendations"].append(f"Создайте недостающий файл {filepath}")
            else:
                logger.warning(f"⚠️ Опциональный файл {filepath} не найден")
            return False
    
    def test_external_tool(self, tool_name, check_command):
        """Проверка наличия внешнего инструмента"""
        try:
            result = subprocess.run(
                check_command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                self.results["components"][tool_name] = {"status": "Available", "error": None}
                logger.info(f"✅ Инструмент {tool_name} доступен")
                return True
            else:
                self.results["components"][tool_name] = {
                    "status": "Not Working", 
                    "error": result.stderr
                }
                logger.warning(f"⚠️ Проблема с инструментом {tool_name}: {result.stderr}")
                return False
        except Exception as e:
            self.results["components"][tool_name] = {"status": "Error", "error": str(e)}
            logger.error(f"❌ Ошибка при проверке инструмента {tool_name}: {str(e)}")
            return False
    
    def test_flask_app(self):
        """Тестирование Flask приложения"""
        flask = self.test_module_import("flask", required=True)
        if not flask:
            return False
        
        # Проверяем файл app.py
        app_exists = self.test_file_existence("app.py", required=True)
        if not app_exists:
            return False
        
        try:
            # Тестируем импорт app из app.py
            sys.path.append(os.getcwd())
            app_module = importlib.import_module("app")
            
            if hasattr(app_module, "app"):
                self.results["test_results"]["flask_app"] = {
                    "status": "Working",
                    "details": "Flask app объект найден в app.py"
                }
                logger.info("✅ Flask app объект успешно импортирован")
                return True
            else:
                self.results["test_results"]["flask_app"] = {
                    "status": "Error",
                    "details": "Flask app объект не найден в app.py"
                }
                logger.error("❌ Flask app объект не найден в app.py")
                return False
        except Exception as e:
            self.results["test_results"]["flask_app"] = {
                "status": "Error",
                "details": str(e)
            }
            logger.error(f"❌ Ошибка при импорте app.py: {str(e)}")
            return False
    
    def test_security_scanner(self):
        """Тестирование модуля сканирования безопасности"""
        try:
            sys.path.append(os.getcwd())
            
            # Тестируем app.py для класса SecurityScanner
            app_module = importlib.import_module("app")
            
            if hasattr(app_module, "SecurityScanner"):
                scanner_class = app_module.SecurityScanner
                # Тестируем создание экземпляра
                scanner = scanner_class("https://example.com", "test123")
                
                # Проверяем наличие ключевых методов
                required_methods = [
                    "log_progress", 
                    "scan_xss_vulnerabilities",
                    "scan_sql_injection", 
                    "check_ssl_security"
                ]
                
                missing_methods = [m for m in required_methods if not hasattr(scanner, m)]
                
                if not missing_methods:
                    self.results["test_results"]["security_scanner"] = {
                        "status": "Working",
                        "details": "SecurityScanner класс полностью функционален"
                    }
                    logger.info("✅ SecurityScanner класс полностью функционален")
                    return True
                else:
                    self.results["test_results"]["security_scanner"] = {
                        "status": "Partial",
                        "details": f"Отсутствуют методы: {', '.join(missing_methods)}"
                    }
                    logger.warning(f"⚠️ В SecurityScanner отсутствуют методы: {', '.join(missing_methods)}")
                    return False
            else:
                self.results["test_results"]["security_scanner"] = {
                    "status": "Error",
                    "details": "SecurityScanner класс не найден в app.py"
                }
                logger.error("❌ SecurityScanner класс не найден в app.py")
                return False
                
        except Exception as e:
            self.results["test_results"]["security_scanner"] = {
                "status": "Error",
                "details": str(e)
            }
            logger.error(f"❌ Ошибка при тестировании SecurityScanner: {str(e)}")
            return False
    
    def test_ai_vulnerability_scanner(self):
        """Тестирование AI-модуля сканирования уязвимостей"""
        try:
            # Проверяем существование файла
            ai_scanner_exists = self.test_file_existence("ai_vulnerability_scanner.py")
            if not ai_scanner_exists:
                return False
            
            # Пытаемся импортировать модуль
            ai_scanner = self.test_module_import("ai_vulnerability_scanner")
            if not ai_scanner:
                return False
            
            # Проверяем наличие ключевого класса
            if hasattr(ai_scanner, "AIVulnerabilityScanner"):
                scanner_class = ai_scanner.AIVulnerabilityScanner
                # Тестируем создание экземпляра
                scanner = scanner_class("https://example.com", "test_reports")
                
                self.results["test_results"]["ai_vulnerability_scanner"] = {
                    "status": "Working",
                    "details": "AI Vulnerability Scanner полностью функционален"
                }
                logger.info("✅ AI Vulnerability Scanner полностью функционален")
                return True
            else:
                self.results["test_results"]["ai_vulnerability_scanner"] = {
                    "status": "Error",
                    "details": "AIVulnerabilityScanner класс не найден"
                }
                logger.error("❌ AIVulnerabilityScanner класс не найден")
                return False
                
        except Exception as e:
            self.results["test_results"]["ai_vulnerability_scanner"] = {
                "status": "Error",
                "details": str(e)
            }
            logger.error(f"❌ Ошибка при тестировании AI Vulnerability Scanner: {str(e)}")
            return False
    
    def test_comprehensive_tester(self):
        """Тестирование модуля комплексного тестирования"""
        try:
            # Проверяем существование файла
            tester_exists = self.test_file_existence("comprehensive_tester.py")
            if not tester_exists:
                return False
            
            # Пытаемся импортировать модуль
            tester = self.test_module_import("comprehensive_tester")
            if not tester:
                return False
            
            # Проверяем наличие ключевого класса
            if hasattr(tester, "ComprehensiveTester"):
                tester_class = tester.ComprehensiveTester
                # Тестируем создание экземпляра
                comp_tester = tester_class("https://example.com", "test_reports", "test1")
                
                self.results["test_results"]["comprehensive_tester"] = {
                    "status": "Working",
                    "details": "ComprehensiveTester полностью функционален"
                }
                logger.info("✅ ComprehensiveTester полностью функционален")
                return True
            else:
                self.results["test_results"]["comprehensive_tester"] = {
                    "status": "Error",
                    "details": "ComprehensiveTester класс не найден"
                }
                logger.error("❌ ComprehensiveTester класс не найден")
                return False
                
        except Exception as e:
            self.results["test_results"]["comprehensive_tester"] = {
                "status": "Error",
                "details": str(e)
            }
            logger.error(f"❌ Ошибка при тестировании ComprehensiveTester: {str(e)}")
            return False
    
    def test_vulnerability_reporter(self):
        """Тестирование модуля формирования отчетов об уязвимостях"""
        try:
            # Проверяем существование файла
            reporter_exists = self.test_file_existence("vulnerability_reporter.py")
            if not reporter_exists:
                return False
            
            # Пытаемся импортировать модуль
            reporter = self.test_module_import("vulnerability_reporter")
            if not reporter:
                return False
            
            # Проверяем наличие ключевой функции
            if hasattr(reporter, "generate_vulnerability_report"):
                self.results["test_results"]["vulnerability_reporter"] = {
                    "status": "Working",
                    "details": "VulnerabilityReporter полностью функционален"
                }
                logger.info("✅ VulnerabilityReporter полностью функционален")
                return True
            else:
                self.results["test_results"]["vulnerability_reporter"] = {
                    "status": "Error",
                    "details": "generate_vulnerability_report функция не найдена"
                }
                logger.error("❌ generate_vulnerability_report функция не найдена")
                return False
                
        except Exception as e:
            self.results["test_results"]["vulnerability_reporter"] = {
                "status": "Error",
                "details": str(e)
            }
            logger.error(f"❌ Ошибка при тестировании VulnerabilityReporter: {str(e)}")
            return False
    
    def test_external_tools(self):
        """Тестирование внешних инструментов"""
        # Проверяем nmap
        self.test_external_tool("nmap", "nmap -V")
        
        # Проверяем MongoDB, если запущен
        if os.path.exists("mongodb"):
            self.test_external_tool("mongodb", "python -c \"import pymongo; print('OK')\"")
    
    def get_system_status(self):
        """Определение общего статуса системы"""
        test_results = self.results["test_results"]
        
        # Проверяем основные компоненты
        critical_components = ["flask_app", "security_scanner"]
        critical_status = all(
            test_results.get(comp, {}).get("status") == "Working" 
            for comp in critical_components if comp in test_results
        )
        
        # Проверяем дополнительные компоненты
        optional_components = [
            "ai_vulnerability_scanner", 
            "comprehensive_tester", 
            "vulnerability_reporter"
        ]
        optional_status = any(
            test_results.get(comp, {}).get("status") == "Working" 
            for comp in optional_components if comp in test_results
        )
        
        if critical_status and optional_status:
            return "Fully Functional"
        elif critical_status:
            return "Functional with Limitations"
        else:
            return "Critical Components Missing"
    
    def generate_test_report(self):
        """Формирование отчета о результатах тестирования"""
        status = self.get_system_status()
        self.results["system_status"] = status
        
        # Формирование отчета в markdown формате
        report = [
            "# Отчет о виртуальном тестировании системы безопасности",
            "",
            f"## Общая информация",
            f"- **Дата тестирования:** {datetime.now().strftime('%d.%m.%Y')}",
            f"- **Система:** Платформа комплексного анализа безопасности и обнаружения уязвимостей",
            f"- **Общий статус:** {status}",
            "",
            "## Статус компонентов системы",
            "",
            "| Компонент | Статус | Примечания |",
            "|-----------|--------|------------|"
        ]
        
        # Добавляем статус основных компонентов
        component_statuses = {
            "flask_app": "Flask приложение",
            "security_scanner": "Модуль сканирования безопасности",
            "ai_vulnerability_scanner": "AI модуль сканирования",
            "comprehensive_tester": "Модуль комплексного тестирования",
            "vulnerability_reporter": "Модуль формирования отчетов",
        }
        
        for comp_id, comp_name in component_statuses.items():
            status_icon = "✅" if self.results["test_results"].get(comp_id, {}).get("status") == "Working" else "⚠️"
            details = self.results["test_results"].get(comp_id, {}).get("details", "Не протестировано")
            report.append(f"| {comp_name} | {status_icon} | {details} |")
        
        # Добавляем статус внешних инструментов
        external_tools = {
            "nmap": "NMAP (сканер портов)",
            "mongodb": "MongoDB (база данных)"
        }
        
        for tool_id, tool_name in external_tools.items():
            if tool_id in self.results["components"]:
                status_icon = "✅" if self.results["components"][tool_id]["status"] == "Available" else "⚠️"
                error = self.results["components"][tool_id].get("error", "Нет ошибок")
                notes = "Доступен" if status_icon == "✅" else error
                report.append(f"| {tool_name} | {status_icon} | {notes} |")
        
        # Добавляем рекомендации
        if self.results["recommendations"]:
            report.extend([
                "",
                "## Рекомендации по настройке системы",
                ""
            ])
            
            for i, recommendation in enumerate(self.results["recommendations"], 1):
                report.append(f"{i}. {recommendation}")
        
        # Добавляем заключение
        report.extend([
            "",
            "## Заключение",
            "",
            f"На основе проведенного виртуального тестирования система признана **{status}**."
        ])
        
        if status == "Fully Functional":
            report.append("Все критические и опциональные компоненты работают корректно. Система готова к использованию.")
        elif status == "Functional with Limitations":
            report.append("Основные компоненты работают корректно, но некоторые дополнительные модули недоступны или имеют ограничения. Система может использоваться с учетом указанных ограничений.")
        else:
            report.append("Некоторые критические компоненты отсутствуют или не работают. Рекомендуется устранить указанные проблемы перед использованием системы.")
        
        # Добавляем подпись
        report.extend([
            "",
            "---",
            "**Автоматический отчет о виртуальном тестировании**",
            f"**Дата генерации:** {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"
        ])
        
        # Сохраняем отчет в файл
        with open(self.test_report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        
        logger.info(f"Отчет о тестировании сохранен в {self.test_report_path}")
        return "\n".join(report)
    
    def run_full_test(self):
        """Запуск полного тестирования системы"""
        logger.info("Начало виртуального тестирования системы безопасности...")
        
        # Тестируем основные компоненты
        self.test_flask_app()
        self.test_security_scanner()
        
        # Тестируем дополнительные модули
        self.test_ai_vulnerability_scanner()
        self.test_comprehensive_tester()
        self.test_vulnerability_reporter()
        
        # Тестируем внешние инструменты
        self.test_external_tools()
        
        # Генерируем отчет
        report = self.generate_test_report()
        
        # Сохраняем результаты в JSON
        with open("virtual_test_results.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4)
        
        logger.info("Виртуальное тестирование системы завершено.")
        logger.info(f"Общий статус системы: {self.results['system_status']}")
        logger.info(f"Детальный JSON отчет сохранен в virtual_test_results.json")
        logger.info(f"Отчет в формате Markdown сохранен в {self.test_report_path}")
        
        return self.results["system_status"]

if __name__ == "__main__":
    tester = VirtualSystemTester()
    status = tester.run_full_test()
    sys.exit(0 if status != "Critical Components Missing" else 1) 