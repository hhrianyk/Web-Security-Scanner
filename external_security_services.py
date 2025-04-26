#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import logging
import requests
import subprocess
import shutil
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("external_security_services.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ExternalSecurityServices")

class ExternalSecurityServices:
    """
    Интегратор внешних инструментов и сервисов для тестирования безопасности.
    
    Включает поддержку популярных инструментов сканирования, таких как:
    - Acunetix
    - Burp Suite
    - OWASP ZAP
    - Nessus
    - Nikto
    - Nuclei
    - Аутсорсинговые сервисы сканирования (HackerOne, Bugcrowd)
    """
    
    def __init__(self, target_url: str, output_dir: str = "external_security_reports", scan_id: str = None):
        """
        Инициализация интегратора внешних сервисов
        
        Args:
            target_url: URL целевого веб-сайта
            output_dir: Директория для сохранения отчетов
            scan_id: Идентификатор сканирования
        """
        self.target_url = self._validate_url(target_url)
        self.output_dir = output_dir
        self.scan_id = scan_id or f"ext_{int(time.time())}"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = os.path.join(output_dir, f"scan_{self.scan_id}_{self.timestamp}")
        
        # Создаем директорию для отчетов
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Инициализация результатов
        self.results = {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target_url": target_url,
            "status": "Initialized",
            "services_used": [],
            "vulnerabilities": [],
            "reports": {}
        }
        
        # Проверка наличия внешних инструментов
        self.available_tools = self._check_available_tools()
        
        logger.info(f"Initialized ExternalSecurityServices for {target_url}")
        logger.info(f"Available external tools: {', '.join(self.available_tools.keys())}")
    
    def _validate_url(self, url: str) -> str:
        """Проверка и нормализация URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """
        Проверка наличия внешних инструментов в системе
        
        Returns:
            Словарь доступных инструментов
        """
        tools = {
            "zap": False,
            "nikto": False,
            "nuclei": False,
            "nmap": False,
            "wpscan": False,
            "sqlmap": False,
            "dirb": False,
            "gobuster": False,
            "amass": False,
            "subfinder": False,
            "masscan": False,
            "wfuzz": False,
            "hydra": False,
            "skipfish": False,
            "nessus": False,
            "metasploit": False,
            "burpsuite": False,
            "acunetix": False
        }
        
        # Проверка наличия исполняемых файлов
        for tool in ["nikto", "nmap", "sqlmap", "dirb", "gobuster", "amass", "subfinder", "masscan", 
                     "wfuzz", "hydra", "skipfish", "wpscan", "nuclei"]:
            if shutil.which(tool):
                tools[tool] = True
                
        # Специальные проверки для некоторых инструментов
        
        # ZAP
        try:
            from zapv2 import ZAPv2
            tools["zap"] = True
        except ImportError:
            pass
            
        # Nessus (проверка наличия API ключа)
        if os.environ.get("NESSUS_API_KEY") and os.environ.get("NESSUS_URL"):
            tools["nessus"] = True
            
        # Metasploit
        if shutil.which("msfconsole"):
            tools["metasploit"] = True
            
        # Burp Suite (проверка наличия API ключа для Burp Enterprise)
        if os.environ.get("BURP_API_KEY") and os.environ.get("BURP_URL"):
            tools["burpsuite"] = True
            
        # Acunetix
        if os.environ.get("ACUNETIX_API_KEY") and os.environ.get("ACUNETIX_URL"):
            tools["acunetix"] = True
            
        return tools
    
    def run_zap_scan(self) -> Dict[str, Any]:
        """
        Запуск сканирования с помощью OWASP ZAP
        
        Returns:
            Результаты сканирования
        """
        if not self.available_tools.get("zap", False):
            logger.warning("OWASP ZAP is not available")
            return {"error": "OWASP ZAP is not available"}
            
        logger.info(f"Starting OWASP ZAP scan for {self.target_url}")
        
        try:
            # Импортируем ZAP API
            from zapv2 import ZAPv2
            
            # Настройки ZAP
            zap_proxy = os.environ.get("ZAP_PROXY", "localhost:8080")
            api_key = os.environ.get("ZAP_API_KEY", None)
            
            # Инициализация ZAP
            zap = ZAPv2(proxies={'http': zap_proxy, 'https': zap_proxy}, apikey=api_key)
            
            # Доступ к целевому сайту
            logger.info(f"Accessing target: {self.target_url}")
            zap.urlopen(self.target_url)
            
            # Сканирование сайта
            logger.info("Starting ZAP spider")
            scan_id = zap.spider.scan(self.target_url)
            
            # Ожидание завершения сканирования
            time.sleep(2)
            while int(zap.spider.status(scan_id)) < 100:
                logger.info(f"Spider progress: {zap.spider.status(scan_id)}%")
                time.sleep(5)
                
            logger.info("Spider completed")
            
            # Активное сканирование
            logger.info("Starting ZAP active scan")
            ascan_id = zap.ascan.scan(self.target_url)
            
            # Ожидание завершения активного сканирования
            time.sleep(2)
            while int(zap.ascan.status(ascan_id)) < 100:
                logger.info(f"Active scan progress: {zap.ascan.status(ascan_id)}%")
                time.sleep(5)
                
            logger.info("Active scan completed")
            
            # Получение результатов
            alerts = zap.core.alerts()
            
            # Сохранение отчета
            report_path = os.path.join(self.report_dir, "zap_report.json")
            with open(report_path, 'w') as f:
                json.dump(alerts, f, indent=4)
                
            # Преобразование результатов в общий формат
            vulnerabilities = []
            for alert in alerts:
                severity = "Info"
                if alert.get("risk") == "High":
                    severity = "High"
                elif alert.get("risk") == "Medium":
                    severity = "Medium"
                elif alert.get("risk") == "Low":
                    severity = "Low"
                    
                vulnerabilities.append({
                    "type": alert.get("name", "Unknown"),
                    "severity": severity,
                    "details": alert.get("description", ""),
                    "url": alert.get("url", ""),
                    "solution": alert.get("solution", ""),
                    "source": "OWASP ZAP"
                })
                
            # Обновление результатов
            self.results["services_used"].append("OWASP ZAP")
            self.results["vulnerabilities"].extend(vulnerabilities)
            self.results["reports"]["zap"] = {
                "report_path": report_path,
                "vulnerabilities_count": len(vulnerabilities),
                "timestamp": datetime.now().isoformat()
            }
            
            return {
                "status": "completed",
                "vulnerabilities": vulnerabilities,
                "report_path": report_path
            }
            
        except Exception as e:
            logger.error(f"Error during ZAP scan: {str(e)}")
            return {"error": str(e)}
    
    def run_nikto_scan(self) -> Dict[str, Any]:
        """
        Запуск сканирования с помощью Nikto
        
        Returns:
            Результаты сканирования
        """
        if not self.available_tools.get("nikto", False):
            logger.warning("Nikto is not available")
            return {"error": "Nikto is not available"}
            
        logger.info(f"Starting Nikto scan for {self.target_url}")
        
        try:
            # Подготовка путей для отчетов
            txt_report_path = os.path.join(self.report_dir, "nikto_report.txt")
            json_report_path = os.path.join(self.report_dir, "nikto_report.json")
            
            # Формирование команды
            command = [
                "nikto", 
                "-h", self.target_url,
                "-o", txt_report_path,
                "-Format", "json",
                "-Output", json_report_path
            ]
            
            # Запуск команды
            logger.info(f"Running command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nikto scan failed: {stderr.decode()}")
                return {"error": stderr.decode()}
                
            logger.info("Nikto scan completed")
            
            # Чтение результатов
            if os.path.exists(json_report_path):
                with open(json_report_path, 'r') as f:
                    nikto_results = json.load(f)
            else:
                logger.warning(f"Nikto JSON report not found at {json_report_path}")
                nikto_results = {"vulnerabilities": []}
                
            # Преобразование результатов в общий формат
            vulnerabilities = []
            
            if "vulnerabilities" in nikto_results:
                for vuln in nikto_results["vulnerabilities"]:
                    severity = "Medium"  # По умолчанию для Nikto
                    
                    # Попытка определить серьезность на основе описания
                    if any(x in vuln.get("description", "").lower() for x in ["critical", "высокая", "high"]):
                        severity = "High"
                    elif any(x in vuln.get("description", "").lower() for x in ["low", "низкая", "info"]):
                        severity = "Low"
                        
                    vulnerabilities.append({
                        "type": vuln.get("title", "Unknown"),
                        "severity": severity,
                        "details": vuln.get("description", ""),
                        "url": vuln.get("url", self.target_url),
                        "solution": "Check Nikto documentation for remediation steps",
                        "source": "Nikto"
                    })
            
            # Обновление результатов
            self.results["services_used"].append("Nikto")
            self.results["vulnerabilities"].extend(vulnerabilities)
            self.results["reports"]["nikto"] = {
                "report_path": json_report_path,
                "txt_report_path": txt_report_path,
                "vulnerabilities_count": len(vulnerabilities),
                "timestamp": datetime.now().isoformat()
            }
            
            return {
                "status": "completed",
                "vulnerabilities": vulnerabilities,
                "report_path": json_report_path
            }
            
        except Exception as e:
            logger.error(f"Error during Nikto scan: {str(e)}")
            return {"error": str(e)}
    
    def run_nuclei_scan(self) -> Dict[str, Any]:
        """
        Запуск сканирования с помощью Nuclei
        
        Returns:
            Результаты сканирования
        """
        if not self.available_tools.get("nuclei", False):
            logger.warning("Nuclei is not available")
            return {"error": "Nuclei is not available"}
            
        logger.info(f"Starting Nuclei scan for {self.target_url}")
        
        try:
            # Подготовка путей для отчетов
            json_report_path = os.path.join(self.report_dir, "nuclei_report.json")
            
            # Формирование команды
            command = [
                "nuclei", 
                "-u", self.target_url,
                "-json",
                "-o", json_report_path,
                "-severity", "low,medium,high,critical",
                "-stats"
            ]
            
            # Запуск команды
            logger.info(f"Running command: {' '.join(command)}")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nuclei scan failed: {stderr.decode()}")
                return {"error": stderr.decode()}
                
            logger.info("Nuclei scan completed")
            
            # Чтение результатов
            vulnerabilities = []
            
            if os.path.exists(json_report_path):
                # Nuclei создает файл с одним JSON-объектом на строку, поэтому читаем построчно
                with open(json_report_path, 'r') as f:
                    for line in f:
                        try:
                            finding = json.loads(line.strip())
                            
                            severity = "Medium"
                            if "info" in finding and "severity" in finding["info"]:
                                severity = finding["info"]["severity"].capitalize()
                                
                            vulnerabilities.append({
                                "type": finding.get("info", {}).get("name", "Unknown"),
                                "severity": severity,
                                "details": finding.get("info", {}).get("description", ""),
                                "url": finding.get("matched-at", self.target_url),
                                "solution": finding.get("info", {}).get("remedy", ""),
                                "source": "Nuclei",
                                "template": finding.get("template", "")
                            })
                        except json.JSONDecodeError:
                            continue
            else:
                logger.warning(f"Nuclei report not found at {json_report_path}")
            
            # Обновление результатов
            self.results["services_used"].append("Nuclei")
            self.results["vulnerabilities"].extend(vulnerabilities)
            self.results["reports"]["nuclei"] = {
                "report_path": json_report_path,
                "vulnerabilities_count": len(vulnerabilities),
                "timestamp": datetime.now().isoformat()
            }
            
            return {
                "status": "completed",
                "vulnerabilities": vulnerabilities,
                "report_path": json_report_path
            }
            
        except Exception as e:
            logger.error(f"Error during Nuclei scan: {str(e)}")
            return {"error": str(e)}
    
    def run_all_available_scans(self) -> Dict[str, Any]:
        """
        Запуск всех доступных сканирований
        
        Returns:
            Результаты всех сканирований
        """
        logger.info(f"Starting all available security scans for {self.target_url}")
        
        # Словарь для хранения результатов
        scan_results = {}
        
        # ZAP сканирование
        if self.available_tools.get("zap", False):
            scan_results["zap"] = self.run_zap_scan()
            
        # Nikto сканирование
        if self.available_tools.get("nikto", False):
            scan_results["nikto"] = self.run_nikto_scan()
            
        # Nuclei сканирование
        if self.available_tools.get("nuclei", False):
            scan_results["nuclei"] = self.run_nuclei_scan()
            
        # Сохранение результатов
        results_path = os.path.join(self.report_dir, "external_scans_results.json")
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        logger.info(f"All scans completed. Results saved to {results_path}")
        logger.info(f"Found {len(self.results['vulnerabilities'])} vulnerabilities across {len(self.results['services_used'])} services")
        
        return {
            "status": "completed",
            "scan_results": scan_results,
            "vulnerabilities_count": len(self.results["vulnerabilities"]),
            "results_path": results_path
        }

def main():
    """Запуск системы из командной строки"""
    import argparse
    
    parser = argparse.ArgumentParser(description="External Security Services Integration")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--output", "-o", default="external_security_reports", help="Output directory for reports")
    
    args = parser.parse_args()
    
    # Инициализация и запуск
    scanner = ExternalSecurityServices(args.url, args.output)
    logger.info(f"Available tools: {', '.join(tool for tool, available in scanner.available_tools.items() if available)}")
    
    results = scanner.run_all_available_scans()
    
    print(f"\nScans completed!")
    print(f"Found {results['vulnerabilities_count']} vulnerabilities")
    print(f"Results saved to: {results['results_path']}")

if __name__ == "__main__":
    main() 