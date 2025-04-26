#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import hashlib
import logging
import requests
import threading
import argparse
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ai_security_tools.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AdvancedAISecurityTools")

class AdvancedAISecurityTools:
    """
    Продвинутые инструменты AI для анализа безопасности веб-приложений.
    
    Использует передовые модели искусственного интеллекта и машинного обучения
    для обнаружения уязвимостей, их анализа и генерации рекомендаций.
    """
    
    def __init__(self, target_url: str, output_dir: str = "ai_security_reports", api_key: Optional[str] = None):
        """
        Инициализация инструментов AI для тестирования безопасности
        
        Args:
            target_url: URL целевого веб-сайта
            output_dir: Директория для сохранения отчетов
            api_key: API ключ для внешних сервисов (опционально)
        """
        self.target_url = self._validate_url(target_url)
        self.output_dir = output_dir
        self.domain = urlparse(target_url).netloc
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.scan_id = hashlib.md5(f"{target_url}_{time.time()}".encode()).hexdigest()[:10]
        self.report_dir = os.path.join(output_dir, f"ai_scan_{self.scan_id}_{int(time.time())}")
        
        # Создаем директорию для отчетов
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Инициализация результатов
        self.results = {
            "scan_id": self.scan_id,
            "target_url": target_url,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "ai_analysis": {},
            "risk_score": 0,
            "recommended_fixes": []
        }
        
        logger.info(f"Initialized AI Security Tools for {target_url}")
    
    def _validate_url(self, url: str) -> str:
        """Проверка и нормализация URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def analyze_security_headers_with_ai(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Анализирует заголовки безопасности с использованием AI
        
        Args:
            headers: Словарь с HTTP заголовками
            
        Returns:
            Результаты анализа заголовков
        """
        logger.info("Analyzing security headers with AI...")
        
        # Извлечение заголовков безопасности
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy', ''),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', ''),
            'X-Frame-Options': headers.get('X-Frame-Options', ''),
            'X-XSS-Protection': headers.get('X-XSS-Protection', ''),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', ''),
            'Referrer-Policy': headers.get('Referrer-Policy', ''),
            'Feature-Policy': headers.get('Feature-Policy', ''),
            'Permissions-Policy': headers.get('Permissions-Policy', '')
        }
        
        # Анализ с помощью AI
        if self.api_key:
            try:
                # Здесь будет запрос к AI API для анализа заголовков
                # В данной реализации это эмуляция анализа
                
                analysis_results = {}
                
                # Анализ CSP
                if security_headers['Content-Security-Policy']:
                    csp = security_headers['Content-Security-Policy']
                    analysis_results['csp'] = {
                        'strength': 'strong' if "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp else 'weak',
                        'issues': [],
                        'recommendations': []
                    }
                    
                    if "'unsafe-inline'" in csp:
                        analysis_results['csp']['issues'].append("Uses 'unsafe-inline' which negates XSS protections")
                        analysis_results['csp']['recommendations'].append("Remove 'unsafe-inline' directive")
                    
                    if "'unsafe-eval'" in csp:
                        analysis_results['csp']['issues'].append("Uses 'unsafe-eval' which allows potentially dangerous code evaluation")
                        analysis_results['csp']['recommendations'].append("Remove 'unsafe-eval' directive")
                    
                    if "default-src 'self'" not in csp and "default-src *" not in csp:
                        analysis_results['csp']['issues'].append("No default-src directive specified")
                        analysis_results['csp']['recommendations'].append("Add 'default-src 'self'' directive")
                else:
                    analysis_results['csp'] = {
                        'strength': 'missing',
                        'issues': ["Content Security Policy not implemented"],
                        'recommendations': ["Implement a strong Content Security Policy to prevent XSS attacks"]
                    }
                
                # Анализ остальных заголовков
                missing_headers = []
                for header, value in security_headers.items():
                    if header != 'Content-Security-Policy' and not value:
                        missing_headers.append(header)
                
                if missing_headers:
                    analysis_results['missing_headers'] = {
                        'headers': missing_headers,
                        'recommendations': [f"Implement {header} header" for header in missing_headers]
                    }
                
                # Оценка общего уровня безопасности заголовков
                header_count = sum(1 for h in security_headers.values() if h)
                if header_count >= 6:
                    analysis_results['overall'] = {
                        'score': 'excellent',
                        'summary': "Security headers implementation is excellent"
                    }
                elif header_count >= 4:
                    analysis_results['overall'] = {
                        'score': 'good',
                        'summary': "Security headers implementation is good but could be improved"
                    }
                else:
                    analysis_results['overall'] = {
                        'score': 'poor',
                        'summary': "Security headers implementation is poor and needs significant improvement"
                    }
                
                return analysis_results
                
            except Exception as e:
                logger.error(f"Error during AI analysis of security headers: {str(e)}")
                return {'error': str(e)}
        else:
            logger.warning("API key not provided, skipping AI analysis of security headers")
            return {'error': 'API key not provided'}
    
    def analyze_vulnerabilities_with_ai(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Анализирует найденные уязвимости с помощью AI
        
        Args:
            vulnerabilities: Список обнаруженных уязвимостей
            
        Returns:
            Результаты анализа уязвимостей
        """
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities with AI...")
        
        if not vulnerabilities:
            return {
                'summary': "No vulnerabilities found to analyze",
                'risk_score': 0,
                'priority_issues': []
            }
        
        if self.api_key:
            try:
                # Эмуляция анализа AI
                
                # Группировка уязвимостей по типу и серьезности
                vuln_types = {}
                severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
                
                for vuln in vulnerabilities:
                    vuln_type = vuln.get('type', 'Unknown')
                    severity = vuln.get('severity', 'Medium')
                    
                    if vuln_type not in vuln_types:
                        vuln_types[vuln_type] = 0
                    vuln_types[vuln_type] += 1
                    
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                # Расчет риск-скора
                risk_score = (
                    severity_counts['Critical'] * 100 +
                    severity_counts['High'] * 40 +
                    severity_counts['Medium'] * 10 +
                    severity_counts['Low'] * 1
                ) / max(1, len(vulnerabilities))
                
                # Определение приоритетных проблем
                priority_issues = []
                for vuln in vulnerabilities:
                    if vuln.get('severity') in ['Critical', 'High']:
                        priority_issues.append({
                            'type': vuln.get('type'),
                            'severity': vuln.get('severity'),
                            'details': vuln.get('details'),
                            'recommendation': vuln.get('remediation', 'Fix this high priority vulnerability')
                        })
                
                # Генерация общих рекомендаций
                general_recommendations = []
                if severity_counts['Critical'] > 0:
                    general_recommendations.append("Address all critical vulnerabilities immediately")
                if severity_counts['High'] > 0:
                    general_recommendations.append("Fix high severity issues as soon as possible")
                if 'XSS' in vuln_types and vuln_types['XSS'] > 0:
                    general_recommendations.append("Implement proper output encoding and Content Security Policy to prevent XSS attacks")
                if 'SQL Injection' in vuln_types and vuln_types['SQL Injection'] > 0:
                    general_recommendations.append("Use parameterized queries or ORM to prevent SQL injection")
                
                # Формирование итогового анализа
                analysis_results = {
                    'summary': f"Found {len(vulnerabilities)} vulnerabilities across {len(vuln_types)} different types",
                    'risk_score': round(risk_score, 2),
                    'severity_distribution': severity_counts,
                    'vulnerability_types': vuln_types,
                    'priority_issues': priority_issues[:5],  # Топ-5 приоритетных проблем
                    'general_recommendations': general_recommendations
                }
                
                return analysis_results
                
            except Exception as e:
                logger.error(f"Error during AI analysis of vulnerabilities: {str(e)}")
                return {'error': str(e)}
        else:
            logger.warning("API key not provided, skipping AI analysis of vulnerabilities")
            return {'error': 'API key not provided'}
    
    def generate_attack_scenarios_with_ai(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Генерирует возможные сценарии атак на основе найденных уязвимостей
        
        Args:
            vulnerabilities: Список обнаруженных уязвимостей
            
        Returns:
            Сценарии атак
        """
        logger.info("Generating attack scenarios with AI...")
        
        if not vulnerabilities:
            return []
        
        if self.api_key:
            try:
                # Эмуляция генерации сценариев атак с помощью AI
                
                attack_scenarios = []
                
                # Проверка на наличие XSS уязвимостей
                xss_vulns = [v for v in vulnerabilities if v.get('type') == 'XSS']
                if xss_vulns:
                    attack_scenarios.append({
                        'name': 'Cross-Site Scripting Data Theft',
                        'description': 'An attacker could inject malicious scripts that steal user cookies and session data',
                        'steps': [
                            'Attacker identifies XSS vulnerability on the website',
                            'Crafts a malicious payload that steals cookies',
                            'Tricks users into clicking a link with the payload',
                            'JavaScript executes in users\' browsers and sends data to attacker'
                        ],
                        'impact': 'High - could lead to account takeover and data theft',
                        'mitigations': [
                            'Implement proper output encoding',
                            'Use Content-Security-Policy header',
                            'Validate and sanitize user input'
                        ]
                    })
                
                # Проверка на наличие SQL Injection
                sql_vulns = [v for v in vulnerabilities if v.get('type') == 'SQL Injection']
                if sql_vulns:
                    attack_scenarios.append({
                        'name': 'SQL Injection Data Breach',
                        'description': 'An attacker could extract sensitive data from the database using SQL injection',
                        'steps': [
                            'Attacker identifies SQL injection vulnerability',
                            'Uses UNION queries to map database structure',
                            'Extracts sensitive data like user credentials',
                            'Uses obtained data for further attacks or sells it'
                        ],
                        'impact': 'Critical - complete database compromise',
                        'mitigations': [
                            'Use parameterized queries or prepared statements',
                            'Implement proper input validation',
                            'Apply principle of least privilege to database users'
                        ]
                    })
                
                # Проверка на CSRF
                csrf_vulns = [v for v in vulnerabilities if 'CSRF' in v.get('type', '')]
                if csrf_vulns:
                    attack_scenarios.append({
                        'name': 'Cross-Site Request Forgery Attack',
                        'description': 'An attacker could trick users into performing unwanted actions',
                        'steps': [
                            'Attacker identifies endpoint vulnerable to CSRF',
                            'Creates a malicious website that sends hidden requests',
                            'Tricks authenticated users into visiting the malicious site',
                            'Actions are performed with the user\'s privileges'
                        ],
                        'impact': 'Medium to High - depending on the vulnerable functionality',
                        'mitigations': [
                            'Implement anti-CSRF tokens',
                            'Use SameSite cookie attribute',
                            'Verify origin and referrer headers'
                        ]
                    })
                
                # Проверка на уязвимости аутентификации
                auth_vulns = [v for v in vulnerabilities if 'Authentication' in v.get('type', '')]
                if auth_vulns:
                    attack_scenarios.append({
                        'name': 'Authentication Bypass',
                        'description': 'An attacker could bypass authentication controls to gain unauthorized access',
                        'steps': [
                            'Attacker identifies weakness in authentication mechanism',
                            'Bypasses login controls through manipulation of requests',
                            'Gains unauthorized access to protected resources',
                            'Accesses sensitive data or functionality'
                        ],
                        'impact': 'Critical - unauthorized access to protected resources',
                        'mitigations': [
                            'Implement secure authentication practices',
                            'Use multi-factor authentication',
                            'Ensure proper session management'
                        ]
                    })
                
                # Комбинированный сценарий для нескольких уязвимостей
                if len(vulnerabilities) >= 3:
                    attack_scenarios.append({
                        'name': 'Multi-Stage Advanced Persistent Threat',
                        'description': 'An attacker could chain multiple vulnerabilities for a sophisticated attack',
                        'steps': [
                            'Initial reconnaissance to map the application',
                            'Exploit of an entry-point vulnerability to gain foothold',
                            'Lateral movement through the application using multiple vulnerabilities',
                            'Data exfiltration or persistent backdoor installation'
                        ],
                        'impact': 'Critical - comprehensive compromise of the application',
                        'mitigations': [
                            'Implement defense in depth',
                            'Regular security testing and monitoring',
                            'Patch all vulnerabilities promptly',
                            'Implement zero trust architecture'
                        ]
                    })
                
                return attack_scenarios
                
            except Exception as e:
                logger.error(f"Error generating attack scenarios with AI: {str(e)}")
                return [{'error': str(e)}]
        else:
            logger.warning("API key not provided, skipping attack scenario generation")
            return [{'error': 'API key not provided'}]
    
    def generate_remediation_plan_with_ai(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Генерирует план устранения уязвимостей с помощью AI
        
        Args:
            vulnerabilities: Список обнаруженных уязвимостей
            
        Returns:
            План устранения уязвимостей
        """
        logger.info("Generating remediation plan with AI...")
        
        if not vulnerabilities:
            return {
                'summary': "No vulnerabilities found to remediate",
                'recommendations': []
            }
        
        if self.api_key:
            try:
                # Эмуляция создания плана устранения с помощью AI
                
                # Группировка уязвимостей по серьезности
                critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
                high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High']
                medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'Medium']
                low_vulns = [v for v in vulnerabilities if v.get('severity') == 'Low']
                
                # Генерация рекомендаций по устранению
                recommendations = []
                
                # Добавление рекомендаций для критических уязвимостей
                if critical_vulns:
                    for vuln in critical_vulns:
                        recommendations.append({
                            'priority': 'Immediate',
                            'vulnerability': vuln.get('type'),
                            'details': vuln.get('details'),
                            'recommendation': vuln.get('remediation', 'Fix this critical vulnerability immediately'),
                            'time_estimate': '1-3 days'
                        })
                
                # Добавление рекомендаций для уязвимостей высокой серьезности
                if high_vulns:
                    for vuln in high_vulns:
                        recommendations.append({
                            'priority': 'High',
                            'vulnerability': vuln.get('type'),
                            'details': vuln.get('details'),
                            'recommendation': vuln.get('remediation', 'Address this high severity issue soon'),
                            'time_estimate': '3-7 days'
                        })
                
                # Добавление рекомендаций для уязвимостей средней серьезности
                if medium_vulns:
                    # Группируем по типу для более лаконичных рекомендаций
                    medium_by_type = {}
                    for vuln in medium_vulns:
                        vuln_type = vuln.get('type')
                        if vuln_type not in medium_by_type:
                            medium_by_type[vuln_type] = []
                        medium_by_type[vuln_type].append(vuln)
                    
                    # Добавляем рекомендации по типам
                    for vuln_type, vulns in medium_by_type.items():
                        if len(vulns) > 1:
                            details = f"Multiple {vuln_type} issues found ({len(vulns)})"
                            remediation = next((v.get('remediation') for v in vulns if v.get('remediation')), 
                                            f"Address {vuln_type} vulnerabilities")
                        else:
                            details = vulns[0].get('details')
                            remediation = vulns[0].get('remediation', f"Fix {vuln_type} vulnerability")
                        
                        recommendations.append({
                            'priority': 'Medium',
                            'vulnerability': vuln_type,
                            'details': details,
                            'recommendation': remediation,
                            'time_estimate': '1-2 weeks'
                        })
                
                # Добавление общих рекомендаций по безопасности
                general_recommendations = [
                    {
                        'priority': 'High',
                        'vulnerability': 'General Security',
                        'details': 'Security Headers Implementation',
                        'recommendation': 'Implement all recommended security headers (CSP, HSTS, etc.)',
                        'time_estimate': '1-3 days'
                    },
                    {
                        'priority': 'Medium',
                        'vulnerability': 'General Security',
                        'details': 'Regular Security Testing',
                        'recommendation': 'Implement regular security testing and scanning',
                        'time_estimate': 'Ongoing'
                    },
                    {
                        'priority': 'Medium',
                        'vulnerability': 'General Security',
                        'details': 'Developer Training',
                        'recommendation': 'Provide security training for development team',
                        'time_estimate': '2-4 weeks'
                    }
                ]
                
                # Добавляем общие рекомендации только если есть реальные уязвимости
                if vulnerabilities:
                    recommendations.extend(general_recommendations)
                
                # Создание плана устранения
                remediation_plan = {
                    'summary': f"Remediation plan for {len(vulnerabilities)} vulnerabilities",
                    'critical_issues': len(critical_vulns),
                    'high_issues': len(high_vulns),
                    'medium_issues': len(medium_vulns),
                    'low_issues': len(low_vulns),
                    'recommendations': recommendations,
                    'estimated_completion': self._estimate_remediation_time(critical_vulns, high_vulns, medium_vulns)
                }
                
                return remediation_plan
                
            except Exception as e:
                logger.error(f"Error generating remediation plan with AI: {str(e)}")
                return {'error': str(e)}
        else:
            logger.warning("API key not provided, skipping AI remediation plan generation")
            return {'error': 'API key not provided'}
    
    def _estimate_remediation_time(self, critical_vulns, high_vulns, medium_vulns):
        """Оценка времени, необходимого для устранения уязвимостей"""
        
        # Базовые оценки времени
        critical_time = len(critical_vulns) * 2  # 2 дня на критическую уязвимость
        high_time = len(high_vulns) * 1  # 1 день на высокую уязвимость
        medium_time = len(medium_vulns) * 0.5  # 0.5 дня на среднюю уязвимость
        
        total_days = critical_time + high_time + medium_time
        
        # Корректировка для учета параллельной работы
        if total_days > 5:
            total_days = 5 + (total_days - 5) * 0.7  # Учитываем параллельную работу
        
        # Округление до ближайшего целого
        total_days = round(total_days)
        
        if total_days <= 0:
            return "Minimal time required"
        elif total_days <= 3:
            return f"Approximately {total_days} days"
        elif total_days <= 10:
            return f"Approximately 1-2 weeks"
        elif total_days <= 20:
            return f"Approximately 2-4 weeks"
        else:
            return f"More than 1 month"
    
    def analyze_code_security_with_ai(self, code_sample: str, language: str) -> Dict[str, Any]:
        """
        Анализирует безопасность кода с помощью AI
        
        Args:
            code_sample: Образец кода для анализа
            language: Язык программирования
            
        Returns:
            Результаты анализа кода
        """
        logger.info(f"Analyzing {language} code security with AI...")
        
        if not code_sample or not language:
            return {
                'error': 'No code sample or language provided'
            }
        
        if self.api_key:
            try:
                # Эмуляция анализа кода с помощью AI
                
                # Общие паттерны небезопасного кода
                security_issues = []
                
                # PHP уязвимости
                if language.lower() == 'php':
                    if 'mysql_query' in code_sample:
                        security_issues.append({
                            'type': 'SQL Injection',
                            'line': code_sample.find('mysql_query'),
                            'description': 'Usage of deprecated mysql_query function that is vulnerable to SQL injection',
                            'recommendation': 'Use prepared statements with PDO or mysqli'
                        })
                        
                    if 'exec(' in code_sample or 'shell_exec(' in code_sample or 'system(' in code_sample:
                        security_issues.append({
                            'type': 'Command Injection',
                            'line': code_sample.find('exec(') if 'exec(' in code_sample else code_sample.find('shell_exec('),
                            'description': 'Usage of shell command execution without proper input sanitization',
                            'recommendation': 'Avoid shell commands if possible, otherwise use escapeshellarg() and validate inputs'
                        })
                        
                    if 'echo $_' in code_sample:
                        security_issues.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'line': code_sample.find('echo $_'),
                            'description': 'Direct output of user input can lead to XSS vulnerabilities',
                            'recommendation': 'Use htmlspecialchars() to encode output'
                        })
                        
                # JavaScript уязвимости
                elif language.lower() == 'javascript':
                    if 'eval(' in code_sample:
                        security_issues.append({
                            'type': 'Code Injection',
                            'line': code_sample.find('eval('),
                            'description': 'Usage of eval() can lead to code injection vulnerabilities',
                            'recommendation': 'Avoid using eval(); use alternative approaches'
                        })
                        
                    if 'document.write(' in code_sample:
                        security_issues.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'line': code_sample.find('document.write('),
                            'description': 'Usage of document.write can lead to XSS vulnerabilities',
                            'recommendation': 'Use safer DOM methods like textContent or createElement'
                        })
                        
                    if 'innerHTML' in code_sample:
                        security_issues.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'line': code_sample.find('innerHTML'),
                            'description': 'Usage of innerHTML with unsanitized input can lead to XSS',
                            'recommendation': 'Use textContent instead or sanitize HTML input'
                        })
                        
                # Python уязвимости
                elif language.lower() == 'python':
                    if 'subprocess' in code_sample and ('shell=True' in code_sample or '.shell(' in code_sample):
                        security_issues.append({
                            'type': 'Command Injection',
                            'line': code_sample.find('shell=True') if 'shell=True' in code_sample else code_sample.find('.shell('),
                            'description': 'Running shell commands with shell=True is vulnerable to command injection',
                            'recommendation': 'Use shell=False and pass arguments as a list'
                        })
                        
                    if 'pickle.loads' in code_sample:
                        security_issues.append({
                            'type': 'Insecure Deserialization',
                            'line': code_sample.find('pickle.loads'),
                            'description': 'Pickle deserialization of untrusted data can lead to RCE',
                            'recommendation': 'Use safer serialization formats like JSON or implement input validation'
                        })
                        
                    if 'eval(' in code_sample:
                        security_issues.append({
                            'type': 'Code Injection',
                            'line': code_sample.find('eval('),
                            'description': 'Usage of eval() can lead to code execution vulnerabilities',
                            'recommendation': 'Avoid using eval(); use safer alternatives'
                        })
                
                # Java уязвимости
                elif language.lower() == 'java':
                    if 'executeQuery(' in code_sample and ('Statement' in code_sample or 'createStatement' in code_sample):
                        security_issues.append({
                            'type': 'SQL Injection',
                            'line': code_sample.find('executeQuery('),
                            'description': 'Usage of Statement instead of PreparedStatement can lead to SQL injection',
                            'recommendation': 'Use PreparedStatement with parameterized queries'
                        })
                        
                    if 'Runtime.getRuntime().exec(' in code_sample:
                        security_issues.append({
                            'type': 'Command Injection',
                            'line': code_sample.find('Runtime.getRuntime().exec('),
                            'description': 'Executing shell commands without proper input validation',
                            'recommendation': 'Validate and sanitize inputs, avoid shell commands if possible'
                        })
                        
                    if 'ObjectInputStream(' in code_sample or 'readObject(' in code_sample:
                        security_issues.append({
                            'type': 'Insecure Deserialization',
                            'line': code_sample.find('ObjectInputStream(') if 'ObjectInputStream(' in code_sample else code_sample.find('readObject('),
                            'description': 'Java deserialization of untrusted data can lead to RCE',
                            'recommendation': 'Use serialization filtering or safer alternatives like JSON'
                        })
                
                # Оценка общего уровня безопасности кода
                if len(security_issues) == 0:
                    security_score = 'Good'
                    summary = 'No obvious security issues detected'
                elif len(security_issues) <= 2:
                    security_score = 'Moderate'
                    summary = f'Found {len(security_issues)} potential security issues'
                else:
                    security_score = 'Poor'
                    summary = f'Found {len(security_issues)} significant security issues'
                
                # Формирование итогового анализа
                code_analysis = {
                    'language': language,
                    'security_score': security_score,
                    'summary': summary,
                    'issues': security_issues,
                    'recommendations': [issue['recommendation'] for issue in security_issues]
                }
                
                return code_analysis
                
            except Exception as e:
                logger.error(f"Error analyzing code security with AI: {str(e)}")
                return {'error': str(e)}
        else:
            logger.warning("API key not provided, skipping AI code security analysis")
            return {'error': 'API key not provided'}
    
    def analyze_website_security_posture(self, target_url: str = None) -> Dict[str, Any]:
        """
        Полный анализ безопасности веб-сайта с использованием AI
        
        Args:
            target_url: URL целевого веб-сайта (если отличается от заданного при инициализации)
            
        Returns:
            Полный анализ безопасности
        """
        logger.info(f"Starting comprehensive AI security analysis for {target_url or self.target_url}")
        
        url = target_url or self.target_url
        
        try:
            # Получение основной страницы для анализа
            response = requests.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }, timeout=10)
            
            # Анализ заголовков безопасности
            headers_analysis = self.analyze_security_headers_with_ai(response.headers)
            
            # Определение технологий на сайте (базовая эвристика)
            technologies = self._detect_technologies(response)
            
            # Базовый анализ уязвимостей (просто для примера)
            sample_vulnerabilities = self._quick_vulnerability_check(url, response)
            
            # Анализ уязвимостей с помощью AI
            vulnerabilities_analysis = self.analyze_vulnerabilities_with_ai(sample_vulnerabilities)
            
            # Генерация сценариев атак
            attack_scenarios = self.generate_attack_scenarios_with_ai(sample_vulnerabilities)
            
            # Генерация плана устранения
            remediation_plan = self.generate_remediation_plan_with_ai(sample_vulnerabilities)
            
            # Агрегация всех результатов
            security_analysis = {
                'target_url': url,
                'scan_timestamp': datetime.now().isoformat(),
                'http_status': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'headers_analysis': headers_analysis,
                'technologies': technologies,
                'sample_vulnerabilities': sample_vulnerabilities,
                'vulnerabilities_analysis': vulnerabilities_analysis,
                'attack_scenarios': attack_scenarios,
                'remediation_plan': remediation_plan,
                'risk_score': vulnerabilities_analysis.get('risk_score', 0)
            }
            
            # Сохранение результатов
            output_file = os.path.join(self.report_dir, f"ai_security_analysis_{int(time.time())}.json")
            with open(output_file, 'w') as f:
                json.dump(security_analysis, f, indent=4)
                
            logger.info(f"Security analysis completed and saved to {output_file}")
            
            return security_analysis
            
        except Exception as e:
            logger.error(f"Error in comprehensive security analysis: {str(e)}")
            return {'error': str(e)}
    
    def _detect_technologies(self, response) -> Dict[str, Any]:
        """
        Определение технологий, используемых на веб-сайте
        
        Args:
            response: Ответ на HTTP запрос
            
        Returns:
            Обнаруженные технологии
        """
        technologies = {
            'server': response.headers.get('Server', 'Unknown'),
            'framework': [],
            'cms': [],
            'javascript_libraries': [],
            'web_technologies': []
        }
        
        html = response.text.lower()
        
        # Определение CMS
        if 'wordpress' in html:
            technologies['cms'].append('WordPress')
        if 'drupal' in html:
            technologies['cms'].append('Drupal')
        if 'joomla' in html:
            technologies['cms'].append('Joomla')
        if 'shopify' in html:
            technologies['cms'].append('Shopify')
        
        # Определение JavaScript библиотек
        if 'jquery' in html:
            technologies['javascript_libraries'].append('jQuery')
        if 'react' in html:
            technologies['javascript_libraries'].append('React')
        if 'angular' in html:
            technologies['javascript_libraries'].append('Angular')
        if 'vue' in html:
            technologies['javascript_libraries'].append('Vue.js')
        
        # Определение веб-фреймворков
        if 'laravel' in html:
            technologies['framework'].append('Laravel')
        if 'django' in html:
            technologies['framework'].append('Django')
        if 'rails' in html:
            technologies['framework'].append('Ruby on Rails')
        if 'express' in html:
            technologies['framework'].append('Express.js')
        if 'spring' in html:
            technologies['framework'].append('Spring')
        
        # Определение других веб-технологий
        if 'bootstrap' in html:
            technologies['web_technologies'].append('Bootstrap')
        if 'tailwind' in html:
            technologies['web_technologies'].append('Tailwind CSS')
        if 'cloudflare' in html or 'cloudflare' in response.headers.get('Server', '').lower():
            technologies['web_technologies'].append('Cloudflare')
        if 'google tag manager' in html or 'gtm' in html:
            technologies['web_technologies'].append('Google Tag Manager')
        if 'google analytics' in html or 'ga.js' in html or 'analytics.js' in html:
            technologies['web_technologies'].append('Google Analytics')
            
        return technologies
    
    def _quick_vulnerability_check(self, url: str, response) -> List[Dict[str, Any]]:
        """
        Быстрая проверка на наличие очевидных уязвимостей
        
        Args:
            url: URL целевого веб-сайта
            response: Ответ на HTTP запрос
            
        Returns:
            Список обнаруженных уязвимостей
        """
        vulnerabilities = []
        
        # Проверка на отсутствие важных заголовков безопасности
        if 'X-Frame-Options' not in response.headers:
            vulnerabilities.append({
                'type': 'Missing Security Header',
                'severity': 'Medium',
                'details': 'X-Frame-Options header is missing, making the site vulnerable to clickjacking',
                'remediation': 'Add X-Frame-Options header set to DENY or SAMEORIGIN'
            })
            
        if 'Content-Security-Policy' not in response.headers:
            vulnerabilities.append({
                'type': 'Missing Security Header',
                'severity': 'Medium',
                'details': 'Content-Security-Policy header is missing, increasing risk of XSS attacks',
                'remediation': 'Implement a strict Content Security Policy'
            })
            
        if 'Strict-Transport-Security' not in response.headers and urlparse(url).scheme == 'https':
            vulnerabilities.append({
                'type': 'Missing Security Header',
                'severity': 'Medium',
                'details': 'HTTP Strict Transport Security (HSTS) header is missing on HTTPS site',
                'remediation': 'Add Strict-Transport-Security header with appropriate max-age value'
            })
            
        # Проверка на использование устаревших версий TLS
        if urlparse(url).scheme == 'https':
            try:
                hostname = urlparse(url).netloc
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocol = ssock.version()
                        if protocol < ssl.PROTOCOL_TLSv1_2:
                            vulnerabilities.append({
                                'type': 'Insecure TLS Version',
                                'severity': 'High',
                                'details': f'Site uses outdated TLS protocol version: {protocol}',
                                'remediation': 'Configure server to use TLS 1.2 or 1.3 only'
                            })
            except:
                pass
                
        # Проверка на явные признаки XSS уязвимостей
        if 'document.location' in response.text or 'document.URL' in response.text:
            vulnerabilities.append({
                'type': 'Potential XSS',
                'severity': 'Medium',
                'details': 'Website uses document.location or document.URL which could lead to DOM-based XSS',
                'remediation': 'Use safer alternatives or properly sanitize location data before using'
            })
            
        # Проверка на использование небезопасных JavaScript функций
        if 'eval(' in response.text:
            vulnerabilities.append({
                'type': 'Unsafe JavaScript',
                'severity': 'Medium',
                'details': 'Website uses eval() which can lead to code injection vulnerabilities',
                'remediation': 'Avoid using eval() and use safer alternatives'
            })
            
        # Проверка на устаревшие библиотеки
        if 'jquery-1.' in response.text or 'jquery-2.' in response.text:
            vulnerabilities.append({
                'type': 'Outdated Library',
                'severity': 'Medium',
                'details': 'Website uses outdated jQuery library which may contain known vulnerabilities',
                'remediation': 'Update to the latest version of jQuery'
            })
            
        return vulnerabilities
    
    def save_results(self, output_name: str = None) -> str:
        """
        Сохраняет результаты анализа в JSON файл
        
        Args:
            output_name: Имя выходного файла (опционально)
            
        Returns:
            Путь к сохраненному файлу
        """
        filename = output_name or f"ai_security_analysis_{int(time.time())}.json"
        output_file = os.path.join(self.report_dir, filename)
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        logger.info(f"Results saved to {output_file}")
        return output_file

def main():
    """Запуск инструмента из командной строки"""
    parser = argparse.ArgumentParser(description="Advanced AI Security Analysis Tools")
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--output", "-o", default="ai_security_reports", help="Output directory for reports")
    parser.add_argument("--api-key", "-k", help="API key for AI services")
    
    args = parser.parse_args()
    
    # Инициализация инструмента
    ai_tools = AdvancedAISecurityTools(args.url, args.output, args.api_key)
    
    # Проведение полного анализа
    security_analysis = ai_tools.analyze_website_security_posture()
    
    print(f"\nSecurity analysis completed!")
    print(f"Risk score: {security_analysis.get('risk_score', 'N/A')}")
    print(f"Found {len(security_analysis.get('sample_vulnerabilities', []))} potential vulnerabilities")
    print(f"Results saved to: {ai_tools.report_dir}")
    
if __name__ == "__main__":
    main() 