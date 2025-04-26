#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import argparse
import datetime
import time
import requests
import socket
import ssl
import dns.resolver
import whois
import subprocess
import nmap
import threading
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Import security testing modules if available
try:
    from injection_attacks import InjectionAttacker
    from xss_attacks import XSSAttacker
    from auth_attacks import AuthAttacker
    from vulnerability_scanner import VulnerabilityScanner
    from osint_tools import OSINTScanner
    from network_tools import NetworkTools
    from social_engineering import SocialEngineeringTester
    from security_framework import SecurityFramework
except ImportError as e:
    print(f"Warning: Some modules couldn't be imported: {e}")
    print("Only core functionality will be available")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("comprehensive_testing.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ComprehensiveTester")

class ComprehensiveTester:
    """
    Comprehensive Web Vulnerability Testing System
    
    Implements a multi-layered testing approach including:
    1. Reconnaissance (Passive and Active)
    2. Architecture Analysis
    3. Manual Testing
    4. Automated Scanning
    5. Specialized Testing
    6. In-depth Testing
    7. Security Mechanism Evaluation
    8. Resilience Testing
    9. Data Protection Verification
    10. Documentation
    """
    
    def __init__(self, target=None, output_dir="security_assessment", scan_id=None):
        self.target = target
        self.output_dir = output_dir
        self.scan_id = scan_id or str(int(time.time()))
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = os.path.join(output_dir, f"assessment_{self.timestamp}")
        
        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Initialize results structure
        self.results = {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target": target,
            "summary": {},
            "reconnaissance": {
                "passive": {},
                "active": {}
            },
            "architecture_analysis": {
                "infrastructure": {},
                "tech_stack": {}
            },
            "manual_testing": {
                "auth": {},
                "business_logic": {}
            },
            "automated_scanning": {
                "static": {},
                "dynamic": {}
            },
            "specialized_testing": {
                "api_security": {},
                "frontend_security": {}
            },
            "indepth_testing": {
                "crypto_security": {},
                "network_security": {}
            },
            "security_mechanisms": {
                "waf_testing": {},
                "ids_testing": {}
            },
            "resilience_testing": {
                "load_testing": {},
                "failover_testing": {}
            },
            "data_analysis": {
                "data_protection": {},
                "privacy": {}
            },
            "remediation": {},
            "status": "Initialized",
            "vulnerabilities": []
        }
        
        # Headers for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        logger.info(f"Initialized ComprehensiveTester for target: {target}")
    
    def log_progress(self, message, section=None):
        """Log progress and update status"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        if not hasattr(self, 'scan_logs'):
            self.scan_logs = []
            
        self.scan_logs.append(log_entry)
        self.results["status"] = message
        logger.info(message)
        
        if section:
            if "section_status" not in self.results:
                self.results["section_status"] = {}
            self.results["section_status"][section] = message
    
    def validate_target(self, target=None):
        """Validate the target URL"""
        target = target or self.target
        if not target:
            raise ValueError("No target specified")
            
        # Add schema if missing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
            
        self.target = target
        self.results["target"] = target
        return target
    
    #===========================
    # 1. RECONNAISSANCE
    #===========================
    
    def run_passive_reconnaissance(self):
        """
        Passive Reconnaissance:
          - WHOIS data
          - DNS records
          - Subdomain discovery
          - Digital footprint analysis
          - Historical site versions
        """
        self.log_progress("Starting passive reconnaissance", "passive_recon")
        
        try:
            hostname = urlparse(self.target).netloc
            passive_results = {}
            
            # WHOIS data
            try:
                whois_data = whois.whois(hostname)
                passive_results["whois"] = {
                    "domain_name": whois_data.domain_name,
                    "registrar": whois_data.registrar,
                    "creation_date": str(whois_data.creation_date),
                    "expiration_date": str(whois_data.expiration_date),
                    "name_servers": whois_data.name_servers,
                    "status": whois_data.status,
                    "emails": whois_data.emails,
                }
                self.log_progress("WHOIS data collected", "passive_recon")
            except Exception as e:
                self.log_progress(f"Error collecting WHOIS data: {str(e)}", "passive_recon")
                passive_results["whois"] = {"error": str(e)}
            
            # DNS records
            try:
                dns_results = {
                    "a_records": [],
                    "aaaa_records": [],
                    "mx_records": [],
                    "ns_records": [],
                    "txt_records": [],
                    "cname_records": []
                }
                
                # A records
                try:
                    answers = dns.resolver.resolve(hostname, 'A')
                    for rdata in answers:
                        dns_results["a_records"].append(str(rdata))
                except Exception:
                    pass
                
                # AAAA records
                try:
                    answers = dns.resolver.resolve(hostname, 'AAAA')
                    for rdata in answers:
                        dns_results["aaaa_records"].append(str(rdata))
                except Exception:
                    pass
                
                # MX records
                try:
                    answers = dns.resolver.resolve(hostname, 'MX')
                    for rdata in answers:
                        dns_results["mx_records"].append(str(rdata))
                except Exception:
                    pass
                
                # NS records
                try:
                    answers = dns.resolver.resolve(hostname, 'NS')
                    for rdata in answers:
                        dns_results["ns_records"].append(str(rdata))
                except Exception:
                    pass
                
                # TXT records
                try:
                    answers = dns.resolver.resolve(hostname, 'TXT')
                    for rdata in answers:
                        dns_results["txt_records"].append(str(rdata))
                except Exception:
                    pass
                
                # CNAME records
                try:
                    answers = dns.resolver.resolve(hostname, 'CNAME')
                    for rdata in answers:
                        dns_results["cname_records"].append(str(rdata))
                except Exception:
                    pass
                
                passive_results["dns"] = dns_results
                self.log_progress("DNS records collected", "passive_recon")
            except Exception as e:
                self.log_progress(f"Error collecting DNS records: {str(e)}", "passive_recon")
                passive_results["dns"] = {"error": str(e)}
            
            # Check for subdomains using OSINT tools if available
            if 'OSINTScanner' in globals():
                try:
                    osint_scanner = OSINTScanner(hostname, self.report_dir)
                    subdomains = osint_scanner.discover_subdomains()
                    passive_results["subdomains"] = subdomains
                    self.log_progress(f"Found {len(subdomains)} subdomains", "passive_recon")
                except Exception as e:
                    self.log_progress(f"Error discovering subdomains: {str(e)}", "passive_recon")
                    passive_results["subdomains"] = {"error": str(e)}
            else:
                passive_results["subdomains"] = {"status": "OSINT module not available"}
            
            # Check for archived versions using Wayback Machine API
            try:
                wayback_url = f"https://archive.org/wayback/available?url={hostname}"
                response = requests.get(wayback_url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("archived_snapshots") and data["archived_snapshots"].get("closest"):
                        passive_results["wayback_machine"] = {
                            "available": True,
                            "url": data["archived_snapshots"]["closest"].get("url"),
                            "timestamp": data["archived_snapshots"]["closest"].get("timestamp")
                        }
                    else:
                        passive_results["wayback_machine"] = {"available": False}
                self.log_progress("Historical site data checked", "passive_recon")
            except Exception as e:
                self.log_progress(f"Error checking historical site data: {str(e)}", "passive_recon")
                passive_results["wayback_machine"] = {"error": str(e)}
            
            # Update results
            self.results["reconnaissance"]["passive"] = passive_results
            self.log_progress("Passive reconnaissance completed", "passive_recon")
            
            return passive_results
            
        except Exception as e:
            self.log_progress(f"Error during passive reconnaissance: {str(e)}", "passive_recon")
            self.results["reconnaissance"]["passive"] = {"error": str(e)}
            return {"error": str(e)}
    
    def run_active_reconnaissance(self):
        """
        Active Reconnaissance:
          - Port scanning
          - Service version detection
          - Technology identification
          - Site structure analysis
          - Hidden directory discovery
        """
        self.log_progress("Starting active reconnaissance", "active_recon")
        
        try:
            hostname = urlparse(self.target).netloc
            active_results = {}
            
            # Port scanning
            try:
                nm = nmap.PortScanner()
                # Scan common web ports
                nm.scan(hostname, '80,443,8080,8443,3000,4000,4443,5000,8000,8008,8800')
                
                port_results = []
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            port_info = {
                                "port": port,
                                "state": nm[host][proto][port]['state'],
                                "service": nm[host][proto][port].get('name', 'unknown'),
                                "product": nm[host][proto][port].get('product', ''),
                                "version": nm[host][proto][port].get('version', '')
                            }
                            port_results.append(port_info)
                
                active_results["port_scan"] = port_results
                self.log_progress(f"Port scan completed, found {len(port_results)} open ports", "active_recon")
            except Exception as e:
                self.log_progress(f"Error during port scanning: {str(e)}", "active_recon")
                active_results["port_scan"] = {"error": str(e)}
            
            # Site crawling and structure analysis
            try:
                response = requests.get(self.target, headers=self.headers, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                links = []
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if href.startswith('/') or href.startswith('./'):
                        full_url = urljoin(self.target, href)
                    elif href.startswith('http'):
                        full_url = href
                    else:
                        full_url = urljoin(self.target, href)
                    
                    if urlparse(full_url).netloc == hostname:
                        links.append(full_url)
                
                # Identify unique paths
                unique_paths = set()
                for link in links:
                    path = urlparse(link).path
                    unique_paths.add(path)
                
                active_results["site_structure"] = {
                    "total_links_found": len(links),
                    "unique_paths": list(unique_paths)
                }
                self.log_progress(f"Site structure analysis completed, found {len(unique_paths)} unique paths", "active_recon")
            except Exception as e:
                self.log_progress(f"Error during site structure analysis: {str(e)}", "active_recon")
                active_results["site_structure"] = {"error": str(e)}
            
            # Technology identification with Wappalyzer API if available
            try:
                # Identify technologies from HTML
                technologies = []
                
                # Check for common JS frameworks
                js_frameworks = {
                    "jquery": "jQuery",
                    "react": "React",
                    "vue": "Vue.js", 
                    "angular": "Angular",
                    "bootstrap": "Bootstrap",
                    "tailwind": "Tailwind CSS",
                    "wordpress": "WordPress",
                    "drupal": "Drupal",
                    "joomla": "Joomla"
                }
                
                for keyword, framework in js_frameworks.items():
                    if keyword in response.text.lower():
                        technologies.append(framework)
                
                # Check for HTTP headers
                server = response.headers.get('Server', '')
                if server:
                    technologies.append(f"Server: {server}")
                
                x_powered_by = response.headers.get('X-Powered-By', '')
                if x_powered_by:
                    technologies.append(f"X-Powered-By: {x_powered_by}")
                
                active_results["technologies"] = technologies
                self.log_progress(f"Technology identification completed, found {len(technologies)} technologies", "active_recon")
            except Exception as e:
                self.log_progress(f"Error during technology identification: {str(e)}", "active_recon")
                active_results["technologies"] = {"error": str(e)}
            
            # Hidden directory discovery using common wordlists
            if 'VulnerabilityScanner' in globals():
                try:
                    scanner = VulnerabilityScanner(self.target, self.report_dir)
                    # Fix the issue by checking if discover_directories method exists
                    if hasattr(scanner, 'discover_directories'):
                        directories = scanner.discover_directories()
                        active_results["directories"] = directories
                        self.log_progress(f"Directory discovery completed, found {len(directories)} directories", "active_recon")
                    else:
                        self.log_progress("discover_directories method not found in VulnerabilityScanner", "active_recon")
                        active_results["directories"] = {"status": "Directory discovery method not available"}
                except Exception as e:
                    self.log_progress(f"Error during directory discovery: {str(e)}", "active_recon")
                    active_results["directories"] = {"error": str(e)}
            else:
                active_results["directories"] = {"status": "VulnerabilityScanner module not available"}
            
            # Update results
            self.results["reconnaissance"]["active"] = active_results
            self.log_progress("Active reconnaissance completed", "active_recon")
            
            return active_results
            
        except Exception as e:
            self.log_progress(f"Error during active reconnaissance: {str(e)}", "active_recon")
            self.results["reconnaissance"]["active"] = {"error": str(e)}
            return {"error": str(e)}
    
    #===========================
    # 2. ARCHITECTURE ANALYSIS
    #===========================
    
    def analyze_infrastructure(self):
        """
        Infrastructure Analysis:
          - Load balancer detection
          - WAF detection
          - CDN analysis
          - DNS configuration testing
        """
        self.log_progress("Starting infrastructure analysis", "infrastructure")
        
        try:
            hostname = urlparse(self.target).netloc
            infrastructure_results = {}
            
            # Load balancer detection
            try:
                # Make multiple requests to check for IP variations
                ip_addresses = set()
                for _ in range(5):
                    try:
                        ip = socket.gethostbyname(hostname)
                        ip_addresses.add(ip)
                    except:
                        pass
                    time.sleep(1)
                
                infrastructure_results["load_balancer"] = {
                    "detected": len(ip_addresses) > 1,
                    "unique_ips": list(ip_addresses)
                }
                self.log_progress("Load balancer detection completed", "infrastructure")
            except Exception as e:
                self.log_progress(f"Error during load balancer detection: {str(e)}", "infrastructure")
                infrastructure_results["load_balancer"] = {"error": str(e)}
            
            # WAF detection
            try:
                waf_detected = False
                waf_type = "Unknown"
                
                # Make a request with suspicious payload
                test_url = f"{self.target}?id='1 OR 1=1"
                response = requests.get(test_url, headers=self.headers, timeout=10)
                
                # Check for WAF signatures
                waf_signatures = {
                    "cloudflare": ["cloudflare", "CF-RAY"],
                    "akamai": ["akamai"],
                    "imperva": ["incapsula"],
                    "aws": ["aws", "amazon"],
                    "f5": ["big-ip", "f5"],
                    "sucuri": ["sucuri"],
                    "wordfence": ["wordfence"]
                }
                
                for waf, signatures in waf_signatures.items():
                    for header_name, header_value in response.headers.items():
                        if any(sig.lower() in header_value.lower() for sig in signatures):
                            waf_detected = True
                            waf_type = waf
                            break
                    
                    if waf_detected:
                        break
                
                # Check for 403/406/429 with WAF signature
                if not waf_detected and response.status_code in [403, 406, 429, 501]:
                    if "firewall" in response.text.lower() or "waf" in response.text.lower():
                        waf_detected = True
                
                infrastructure_results["waf"] = {
                    "detected": waf_detected,
                    "type": waf_type
                }
                self.log_progress("WAF detection completed", "infrastructure")
            except Exception as e:
                self.log_progress(f"Error during WAF detection: {str(e)}", "infrastructure")
                infrastructure_results["waf"] = {"error": str(e)}
            
            # CDN analysis
            try:
                cdn_detected = False
                cdn_provider = "Unknown"
                
                # Check for CDN signatures in headers
                cdn_signatures = {
                    "cloudflare": ["cloudflare", "CF-RAY"],
                    "akamai": ["akamai"],
                    "cloudfront": ["cloudfront", "amazon"],
                    "fastly": ["fastly"],
                    "maxcdn": ["maxcdn"],
                    "keycdn": ["keycdn"],
                    "cachefly": ["cachefly"]
                }
                
                response = requests.get(self.target, headers=self.headers, timeout=10)
                
                for cdn, signatures in cdn_signatures.items():
                    for header_name, header_value in response.headers.items():
                        if any(sig.lower() in header_value.lower() for sig in signatures):
                            cdn_detected = True
                            cdn_provider = cdn
                            break
                    
                    if cdn_detected:
                        break
                
                infrastructure_results["cdn"] = {
                    "detected": cdn_detected,
                    "provider": cdn_provider
                }
                self.log_progress("CDN analysis completed", "infrastructure")
            except Exception as e:
                self.log_progress(f"Error during CDN analysis: {str(e)}", "infrastructure")
                infrastructure_results["cdn"] = {"error": str(e)}
            
            # DNS configuration testing
            try:
                dns_config = {
                    "spf_record": False,
                    "dmarc_record": False,
                    "dnssec": False
                }
                
                # Check SPF record
                try:
                    answers = dns.resolver.resolve(hostname, 'TXT')
                    for rdata in answers:
                        if "v=spf1" in str(rdata):
                            dns_config["spf_record"] = True
                            break
                except:
                    pass
                
                # Check DMARC record
                try:
                    answers = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
                    for rdata in answers:
                        if "v=DMARC1" in str(rdata):
                            dns_config["dmarc_record"] = True
                            break
                except:
                    pass
                
                # Check DNSSEC
                try:
                    answers = dns.resolver.resolve(hostname, 'DNSKEY')
                    dns_config["dnssec"] = len(answers) > 0
                except:
                    pass
                
                infrastructure_results["dns_configuration"] = dns_config
                self.log_progress("DNS configuration testing completed", "infrastructure")
            except Exception as e:
                self.log_progress(f"Error during DNS configuration testing: {str(e)}", "infrastructure")
                infrastructure_results["dns_configuration"] = {"error": str(e)}
            
            # Update results
            self.results["architecture_analysis"]["infrastructure"] = infrastructure_results
            self.log_progress("Infrastructure analysis completed", "infrastructure")
            
            return infrastructure_results
            
        except Exception as e:
            self.log_progress(f"Error during infrastructure analysis: {str(e)}", "infrastructure")
            self.results["architecture_analysis"]["infrastructure"] = {"error": str(e)}
            return {"error": str(e)}
    
    def analyze_tech_stack(self):
        """
        Technology Stack Analysis:
          - Software version analysis
          - Dependencies and libraries
          - Framework identification
          - Database detection
        """
        self.log_progress("Starting technology stack analysis", "tech_stack")
        
        try:
            tech_stack_results = {}
            
            # Make request to target
            response = requests.get(self.target, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Software version analysis
            try:
                versions = {}
                
                # Check meta tags for CMS versions
                for meta in soup.find_all('meta'):
                    if meta.get('name') == 'generator':
                        content = meta.get('content', '')
                        if content:
                            if 'wordpress' in content.lower():
                                versions['wordpress'] = content
                            elif 'drupal' in content.lower():
                                versions['drupal'] = content
                            elif 'joomla' in content.lower():
                                versions['joomla'] = content
                            else:
                                versions['other_cms'] = content
                
                # Check response headers for server/software versions
                if 'Server' in response.headers:
                    versions['server'] = response.headers['Server']
                
                if 'X-Powered-By' in response.headers:
                    versions['powered_by'] = response.headers['X-Powered-By']
                
                tech_stack_results["versions"] = versions
                self.log_progress("Software version analysis completed", "tech_stack")
            except Exception as e:
                self.log_progress(f"Error during software version analysis: {str(e)}", "tech_stack")
                tech_stack_results["versions"] = {"error": str(e)}
            
            # Dependencies and libraries
            try:
                libraries = []
                
                # Check for JavaScript libraries
                js_libraries = []
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    if 'jquery' in src.lower():
                        js_libraries.append({"name": "jQuery", "path": src})
                    elif 'bootstrap' in src.lower():
                        js_libraries.append({"name": "Bootstrap", "path": src})
                    elif 'react' in src.lower():
                        js_libraries.append({"name": "React", "path": src})
                    elif 'angular' in src.lower():
                        js_libraries.append({"name": "Angular", "path": src})
                    elif 'vue' in src.lower():
                        js_libraries.append({"name": "Vue.js", "path": src})
                
                # Check for CSS libraries
                css_libraries = []
                for link in soup.find_all('link', rel='stylesheet'):
                    href = link.get('href', '')
                    if 'bootstrap' in href.lower():
                        css_libraries.append({"name": "Bootstrap CSS", "path": href})
                    elif 'tailwind' in href.lower():
                        css_libraries.append({"name": "Tailwind CSS", "path": href})
                    elif 'materialize' in href.lower():
                        css_libraries.append({"name": "Materialize CSS", "path": href})
                    elif 'foundation' in href.lower():
                        css_libraries.append({"name": "Foundation CSS", "path": href})
                
                tech_stack_results["libraries"] = {
                    "javascript": js_libraries,
                    "css": css_libraries
                }
                self.log_progress("Dependencies and libraries analysis completed", "tech_stack")
            except Exception as e:
                self.log_progress(f"Error during dependencies analysis: {str(e)}", "tech_stack")
                tech_stack_results["libraries"] = {"error": str(e)}
            
            # Framework identification
            try:
                frameworks = []
                
                # Check HTML for framework signatures
                html = response.text.lower()
                framework_signatures = {
                    "laravel": ["laravel", "csrf-token"],
                    "django": ["django", "csrfmiddlewaretoken"],
                    "flask": ["flask", "flash"],
                    "express": ["express", "node_modules"],
                    "asp.net": ["asp.net", "__viewstate"],
                    "spring": ["spring", "jsessionid"],
                    "ruby on rails": ["rails", "csrf-token"]
                }
                
                for framework, signatures in framework_signatures.items():
                    if any(sig in html for sig in signatures):
                        frameworks.append(framework)
                
                tech_stack_results["frameworks"] = frameworks
                self.log_progress("Framework identification completed", "tech_stack")
            except Exception as e:
                self.log_progress(f"Error during framework identification: {str(e)}", "tech_stack")
                tech_stack_results["frameworks"] = {"error": str(e)}
            
            # Database detection
            try:
                databases = []
                
                # Error-based database detection
                db_signatures = {
                    "mysql": ["mysql", "mysqli", "mariadb"],
                    "postgresql": ["pgsql", "postgresql"],
                    "mssql": ["sqlserver", "microsoft sql server"],
                    "oracle": ["ora-", "oracle"],
                    "mongodb": ["mongodb", "bson"],
                    "redis": ["redis"],
                    "cassandra": ["cassandra"]
                }
                
                # Try to trigger database errors
                test_urls = [
                    f"{self.target}?id=1'",
                    f"{self.target}?id=1\"",
                    f"{self.target}?id=1)",
                    f"{self.target}?id=1;"
                ]
                
                for test_url in test_urls:
                    try:
                        error_response = requests.get(test_url, headers=self.headers, timeout=5)
                        error_text = error_response.text.lower()
                        
                        for db, signatures in db_signatures.items():
                            if any(sig in error_text for sig in signatures):
                                if db not in databases:
                                    databases.append(db)
                    except:
                        pass
                
                tech_stack_results["databases"] = databases
                self.log_progress("Database detection completed", "tech_stack")
            except Exception as e:
                self.log_progress(f"Error during database detection: {str(e)}", "tech_stack")
                tech_stack_results["databases"] = {"error": str(e)}
            
            # Update results
            self.results["architecture_analysis"]["tech_stack"] = tech_stack_results
            self.log_progress("Technology stack analysis completed", "tech_stack")
            
            return tech_stack_results
            
        except Exception as e:
            self.log_progress(f"Error during technology stack analysis: {str(e)}", "tech_stack")
            self.results["architecture_analysis"]["tech_stack"] = {"error": str(e)}
            return {"error": str(e)}
    
    #===========================
    # Run complete assessment
    #===========================
    
    def run_full_assessment(self):
        """Run all testing phases in the comprehensive methodology"""
        self.log_progress("Starting comprehensive vulnerability assessment")
        
        # Validate target
        self.validate_target()
        
        # Phase 1: Reconnaissance
        self.run_passive_reconnaissance()
        self.run_active_reconnaissance()
        
        # Phase 2: Architecture Analysis
        self.analyze_infrastructure()
        self.analyze_tech_stack()
        
        # Phases 3-10 would be implemented here, integrating with other modules
        # For full implementation, they would call the appropriate modules:
        # - self.run_manual_testing()
        # - self.run_automated_scanning()
        # - self.run_specialized_testing()
        # - self.run_indepth_testing()
        # - self.test_security_mechanisms()
        # - self.test_resilience()
        # - self.analyze_data_protection()
        # - self.generate_documentation()
        
        self.log_progress("Comprehensive vulnerability assessment completed")
        return self.results
    
    def save_results(self, filename=None):
        """Save assessment results to file"""
        if not filename:
            filename = os.path.join(self.report_dir, "comprehensive_assessment_report.json")
            
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        logger.info(f"Assessment results saved to {filename}")
        return filename

def main():
    """Main function to run the tool from command line"""
    parser = argparse.ArgumentParser(description="Comprehensive Web Vulnerability Testing Tool")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--output", "-o", default="security_assessment", help="Output directory for scan results")
    parser.add_argument("--reconnaissance-only", action="store_true", help="Only run reconnaissance phase")
    parser.add_argument("--passive-only", action="store_true", help="Only run passive reconnaissance")
    parser.add_argument("--active-only", action="store_true", help="Only run active reconnaissance")
    parser.add_argument("--architecture-only", action="store_true", help="Only run architecture analysis")
    
    args = parser.parse_args()
    
    tester = ComprehensiveTester(args.target, args.output)
    
    if args.passive_only:
        tester.run_passive_reconnaissance()
    elif args.active_only:
        tester.run_active_reconnaissance()
    elif args.reconnaissance_only:
        tester.run_passive_reconnaissance()
        tester.run_active_reconnaissance()
    elif args.architecture_only:
        tester.analyze_infrastructure()
        tester.analyze_tech_stack()
    else:
        tester.run_full_assessment()
    
    tester.save_results()
    
    print(f"Assessment completed. Results saved to {tester.report_dir}/")

if __name__ == "__main__":
    main() 