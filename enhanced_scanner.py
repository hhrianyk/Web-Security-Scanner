#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import requests
import socket
import whois
import dns.resolver
import time
import json
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class EnhancedSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.ip = None
        self.results = {
            "target": target_url,
            "domain_info": {},
            "osint_data": {},
            "network_analysis": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def run_full_scan(self):
        """Run the enhanced security scanner with all modules"""
        print(f"[+] Starting enhanced security scan for {self.target_url}")
        
        # 1. Gather basic information
        self._gather_basic_info()
        
        # 2. Run OSINT modules
        self._run_osint_modules()
        
        # 3. Run network analysis
        self._run_network_analysis()
        
        # 4. Run vulnerability scans
        self._run_vulnerability_scans()
        
        # 5. Generate recommendations
        self._generate_recommendations()
        
        print(f"[+] Scan completed for {self.target_url}")
        return self.results
    
    def _gather_basic_info(self):
        """Gather basic information about the target"""
        print("[+] Gathering basic target information...")
        
        try:
            # Resolve IP address
            self.ip = socket.gethostbyname(self.domain)
            self.results["domain_info"]["ip_address"] = self.ip
            
            # Initial request
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            self.results["domain_info"]["status_code"] = response.status_code
            
            # Server information
            if 'Server' in response.headers:
                self.results["domain_info"]["server"] = response.headers['Server']
            
            # Parse technologies
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract metadata
            meta_tags = {}
            for meta in soup.find_all('meta'):
                if meta.get('name'):
                    meta_tags[meta.get('name')] = meta.get('content')
            
            self.results["domain_info"]["meta_tags"] = meta_tags
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    links.append(href)
                else:
                    links.append(urljoin(self.target_url, href))
            
            self.results["domain_info"]["external_links"] = [l for l in links if self.domain not in l]
            self.results["domain_info"]["internal_links"] = [l for l in links if self.domain in l]
            
            print(f"[+] Basic information gathered. IP: {self.ip}")
            
        except Exception as e:
            print(f"[!] Error gathering basic info: {str(e)}")
            self.results["domain_info"]["error"] = str(e)
    
    def _run_osint_modules(self):
        """Run OSINT modules to gather intelligence"""
        print("[+] Running OSINT modules...")
        
        # WHOIS information
        try:
            w = whois.whois(self.domain)
            self.results["osint_data"]["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
            }
            print(f"[+] WHOIS information gathered for {self.domain}")
        except Exception as e:
            print(f"[!] Error gathering WHOIS data: {str(e)}")
        
        # DNS records
        try:
            dns_records = {
                "A": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "CNAME": []
            }
            
            for record_type in dns_records.keys():
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    for rdata in answers:
                        dns_records[record_type].append(str(rdata))
                except Exception:
                    pass
            
            self.results["osint_data"]["dns_records"] = dns_records
            print(f"[+] DNS records gathered for {self.domain}")
        except Exception as e:
            print(f"[!] Error gathering DNS records: {str(e)}")
        
        # Check for subdomains (simple check)
        try:
            common_subdomains = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "api"]
            discovered_subdomains = []
            
            for subdomain in common_subdomains:
                try:
                    subdomain_url = f"{subdomain}.{self.domain}"
                    socket.gethostbyname(subdomain_url)
                    discovered_subdomains.append(subdomain_url)
                except socket.error:
                    pass
            
            self.results["osint_data"]["discovered_subdomains"] = discovered_subdomains
            print(f"[+] Discovered {len(discovered_subdomains)} subdomains")
        except Exception as e:
            print(f"[!] Error checking subdomains: {str(e)}")
        
        # Email security analysis
        try:
            email_security = {
                "spf": False,
                "dmarc": False,
                "dkim_configured": None
            }
            
            # Check SPF
            try:
                spf_records = dns.resolver.resolve(self.domain, 'TXT')
                for record in spf_records:
                    if 'v=spf1' in str(record):
                        email_security["spf"] = True
                        break
            except:
                pass
            
            # Check DMARC
            try:
                dmarc_records = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
                for record in dmarc_records:
                    if 'v=DMARC1' in str(record):
                        email_security["dmarc"] = True
                        break
            except:
                pass
            
            self.results["osint_data"]["email_security"] = email_security
            print(f"[+] Email security analysis completed")
        except Exception as e:
            print(f"[!] Error checking email security: {str(e)}")
    
    def _run_network_analysis(self):
        """Run network analysis modules"""
        print("[+] Running network analysis...")
        
        # Port scanning (limited version for demo)
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 8443]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.ip, port))
                if result == 0:
                    service = socket.getservbyport(port) if port < 1024 else "unknown"
                    open_ports.append({"port": port, "service": service})
                sock.close()
            
            self.results["network_analysis"]["open_ports"] = open_ports
            print(f"[+] Discovered {len(open_ports)} open ports")
        except Exception as e:
            print(f"[!] Error scanning ports: {str(e)}")
        
        # SSL/TLS analysis
        if 443 in [p["port"] for p in self.results["network_analysis"].get("open_ports", [])]:
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        self.results["network_analysis"]["ssl_info"] = {
                            "protocol_version": ssock.version(),
                            "cipher": ssock.cipher(),
                            "certificate": {
                                "subject": dict(x[0] for x in cert['subject']),
                                "issuer": dict(x[0] for x in cert['issuer']),
                                "version": cert['version'],
                                "not_before": cert['notBefore'],
                                "not_after": cert['notAfter']
                            }
                        }
                print(f"[+] SSL/TLS analysis completed")
            except Exception as e:
                print(f"[!] Error analyzing SSL/TLS: {str(e)}")
        
        # HTTP Security Headers
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options', None),
                'X-XSS-Protection': headers.get('X-XSS-Protection', None),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', None),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', None),
                'Content-Security-Policy': headers.get('Content-Security-Policy', None),
                'Referrer-Policy': headers.get('Referrer-Policy', None),
                'Feature-Policy': headers.get('Feature-Policy', None),
                'Permissions-Policy': headers.get('Permissions-Policy', None)
            }
            
            self.results["network_analysis"]["security_headers"] = security_headers
            print(f"[+] HTTP security headers analyzed")
        except Exception as e:
            print(f"[!] Error analyzing HTTP headers: {str(e)}")
    
    def _run_vulnerability_scans(self):
        """Run vulnerability scanning modules"""
        print("[+] Running vulnerability scans...")
        
        # Check for common web vulnerabilities (simplified for demo)
        try:
            vulnerabilities = []
            
            # 1. Basic XSS detection
            xss_payload = "<script>alert('XSS')</script>"
            test_url = f"{self.target_url}?test={xss_payload}"
            response = requests.get(test_url, headers=self.headers, timeout=10)
            
            if xss_payload in response.text:
                vulnerabilities.append({
                    "type": "XSS",
                    "severity": "High",
                    "description": "Cross-Site Scripting vulnerability detected",
                    "location": "URL parameter 'test'",
                    "details": "The application reflects user input without proper encoding",
                    "remediation": "Implement proper input validation and output encoding"
                })
            
            # 2. Basic SQL Injection detection
            sqli_payloads = ["' OR '1'='1", "'; DROP TABLE users--"]
            for payload in sqli_payloads:
                test_url = f"{self.target_url}?id={payload}"
                response = requests.get(test_url, headers=self.headers, timeout=10)
                
                error_patterns = ["SQL syntax", "mysql_fetch_array", "ORA-01756", "sqlite3.OperationalError"]
                for pattern in error_patterns:
                    if pattern in response.text:
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "description": "SQL Injection vulnerability detected",
                            "location": "URL parameter 'id'",
                            "details": f"SQL error message revealed with payload: {payload}",
                            "remediation": "Use parameterized queries or prepared statements"
                        })
                        break
            
            # 3. Missing security headers vulnerability
            security_headers = self.results["network_analysis"].get("security_headers", {})
            missing_headers = []
            
            critical_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options allows clickjacking attacks',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options allows MIME-sniffing attacks',
                'Content-Security-Policy': 'Missing CSP allows various code injection attacks',
                'Strict-Transport-Security': 'Missing HSTS allows SSL stripping attacks'
            }
            
            for header, impact in critical_headers.items():
                if not security_headers.get(header):
                    missing_headers.append({"header": header, "impact": impact})
            
            if missing_headers:
                vulnerabilities.append({
                    "type": "Missing Security Headers",
                    "severity": "Medium",
                    "description": "Important security headers are missing",
                    "details": missing_headers,
                    "remediation": "Configure web server to include the missing security headers"
                })
            
            # 4. Open ports vulnerability
            dangerous_ports = {
                21: "FTP - Often has weak authentication and transmits data in cleartext",
                22: "SSH - Ensure strong authentication and latest version",
                23: "Telnet - Transmits data in cleartext, should be disabled",
                25: "SMTP - Ensure it's not an open relay and is properly configured",
                139: "NetBIOS - Often exploited in Windows systems",
                445: "SMB - Often targeted by ransomware and worms"
            }
            
            risky_ports = []
            for port_info in self.results["network_analysis"].get("open_ports", []):
                port = port_info["port"]
                if port in dangerous_ports:
                    risky_ports.append({
                        "port": port,
                        "service": port_info["service"],
                        "risk": dangerous_ports[port]
                    })
            
            if risky_ports:
                vulnerabilities.append({
                    "type": "Dangerous Open Ports",
                    "severity": "High",
                    "description": "Potentially dangerous ports are open on the target",
                    "details": risky_ports,
                    "remediation": "Close unnecessary ports and secure essential services"
                })
                        
            self.results["vulnerabilities"] = vulnerabilities
            print(f"[+] Discovered {len(vulnerabilities)} potential vulnerabilities")
        except Exception as e:
            print(f"[!] Error during vulnerability scanning: {str(e)}")
    
    def _generate_recommendations(self):
        """Generate security recommendations based on findings"""
        print("[+] Generating recommendations...")
        
        recommendations = []
        
        # Based on vulnerabilities
        for vuln in self.results["vulnerabilities"]:
            recommendations.append({
                "priority": "High" if vuln["severity"] in ["Critical", "High"] else "Medium",
                "title": f"Fix {vuln['type']} vulnerability",
                "description": vuln.get("remediation", "Address the identified vulnerability"),
                "related_to": vuln["type"]
            })
        
        # Based on missing security headers
        security_headers = self.results["network_analysis"].get("security_headers", {})
        if not security_headers.get('Content-Security-Policy'):
            recommendations.append({
                "priority": "Medium",
                "title": "Implement Content Security Policy",
                "description": "Configure a strict CSP header to mitigate XSS and data injection attacks",
                "example": "Content-Security-Policy: default-src 'self'; script-src 'self'"
            })
        
        # Based on email security
        email_security = self.results["osint_data"].get("email_security", {})
        if not email_security.get("spf"):
            recommendations.append({
                "priority": "Medium",
                "title": "Implement SPF for email security",
                "description": "Add an SPF record to prevent email spoofing",
                "example": "v=spf1 ip4:192.0.2.0/24 include:_spf.example.com -all"
            })
        
        if not email_security.get("dmarc"):
            recommendations.append({
                "priority": "Medium",
                "title": "Implement DMARC for email security",
                "description": "Add a DMARC record to enhance email authentication",
                "example": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
            })
        
        # Based on network findings
        open_ports = self.results["network_analysis"].get("open_ports", [])
        if len(open_ports) > 3:
            recommendations.append({
                "priority": "Medium",
                "title": "Reduce attack surface by closing unnecessary ports",
                "description": "Review and close all ports that are not absolutely necessary for operation",
                "related_to": "Network Security"
            })
        
        # General recommendations
        recommendations.append({
            "priority": "Medium",
            "title": "Implement a Web Application Firewall (WAF)",
            "description": "Deploy a WAF to protect against common web attacks",
            "related_to": "Network Security"
        })
        
        recommendations.append({
            "priority": "High",
            "title": "Regular vulnerability scanning",
            "description": "Perform regular automated and manual security testing",
            "related_to": "Security Process"
        })
        
        recommendations.append({
            "priority": "Medium",
            "title": "Create a security response plan",
            "description": "Develop a plan for responding to security incidents",
            "related_to": "Security Process"
        })
        
        self.results["recommendations"] = recommendations
        print(f"[+] Generated {len(recommendations)} security recommendations")

def main():
    if len(sys.argv) < 2:
        print("Usage: python enhanced_scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = EnhancedSecurityScanner(target_url)
    results = scanner.run_full_scan()
    
    # Save results to JSON file
    output_file = f"scan_results_{urlparse(target_url).netloc}_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main() 