#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import argparse
import datetime
import concurrent.futures
from urllib.parse import urlparse
import requests

# Import existing modules
try:
    from network_tools_advanced import AdvancedNetworkTools
    from osint_tools import OSINTTools
    from social_engineering import SocialEngineeringToolkit
    from vulnerability_scanner import VulnerabilityScanner
    # Import new w3af AI and IBM Watson integrations
    from w3af_ai_integration import W3afAIIntegration
    from ibm_watson_security_integration import IBMWatsonSecurityIntegration
    # Import DNS spoofing tools
    from dns_spoof_integration import (
        list_dns_spoof_tools, 
        get_dns_spoof_tool, 
        install_dns_spoof_tool,
        start_dns_spoof_attack,
        stop_dns_spoof_attack,
        stop_all_dns_spoof_attacks,
        get_dns_spoof_status
    )
    # Add compatibility class for integration modules
    from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, download_file, security_tools_manager
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure all required modules are in the same directory or in your PYTHONPATH")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_framework.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecurityFramework")

class SecurityFramework:
    """
    Comprehensive security assessment framework that integrates:
    - Advanced network scanning tools
    - OSINT capabilities
    - Social engineering tools
    - Web vulnerability scanning
    - Detailed mitigation and remediation instructions
    - AI-enhanced w3af for manual testing simulation
    - IBM Watson for Cybersecurity analysis
    """
    
    def __init__(self, target=None, output_dir="security_assessment"):
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = os.path.join(output_dir, f"report_{self.timestamp}")
        
        # Initialize sub-components
        self.network_tools = AdvancedNetworkTools(target, os.path.join(self.report_dir, "network"))
        self.osint_tools = OSINTTools(target, os.path.join(self.report_dir, "osint"))
        self.social_tools = SocialEngineeringToolkit(os.path.join(self.report_dir, "social"))
        self.web_scanner = VulnerabilityScanner(
            target_url=target,
            scan_id=self.timestamp,
            output_dir=os.path.join(self.report_dir, "web")
        )
        
        # Initialize new components
        self.w3af_ai = W3afAIIntegration(
            target=target,
            output_dir=os.path.join(self.report_dir, "w3af_ai")
        )
        self.ibm_watson = IBMWatsonSecurityIntegration(
            output_dir=os.path.join(self.report_dir, "ibm_watson")
        )
        
        # Create output directories
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "network"), exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "osint"), exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "social"), exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "web"), exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "w3af_ai"), exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "ibm_watson"), exist_ok=True)
        os.makedirs(os.path.join(self.report_dir, "dns_spoof"), exist_ok=True)
        
        # Results storage
        self.results = {
            "timestamp": self.timestamp,
            "target": target,
            "summary": {},
            "network": {},
            "osint": {},
            "web": {},
            "social_engineering": {},
            "remediation": {},
            "w3af_ai": {},
            "ibm_watson": {},
            "dns_spoofing": {}
        }
        
        logger.info(f"Initialized SecurityFramework for target: {target}")

    def validate_target(self, target=None):
        """Validate and normalize the target"""
        target = target or self.target
        if not target:
            raise ValueError("No target specified")
            
        # Check if it's an IP address
        if all(c.isdigit() or c == '.' for c in target) and len(target.split('.')) == 4:
            return {
                "type": "ip",
                "ip": target,
                "original": target
            }
            
        # Check if it's a domain
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        if not parsed.scheme and '.' in domain:
            # No scheme, but looks like a domain
            return {
                "type": "domain",
                "domain": domain,
                "url": f"http://{domain}",
                "original": target
            }
        elif parsed.scheme and parsed.netloc:
            # Full URL
            return {
                "type": "url",
                "domain": parsed.netloc,
                "url": target,
                "original": target
            }
            
        # If we can't determine the type
        raise ValueError(f"Invalid target format: {target}")

    def run_network_assessment(self, target_info=None):
        """Run comprehensive network security assessment"""
        logger.info("Starting network security assessment")
        target = target_info or self.validate_target()
        
        # Run all network scans
        if target["type"] == "domain" or target["type"] == "url":
            self.network_tools.target = target["domain"]
        else:
            self.network_tools.target = target["ip"]
            
        # Run scans
        try:
            self.network_tools.run_all_scans()
            self.results["network"] = self.network_tools.results
            logger.info("Network assessment completed successfully")
        except Exception as e:
            logger.error(f"Error during network assessment: {str(e)}")
            self.results["network"]["error"] = str(e)
            
        return self.results["network"]

    def run_osint_assessment(self, target_info=None):
        """Run open source intelligence gathering"""
        logger.info("Starting OSINT assessment")
        target = target_info or self.validate_target()
        
        # Set appropriate target
        if target["type"] == "domain" or target["type"] == "url":
            self.osint_tools.target = target["domain"]
        else:
            self.osint_tools.target = target["ip"]
            
        # Run all OSINT tools
        try:
            self.osint_tools.run_all_osint()
            self.results["osint"] = self.osint_tools.results
            logger.info("OSINT assessment completed successfully")
        except Exception as e:
            logger.error(f"Error during OSINT assessment: {str(e)}")
            self.results["osint"]["error"] = str(e)
            
        return self.results["osint"]

    def run_web_vulnerability_scan(self, target_info=None):
        """Run web vulnerability scanning"""
        logger.info("Starting web vulnerability assessment")
        target = target_info or self.validate_target()
        
        # Needs URL for web scanning
        if target["type"] == "domain":
            url = f"http://{target['domain']}"
        elif target["type"] == "url":
            url = target["url"]
        else:
            url = f"http://{target['ip']}"
            
        # Update web scanner target
        self.web_scanner.target_url = url
            
        # Run web vulnerability scan
        try:
            scan_results = {}
            
            # Run the scan
            self.web_scanner.run_scan()
            
            # Get results
            scan_results = {
                "vulnerabilities": self.web_scanner.vulnerabilities,
                "summary": self.web_scanner.results.get("summary", {})
            }
            
            self.results["web"] = scan_results
            logger.info("Web vulnerability scan completed successfully")
        except Exception as e:
            logger.error(f"Error during web vulnerability scan: {str(e)}")
            self.results["web"]["error"] = str(e)
            
        return self.results["web"]

    def prepare_social_engineering_assessment(self, target_info=None):
        """
        Prepare social engineering assessment based on OSINT data
        This doesn't actually send anything but prepares templates
        based on gathered information
        """
        logger.info("Preparing social engineering assessment")
        target = target_info or self.validate_target()
        
        try:
            # Generate common templates
            templates = self.social_tools.generate_common_templates()
            landing_pages = self.social_tools.generate_landing_pages()
            
            # Create a sample campaign
            campaign_name = f"Assessment {self.timestamp}"
            if templates and len(templates) > 0:
                template_id = templates[0]["id"]
                landing_page_id = landing_pages[0]["id"] if landing_pages and len(landing_pages) > 0 else None
                
                # Use OSINT data to build target list if available
                targets = []
                if "email_harvesting" in self.results["osint"] and "emails" in self.results["osint"]["email_harvesting"]:
                    for email in self.results["osint"]["email_harvesting"]["emails"]:
                        targets.append({"email": email, "first_name": "", "last_name": ""})
                
                # Create campaign (simulation only)
                campaign = self.social_tools.create_campaign(
                    name=campaign_name,
                    template_id=template_id,
                    landing_page_id=landing_page_id,
                    targets=targets,
                    tracking_url=None
                )
                
                self.results["social_engineering"] = {
                    "campaign": campaign,
                    "templates": templates,
                    "landing_pages": landing_pages,
                    "targets": targets
                }
            else:
                self.results["social_engineering"] = {
                    "templates": templates,
                    "landing_pages": landing_pages
                }
                
            logger.info("Social engineering assessment preparation completed")
        except Exception as e:
            logger.error(f"Error preparing social engineering assessment: {str(e)}")
            self.results["social_engineering"]["error"] = str(e)
            
        return self.results["social_engineering"]

    def generate_mitigation_recommendations(self):
        """
        Generate detailed mitigation recommendations based on all findings
        """
        logger.info("Generating mitigation recommendations")
        
        remediation = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "best_practices": []
        }
        
        # Process network findings
        if "network" in self.results:
            network_data = self.results["network"]
            
            # Check for open ports
            if "port_scan" in network_data:
                for host, host_data in network_data["port_scan"].items():
                    if "ports" in host_data:
                        for proto, ports in host_data["ports"].items():
                            for port, port_info in ports.items():
                                if port_info["state"] == "open" and int(port) not in [80, 443]:
                                    service = port_info.get("service", "unknown")
                                    remediation["medium_priority"].append({
                                        "issue": f"Open {service} port {port}/{proto}",
                                        "details": f"An open {service} service was detected on port {port}.",
                                        "recommendation": f"Close port {port} if not required or restrict access using a firewall.",
                                        "references": [
                                            "https://www.sans.org/security-resources/policies/general/pdf/firewall-configuration-policy"
                                        ]
                                    })
            
            # Check SSL/TLS security
            if "ssl_analysis" in network_data:
                ssl_data = network_data["ssl_analysis"]
                if "security_assessment" in ssl_data and not ssl_data["security_assessment"].get("is_secure_protocol", True):
                    protocol = ssl_data.get("connection", {}).get("protocol", "unknown")
                    remediation["high_priority"].append({
                        "issue": f"Insecure SSL/TLS protocol ({protocol})",
                        "details": f"The server is using {protocol} which is considered insecure.",
                        "recommendation": "Upgrade to TLSv1.2 or TLSv1.3 and disable older protocols.",
                        "implementation": [
                            "For Nginx: Add 'ssl_protocols TLSv1.2 TLSv1.3;' to your server block",
                            "For Apache: Add 'SSLProtocol -all +TLSv1.2 +TLSv1.3' to your configuration",
                            "For HAProxy: Add 'ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11' to your configuration"
                        ],
                        "references": [
                            "https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet"
                        ]
                    })
        
        # Process web vulnerabilities
        if "web" in self.results:
            web_data = self.results["web"]
            
            # XSS vulnerabilities
            if "xss" in web_data and web_data["xss"].get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Cross-Site Scripting (XSS) vulnerability",
                    "details": "The application is vulnerable to cross-site scripting attacks, which could allow attackers to inject malicious scripts.",
                    "recommendation": "Implement proper input validation and output encoding.",
                    "implementation": [
                        "Sanitize all user input using context-specific encoding",
                        "Implement Content Security Policy (CSP) headers",
                        "Use modern frameworks that automatically escape output",
                        "Sample code fix: htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8')"
                    ],
                    "references": [
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                })
            
            # SQL Injection vulnerabilities
            if "sql_injection" in web_data and web_data["sql_injection"].get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "SQL Injection vulnerability",
                    "details": "The application is vulnerable to SQL injection attacks, which could allow attackers to access, modify, or delete database data.",
                    "recommendation": "Use parameterized queries or prepared statements.",
                    "implementation": [
                        "Replace dynamic SQL with parameterized queries",
                        "Example PHP fix: $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?'); $stmt->execute([$email]);",
                        "Example Python fix: cursor.execute('SELECT * FROM users WHERE email = %s', (email,))",
                        "Use an ORM (Object Relational Mapper) when possible"
                    ],
                    "references": [
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ]
                })
            
            # Security headers
            if "security_headers" in web_data and web_data["security_headers"].get("missing_headers", []):
                missing = web_data["security_headers"].get("missing_headers", [])
                header_recommendations = {
                    "X-XSS-Protection": "Add 'X-XSS-Protection: 1; mode=block'",
                    "X-Frame-Options": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
                    "X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff'",
                    "Content-Security-Policy": "Implement a Content Security Policy",
                    "Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
                }
                
                implementations = []
                for header in missing:
                    if header in header_recommendations:
                        implementations.append(header_recommendations[header])
                
                remediation["medium_priority"].append({
                    "issue": "Missing security headers",
                    "details": f"The application is missing important security headers: {', '.join(missing)}",
                    "recommendation": "Implement the missing security headers to enhance application security.",
                    "implementation": implementations,
                    "references": [
                        "https://owasp.org/www-project-secure-headers/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                    ]
                })
        
        # Process OSINT findings
        if "osint" in self.results:
            osint_data = self.results["osint"]
            
            # Check for email exposure
            if "email_harvesting" in osint_data and "emails" in osint_data["email_harvesting"]:
                emails = osint_data["email_harvesting"]["emails"]
                if len(emails) > 0:
                    remediation["medium_priority"].append({
                        "issue": "Exposed email addresses",
                        "details": f"Found {len(emails)} email addresses publicly available online.",
                        "recommendation": "Reduce email exposure to prevent phishing attacks.",
                        "implementation": [
                            "Use contact forms instead of publishing email addresses",
                            "Use email masking or obfuscation techniques on websites",
                            "Consider using role-based email addresses (e.g., info@domain.com) on public websites"
                        ],
                        "references": [
                            "https://www.sans.org/security-awareness-training/resources/social-engineering"
                        ]
                    })
            
            # Check for data breaches
            if "data_breaches" in osint_data and "breaches" in osint_data["data_breaches"]:
                breaches = osint_data["data_breaches"]["breaches"]
                if len(breaches) > 0:
                    remediation["high_priority"].append({
                        "issue": "Previous data breaches detected",
                        "details": f"The domain was involved in {len(breaches)} previous data breaches.",
                        "recommendation": "Implement stronger security controls and consider password resets.",
                        "implementation": [
                            "Force password resets for all users",
                            "Implement multi-factor authentication",
                            "Review and update security policies",
                            "Conduct security training for all employees"
                        ],
                        "references": [
                            "https://owasp.org/www-community/controls/Credential_and_Session_Management"
                        ]
                    })
        
        # Add best practices
        remediation["best_practices"] = [
            {
                "issue": "Regular security assessments",
                "recommendation": "Conduct regular security assessments and penetration testing.",
                "implementation": [
                    "Schedule quarterly vulnerability scans",
                    "Conduct annual penetration testing",
                    "Implement a bug bounty program"
                ]
            },
            {
                "issue": "Security awareness training",
                "recommendation": "Provide security awareness training for all employees.",
                "implementation": [
                    "Conduct regular phishing simulations",
                    "Provide role-specific security training",
                    "Create and distribute security policy documentation"
                ]
            },
            {
                "issue": "Incident response plan",
                "recommendation": "Develop and test an incident response plan.",
                "implementation": [
                    "Create a formal incident response procedure",
                    "Assign roles and responsibilities",
                    "Conduct tabletop exercises"
                ]
            }
        ]
        
        self.results["remediation"] = remediation
        return remediation

    def run_w3af_ai_assessment(self, target_info=None):
        """Run w3af with AI-enhanced manual testing simulation"""
        logger.info("Starting w3af AI assessment with manual testing simulation")
        target = target_info or self.validate_target()
        
        # Set appropriate target
        if target["type"] == "url":
            target_url = target["url"]
        elif target["type"] == "domain":
            target_url = f"http://{target['domain']}"
        else:
            target_url = f"http://{target['ip']}"
            
        # Update w3af AI target
        self.w3af_ai.target_url = target_url
            
        # Run w3af AI assessment
        try:
            # First ensure w3af is installed
            if not self.w3af_ai.is_installed:
                self.w3af_ai.install()
                
            # Run full assessment
            assessment_results = self.w3af_ai.run_full_assessment(target_url)
            self.results["w3af_ai"] = assessment_results
            logger.info("w3af AI assessment completed successfully")
        except Exception as e:
            logger.error(f"Error during w3af AI assessment: {str(e)}")
            self.results["w3af_ai"]["error"] = str(e)
            
        return self.results["w3af_ai"]
        
    def run_ibm_watson_analysis(self, findings=None):
        """Run IBM Watson for Cybersecurity analysis"""
        logger.info("Starting IBM Watson for Cybersecurity analysis")
        
        # Combine findings from other assessments
        findings = findings or {
            "web_vulnerabilities": self.results.get("web", {}),
            "network_findings": self.results.get("network", {}),
            "w3af_findings": self.results.get("w3af_ai", {})
        }
        
        # Generate security events from findings
        security_events = self._generate_security_events_from_findings(findings)
        
        # Run IBM Watson analysis
        try:
            analysis_results = self.ibm_watson.run_comprehensive_analysis(
                scan_results=findings,
                security_events=security_events
            )
            
            self.results["ibm_watson"] = analysis_results
            logger.info("IBM Watson security analysis completed successfully")
        except Exception as e:
            logger.error(f"Error during IBM Watson security analysis: {str(e)}")
            self.results["ibm_watson"]["error"] = str(e)
            
        return self.results["ibm_watson"]
    
    def _generate_security_events_from_findings(self, findings):
        """Generate security events from findings for IBM Watson analysis"""
        events = []
        
        # Process web vulnerabilities
        if "web_vulnerabilities" in findings:
            web_vulns = findings["web_vulnerabilities"]
            if "vulnerabilities" in web_vulns:
                for vuln in web_vulns.get("vulnerabilities", []):
                    events.append({
                        "id": f"E{len(events) + 1}",
                        "type": "Vulnerability",
                        "description": f"Web vulnerability found: {vuln.get('plugin', 'Unknown')}",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "severity": "HIGH",
                        "source": "Web Scanner",
                        "details": vuln
                    })
        
        # Process network findings
        if "network_findings" in findings:
            network = findings["network_findings"]
            if "port_scan" in network:
                for host, host_data in network.get("port_scan", {}).items():
                    for proto, ports in host_data.get("ports", {}).items():
                        for port, port_info in ports.items():
                            if port_info.get("state") == "open":
                                events.append({
                                    "id": f"E{len(events) + 1}",
                                    "type": "Open Port",
                                    "description": f"Open port found: {port}/{proto} - {port_info.get('service', 'unknown')}",
                                    "timestamp": datetime.datetime.now().isoformat(),
                                    "severity": "MEDIUM",
                                    "source": "Network Scanner",
                                    "details": {
                                        "host": host,
                                        "port": port,
                                        "protocol": proto,
                                        "service": port_info.get("service", "unknown")
                                    }
                                })
        
        # Process w3af findings
        if "w3af_findings" in findings:
            w3af = findings["w3af_findings"]
            if "automated_scan" in w3af:
                for vuln in w3af.get("automated_scan", {}).get("vulnerabilities", []):
                    events.append({
                        "id": f"E{len(events) + 1}",
                        "type": "W3af Finding",
                        "description": f"W3af vulnerability found: {vuln.get('plugin', 'Unknown')}",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "severity": "HIGH",
                        "source": "W3af Scanner",
                        "details": vuln
                    })
            
            if "simulated_manual_tests" in w3af:
                events.append({
                    "id": f"E{len(events) + 1}",
                    "type": "Manual Testing",
                    "description": "Results from manual testing simulation",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "severity": "INFO",
                    "source": "W3af AI",
                    "details": w3af.get("simulated_manual_tests", {})
                })
        
        return events

    def run_comprehensive_assessment(self, target=None):
        """Run all assessment components in parallel"""
        target = target or self.target
        if not target:
            raise ValueError("No target specified for assessment")
            
        logger.info(f"Starting comprehensive security assessment for {target}")
        
        # Validate and normalize target
        target_info = self.validate_target(target)
        self.target = target_info["original"]
        
        # Use thread pool to run assessments in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            network_future = executor.submit(self.run_network_assessment, target_info)
            osint_future = executor.submit(self.run_osint_assessment, target_info)
            web_future = executor.submit(self.run_web_vulnerability_scan, target_info)
            w3af_future = executor.submit(self.run_w3af_ai_assessment, target_info)
            
            # Wait for all to complete
            network_results = network_future.result()
            osint_results = osint_future.result()
            web_results = web_future.result()
            w3af_results = w3af_future.result()
        
        # Process social engineering assessment (depends on OSINT)
        self.prepare_social_engineering_assessment(target_info)
        
        # Run AI-powered vulnerability check
        try:
            logger.info("Running AI-powered vulnerability analysis")
            ai_results = self.check_vulnerabilities_with_ai(target_info)
            if "error" in ai_results:
                logger.warning(f"AI vulnerability check completed with errors: {ai_results['error']}")
            else:
                logger.info("AI vulnerability check completed successfully")
        except Exception as e:
            logger.error(f"Error during AI vulnerability check: {str(e)}")
        
        # Run IBM Watson security analysis (depends on other scan results)
        ibm_results = self.run_ibm_watson_analysis()
        
        # Generate recommendations
        self.generate_mitigation_recommendations()
        
        # Create summary
        self.generate_summary()
        
        # Save results
        self.save_results()
        
        logger.info(f"Comprehensive assessment completed for {target}")
        return self.results

    def generate_summary(self):
        """Generate an executive summary of findings"""
        # Include results from w3af AI and IBM Watson in the summary
        
        # Calculate risk levels
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # Count vulnerabilities from standard web scan
        web_vulns = self.results.get("web", {}).get("vulnerabilities", [])
        for vuln in web_vulns:
            severity = vuln.get("severity", "").lower()
            if severity == "high" or severity == "critical":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            else:
                low_count += 1
        
        # Count vulnerabilities from w3af scan
        w3af_vulns = self.results.get("w3af_ai", {}).get("automated_scan", {}).get("vulnerabilities", [])
        for vuln in w3af_vulns:
            severity = vuln.get("details", {}).get("severity", "").lower()
            if severity == "high" or severity == "critical":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            else:
                low_count += 1
        
        # Get risk assessment from IBM Watson
        watson_risk = self.results.get("ibm_watson", {}).get("risk_scoring", {}).get("risk_assessment", {})
        watson_score = watson_risk.get("overall_score", 0)
        watson_severity = watson_risk.get("severity", "UNKNOWN")
        
        # Calculate overall risk level
        risk_level = self._calculate_risk_level(high_count + medium_count)
        
        # Get top recommendations
        top_recommendations = self._get_top_recommendations()
        
        # Create summary
        summary = {
            "risk_level": risk_level,
            "watson_risk_score": watson_score,
            "watson_severity": watson_severity,
            "vulnerability_counts": {
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "total": high_count + medium_count + low_count
            },
            "top_findings": [],
            "top_recommendations": top_recommendations,
            "assessment_modules": [
                "Network Security",
                "OSINT",
                "Web Application Security",
                "Social Engineering",
                "W3af AI Manual Testing Simulation",
                "IBM Watson Security Analysis"
            ]
        }
        
        # Add top findings
        # From standard web scan
        for vuln in web_vulns[:3]:  # Top 3
            summary["top_findings"].append({
                "source": "Web Scanner",
                "type": vuln.get("type", "Unknown"),
                "severity": vuln.get("severity", "Unknown"),
                "description": vuln.get("description", "No description")
            })
        
        # From w3af scan
        for vuln in w3af_vulns[:3]:  # Top 3
            summary["top_findings"].append({
                "source": "W3af Scanner",
                "type": vuln.get("plugin", "Unknown"),
                "severity": vuln.get("details", {}).get("severity", "Unknown"),
                "description": vuln.get("details", {}).get("description", "No description")
            })
        
        # From IBM Watson
        watson_findings = self.results.get("ibm_watson", {}).get("vulnerability_assessment", {}).get("vulnerabilities", [])
        for vuln in watson_findings[:3]:  # Top 3
            summary["top_findings"].append({
                "source": "IBM Watson",
                "type": vuln.get("title", "Unknown"),
                "severity": vuln.get("severity", "Unknown"),
                "description": vuln.get("description", "No description")
            })
        
        self.results["summary"] = summary
        return summary

    def _calculate_risk_level(self, vuln_count):
        """Calculate overall risk level based on vulnerability counts"""
        if vuln_count["critical"] > 0:
            return "Critical"
        elif vuln_count["high"] > 2:
            return "High"
        elif vuln_count["high"] > 0 or vuln_count["medium"] > 3:
            return "Medium"
        elif vuln_count["medium"] > 0:
            return "Low"
        else:
            return "Minimal"

    def _get_top_recommendations(self, count=3):
        """Get top priority recommendations"""
        recommendations = []
        
        # Add high priority items first
        recommendations.extend([item["recommendation"] for item in self.results["remediation"]["high_priority"]])
        
        # Add medium priority if needed
        if len(recommendations) < count:
            recommendations.extend([item["recommendation"] for item in self.results["remediation"]["medium_priority"]])
        
        # Add low priority if still needed
        if len(recommendations) < count:
            recommendations.extend([item["recommendation"] for item in self.results["remediation"]["low_priority"]])
        
        # Return only requested number
        return recommendations[:count]

    def check_vulnerabilities_with_ai(self, target_info=None, api_key=None):
        """
        Check for vulnerabilities using an external AI system
        
        This function sends the target information and scan data to an external
        AI system for advanced vulnerability analysis. The AI can detect complex
        patterns and potential vulnerabilities that might be missed by traditional scanning.
        
        Args:
            target_info (dict): Target information dictionary. If None, uses the current target.
            api_key (str): API key for the AI service. If None, tries to use environment variable.
            
        Returns:
            dict: Results from the AI vulnerability analysis
        """
        logger.info("Starting AI-powered vulnerability assessment")
        target = target_info or self.validate_target()
        
        # Prepare data to send to AI service
        scan_data = {
            "target": target,
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_results": {
                "network": self.results.get("network", {}),
                "web": self.results.get("web", {}),
                "osint": self.results.get("osint", {})
            }
        }
        
        try:
            # Try to use our AIVulnerabilityChecker if available
            try:
                from ai_vulnerability_checker import AIVulnerabilityChecker
                logger.info("Using AIVulnerabilityChecker for analysis")
                
                ai_checker = AIVulnerabilityChecker(api_key=api_key)
                ai_results = ai_checker.analyze_vulnerabilities(scan_data)
                
            except ImportError:
                # Fall back to direct API call if the module is not available
                logger.info("AIVulnerabilityChecker not available, using direct API call")
                
                # Use API key from environment if not provided
                if not api_key:
                    api_key = os.environ.get("AI_SECURITY_API_KEY")
                    if not api_key:
                        logger.error("No API key provided for AI vulnerability check")
                        return {"error": "No API key provided"}
                
                # Make API request to AI service
                logger.info(f"Sending data to AI vulnerability service for analysis")
                ai_service_url = os.environ.get("AI_SECURITY_SERVICE_URL", "https://api.ai-security-analysis.com/v1/analyze")
                
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                }
                
                response = requests.post(
                    ai_service_url,
                    headers=headers,
                    json=scan_data,
                    timeout=60  # Longer timeout as AI processing might take time
                )
                
                if response.status_code != 200:
                    logger.error(f"AI service returned error: {response.status_code} - {response.text}")
                    return {
                        "success": False,
                        "error": f"AI service error: {response.status_code}",
                        "message": response.text
                    }
                
                # Process AI results
                ai_results = response.json()
            
            # Add AI-detected vulnerabilities to our results
            if "detected_vulnerabilities" in ai_results:
                for ai_vuln in ai_results["detected_vulnerabilities"]:
                    # Add AI source to vulnerability
                    ai_vuln["detection_source"] = "ai"
                    ai_vuln["ai_confidence"] = ai_vuln.get("confidence", "Medium")
                    
                    # Add to overall results
                    self.results["vulnerabilities"].append(ai_vuln)
            
            # Add AI insights to results
            if "insights" in ai_results:
                if "ai_insights" not in self.results:
                    self.results["ai_insights"] = []
                self.results["ai_insights"].extend(ai_results["insights"])
            
            # Add AI recommendations
            if "recommendations" in ai_results:
                for rec in ai_results["recommendations"]:
                    priority = rec.get("priority", "medium").lower()
                    if priority == "high":
                        if "ai_recommendations" not in self.results["remediation"]["high_priority"]:
                            self.results["remediation"]["high_priority"].append(rec)
                    elif priority == "medium":
                        if "ai_recommendations" not in self.results["remediation"]["medium_priority"]:
                            self.results["remediation"]["medium_priority"].append(rec)
                    elif priority == "low":
                        if "ai_recommendations" not in self.results["remediation"]["low_priority"]:
                            self.results["remediation"]["low_priority"].append(rec)
            
            # Update summary with AI information
            self.results["summary"]["ai_powered"] = True
            self.results["summary"]["ai_model_version"] = ai_results.get("model_version", "unknown")
            self.results["summary"]["ai_analysis_timestamp"] = ai_results.get("timestamp", datetime.datetime.now().isoformat())
            
            logger.info("AI vulnerability assessment completed successfully")
            return ai_results
            
        except Exception as e:
            logger.error(f"Error during AI vulnerability check: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def save_results(self, filename=None):
        """Save assessment results to file"""
        if not filename:
            filename = os.path.join(self.report_dir, "security_assessment_report.json")
            
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        logger.info(f"Assessment results saved to {filename}")
        return filename

    def generate_html_report(self, filename=None):
        """Generate an HTML report from the assessment results"""
        if not filename:
            filename = os.path.join(self.report_dir, "security_assessment_report.html")
        
        # Simple HTML report template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h2 { color: #2980b9; margin-top: 30px; }
                h3 { color: #3498db; }
                .container { max-width: 1200px; margin: 0 auto; }
                .summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
                .high { background-color: #f8d7da; padding: 15px; border-left: 5px solid #dc3545; margin-bottom: 15px; }
                .medium { background-color: #fff3cd; padding: 15px; border-left: 5px solid #ffc107; margin-bottom: 15px; }
                .low { background-color: #d1ecf1; padding: 15px; border-left: 5px solid #17a2b8; margin-bottom: 15px; }
                .ai-insight { background-color: #e8f4f8; padding: 15px; border-left: 5px solid #4a69bd; margin-bottom: 15px; }
                table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .footer { margin-top: 50px; font-size: 0.8em; text-align: center; color: #7f8c8d; }
                .ai-badge { display: inline-block; background-color: #4a69bd; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Assessment Report</h1>
                
                <div class="summary">
                    <h2>Executive Summary</h2>
                    <p><strong>Target:</strong> {target}</p>
                    <p><strong>Assessment Date:</strong> {assessment_date}</p>
                    <p><strong>Overall Risk Level:</strong> {risk_level}</p>
                    <p><strong>Total Vulnerabilities:</strong> {total_vulnerabilities}</p>
                    <ul>
                        <li>Critical: {critical_vulnerabilities}</li>
                        <li>High: {high_vulnerabilities}</li>
                        <li>Medium: {medium_vulnerabilities}</li>
                        <li>Low: {low_vulnerabilities}</li>
                    </ul>
                    {ai_summary}
                    
                    <h3>Top Recommendations</h3>
                    <ol>
                        {top_recommendations}
                    </ol>
                </div>
                
                <h2>Detailed Findings</h2>
                
                <h3>High Priority Issues</h3>
                {high_priority_issues}
                
                <h3>Medium Priority Issues</h3>
                {medium_priority_issues}
                
                <h3>Low Priority Issues</h3>
                {low_priority_issues}
                
                <h2>Technical Details</h2>
                
                <h3>Network Scan Results</h3>
                {network_results}
                
                <h3>Web Vulnerability Scan Results</h3>
                {web_results}
                
                <h3>OSINT Findings</h3>
                {osint_results}
                
                {ai_insights_section}
                
                <h2>Best Practices</h2>
                {best_practices}
                
                <div class="footer">
                    <p>Report generated on {generation_date} by Security Framework</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Format high priority issues
        high_priority_html = ""
        for issue in self.results["remediation"]["high_priority"]:
            # Add AI badge if this is an AI-detected issue
            ai_badge = ""
            if issue.get("detection_source") == "ai":
                ai_badge = '<span class="ai-badge">AI Detected</span>'
                
            high_priority_html += f"""
            <div class="high">
                <h4>{issue["issue"]} {ai_badge}</h4>
                <p><strong>Details:</strong> {issue["details"]}</p>
                <p><strong>Recommendation:</strong> {issue["recommendation"]}</p>
                
                <p><strong>Implementation:</strong></p>
                <ul>
                    {"".join([f"<li>{step}</li>" for step in issue.get("implementation", [])])}
                </ul>
                
                <p><strong>References:</strong></p>
                <ul>
                    {"".join([f"<li><a href='{ref}' target='_blank'>{ref}</a></li>" for ref in issue.get("references", [])])}
                </ul>
            </div>
            """
            
        # Format medium priority issues
        medium_priority_html = ""
        for issue in self.results["remediation"]["medium_priority"]:
            # Add AI badge if this is an AI-detected issue
            ai_badge = ""
            if issue.get("detection_source") == "ai":
                ai_badge = '<span class="ai-badge">AI Detected</span>'
                
            medium_priority_html += f"""
            <div class="medium">
                <h4>{issue["issue"]} {ai_badge}</h4>
                <p><strong>Details:</strong> {issue["details"]}</p>
                <p><strong>Recommendation:</strong> {issue["recommendation"]}</p>
                
                <p><strong>Implementation:</strong></p>
                <ul>
                    {"".join([f"<li>{step}</li>" for step in issue.get("implementation", [])])}
                </ul>
                
                <p><strong>References:</strong></p>
                <ul>
                    {"".join([f"<li><a href='{ref}' target='_blank'>{ref}</a></li>" for ref in issue.get("references", [])])}
                </ul>
            </div>
            """
            
        # Format low priority issues
        low_priority_html = ""
        for issue in self.results["remediation"]["low_priority"]:
            # Add AI badge if this is an AI-detected issue
            ai_badge = ""
            if issue.get("detection_source") == "ai":
                ai_badge = '<span class="ai-badge">AI Detected</span>'
                
            low_priority_html += f"""
            <div class="low">
                <h4>{issue["issue"]} {ai_badge}</h4>
                <p><strong>Details:</strong> {issue["details"]}</p>
                <p><strong>Recommendation:</strong> {issue["recommendation"]}</p>
                
                <p><strong>Implementation:</strong></p>
                <ul>
                    {"".join([f"<li>{step}</li>" for step in issue.get("implementation", [])])}
                </ul>
                
                <p><strong>References:</strong></p>
                <ul>
                    {"".join([f"<li><a href='{ref}' target='_blank'>{ref}</a></li>" for ref in issue.get("references", [])])}
                </ul>
            </div>
            """
            
        # Format best practices
        best_practices_html = ""
        for practice in self.results["remediation"]["best_practices"]:
            best_practices_html += f"""
            <div>
                <h4>{practice["issue"]}</h4>
                <p><strong>Recommendation:</strong> {practice["recommendation"]}</p>
                
                <p><strong>Implementation:</strong></p>
                <ul>
                    {"".join([f"<li>{step}</li>" for step in practice.get("implementation", [])])}
                </ul>
            </div>
            """
        
        # Format top recommendations
        top_recommendations_html = ""
        for rec in self.results["summary"]["primary_recommendations"]:
            top_recommendations_html += f"<li>{rec}</li>"
            
        # Simplified technical details
        network_results_html = "<p>Port scan found {open_ports} open ports. Full details available in the JSON report.</p>"
        web_results_html = "<p>Web vulnerability scan details available in the JSON report.</p>"
        osint_results_html = "<p>OSINT analysis details available in the JSON report.</p>"
        
        # AI Summary section (only if AI was used)
        ai_summary_html = ""
        if self.results["summary"].get("ai_powered"):
            ai_summary_html = f"""
            <p><strong>AI-Powered Analysis:</strong> Yes</p>
            <p><strong>AI Model Version:</strong> {self.results["summary"].get("ai_model_version", "Unknown")}</p>
            """
        
        # AI Insights section (only if available)
        ai_insights_html = ""
        if "ai_insights" in self.results and self.results["ai_insights"]:
            insights_html = ""
            for insight in self.results["ai_insights"]:
                insights_html += f"""
                <div class="ai-insight">
                    <h4>{insight.get("title", "AI Insight")}</h4>
                    <p>{insight.get("description", "")}</p>
                    {f'<p><strong>Confidence:</strong> {insight.get("confidence", "Medium")}</p>' if "confidence" in insight else ""}
                    {f'<p><strong>Impact:</strong> {insight.get("impact", "")}</p>' if "impact" in insight else ""}
                </div>
                """
            
            ai_insights_html = f"""
            <h2>AI Security Insights</h2>
            <p>The following insights were generated by AI analysis of the target and scan results:</p>
            {insights_html}
            """
        
        # Fill in the template
        html_content = html_template.format(
            target=self.results["summary"]["target"],
            assessment_date=self.results["summary"]["assessment_date"],
            risk_level=self.results["summary"]["risk_level"],
            total_vulnerabilities=self.results["summary"]["total_vulnerabilities"],
            critical_vulnerabilities=self.results["summary"]["vulnerabilities"]["critical"],
            high_vulnerabilities=self.results["summary"]["vulnerabilities"]["high"],
            medium_vulnerabilities=self.results["summary"]["vulnerabilities"]["medium"],
            low_vulnerabilities=self.results["summary"]["vulnerabilities"]["low"],
            top_recommendations=top_recommendations_html,
            high_priority_issues=high_priority_html or "<p>No high priority issues found.</p>",
            medium_priority_issues=medium_priority_html or "<p>No medium priority issues found.</p>",
            low_priority_issues=low_priority_html or "<p>No low priority issues found.</p>",
            network_results=network_results_html.format(open_ports=self.results["summary"]["open_ports"]),
            web_results=web_results_html,
            osint_results=osint_results_html,
            ai_summary=ai_summary_html,
            ai_insights_section=ai_insights_html,
            best_practices=best_practices_html,
            generation_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Write to file
        with open(filename, 'w') as f:
            f.write(html_content)
            
        logger.info(f"HTML report generated at {filename}")
        return filename

    def run_dns_spoofing_attack(self, 
                               tool="dnschef", 
                               interface="eth0", 
                               domains=None, 
                               targets=None, 
                               **kwargs):
        """
        Run a DNS spoofing attack
        
        Args:
            tool: Tool to use ("dnschef", "ettercap", or "responder")
            interface: Network interface to use
            domains: Dictionary of domains to spoof (domain -> ip)
            targets: List of targets for the attack
            **kwargs: Additional tool-specific parameters
            
        Returns:
            Dict: DNS spoofing results
        """
        logger.info(f"Starting DNS spoofing attack using {tool}")
        
        # Set default domains if none provided
        if domains is None:
            target_info = self.validate_target()
            if target_info["type"] == "domain" or target_info["type"] == "url":
                domain = target_info["domain"]
                # Default to localhost for demonstration purposes
                domains = {domain: "127.0.0.1"}
                
        # Check if the tool is installed
        tools_status = list_dns_spoof_tools()
        if tool in tools_status and not tools_status[tool]["installed"]:
            logger.info(f"{tool} is not installed. Installing...")
            install_dns_spoof_tool(tool)
        
        try:
            # Start the attack
            result = start_dns_spoof_attack(
                tool=tool,
                interface=interface,
                domains=domains,
                targets=targets,
                **kwargs
            )
            
            self.results["dns_spoofing"] = {
                "timestamp": datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
                "tool": tool,
                "status": result.get("status"),
                "message": result.get("message"),
                "domains": domains,
                "targets": targets,
                "interface": interface,
                "additional_params": kwargs
            }
            
            # Store the tool status
            self.results["dns_spoofing"]["tool_status"] = get_dns_spoof_status(tool)
            
            logger.info(f"DNS spoofing attack completed with status: {result.get('status')}")
        except Exception as e:
            logger.error(f"Error during DNS spoofing attack: {str(e)}")
            self.results["dns_spoofing"]["error"] = str(e)
            
        return self.results["dns_spoofing"]
    
    def stop_dns_spoofing_attack(self, tool=None):
        """
        Stop DNS spoofing attacks
        
        Args:
            tool: Specific tool to stop, or None to stop all
            
        Returns:
            Dict: Results of stopping the attack(s)
        """
        try:
            if tool:
                logger.info(f"Stopping DNS spoofing attack using {tool}")
                result = stop_dns_spoof_attack(tool)
                status = {tool: result}
            else:
                logger.info("Stopping all DNS spoofing attacks")
                status = stop_all_dns_spoof_attacks()
                
            self.results["dns_spoofing"]["stopped"] = True
            self.results["dns_spoofing"]["stop_status"] = status
            
            return status
        except Exception as e:
            logger.error(f"Error stopping DNS spoofing attack: {str(e)}")
            return {"error": str(e)}
    
    def get_dns_spoofing_status(self, tool=None):
        """
        Get the status of DNS spoofing attacks
        
        Args:
            tool: Specific tool to check, or None to check all
            
        Returns:
            Dict: Status of the DNS spoofing tool(s)
        """
        return get_dns_spoof_status(tool)

# Ensure integration modules can find SecurityToolBase even when imported directly
__all__ = ['SecurityToolBase', 'register_tool', 'get_tools_directory', 'download_file', 'security_tools_manager']

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Comprehensive Security Assessment Framework")
    
    # General arguments
    parser.add_argument("--target", help="Target URL, domain, or IP address")
    parser.add_argument("--output-dir", default="security_assessment", help="Output directory for reports")
    
    # Assessment types
    assessment_group = parser.add_argument_group("Assessment Types")
    assessment_group.add_argument("--network", action="store_true", help="Run network assessment")
    assessment_group.add_argument("--osint", action="store_true", help="Run OSINT assessment")
    assessment_group.add_argument("--web", action="store_true", help="Run web vulnerability assessment")
    assessment_group.add_argument("--social", action="store_true", help="Prepare social engineering templates")
    assessment_group.add_argument("--w3af", action="store_true", help="Run w3af AI assessment")
    assessment_group.add_argument("--watson", action="store_true", help="Run IBM Watson security analysis")
    assessment_group.add_argument("--comprehensive", action="store_true", help="Run comprehensive assessment")
    assessment_group.add_argument("--ai-check", action="store_true", help="Check vulnerabilities with AI")
    
    # DNS Spoofing options
    dns_spoof_group = parser.add_argument_group("DNS Spoofing")
    dns_spoof_group.add_argument("--dns-spoof", action="store_true", help="Run DNS spoofing attack")
    dns_spoof_group.add_argument("--dns-tool", choices=["dnschef", "ettercap", "responder"], default="dnschef", help="DNS spoofing tool to use")
    dns_spoof_group.add_argument("--interface", default="eth0", help="Network interface to use")
    dns_spoof_group.add_argument("--domain", help="Domain to spoof (used with --ip)")
    dns_spoof_group.add_argument("--ip", help="IP to redirect to (used with --domain)")
    dns_spoof_group.add_argument("--domains-file", help="JSON file containing domains to spoof {domain: ip, ...}")
    dns_spoof_group.add_argument("--targets", nargs="+", help="Targets for Ettercap (IP addresses/ranges)")
    dns_spoof_group.add_argument("--stop-dns-spoof", action="store_true", help="Stop DNS spoofing attack")
    dns_spoof_group.add_argument("--list-dns-tools", action="store_true", help="List DNS spoofing tools")
    
    # Report options
    report_group = parser.add_argument_group("Reporting")
    report_group.add_argument("--save", action="store_true", help="Save results to JSON file")
    report_group.add_argument("--report", action="store_true", help="Generate HTML report")
    
    args = parser.parse_args()
    
    # Check for required arguments
    if not args.target and not args.list_dns_tools and not args.stop_dns_spoof:
        parser.error("Target is required unless just listing DNS tools or stopping DNS spoofing")
        
    framework = SecurityFramework(args.target, args.output_dir)
    results = {}
    
    try:
        # List DNS spoofing tools if requested
        if args.list_dns_tools:
            tools = list_dns_spoof_tools()
            print("\nAvailable DNS Spoofing Tools:")
            print("============================")
            for name, info in tools.items():
                print(f"\n{info['name']}")
                print("-" * len(info['name']))
                print(f"Description: {info['description']}")
                print(f"Installed: {'Yes' if info['installed'] else 'No'}")
                print(f"Running: {'Yes' if info['running'] else 'No'}")
            return
            
        # Stop DNS spoofing attack if requested
        if args.stop_dns_spoof:
            print("Stopping DNS spoofing attacks...")
            status = framework.stop_dns_spoofing_attack(args.dns_tool if args.dns_tool else None)
            print(f"Stop status: {status}")
            return
            
        # Run DNS spoofing attack if requested
        if args.dns_spoof:
            # Build domains dictionary
            domains = {}
            
            if args.domain and args.ip:
                domains[args.domain] = args.ip
                
            if args.domains_file:
                try:
                    with open(args.domains_file, "r") as f:
                        domains.update(json.load(f))
                except Exception as e:
                    print(f"Error reading domains file: {e}")
                    return
                    
            print(f"Starting DNS spoofing attack using {args.dns_tool}...")
            result = framework.run_dns_spoofing_attack(
                tool=args.dns_tool,
                interface=args.interface,
                domains=domains,
                targets=args.targets
            )
            
            print(f"DNS spoofing attack status: {result.get('status')}")
            print(f"Message: {result.get('message')}")
            
            # Add to results
            results["dns_spoofing"] = result
            
        # No operations specified, just validate the target
        if not any([
            args.network, args.osint, args.web, args.social, 
            args.w3af, args.watson, args.comprehensive, args.ai_check,
            args.dns_spoof
        ]):
            target_info = framework.validate_target()
            print(f"Validated target: {target_info}")
            
        # Run requested assessments
        if args.network:
            print("Running network assessment...")
            results["network"] = framework.run_network_assessment()
            
        if args.osint:
            print("Running OSINT assessment...")
            results["osint"] = framework.run_osint_assessment()
            
        if args.web:
            print("Running web vulnerability assessment...")
            results["web"] = framework.run_web_vulnerability_scan()
            
        if args.social:
            print("Preparing social engineering templates...")
            results["social"] = framework.prepare_social_engineering_assessment()
            
        if args.w3af:
            print("Running w3af AI assessment...")
            results["w3af"] = framework.run_w3af_ai_assessment()
            
        if args.watson:
            print("Running IBM Watson security analysis...")
            results["watson"] = framework.run_ibm_watson_analysis()
            
        if args.comprehensive:
            print("Running comprehensive assessment...")
            results = framework.run_comprehensive_assessment()
            
        if args.ai_check:
            print("Checking vulnerabilities with AI...")
            results["ai_check"] = framework.check_vulnerabilities_with_ai()
            
        # Generate recommendations if assessments were run
        if results:
            print("Generating mitigation recommendations...")
            results["remediation"] = framework.generate_mitigation_recommendations()
            
        # Save results if requested
        if args.save:
            filename = framework.save_results()
            print(f"Results saved to {filename}")
            
        # Generate HTML report if requested
        if args.report:
            report_file = framework.generate_html_report()
            print(f"HTML report generated: {report_file}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    main() 