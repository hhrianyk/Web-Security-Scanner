#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import argparse
import datetime
import time

# Import our security testing modules
try:
    from injection_attacks import InjectionAttacker
    from xss_attacks import XSSAttacker
    from auth_attacks import AuthAttacker
except ImportError as e:
    print(f"Error importing security testing modules: {e}")
    print("Make sure all required modules are in the same directory or in your PYTHONPATH")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("advanced_security_tester.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AdvancedSecurityTester")

class AdvancedSecurityTester:
    """
    Advanced Security Testing Framework that integrates multiple testing modules:
    - Injection attacks (SQL, NoSQL, Command)
    - Cross-Site Scripting (XSS) attacks
    - Authentication and Authorization attacks
    - Path Traversal and File Inclusion attacks (coming soon)
    - Server-Side Request Forgery (SSRF) (coming soon)
    - Cross-Site Request Forgery (CSRF) (coming soon)
    - XML-based attacks (coming soon)
    - Deserialization vulnerabilities (coming soon)
    """
    
    def __init__(self, target=None, output_dir="security_assessment"):
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = os.path.join(output_dir, f"assessment_{self.timestamp}")
        
        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Initialize results dictionary
        self.results = {
            "timestamp": self.timestamp,
            "target": target,
            "summary": {},
            "injection_attacks": {},
            "xss_attacks": {},
            "auth_attacks": {},
            "file_system_attacks": {},
            "remediation": {}
        }
        
        logger.info(f"Initialized AdvancedSecurityTester for target: {target}")
    
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
    
    def run_injection_tests(self):
        """Run injection attack tests"""
        logger.info("Starting injection attack tests")
        
        try:
            # Create output directory
            injection_dir = os.path.join(self.report_dir, "injection")
            os.makedirs(injection_dir, exist_ok=True)
            
            # Initialize injection attacker
            injection_attacker = InjectionAttacker(self.target, injection_dir)
            
            # Run tests
            start_time = time.time()
            injection_results = injection_attacker.run_all_tests()
            duration = time.time() - start_time
            
            # Save results
            self.results["injection_attacks"] = {
                "results": injection_results,
                "duration": duration,
                "vulnerable": injection_results.get("vulnerable", False),
                "total_vulnerabilities": injection_results.get("total_vulnerabilities", 0)
            }
            
            logger.info(f"Injection attack tests completed in {duration:.2f} seconds")
            return self.results["injection_attacks"]
            
        except Exception as e:
            logger.error(f"Error during injection attack tests: {str(e)}")
            self.results["injection_attacks"] = {
                "error": str(e),
                "vulnerable": False
            }
            return self.results["injection_attacks"]
    
    def run_xss_tests(self):
        """Run XSS attack tests"""
        logger.info("Starting XSS attack tests")
        
        try:
            # Create output directory
            xss_dir = os.path.join(self.report_dir, "xss")
            os.makedirs(xss_dir, exist_ok=True)
            
            # Initialize XSS attacker
            xss_attacker = XSSAttacker(self.target, xss_dir)
            
            # Run tests
            start_time = time.time()
            xss_results = xss_attacker.run_all_tests()
            duration = time.time() - start_time
            
            # Save results
            self.results["xss_attacks"] = {
                "results": xss_results,
                "duration": duration,
                "vulnerable": xss_results.get("vulnerable", False),
                "total_vulnerabilities": xss_results.get("total_vulnerabilities", 0)
            }
            
            logger.info(f"XSS attack tests completed in {duration:.2f} seconds")
            return self.results["xss_attacks"]
            
        except Exception as e:
            logger.error(f"Error during XSS attack tests: {str(e)}")
            self.results["xss_attacks"] = {
                "error": str(e),
                "vulnerable": False
            }
            return self.results["xss_attacks"]
    
    def run_auth_tests(self):
        """Run authentication and authorization attack tests"""
        logger.info("Starting authentication attack tests")
        
        try:
            # Create output directory
            auth_dir = os.path.join(self.report_dir, "auth")
            os.makedirs(auth_dir, exist_ok=True)
            
            # Initialize auth attacker
            auth_attacker = AuthAttacker(self.target, auth_dir)
            
            # Run tests
            start_time = time.time()
            auth_results = auth_attacker.run_all_tests()
            duration = time.time() - start_time
            
            # Save results
            self.results["auth_attacks"] = {
                "results": auth_results,
                "duration": duration,
                "vulnerable": auth_results.get("vulnerable", False)
            }
            
            logger.info(f"Authentication attack tests completed in {duration:.2f} seconds")
            return self.results["auth_attacks"]
            
        except Exception as e:
            logger.error(f"Error during authentication attack tests: {str(e)}")
            self.results["auth_attacks"] = {
                "error": str(e),
                "vulnerable": False
            }
            return self.results["auth_attacks"]
    
    def generate_summary(self):
        """Generate a summary of all test results"""
        logger.info("Generating assessment summary")
        
        # Count total vulnerabilities
        total_vulnerabilities = 0
        if self.results["injection_attacks"].get("vulnerable", False):
            total_vulnerabilities += self.results["injection_attacks"].get("total_vulnerabilities", 0)
        if self.results["xss_attacks"].get("vulnerable", False):
            total_vulnerabilities += self.results["xss_attacks"].get("total_vulnerabilities", 0)
        if self.results["auth_attacks"].get("vulnerable", False):
            auth_vulns = 0
            # Count auth vulnerabilities
            auth_results = self.results["auth_attacks"].get("results", {})
            if auth_results.get("brute_force", {}).get("vulnerable", False):
                auth_vulns += 1
            if auth_results.get("session_attacks", {}).get("vulnerable", False):
                session_results = auth_results.get("session_attacks", {})
                if session_results.get("session_fixation", {}).get("vulnerable", False):
                    auth_vulns += 1
                if session_results.get("session_hijacking", {}).get("vulnerable", False):
                    auth_vulns += 1
                if session_results.get("session_prediction", {}).get("vulnerable", False):
                    auth_vulns += 1
            if auth_results.get("oauth_vulnerabilities", {}).get("vulnerable", False):
                auth_vulns += auth_results.get("oauth_vulnerabilities", {}).get("vulnerabilities_count", 0)
            total_vulnerabilities += auth_vulns
        
        # Determine overall risk level
        risk_level = "Low"
        if total_vulnerabilities > 10:
            risk_level = "Critical"
        elif total_vulnerabilities > 5:
            risk_level = "High"
        elif total_vulnerabilities > 2:
            risk_level = "Medium"
            
        # Create summary
        self.results["summary"] = {
            "assessment_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "total_vulnerabilities": total_vulnerabilities,
            "risk_level": risk_level,
            "vulnerable_areas": {
                "injection": self.results["injection_attacks"].get("vulnerable", False),
                "xss": self.results["xss_attacks"].get("vulnerable", False),
                "auth": self.results["auth_attacks"].get("vulnerable", False),
                "file_system": self.results["file_system_attacks"].get("vulnerable", False),
            }
        }
        
        return self.results["summary"]
    
    def generate_remediation(self):
        """Generate remediation recommendations"""
        logger.info("Generating remediation recommendations")
        
        remediation = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "best_practices": []
        }
        
        # Add injection attack remediations
        if self.results["injection_attacks"].get("vulnerable", False):
            injection_results = self.results["injection_attacks"].get("results", {})
            
            # SQL Injection remediation
            if injection_results.get("sql_injection", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "SQL Injection Vulnerability",
                    "details": "Application is vulnerable to SQL injection attacks",
                    "recommendation": "Use parameterized queries or prepared statements. Never build SQL queries using string concatenation with user input.",
                    "example": "Instead of: \"SELECT * FROM users WHERE username = '\" + username + \"'\"\nUse: \"SELECT * FROM users WHERE username = ?\" with parameters",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ]
                })
            
            # NoSQL Injection remediation
            if injection_results.get("nosql_injection", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "NoSQL Injection Vulnerability",
                    "details": "Application is vulnerable to NoSQL injection attacks",
                    "recommendation": "Sanitize and validate all user inputs before using them in NoSQL queries. Use strict schema validation.",
                    "example": "Instead of: db.users.find({username: username})\nUse: db.users.find({username: sanitize(username)})",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
                    ]
                })
            
            # Command Injection remediation
            if injection_results.get("command_injection", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Command Injection Vulnerability",
                    "details": "Application is vulnerable to OS command injection attacks",
                    "recommendation": "Avoid using OS commands in web applications. If necessary, use a whitelist of allowed commands and parameters.",
                    "example": "Instead of: exec(\"ping \" + user_input)\nUse a library or API that provides the required functionality without shell commands",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                    ]
                })
        
        # Add XSS attack remediations
        if self.results["xss_attacks"].get("vulnerable", False):
            xss_results = self.results["xss_attacks"].get("results", {})
            
            # Reflected XSS remediation
            if xss_results.get("reflected_xss", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Reflected Cross-Site Scripting (XSS) Vulnerability",
                    "details": "Application is vulnerable to reflected XSS attacks",
                    "recommendation": "Implement proper input validation and output encoding. Use Content-Security-Policy headers.",
                    "example": "Instead of: document.write(\"<p>\" + userInput + \"</p>\")\nUse: document.createElement(\"p\").textContent = userInput",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                })
            
            # Stored XSS remediation
            if xss_results.get("stored_xss", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Stored Cross-Site Scripting (XSS) Vulnerability",
                    "details": "Application is vulnerable to stored XSS attacks",
                    "recommendation": "Implement proper input sanitization and output encoding for stored data. Use Content-Security-Policy headers.",
                    "example": "Use dedicated HTML sanitization libraries to clean user input before storing",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                })
            
            # DOM XSS remediation
            if xss_results.get("dom_xss", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "DOM-based Cross-Site Scripting (XSS) Vulnerability",
                    "details": "Application is vulnerable to DOM-based XSS attacks",
                    "recommendation": "Use safe JavaScript methods, avoid dangerous functions like innerHTML, document.write, and eval.",
                    "example": "Instead of: element.innerHTML = data\nUse: element.textContent = data",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
                    ]
                })
        
        # Add authentication attack remediations
        if self.results["auth_attacks"].get("vulnerable", False):
            auth_results = self.results["auth_attacks"].get("results", {})
            
            # Brute force remediation
            if auth_results.get("brute_force", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Brute Force Vulnerability",
                    "details": "Application is vulnerable to brute force attacks against authentication",
                    "recommendation": "Implement account lockout, rate limiting, and CAPTCHA. Use strong password policies.",
                    "example": "Limit login attempts to 5 per minute. Lock accounts after 10 failed attempts until manual reset.",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ]
                })
            
            # Session attacks remediation
            session_results = auth_results.get("session_attacks", {})
            if session_results.get("session_fixation", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Session Fixation Vulnerability",
                    "details": "Application is vulnerable to session fixation attacks",
                    "recommendation": "Always issue a new session ID after authentication. Never accept session IDs from URL parameters.",
                    "example": "Upon successful login, invalidate the old session and create a new one.",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ]
                })
                
            if session_results.get("session_hijacking", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Session Hijacking Vulnerability",
                    "details": "Session cookies are not properly protected",
                    "recommendation": "Use secure, HttpOnly, and SameSite flags on cookies. Implement proper session timeouts.",
                    "example": "Set-Cookie: sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ]
                })
                
            if session_results.get("session_prediction", {}).get("vulnerable", False):
                remediation["high_priority"].append({
                    "issue": "Session Prediction Vulnerability",
                    "details": "Session IDs are predictable or not sufficiently random",
                    "recommendation": "Use cryptographically secure random values for session IDs with sufficient length.",
                    "example": "Generate session IDs with at least 128 bits of entropy using a secure random number generator.",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ]
                })
            
            # OAuth vulnerabilities remediation
            oauth_results = auth_results.get("oauth_vulnerabilities", {})
            if oauth_results.get("vulnerable", False):
                if any(v["type"] == "Open Redirect" for v in oauth_results.get("vulnerabilities", [])):
                    remediation["high_priority"].append({
                        "issue": "OAuth Open Redirect Vulnerability",
                        "details": "OAuth implementation allows open redirects",
                        "recommendation": "Validate all redirect URLs against a whitelist of allowed domains.",
                        "example": "Check that the redirect_uri parameter points to a trusted domain before proceeding.",
                        "references": [
                            "https://oauth.net/articles/authentication/"
                        ]
                    })
                    
                if any(v["type"] == "OAuth Token Theft" for v in oauth_results.get("vulnerabilities", [])):
                    remediation["high_priority"].append({
                        "issue": "OAuth Token Theft Vulnerability",
                        "details": "OAuth implementation is vulnerable to token theft",
                        "recommendation": "Use HTTPS for all OAuth endpoints, validate redirect URIs, implement PKCE for authorization code flow.",
                        "example": "Ensure redirect_uri validation is strict and reject requests with invalid URIs.",
                        "references": [
                            "https://oauth.net/2/pkce/"
                        ]
                    })
        
        # Add best practices
        remediation["best_practices"] = [
            {
                "issue": "Regular Security Testing",
                "recommendation": "Conduct regular security assessments and penetration testing.",
                "details": "Implement a continuous security testing schedule to identify vulnerabilities before they can be exploited."
            },
            {
                "issue": "Security Headers",
                "recommendation": "Implement all recommended security headers.",
                "details": "Add Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and other security headers to all responses."
            },
            {
                "issue": "Keep Dependencies Updated",
                "recommendation": "Regularly update all dependencies and frameworks.",
                "details": "Outdated components often contain known vulnerabilities that can be easily exploited."
            },
            {
                "issue": "Input Validation",
                "recommendation": "Implement strict input validation for all user inputs.",
                "details": "Validate inputs on both client and server side, preferably using a whitelist approach."
            }
        ]
        
        self.results["remediation"] = remediation
        return remediation
    
    def run_comprehensive_assessment(self, target=None):
        """Run a comprehensive security assessment"""
        start_time = time.time()
        
        # Validate target
        target = self.validate_target(target)
        logger.info(f"Starting comprehensive security assessment for {target}")
        
        # Run all tests
        self.run_injection_tests()
        self.run_xss_tests()
        self.run_auth_tests()
        
        # Generate summary and recommendations
        self.generate_summary()
        self.generate_remediation()
        
        # Calculate duration
        duration = time.time() - start_time
        self.results["duration"] = duration
        
        logger.info(f"Comprehensive assessment completed in {duration:.2f} seconds")
        return self.results
    
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
        html_report = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #2980b9; margin-top: 30px; }}
                h3 {{ color: #3498db; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .summary {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
                .high {{ background-color: #f8d7da; padding: 15px; border-left: 5px solid #dc3545; margin-bottom: 15px; }}
                .medium {{ background-color: #fff3cd; padding: 15px; border-left: 5px solid #ffc107; margin-bottom: 15px; }}
                .low {{ background-color: #d1ecf1; padding: 15px; border-left: 5px solid #17a2b8; margin-bottom: 15px; }}
                .footer {{ margin-top: 50px; border-top: 1px solid #ddd; padding-top: 20px; font-size: 0.8em; color: #7f8c8d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Advanced Security Assessment Report</h1>
                
                <div class="summary">
                    <h2>Executive Summary</h2>
                    <p><strong>Target:</strong> {self.results["target"]}</p>
                    <p><strong>Assessment Date:</strong> {self.results["summary"]["assessment_date"]}</p>
                    <p><strong>Risk Level:</strong> {self.results["summary"]["risk_level"]}</p>
                    <p><strong>Total Vulnerabilities Found:</strong> {self.results["summary"]["total_vulnerabilities"]}</p>
                    
                    <h3>Vulnerability Areas</h3>
                    <ul>
                        <li>Injection Attacks: {"Vulnerable" if self.results["summary"]["vulnerable_areas"]["injection"] else "Not Vulnerable"}</li>
                        <li>Cross-Site Scripting (XSS): {"Vulnerable" if self.results["summary"]["vulnerable_areas"]["xss"] else "Not Vulnerable"}</li>
                        <li>Authentication & Authorization: {"Vulnerable" if self.results["summary"]["vulnerable_areas"]["auth"] else "Not Vulnerable"}</li>
                    </ul>
                </div>
                
                <h2>High Priority Recommendations</h2>
        """
        
        # Add high priority recommendations
        high_recs = self.results["remediation"]["high_priority"]
        if high_recs:
            for rec in high_recs:
                html_report += f"""
                <div class="high">
                    <h3>{rec["issue"]}</h3>
                    <p><strong>Details:</strong> {rec["details"]}</p>
                    <p><strong>Recommendation:</strong> {rec["recommendation"]}</p>
                </div>
                """
        else:
            html_report += "<p>No high priority issues found.</p>"
        
        html_report += """
                <h2>Medium Priority Recommendations</h2>
        """
        
        # Add medium priority recommendations
        medium_recs = self.results["remediation"]["medium_priority"]
        if medium_recs:
            for rec in medium_recs:
                html_report += f"""
                <div class="medium">
                    <h3>{rec["issue"]}</h3>
                    <p><strong>Details:</strong> {rec["details"]}</p>
                    <p><strong>Recommendation:</strong> {rec["recommendation"]}</p>
                </div>
                """
        else:
            html_report += "<p>No medium priority issues found.</p>"
        
        html_report += """
                <h2>Best Practices</h2>
        """
        
        # Add best practices
        best_practices = self.results["remediation"]["best_practices"]
        for practice in best_practices:
            html_report += f"""
            <div class="low">
                <h3>{practice["issue"]}</h3>
                <p><strong>Recommendation:</strong> {practice["recommendation"]}</p>
                <p>{practice["details"]}</p>
            </div>
            """
        
        # Close the HTML
        html_report += f"""
                <div class="footer">
                    <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} using Advanced Security Tester</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write to file
        with open(filename, 'w') as f:
            f.write(html_report)
            
        logger.info(f"HTML report saved to {filename}")
        return filename

def main():
    """Command line interface for the security tester"""
    parser = argparse.ArgumentParser(description="Advanced Security Testing Framework")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("--output", "-o", help="Output directory for results", default="security_assessment")
    parser.add_argument("--injection-only", action="store_true", help="Run only injection tests")
    parser.add_argument("--xss-only", action="store_true", help="Run only XSS tests")
    parser.add_argument("--auth-only", action="store_true", help="Run only authentication tests")
    parser.add_argument("--format", choices=["json", "html", "both"], default="both", help="Report format")
    args = parser.parse_args()
    
    tester = AdvancedSecurityTester(args.target, args.output)
    
    try:
        if args.injection_only:
            tester.run_injection_tests()
        elif args.xss_only:
            tester.run_xss_tests()
        elif args.auth_only:
            tester.run_auth_tests()
        else:
            tester.run_comprehensive_assessment()
            
        # Generate reports
        if args.format in ["json", "both"]:
            json_report = tester.save_results()
            print(f"JSON report saved to: {json_report}")
            
        if args.format in ["html", "both"]:
            html_report = tester.generate_html_report()
            print(f"HTML report saved to: {html_report}")
            
    except Exception as e:
        logger.critical(f"Critical error: {str(e)}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main()) 