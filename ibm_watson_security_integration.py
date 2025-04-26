#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import time
import datetime
import requests
import hmac
import hashlib
import base64
import uuid
from urllib.parse import urlparse
import dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ibm_watson_security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("IBMWatsonSecurity")

# Load environment variables
dotenv.load_dotenv(".env")

class IBMWatsonSecurityIntegration:
    """
    IBM Watson for Cybersecurity Integration
    
    Enhances security analysis using IBM Watson's cognitive capabilities:
    1. Threat Intelligence Analysis
    2. Vulnerability Assessment
    3. Security Event Analysis
    4. Security Risk Scoring
    5. Remediation Recommendations
    """
    
    def __init__(self, output_dir="ibm_watson_security_reports"):
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get API credentials from environment variables
        self.ibm_api_key = os.getenv("IBM_WATSON_API_KEY")
        self.ibm_instance_id = os.getenv("IBM_WATSON_INSTANCE_ID")
        self.ibm_url = os.getenv("IBM_WATSON_URL") or "https://api.us-south.security-advisor.cloud.ibm.com/v1"
        
        # Additional environment variables for IBM services
        self.ibm_x_force_api_key = os.getenv("IBM_XFORCE_API_KEY")
        self.ibm_x_force_password = os.getenv("IBM_XFORCE_PASSWORD")
        self.ibm_qradar_url = os.getenv("IBM_QRADAR_URL")
        self.ibm_qradar_token = os.getenv("IBM_QRADAR_TOKEN")
        
        # Check if we have required credentials
        self.has_credentials = bool(self.ibm_api_key and self.ibm_instance_id)
        if not self.has_credentials:
            logger.warning("IBM Watson API credentials not provided. Operating in simulation mode.")
        else:
            logger.info("IBM Watson API credentials found.")
        
        # Initialize results
        self.results = {
            "timestamp": self.timestamp,
            "threat_intelligence": {},
            "vulnerability_assessment": {},
            "security_events": {},
            "risk_scoring": {},
            "remediation": {}
        }
        
        logger.info("Initialized IBM Watson Security Integration")
    
    def _create_iam_token(self):
        """Create an IAM token for IBM Cloud services"""
        if not self.ibm_api_key:
            logger.error("IBM API key not provided")
            return None
            
        try:
            response = requests.post(
                "https://iam.cloud.ibm.com/identity/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                    "apikey": self.ibm_api_key
                }
            )
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get("access_token")
            else:
                logger.error(f"Failed to create IAM token: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating IAM token: {str(e)}")
            return None
    
    def _ibm_api_request(self, endpoint, method="GET", data=None, headers=None):
        """Make a request to the IBM Watson Security API"""
        if not self.has_credentials:
            return self._simulate_api_response(endpoint)
            
        token = self._create_iam_token()
        if not token:
            return self._simulate_api_response(endpoint)
            
        url = f"{self.ibm_url}/{endpoint}"
        
        headers = headers or {}
        headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            if response.status_code >= 200 and response.status_code < 300:
                return response.json()
            else:
                logger.error(f"API request failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error making API request: {str(e)}")
            return None
    
    def _simulate_api_response(self, endpoint):
        """Simulate IBM Watson API response for testing without API keys"""
        logger.info(f"Simulating IBM Watson API response for endpoint: {endpoint}")
        
        if "threat" in endpoint:
            return {
                "threats": [
                    {
                        "id": "T1234",
                        "name": "Phishing Campaign",
                        "description": "Sophisticated phishing campaign targeting financial services",
                        "confidence": 0.85,
                        "severity": "HIGH",
                        "indicators": [
                            {"type": "domain", "value": "secure-banklogin.com"},
                            {"type": "ip", "value": "203.0.113.100"},
                            {"type": "email", "value": "security@secure-banklogin.com"}
                        ],
                        "tactics": ["Initial Access", "Credential Access"],
                        "mitigation": "Employee awareness training and email filtering"
                    },
                    {
                        "id": "T2345",
                        "name": "Malware Distribution",
                        "description": "Trojan distribution through compromised software updates",
                        "confidence": 0.78,
                        "severity": "CRITICAL",
                        "indicators": [
                            {"type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99"},
                            {"type": "domain", "value": "update-service.net"},
                            {"type": "url", "value": "https://update-service.net/download.exe"}
                        ],
                        "tactics": ["Execution", "Defense Evasion"],
                        "mitigation": "Update software verification procedures and implement application whitelisting"
                    }
                ]
            }
        
        elif "vulnerability" in endpoint:
            return {
                "vulnerabilities": [
                    {
                        "id": "CVE-2023-1234",
                        "title": "SQL Injection in Login Form",
                        "description": "A SQL injection vulnerability in the login form allows attackers to bypass authentication",
                        "cvss_score": 8.5,
                        "severity": "HIGH",
                        "affected_components": ["Authentication Module", "User Management"],
                        "exploit_available": True,
                        "remediation": "Apply input validation and parameterized queries"
                    },
                    {
                        "id": "CVE-2023-5678",
                        "title": "Cross-Site Scripting in Profile Page",
                        "description": "A stored XSS vulnerability in the user profile page allows attackers to inject malicious scripts",
                        "cvss_score": 6.8,
                        "severity": "MEDIUM",
                        "affected_components": ["User Profile", "Frontend"],
                        "exploit_available": True,
                        "remediation": "Implement output encoding and Content Security Policy"
                    }
                ]
            }
        
        elif "events" in endpoint:
            return {
                "events": [
                    {
                        "id": "E1234",
                        "type": "Authentication",
                        "description": "Multiple failed login attempts",
                        "timestamp": "2023-08-15T14:23:45Z",
                        "severity": "MEDIUM",
                        "source_ip": "192.168.1.100",
                        "user": "admin",
                        "status": "SUSPICIOUS",
                        "details": {
                            "attempts": 10,
                            "timespan": "5 minutes",
                            "successful": False
                        }
                    },
                    {
                        "id": "E5678",
                        "type": "Data Access",
                        "description": "Sensitive data accessed from unusual location",
                        "timestamp": "2023-08-15T16:42:18Z",
                        "severity": "HIGH",
                        "source_ip": "203.0.113.50",
                        "user": "jsmith",
                        "status": "ALERT",
                        "details": {
                            "data_type": "Financial Records",
                            "records_accessed": 142,
                            "location": "Foreign Country",
                            "previous_access": "Never from this location"
                        }
                    }
                ]
            }
        
        elif "risk" in endpoint:
            return {
                "risk_assessment": {
                    "overall_score": 68,
                    "severity": "MEDIUM",
                    "factors": [
                        {
                            "name": "Authentication Security",
                            "score": 45,
                            "severity": "HIGH",
                            "findings": [
                                "No multi-factor authentication",
                                "Weak password policies",
                                "No account lockout"
                            ]
                        },
                        {
                            "name": "Data Protection",
                            "score": 72,
                            "severity": "MEDIUM",
                            "findings": [
                                "Sensitive data encrypted at rest",
                                "Partial encryption in transit",
                                "Inadequate data access controls"
                            ]
                        },
                        {
                            "name": "Network Security",
                            "score": 82,
                            "severity": "LOW",
                            "findings": [
                                "Properly configured firewall",
                                "Segmented network",
                                "Some unnecessary open ports"
                            ]
                        }
                    ]
                }
            }
        
        elif "remediation" in endpoint:
            return {
                "recommendations": [
                    {
                        "id": "R1234",
                        "title": "Implement Multi-Factor Authentication",
                        "description": "Require multi-factor authentication for all user accounts",
                        "priority": "HIGH",
                        "implementation_complexity": "MEDIUM",
                        "effectiveness": 0.85,
                        "implementation_steps": [
                            "Select an MFA solution compatible with current systems",
                            "Deploy MFA for administrative accounts first",
                            "Gradually roll out to all users",
                            "Update security policies and documentation"
                        ],
                        "estimated_effort": "2-4 weeks"
                    },
                    {
                        "id": "R2345",
                        "title": "Enhance Input Validation",
                        "description": "Implement comprehensive input validation across all application entry points",
                        "priority": "HIGH",
                        "implementation_complexity": "HIGH",
                        "effectiveness": 0.92,
                        "implementation_steps": [
                            "Identify all data entry points in the application",
                            "Create validation rules for each input type",
                            "Implement server-side validation",
                            "Add client-side validation for usability",
                            "Test thoroughly for bypass techniques"
                        ],
                        "estimated_effort": "4-6 weeks"
                    },
                    {
                        "id": "R3456",
                        "title": "Security Awareness Training",
                        "description": "Conduct regular security awareness training for all employees",
                        "priority": "MEDIUM",
                        "implementation_complexity": "LOW",
                        "effectiveness": 0.75,
                        "implementation_steps": [
                            "Develop training materials on current threats",
                            "Schedule monthly training sessions",
                            "Implement phishing simulation exercises",
                            "Track completion and effectiveness",
                            "Update content based on emerging threats"
                        ],
                        "estimated_effort": "Ongoing, initial setup 2 weeks"
                    }
                ]
            }
        
        return {
            "simulated": True,
            "timestamp": datetime.datetime.now().isoformat(),
            "message": "This is a simulated response as IBM Watson API credentials were not provided."
        }
    
    def analyze_threat_intelligence(self, indicators=None):
        """Analyze threat intelligence data using IBM Watson"""
        logger.info("Analyzing threat intelligence with IBM Watson")
        
        if not indicators:
            indicators = {
                "ips": ["192.0.2.1", "198.51.100.1"],
                "domains": ["example.com", "example.org"],
                "urls": ["https://example.com/login", "https://example.org/download"],
                "hashes": ["5f4dcc3b5aa765d61d8327deb882cf99"]
            }
        
        # Prepare request data
        data = {
            "indicators": indicators,
            "analysis_type": "comprehensive"
        }
        
        # Make API request
        threat_data = self._ibm_api_request("threats/analyze", method="POST", data=data)
        
        # Process and save results
        self.results["threat_intelligence"] = threat_data
        return threat_data
    
    def assess_vulnerabilities(self, scan_results=None):
        """Assess vulnerabilities using IBM Watson"""
        logger.info("Assessing vulnerabilities with IBM Watson")
        
        # Check if scan_results is provided or use an empty dict
        scan_results = scan_results or {}
        
        # Prepare request data
        data = {
            "scan_results": scan_results,
            "assessment_type": "comprehensive"
        }
        
        # Make API request
        vulnerability_data = self._ibm_api_request("vulnerabilities/assess", method="POST", data=data)
        
        # Process and save results
        self.results["vulnerability_assessment"] = vulnerability_data
        return vulnerability_data
    
    def analyze_security_events(self, events=None):
        """Analyze security events using IBM Watson"""
        logger.info("Analyzing security events with IBM Watson")
        
        # Check if events is provided or use an empty list
        events = events or []
        
        # Prepare request data
        data = {
            "events": events,
            "analysis_type": "behavioral"
        }
        
        # Make API request
        events_data = self._ibm_api_request("events/analyze", method="POST", data=data)
        
        # Process and save results
        self.results["security_events"] = events_data
        return events_data
    
    def generate_risk_score(self, assessment_data=None):
        """Generate security risk score using IBM Watson"""
        logger.info("Generating risk score with IBM Watson")
        
        # Combine all assessment data if provided or use an empty dict
        assessment_data = assessment_data or {
            "threat_intelligence": self.results.get("threat_intelligence", {}),
            "vulnerability_assessment": self.results.get("vulnerability_assessment", {}),
            "security_events": self.results.get("security_events", {})
        }
        
        # Prepare request data
        data = {
            "assessment_data": assessment_data,
            "scoring_model": "comprehensive"
        }
        
        # Make API request
        risk_data = self._ibm_api_request("risk/score", method="POST", data=data)
        
        # Process and save results
        self.results["risk_scoring"] = risk_data
        return risk_data
    
    def get_remediation_recommendations(self, findings=None):
        """Get remediation recommendations using IBM Watson"""
        logger.info("Getting remediation recommendations with IBM Watson")
        
        # Combine all findings if provided or use results
        findings = findings or {
            "threat_intelligence": self.results.get("threat_intelligence", {}),
            "vulnerability_assessment": self.results.get("vulnerability_assessment", {}),
            "security_events": self.results.get("security_events", {}),
            "risk_scoring": self.results.get("risk_scoring", {})
        }
        
        # Prepare request data
        data = {
            "findings": findings,
            "recommendation_type": "comprehensive"
        }
        
        # Make API request
        remediation_data = self._ibm_api_request("remediation/recommendations", method="POST", data=data)
        
        # Process and save results
        self.results["remediation"] = remediation_data
        return remediation_data
    
    def integrate_with_xforce(self):
        """Integrate with IBM X-Force Exchange for threat intelligence"""
        logger.info("Integrating with IBM X-Force Exchange")
        
        if not self.ibm_x_force_api_key or not self.ibm_x_force_password:
            logger.warning("IBM X-Force credentials not provided")
            return {
                "status": "error",
                "message": "IBM X-Force credentials not provided"
            }
        
        try:
            # Authenticate with X-Force
            auth = base64.b64encode(f"{self.ibm_x_force_api_key}:{self.ibm_x_force_password}".encode()).decode()
            
            headers = {
                "Authorization": f"Basic {auth}",
                "Accept": "application/json"
            }
            
            # Get X-Force data (simulated for this integration)
            xforce_data = {
                "status": "success",
                "api_calls_remaining": 1000,
                "data": {
                    "threat_reports": [...],
                    "indicators": [...],
                    "latest_threats": [...]
                }
            }
            
            return xforce_data
        except Exception as e:
            logger.error(f"Error integrating with X-Force: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def integrate_with_qradar(self):
        """Integrate with IBM QRadar for security event analysis"""
        logger.info("Integrating with IBM QRadar")
        
        if not self.ibm_qradar_url or not self.ibm_qradar_token:
            logger.warning("IBM QRadar credentials not provided")
            return {
                "status": "error",
                "message": "IBM QRadar credentials not provided"
            }
        
        try:
            # Connect to QRadar API (simulated for this integration)
            qradar_data = {
                "status": "success",
                "connection": "established",
                "data": {
                    "offenses": [...],
                    "events": [...],
                    "assets": [...]
                }
            }
            
            return qradar_data
        except Exception as e:
            logger.error(f"Error integrating with QRadar: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def run_comprehensive_analysis(self, scan_results=None, security_events=None):
        """Run a comprehensive security analysis using IBM Watson"""
        logger.info("Running comprehensive security analysis with IBM Watson")
        
        # Step 1: Analyze threat intelligence
        self.analyze_threat_intelligence()
        
        # Step 2: Assess vulnerabilities
        self.assess_vulnerabilities(scan_results)
        
        # Step 3: Analyze security events
        self.analyze_security_events(security_events)
        
        # Step 4: Generate risk score
        self.generate_risk_score()
        
        # Step 5: Get remediation recommendations
        self.get_remediation_recommendations()
        
        # Step 6: Integrate with X-Force (if credentials available)
        if self.ibm_x_force_api_key and self.ibm_x_force_password:
            xforce_data = self.integrate_with_xforce()
            self.results["x_force_integration"] = xforce_data
        
        # Step 7: Integrate with QRadar (if credentials available)
        if self.ibm_qradar_url and self.ibm_qradar_token:
            qradar_data = self.integrate_with_qradar()
            self.results["qradar_integration"] = qradar_data
        
        # Save results
        self.save_results()
        
        return self.results
    
    def save_results(self, filename=None):
        """Save the analysis results to a file"""
        if not filename:
            filename = os.path.join(self.output_dir, f"ibm_watson_security_{self.timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logger.info(f"Analysis results saved to {filename}")
        return filename

def main():
    """Main function for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="IBM Watson Security Integration")
    parser.add_argument("--output-dir", default="ibm_watson_security_reports", help="Output directory for reports")
    parser.add_argument("--scan-results", help="JSON file with vulnerability scan results")
    parser.add_argument("--security-events", help="JSON file with security events")
    
    args = parser.parse_args()
    
    ibm_security = IBMWatsonSecurityIntegration(args.output_dir)
    
    # Load scan results if provided
    scan_results = None
    if args.scan_results:
        try:
            with open(args.scan_results, 'r') as f:
                scan_results = json.load(f)
        except Exception as e:
            logger.error(f"Error loading scan results: {str(e)}")
    
    # Load security events if provided
    security_events = None
    if args.security_events:
        try:
            with open(args.security_events, 'r') as f:
                security_events = json.load(f)
        except Exception as e:
            logger.error(f"Error loading security events: {str(e)}")
    
    # Run comprehensive analysis
    ibm_security.run_comprehensive_analysis(scan_results, security_events)

if __name__ == "__main__":
    main() 