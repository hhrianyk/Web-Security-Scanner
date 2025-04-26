#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import argparse
import datetime
import time
import threading
import concurrent.futures
from urllib.parse import urlparse
import requests
import dotenv

# Import system components
from security_framework import SecurityFramework
from ai_security_integrator import AISecurityIntegrator
from ai_vulnerability_scanner import AIVulnerabilityScanner
from comprehensive_tester import ComprehensiveTester
from network_tools_advanced import AdvancedNetworkTools
from osint_tools import OSINTTools
from social_engineering import SocialEngineeringToolkit
from vulnerability_scanner import VulnerabilityScanner
from client_vulnerability_report import ClientVulnerabilityReport
from advanced_ai_security_tools import AdvancedAISecurityTools

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_platform.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecurityPlatform")

# Load environment variables
dotenv.load_dotenv(".env.template", override=True)
dotenv.load_dotenv(".env.security_ai.template", override=True)

class SecurityPlatform:
    """
    Unified Security Platform
    
    Integrates all security tools into a cohesive platform:
    1. Network scanning tools
    2. OSINT reconnaissance tools
    3. Web vulnerability scanning
    4. AI-powered security analysis
    5. Social engineering toolkit
    6. Comprehensive testing framework
    7. Client reporting
    """
    
    def __init__(self, target=None, output_dir="security_platform_reports"):
        self.target = target
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(output_dir, f"assessment_{self.timestamp}")
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Platform configuration
        self.config = {
            "modules": {
                "network_scanning": True,
                "osint_reconnaissance": True,
                "web_vulnerability_scanning": True,
                "ai_security_analysis": True,
                "social_engineering": True,
                "comprehensive_testing": True,
                "client_reporting": True
            },
            "concurrency": {
                "max_workers": 5,
                "timeout": 600
            },
            "reporting": {
                "formats": ["json", "html", "pdf"],
                "include_raw_data": True,
                "include_screenshots": True
            }
        }
        
        # Component initialization will be lazy-loaded
        self._security_framework = None
        self._ai_integrator = None
        self._comprehensive_tester = None
        self._vulnerability_scanner = None
        self._client_reporter = None
        self._advanced_ai_tools = None
        
        # Results storage
        self.results = {
            "timestamp": self.timestamp,
            "target": target,
            "summary": {},
            "network": {},
            "osint": {},
            "web": {},
            "ai_analysis": {},
            "social_engineering": {},
            "comprehensive_tests": {},
            "remediation": {}
        }
        
        logger.info(f"Initialized SecurityPlatform for target: {target}")

    @property
    def security_framework(self):
        """Lazy-load the security framework"""
        if self._security_framework is None:
            logger.info("Initializing security framework")
            self._security_framework = SecurityFramework(
                target=self.target,
                output_dir=os.path.join(self.output_dir, "framework")
            )
        return self._security_framework
    
    @property
    def ai_integrator(self):
        """Lazy-load the AI security integrator"""
        if self._ai_integrator is None:
            logger.info("Initializing AI security integrator")
            self._ai_integrator = AISecurityIntegrator(
                target=self.target,
                output_dir=os.path.join(self.output_dir, "ai_analysis")
            )
        return self._ai_integrator
    
    @property
    def comprehensive_tester(self):
        """Lazy-load the comprehensive tester"""
        if self._comprehensive_tester is None:
            logger.info("Initializing comprehensive tester")
            self._comprehensive_tester = ComprehensiveTester(
                target=self.target,
                output_dir=os.path.join(self.output_dir, "comprehensive"),
                scan_id=self.timestamp
            )
        return self._comprehensive_tester
    
    @property
    def vulnerability_scanner(self):
        """Lazy-load the vulnerability scanner"""
        if self._vulnerability_scanner is None:
            logger.info("Initializing vulnerability scanner")
            self._vulnerability_scanner = VulnerabilityScanner(
                self.target, 
                str(int(time.time()))  # Используем timestamp как scan_id
            )
        return self._vulnerability_scanner
    
    @property
    def client_reporter(self):
        """Lazy-load the client reporter"""
        if self._client_reporter is None:
            logger.info("Initializing client vulnerability reporter")
            self._client_reporter = ClientVulnerabilityReport(
                output_dir=os.path.join(self.output_dir, "client_reports")
            )
        return self._client_reporter
    
    @property
    def advanced_ai_tools(self):
        """Lazy-load the advanced AI security tools"""
        if self._advanced_ai_tools is None:
            logger.info("Initializing advanced AI security tools")
            self._advanced_ai_tools = AdvancedAISecurityTools(
                target=self.target,
                output_dir=os.path.join(self.output_dir, "advanced_ai")
            )
        return self._advanced_ai_tools

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

    def run_network_assessment(self):
        """Run network security assessment"""
        if not self.config["modules"]["network_scanning"]:
            logger.info("Network scanning module disabled, skipping")
            return {}
            
        logger.info("Starting network security assessment")
        try:
            results = self.security_framework.run_network_assessment()
            self.results["network"] = results
            logger.info("Network assessment completed successfully")
            return results
        except Exception as e:
            logger.error(f"Error during network assessment: {str(e)}")
            self.results["network"]["error"] = str(e)
            return {"error": str(e)}

    def run_osint_assessment(self):
        """Run OSINT reconnaissance"""
        if not self.config["modules"]["osint_reconnaissance"]:
            logger.info("OSINT reconnaissance module disabled, skipping")
            return {}
            
        logger.info("Starting OSINT assessment")
        try:
            results = self.security_framework.run_osint_assessment()
            self.results["osint"] = results
            logger.info("OSINT assessment completed successfully")
            return results
        except Exception as e:
            logger.error(f"Error during OSINT assessment: {str(e)}")
            self.results["osint"]["error"] = str(e)
            return {"error": str(e)}

    def run_web_vulnerability_scan(self):
        """Run web vulnerability scanning"""
        if not self.config["modules"]["web_vulnerability_scanning"]:
            logger.info("Web vulnerability scanning module disabled, skipping")
            return {}
            
        logger.info("Starting web vulnerability assessment")
        try:
            # Run comprehensive vulnerability scan
            self.vulnerability_scanner.run_scan()
            vulnerabilities = self.vulnerability_scanner.vulnerabilities
            
            # Run framework web scan
            framework_results = self.security_framework.run_web_vulnerability_scan()
            
            # Merge results
            web_results = {
                "vulnerabilities": vulnerabilities,
                "framework_scan": framework_results
            }
            
            self.results["web"] = web_results
            logger.info("Web vulnerability scan completed successfully")
            return web_results
        except Exception as e:
            logger.error(f"Error during web vulnerability scan: {str(e)}")
            self.results["web"]["error"] = str(e)
            return {"error": str(e)}

    def run_ai_security_analysis(self):
        """Run AI-powered security analysis"""
        if not self.config["modules"]["ai_security_analysis"]:
            logger.info("AI security analysis module disabled, skipping")
            return {}
            
        logger.info("Starting AI security analysis")
        try:
            # Get vulnerabilities from web scan
            vulnerabilities = self.results.get("web", {}).get("vulnerabilities", [])
            
            # Perform AI analysis
            analysis = self.ai_integrator.analyze_vulnerabilities(vulnerabilities)
            exploitation_paths = self.ai_integrator.determine_exploitation_paths(vulnerabilities)
            remediation = self.ai_integrator.generate_remediation_recommendations(vulnerabilities)
            
            # Get attack surface analysis
            attack_surface = self.ai_integrator.analyze_attack_surface(self.target, self.results)
            
            # Get executive summary
            executive_summary = self.ai_integrator.generate_executive_summary(self.results)
            
            # Run advanced AI tools analysis
            advanced_analysis = self.advanced_ai_tools.analyze_target()
            
            ai_results = {
                "vulnerability_analysis": analysis,
                "exploitation_paths": exploitation_paths,
                "remediation": remediation,
                "attack_surface": attack_surface,
                "executive_summary": executive_summary,
                "advanced_analysis": advanced_analysis
            }
            
            self.results["ai_analysis"] = ai_results
            logger.info("AI security analysis completed successfully")
            return ai_results
        except Exception as e:
            logger.error(f"Error during AI security analysis: {str(e)}")
            self.results["ai_analysis"]["error"] = str(e)
            return {"error": str(e)}

    def run_social_engineering_assessment(self):
        """Run social engineering assessment"""
        if not self.config["modules"]["social_engineering"]:
            logger.info("Social engineering module disabled, skipping")
            return {}
            
        logger.info("Starting social engineering assessment")
        try:
            results = self.security_framework.prepare_social_engineering_assessment()
            self.results["social_engineering"] = results
            logger.info("Social engineering assessment completed successfully")
            return results
        except Exception as e:
            logger.error(f"Error during social engineering assessment: {str(e)}")
            self.results["social_engineering"]["error"] = str(e)
            return {"error": str(e)}

    def run_comprehensive_testing(self):
        """Run comprehensive security testing"""
        if not self.config["modules"]["comprehensive_testing"]:
            logger.info("Comprehensive testing module disabled, skipping")
            return {}
            
        logger.info("Starting comprehensive security testing")
        try:
            # Run all comprehensive tests
            self.comprehensive_tester.run_all_tests()
            
            # Get test results
            results = self.comprehensive_tester.get_results()
            
            self.results["comprehensive_tests"] = results
            logger.info("Comprehensive testing completed successfully")
            return results
        except Exception as e:
            logger.error(f"Error during comprehensive testing: {str(e)}")
            self.results["comprehensive_tests"]["error"] = str(e)
            return {"error": str(e)}

    def generate_client_report(self):
        """Generate client-friendly vulnerability report"""
        if not self.config["modules"]["client_reporting"]:
            logger.info("Client reporting module disabled, skipping")
            return {}
            
        logger.info("Generating client vulnerability report")
        try:
            # Prepare data for client report
            report_data = {
                "target": self.target,
                "timestamp": self.timestamp,
                "vulnerabilities": self.results.get("web", {}).get("vulnerabilities", []),
                "remediation": self.results.get("ai_analysis", {}).get("remediation", {}),
                "executive_summary": self.results.get("ai_analysis", {}).get("executive_summary", "")
            }
            
            # Generate report
            report_path = self.client_reporter.generate_report(
                target=self.target,
                vulnerabilities=report_data["vulnerabilities"],
                remediation=report_data["remediation"],
                executive_summary=report_data["executive_summary"]
            )
            
            report_result = {
                "report_path": report_path,
                "report_data": report_data
            }
            
            self.results["client_report"] = report_result
            logger.info(f"Client report generated successfully: {report_path}")
            return report_result
        except Exception as e:
            logger.error(f"Error generating client report: {str(e)}")
            self.results["client_report"] = {"error": str(e)}
            return {"error": str(e)}

    def generate_remediation_recommendations(self):
        """Generate unified remediation recommendations"""
        logger.info("Generating unified remediation recommendations")
        
        try:
            # Use AI to generate remediation recommendations
            ai_remediation = self.results.get("ai_analysis", {}).get("remediation", {})
            
            # Use security framework to generate recommendations
            framework_remediation = self.security_framework.generate_mitigation_recommendations()
            
            # Combine recommendations
            combined_remediation = {
                "ai_recommendations": ai_remediation,
                "framework_recommendations": framework_remediation,
                "high_priority": framework_remediation.get("high_priority", []),
                "medium_priority": framework_remediation.get("medium_priority", []),
                "low_priority": framework_remediation.get("low_priority", []),
                "best_practices": framework_remediation.get("best_practices", [])
            }
            
            self.results["remediation"] = combined_remediation
            logger.info("Remediation recommendations generated successfully")
            return combined_remediation
        except Exception as e:
            logger.error(f"Error generating remediation recommendations: {str(e)}")
            self.results["remediation"]["error"] = str(e)
            return {"error": str(e)}

    def generate_executive_summary(self):
        """Generate executive summary of findings"""
        logger.info("Generating executive summary")
        
        try:
            # Use AI-generated summary if available
            ai_summary = self.results.get("ai_analysis", {}).get("executive_summary", "")
            
            # Generate summary from security framework
            self.security_framework.generate_summary()
            framework_summary = self.results.get("summary", {})
            
            # Create combined summary
            summary = {
                "ai_summary": ai_summary,
                "framework_summary": framework_summary,
                "risk_level": framework_summary.get("risk_level", "Unknown"),
                "top_findings": framework_summary.get("top_findings", []),
                "recommendation_summary": framework_summary.get("recommendation_summary", [])
            }
            
            self.results["summary"] = summary
            logger.info("Executive summary generated successfully")
            return summary
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            self.results["summary"]["error"] = str(e)
            return {"error": str(e)}

    def save_results(self, filename=None):
        """Save the assessment results to a file"""
        if not filename:
            filename = os.path.join(self.output_dir, f"security_assessment_{self.timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        logger.info(f"Assessment results saved to {filename}")
        return filename

    def generate_html_report(self, filename=None):
        """Generate an HTML report of the assessment results"""
        if not filename:
            filename = os.path.join(self.output_dir, f"security_assessment_{self.timestamp}.html")
        
        # Use security framework to generate HTML report
        self.security_framework.generate_html_report(filename)
        
        logger.info(f"HTML report generated at {filename}")
        return filename

    def run_full_assessment(self, target=None):
        """Run a full security assessment using all available tools"""
        target = target or self.target
        if not target:
            raise ValueError("No target specified for assessment")
            
        logger.info(f"Starting full security assessment for {target}")
        
        # Validate and normalize target
        target_info = self.validate_target(target)
        self.target = target_info["original"]
        
        # Use thread pool to run assessments in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["concurrency"]["max_workers"]) as executor:
            # Start all tasks
            network_future = executor.submit(self.run_network_assessment)
            osint_future = executor.submit(self.run_osint_assessment)
            web_future = executor.submit(self.run_web_vulnerability_scan)
            comprehensive_future = executor.submit(self.run_comprehensive_testing)
            
            # Wait for results with timeout
            timeout = self.config["concurrency"]["timeout"]
            network_results = network_future.result(timeout=timeout)
            osint_results = osint_future.result(timeout=timeout)
            web_results = web_future.result(timeout=timeout)
            comprehensive_results = comprehensive_future.result(timeout=timeout)
        
        # Run sequential tasks that depend on previous results
        self.run_social_engineering_assessment()
        self.run_ai_security_analysis()
        
        # Generate reports and recommendations
        self.generate_remediation_recommendations()
        self.generate_executive_summary()
        self.generate_client_report()
        
        # Save results
        self.save_results()
        
        # Generate HTML report
        self.generate_html_report()
        
        logger.info(f"Full security assessment completed for {target}")
        return self.results
        
    def configure(self, config):
        """Configure the security platform"""
        if config:
            # Merge configurations
            for section, settings in config.items():
                if section in self.config:
                    if isinstance(settings, dict):
                        self.config[section].update(settings)
                    else:
                        self.config[section] = settings
                else:
                    self.config[section] = settings
        
        logger.info("Security platform configured")
        return self.config

def main():
    """Main function for command line usage"""
    parser = argparse.ArgumentParser(description="Unified Security Platform")
    parser.add_argument("target", nargs="?", help="Target URL, domain, or IP to assess")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--output", help="Output directory for reports")
    parser.add_argument("--module", action="append", help="Enable specific modules only")
    parser.add_argument("--list-modules", action="store_true", help="List available modules")
    parser.add_argument("--disable", action="append", help="Disable specific modules")
    
    args = parser.parse_args()
    
    if args.list_modules:
        print("Available Security Platform Modules:")
        print("  network_scanning - Network infrastructure scanning")
        print("  osint_reconnaissance - Open-source intelligence gathering")
        print("  web_vulnerability_scanning - Web application vulnerability scanning")
        print("  ai_security_analysis - AI-powered security analysis")
        print("  social_engineering - Social engineering assessment")
        print("  comprehensive_testing - Comprehensive security testing")
        print("  client_reporting - Client-friendly reporting")
        sys.exit(0)
    
    # Initialize platform with target
    output_dir = args.output or "security_platform_reports"
    platform = SecurityPlatform(target=args.target, output_dir=output_dir)
    
    # Load configuration from file if specified
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                platform.configure(config)
        except Exception as e:
            logger.error(f"Error loading configuration file: {str(e)}")
            sys.exit(1)
    
    # Configure modules based on command line arguments
    if args.module:
        # Disable all modules first
        for module in platform.config["modules"]:
            platform.config["modules"][module] = False
        
        # Enable only specified modules
        for module in args.module:
            if module in platform.config["modules"]:
                platform.config["modules"][module] = True
            else:
                logger.warning(f"Unknown module: {module}")
    
    # Disable specific modules
    if args.disable:
        for module in args.disable:
            if module in platform.config["modules"]:
                platform.config["modules"][module] = False
            else:
                logger.warning(f"Unknown module: {module}")
    
    # Run assessment if target is provided
    if args.target:
        try:
            results = platform.run_full_assessment()
            print(f"Assessment completed. Results saved to {platform.output_dir}")
        except Exception as e:
            logger.error(f"Error during assessment: {str(e)}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()