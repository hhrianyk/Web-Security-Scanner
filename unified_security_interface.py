#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified Security Interface

This module provides a unified interface for multiple security testing approaches:
1. Comprehensive automated testing through all connected services and tools
2. Testing using AI-powered tools
3. Testing by simulating manual testing based on AI services
4. Individual testing using each connected tool/service separately
5. Detailed technical reporting on vulnerabilities, exploits, and potential applications
6. Searching for exploits for detected services and generating detailed usage reports

Each mode generates detailed technical reports with information about vulnerabilities, 
exploits, attack vectors, and remediation strategies.
"""

import os
import sys
import json
import logging
import argparse
import datetime
import time
import concurrent.futures
from typing import Dict, List, Any, Optional, Union
import importlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("unified_security_interface.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("UnifiedSecurityInterface")

# Try to import core security components
try:
    from security_integrator import SecurityToolIntegrator
    INTEGRATOR_AVAILABLE = True
except ImportError:
    logger.warning("SecurityToolIntegrator not available. Limited functionality.")
    INTEGRATOR_AVAILABLE = False

try:
    from unified_security_tools import UnifiedSecuritySystem
    UNIFIED_SYSTEM_AVAILABLE = True
except ImportError:
    logger.warning("UnifiedSecuritySystem not available. Limited functionality.")
    UNIFIED_SYSTEM_AVAILABLE = False

try:
    from comprehensive_tester import ComprehensiveTester
    COMPREHENSIVE_TESTER_AVAILABLE = True
except ImportError:
    logger.warning("ComprehensiveTester not available. Limited functionality.")
    COMPREHENSIVE_TESTER_AVAILABLE = False

try:
    from ai_vulnerability_scanner import AIVulnerabilityScanner
    AI_SCANNER_AVAILABLE = True
except ImportError:
    logger.warning("AIVulnerabilityScanner not available. Limited functionality.")
    AI_SCANNER_AVAILABLE = False

try:
    from vulnerability_reporter import VulnerabilityReporter
    REPORTER_AVAILABLE = True
except ImportError:
    logger.warning("VulnerabilityReporter not available. Basic reporting only.")
    REPORTER_AVAILABLE = False

# New import for exploit search system
try:
    from exploit_search_system import ExploitSearchSystem
    EXPLOIT_SEARCH_AVAILABLE = True
except ImportError:
    logger.warning("ExploitSearchSystem not available. Exploit search functionality disabled.")
    EXPLOIT_SEARCH_AVAILABLE = False


class UnifiedSecurityInterface:
    """
    Unified Security Interface for multiple security testing modes.
    
    This class provides a unified interface for:
    1. Comprehensive automated testing
    2. AI-powered testing
    3. AI-simulated manual testing
    4. Individual tool testing
    5. Comprehensive reporting
    6. Exploit searching for detected services
    """
    
    def __init__(self, target=None, output_dir="security_reports"):
        """
        Initialize the unified security interface.
        
        Args:
            target: Target URL, domain, or IP to scan
            output_dir: Directory for storing reports and results
        """
        self.target = target
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir
        self.report_dir = os.path.join(output_dir, f"assessment_{self.timestamp}")
        
        # Ensure output directories exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Initialize components based on availability
        self.security_tools = None
        self.unified_system = None
        self.comprehensive_tester = None
        self.ai_scanner = None
        self.vulnerability_reporter = None
        self.exploit_search_system = None
        
        # Initialize available components
        self._initialize_components()
        
        # Discover available security tools
        self.available_tools = self._discover_available_tools()
        
        logger.info(f"Unified Security Interface initialized for target: {target}")
    
    def _initialize_components(self):
        """Initialize all available security components"""
        # Initialize core security components
        if INTEGRATOR_AVAILABLE:
            try:
                self.security_tools = SecurityToolIntegrator()
                logger.info("SecurityToolIntegrator initialized")
            except Exception as e:
                logger.error(f"Error initializing SecurityToolIntegrator: {str(e)}")
        
        if UNIFIED_SYSTEM_AVAILABLE:
            try:
                self.unified_system = UnifiedSecuritySystem()
                logger.info("UnifiedSecuritySystem initialized")
            except Exception as e:
                logger.error(f"Error initializing UnifiedSecuritySystem: {str(e)}")
        
        if COMPREHENSIVE_TESTER_AVAILABLE and self.target:
            try:
                self.comprehensive_tester = ComprehensiveTester(self.target, self.report_dir)
                logger.info("ComprehensiveTester initialized")
            except Exception as e:
                logger.error(f"Error initializing ComprehensiveTester: {str(e)}")
        
        if AI_SCANNER_AVAILABLE and self.target:
            try:
                self.ai_scanner = AIVulnerabilityScanner(self.target, self.report_dir)
                logger.info("AIVulnerabilityScanner initialized")
            except Exception as e:
                logger.error(f"Error initializing AIVulnerabilityScanner: {str(e)}")
        
        if REPORTER_AVAILABLE:
            try:
                self.vulnerability_reporter = VulnerabilityReporter(self.report_dir)
                logger.info("VulnerabilityReporter initialized")
            except Exception as e:
                logger.error(f"Error initializing VulnerabilityReporter: {str(e)}")
                
        # Initialize exploit search system
        if EXPLOIT_SEARCH_AVAILABLE:
            try:
                self.exploit_search_system = ExploitSearchSystem(output_dir=os.path.join(self.report_dir, "exploit_search"))
                logger.info("ExploitSearchSystem initialized")
            except Exception as e:
                logger.error(f"Error initializing ExploitSearchSystem: {str(e)}")
    
    def _discover_available_tools(self) -> List[str]:
        """Discover all available security tools in the system"""
        available_tools = []
        
        # Get tools from SecurityToolIntegrator if available
        if self.security_tools:
            try:
                tools_list = self.security_tools.list_available_tools()
                for tool in tools_list:
                    available_tools.append(tool["name"])
            except Exception as e:
                logger.error(f"Error discovering tools via SecurityToolIntegrator: {str(e)}")
        
        # Dynamic module discovery as fallback
        security_modules = [
            "vulnerability_scanner",
            "ai_vulnerability_scanner",
            "comprehensive_tester",
            "exploit_documenter",
            "client_vulnerability_report",
            "security_framework",
            "dns_spoof_integration",
            "comprehensive_pentesting",
            "security_platform",
            "ai_security_integrator",
            "ibm_watson_security_integration",
            "w3af_ai_integration",
            "nuclei_integration",
            "nessus_integration",
            "rapid7_integration",
            "nvd_integration",
            "vulners_integration",
            "metasploit_integration",
            "exploitdb_integration",
            "burpsuite_integration",
            "mitmproxy_integration",
            "sonarqube_integration",
            "bandit_integration",
            "dirbuster_integration"
        ]
        
        for module_name in security_modules:
            try:
                # Check if module exists
                if importlib.util.find_spec(module_name):
                    if module_name not in available_tools:
                        available_tools.append(module_name)
            except ImportError:
                pass
        
        logger.info(f"Discovered {len(available_tools)} security tools")
        return available_tools
    
    def mode1_comprehensive_automated_testing(self) -> Dict:
        """
        Mode 1: Comprehensive automated testing through all connected services and tools
        
        This mode runs a full automated scan using all available security tools
        and generates a comprehensive report.
        
        Returns:
            Dict containing assessment results
        """
        logger.info("Starting Mode 1: Comprehensive automated testing")
        
        # Use UnifiedSecuritySystem for the most comprehensive testing
        if self.unified_system:
            try:
                logger.info("Running comprehensive assessment using UnifiedSecuritySystem")
                results = self.unified_system.start_assessment(
                    target=self.target,
                    assessment_type="full",
                    modules=["network", "osint", "web", "ai", "social", "comprehensive", "report"],
                    format="all",
                    async_execution=False
                )
                logger.info("Comprehensive automated testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running comprehensive automated testing: {str(e)}")
        
        # Fallback to SecurityToolIntegrator
        elif self.security_tools:
            try:
                logger.info("Running comprehensive assessment using SecurityToolIntegrator")
                results = self.security_tools.execute_workflow("full_assessment", self.target)
                logger.info("Comprehensive automated testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running comprehensive automated testing: {str(e)}")
        
        # Fallback to ComprehensiveTester
        elif self.comprehensive_tester:
            try:
                logger.info("Running comprehensive assessment using ComprehensiveTester")
                self.comprehensive_tester.run_full_assessment()
                results = self.comprehensive_tester.save_results()
                logger.info("Comprehensive automated testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running comprehensive automated testing: {str(e)}")
        
        logger.error("No suitable testing system available for comprehensive automated testing")
        return {"error": "No suitable testing system available"}
    
    def mode2_ai_powered_testing(self) -> Dict:
        """
        Mode 2: Testing using AI-powered tools
        
        This mode uses AI-powered tools to perform vulnerability assessment
        and generates a detailed report with AI-enhanced analysis.
        
        Returns:
            Dict containing assessment results
        """
        logger.info("Starting Mode 2: Testing using AI-powered tools")
        
        # Use AIVulnerabilityScanner for AI-powered testing
        if self.ai_scanner:
            try:
                logger.info("Running AI-powered vulnerability assessment")
                self.ai_scanner.run_scan()
                results = self.ai_scanner.results
                logger.info("AI-powered testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running AI-powered testing: {str(e)}")
        
        # Fallback to UnifiedSecuritySystem with AI modules
        elif self.unified_system:
            try:
                logger.info("Running AI-powered assessment using UnifiedSecuritySystem")
                results = self.unified_system.start_assessment(
                    target=self.target,
                    assessment_type="ai",
                    modules=["ai"],
                    format="all",
                    async_execution=False
                )
                logger.info("AI-powered testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running AI-powered testing: {str(e)}")
        
        # Fallback to SecurityToolIntegrator
        elif self.security_tools:
            try:
                logger.info("Running AI security workflow using SecurityToolIntegrator")
                results = self.security_tools.execute_workflow("ai_security_analysis", self.target)
                logger.info("AI-powered testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running AI-powered testing: {str(e)}")
        
        logger.error("No suitable AI testing system available")
        return {"error": "No suitable AI testing system available"}
    
    def mode3_simulated_manual_testing(self) -> Dict:
        """
        Mode 3: Testing by simulating manual testing based on AI services
        
        This mode uses AI to simulate manual penetration testing techniques
        and generates a detailed report with findings.
        
        Returns:
            Dict containing assessment results
        """
        logger.info("Starting Mode 3: AI-simulated manual testing")
        
        # Try to import w3af AI integration for simulated manual testing
        w3af_ai_available = False
        try:
            from w3af_ai_integration import W3afAIIntegration
            w3af_ai_available = True
        except ImportError:
            logger.warning("W3afAIIntegration not available, trying alternatives")
        
        # Try to import IBM Watson integration as an alternative
        watson_available = False
        if not w3af_ai_available:
            try:
                from ibm_watson_security_integration import IBMWatsonSecurityIntegration
                watson_available = True
            except ImportError:
                logger.warning("IBMWatsonSecurityIntegration not available, trying alternatives")
        
        # Use W3afAIIntegration for manual testing simulation
        if w3af_ai_available:
            try:
                logger.info("Running simulated manual testing using W3afAIIntegration")
                w3af_ai = W3afAIIntegration(self.target, self.report_dir)
                results = w3af_ai.run_ai_manual_simulation()
                logger.info("W3afAIIntegration simulated manual testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running simulated manual testing: {str(e)}")
        
        # Use IBM Watson as an alternative
        elif watson_available:
            try:
                logger.info("Running simulated manual testing using IBMWatsonSecurityIntegration")
                watson = IBMWatsonSecurityIntegration(self.target, self.report_dir)
                results = watson.run_ai_manual_simulation()
                logger.info("IBMWatsonSecurityIntegration simulated manual testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running simulated manual testing: {str(e)}")
        
        # Fallback to AIVulnerabilityScanner
        elif self.ai_scanner:
            try:
                logger.info("Running AI simulation using AIVulnerabilityScanner (partial capability)")
                self.ai_scanner.run_scan()
                results = self.ai_scanner.results
                logger.info("AIVulnerabilityScanner testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running AI-powered testing: {str(e)}")
        
        # Fallback to UnifiedSecuritySystem
        elif self.unified_system:
            try:
                logger.info("Running simulated manual testing using UnifiedSecuritySystem")
                results = self.unified_system.start_assessment(
                    target=self.target,
                    assessment_type="ai",
                    modules=["ai", "comprehensive"],
                    format="all",
                    async_execution=False
                )
                logger.info("Simulated manual testing completed successfully")
                return results
            except Exception as e:
                logger.error(f"Error running simulated manual testing: {str(e)}")
        
        logger.error("No suitable system available for simulated manual testing")
        return {"error": "No suitable system available for simulated manual testing"}
    
    def mode4_individual_tool_testing(self, tool_name=None) -> Dict:
        """
        Mode 4: Individual testing using each connected tool/service separately
        
        This mode runs a specific security tool or all tools individually
        and generates separate reports for each.
        
        Args:
            tool_name: Name of the specific tool to use, or None to use all tools
            
        Returns:
            Dict containing assessment results
        """
        logger.info(f"Starting Mode 4: Individual tool testing {'(all tools)' if not tool_name else f'({tool_name})'}")
        
        results = {}
        tools_to_run = [tool_name] if tool_name else self.available_tools
        
        # Use SecurityToolIntegrator for tool execution
        if self.security_tools:
            try:
                for tool in tools_to_run:
                    logger.info(f"Running individual tool: {tool}")
                    try:
                        if tool in self.available_tools:
                            tool_result = self.security_tools.execute_tool(tool, "run", target=self.target)
                            results[tool] = tool_result
                            logger.info(f"Tool {tool} completed successfully")
                        else:
                            logger.warning(f"Tool {tool} not available")
                            results[tool] = {"error": "Tool not available"}
                    except Exception as e:
                        logger.error(f"Error running tool {tool}: {str(e)}")
                        results[tool] = {"error": str(e)}
                
                logger.info(f"Individual tool testing completed for {len(results)} tools")
                return results
            except Exception as e:
                logger.error(f"Error in individual tool testing: {str(e)}")
        
        # Fallback to direct module imports if SecurityToolIntegrator is not available
        else:
            for tool in tools_to_run:
                logger.info(f"Running individual tool via direct import: {tool}")
                try:
                    module = importlib.import_module(tool)
                    # Try to find a class with the same name as the module
                    class_name = ''.join(word.capitalize() for word in tool.split('_'))
                    if hasattr(module, class_name):
                        tool_class = getattr(module, class_name)
                        tool_instance = tool_class(self.target, self.report_dir)
                        if hasattr(tool_instance, 'run'):
                            tool_result = tool_instance.run()
                        elif hasattr(tool_instance, 'run_scan'):
                            tool_result = tool_instance.run_scan()
                        elif hasattr(tool_instance, 'scan'):
                            tool_result = tool_instance.scan()
                        else:
                            logger.warning(f"No standard run method found for {tool}")
                            tool_result = {"error": "No standard run method found"}
                        
                        results[tool] = tool_result
                        logger.info(f"Tool {tool} completed successfully")
                    else:
                        logger.warning(f"Class {class_name} not found in module {tool}")
                        results[tool] = {"error": f"Class {class_name} not found in module {tool}"}
                except Exception as e:
                    logger.error(f"Error running tool {tool}: {str(e)}")
                    results[tool] = {"error": str(e)}
        
        return results
    
    def mode5_generate_technical_report(self, results, report_type="detailed") -> Dict:
        """
        Mode 5: Generate a comprehensive technical report
        
        This mode generates a detailed technical report on vulnerabilities,
        exploits, potential attack vectors, and remediation strategies.
        
        Args:
            results: Results from previous security testing
            report_type: Type of report to generate (basic, detailed, executive, component, exploit)
            
        Returns:
            Dict containing report paths and metadata
        """
        logger.info(f"Starting Mode 5: Generating {report_type} technical report")
        
        report_files = {}
        
        # Use VulnerabilityReporter for report generation
        if self.vulnerability_reporter:
            try:
                # Generate report based on report type
                if report_type == "component" or report_type == "detailed":
                    # Generate detailed vulnerable component report
                    if results and ("vulnerabilities" in results or "scan_results" in results):
                        vulnerability_data = results.get("vulnerabilities", results.get("scan_results", {}))
                        
                        logger.info("Generating detailed vulnerable component report")
                        component_report = self.vulnerability_reporter.generate_vulnerable_component_report(vulnerability_data)
                        
                        # Save component report to file
                        component_report_file = os.path.join(self.report_dir, "vulnerable_components_report.md")
                        with open(component_report_file, 'w', encoding='utf-8') as f:
                            f.write(component_report)
                        
                        report_files["component_report"] = component_report_file
                        logger.info(f"Vulnerable component report saved to {component_report_file}")
                
                if report_type == "exploit" or report_type == "detailed":
                    # Generate detailed exploit report
                    if results and ("exploits" in results or "exploit_results" in results):
                        exploit_data = results.get("exploits", results.get("exploit_results", {}))
                        
                        logger.info("Generating detailed exploit report")
                        exploit_report = self.vulnerability_reporter.generate_exploit_report(exploit_data)
                        
                        # Save exploit report to file
                        exploit_report_file = os.path.join(self.report_dir, "exploits_report.md")
                        with open(exploit_report_file, 'w', encoding='utf-8') as f:
                            f.write(exploit_report)
                        
                        report_files["exploit_report"] = exploit_report_file
                        logger.info(f"Exploit report saved to {exploit_report_file}")
                
                # Generate standard reports as well if detailed report requested
                if report_type != "component" and report_type != "exploit":
                    # Generate report using standard method
                    report_path = self.vulnerability_reporter.generate_report(
                        results,
                        report_format=["md", "html", "pdf"] if report_type == "detailed" else ["md", "html"],
                        report_type=report_type
                    )
                    
                    if report_path:
                        report_files["standard_report"] = report_path
                        logger.info(f"Standard {report_type} report generated successfully at {report_path}")
            
            except Exception as e:
                logger.error(f"Error generating technical report: {str(e)}")
                return {"error": str(e)}
        
        else:
            logger.error("VulnerabilityReporter not available")
            return {"error": "VulnerabilityReporter not available"}
        
        if not report_files:
            logger.warning("No reports were generated")
            return {"error": "No reports were generated"}
        
        logger.info(f"Technical report generation completed: {report_files}")
        return {"report_files": report_files}
    
    def mode6_exploit_search(self, services=None, services_file=None, scan_type="standard") -> Dict:
        """
        Mode 6: Search for exploits for detected services
        
        This mode scans the target for services and searches for exploits,
        generating a comprehensive report with detailed usage instructions.
        
        Args:
            services: List of service dictionaries or None to detect or use a file
            services_file: Path to a JSON file containing service information
            scan_type: Type of scan to perform (quick, standard, comprehensive)
            
        Returns:
            Dict containing paths to exploit search results and reports
        """
        logger.info("Starting Mode 6: Exploit search for detected services")
        
        if not EXPLOIT_SEARCH_AVAILABLE or not self.exploit_search_system:
            logger.error("ExploitSearchSystem not available. Exploit search functionality disabled.")
            return {"error": "ExploitSearchSystem not available"}
        
        result_paths = {}
        
        # Detect services if not provided
        if not services and not services_file:
            logger.info(f"Detecting services on target: {self.target}")
            detected_services = self.exploit_search_system.detect_services(
                target=self.target, 
                scan_type=scan_type
            )
            
            result_paths["services_file"] = os.path.join(self.exploit_search_system.report_dir, "detected_services.json")
            services = detected_services.get("services", [])
        elif services_file:
            # Load services from file
            with open(services_file, 'r') as f:
                services_data = json.load(f)
                services = services_data.get("services", [])
            
            result_paths["services_file"] = services_file
        
        if not services:
            logger.error("No services detected or provided for exploit search")
            return {"error": "No services detected"}
        
        logger.info(f"Searching for exploits for {len(services)} services")
        
        # Search for exploits
        exploit_results = self.exploit_search_system.search_exploits(services=services)
        result_paths["exploit_results_file"] = os.path.join(self.exploit_search_system.report_dir, "exploit_search_results.json")
        
        # Document exploits
        documented_results = self.exploit_search_system.document_exploits(exploit_results=exploit_results)
        result_paths["documented_exploits_file"] = os.path.join(self.exploit_search_system.report_dir, "documented_exploits.json")
        
        # Generate report
        report_file = self.exploit_search_system.generate_comprehensive_report(documented_results=documented_results)
        result_paths["report_file"] = report_file
        
        # Check for exploitation guide
        exploitation_guide = os.path.join(self.exploit_search_system.report_dir, "exploitation_guide.md")
        if os.path.exists(exploitation_guide):
            result_paths["exploitation_guide"] = exploitation_guide
        
        # HTML report
        html_report = os.path.join(self.exploit_search_system.report_dir, "comprehensive_exploit_report.html")
        if os.path.exists(html_report):
            result_paths["html_report"] = html_report
        
        logger.info(f"Exploit search completed. Report available at: {report_file}")
        
        return {
            "status": "success",
            "result_paths": result_paths,
            "report_dir": self.exploit_search_system.report_dir,
            "services_count": len(services),
            "exploits_count": len(documented_results.get("exploits", []))
        }
    
    def list_available_tools(self) -> List[str]:
        """List all available security tools"""
        return self.available_tools
    
    def run_all_modes(self) -> Dict:
        """
        Run all testing modes and generate a comprehensive report
        
        Returns:
            Dict containing consolidated results and report paths
        """
        logger.info("Starting complete security testing with all modes")
        
        # Track results from each mode
        consolidated_results = {
            "timestamp": self.timestamp,
            "target": self.target,
            "mode1_comprehensive": None,
            "mode2_ai_powered": None,
            "mode3_simulated_manual": None,
            "mode4_individual_tools": None,
            "mode6_exploit_search": None,
            "report_paths": {}
        }
        
        # Run Mode 1: Comprehensive testing
        try:
            logger.info("Running Mode 1: Comprehensive automated testing")
            mode1_results = self.mode1_comprehensive_automated_testing()
            consolidated_results["mode1_comprehensive"] = mode1_results
        except Exception as e:
            logger.error(f"Error in Mode 1: {str(e)}")
            consolidated_results["mode1_comprehensive"] = {"error": str(e)}
        
        # Run Mode 2: AI-powered testing
        try:
            logger.info("Running Mode 2: AI-powered testing")
            mode2_results = self.mode2_ai_powered_testing()
            consolidated_results["mode2_ai_powered"] = mode2_results
        except Exception as e:
            logger.error(f"Error in Mode 2: {str(e)}")
            consolidated_results["mode2_ai_powered"] = {"error": str(e)}
        
        # Run Mode 3: Simulated manual testing
        try:
            logger.info("Running Mode 3: Simulated manual testing")
            mode3_results = self.mode3_simulated_manual_testing()
            consolidated_results["mode3_simulated_manual"] = mode3_results
        except Exception as e:
            logger.error(f"Error in Mode 3: {str(e)}")
            consolidated_results["mode3_simulated_manual"] = {"error": str(e)}
        
        # Run Mode 4: Individual tool testing (limit to key tools to avoid excessive testing)
        try:
            logger.info("Running Mode 4: Individual tool testing")
            key_tools = [
                "vulnerability_scanner",
                "osint_scanner",
                "nessus_integration",
                "nuclei_integration",
                "burpsuite_integration",
                "metasploit_integration"
            ]
            
            available_key_tools = [tool for tool in key_tools if tool in self.available_tools]
            
            if available_key_tools:
                mode4_results = {}
                for tool in available_key_tools:
                    tool_result = self.mode4_individual_tool_testing(tool)
                    mode4_results[tool] = tool_result.get(tool, {"error": "No result"})
                
                consolidated_results["mode4_individual_tools"] = mode4_results
            else:
                logger.warning("No key tools available for Mode 4")
                consolidated_results["mode4_individual_tools"] = {"error": "No key tools available"}
        except Exception as e:
            logger.error(f"Error in Mode 4: {str(e)}")
            consolidated_results["mode4_individual_tools"] = {"error": str(e)}
        
        # Run Mode 6: Exploit search
        try:
            logger.info("Running Mode 6: Exploit search for detected services")
            results = self.mode6_exploit_search()
            consolidated_results["mode6_exploit_search"] = results
        except Exception as e:
            logger.error(f"Error in Mode 6: {str(e)}")
            consolidated_results["mode6_exploit_search"] = {"error": str(e)}
        
        # Run Mode 5: Generate comprehensive technical report
        try:
            logger.info("Running Mode 5: Generate technical report")
            report_result = self.mode5_generate_technical_report(consolidated_results, report_type="detailed")
            consolidated_results["report_paths"] = report_result.get("report_files", {})
        except Exception as e:
            logger.error(f"Error in Mode 5: {str(e)}")
            consolidated_results["report_generation_error"] = str(e)
        
        logger.info("Complete security testing with all modes finished")
        return consolidated_results


def main():
    """Main function for the unified security interface"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Unified Security Interface")
    parser.add_argument("--target", help="Target URL, domain, or IP address")
    parser.add_argument("--output-dir", default="security_reports", help="Output directory for reports")
    parser.add_argument("--mode", type=int, choices=[1, 2, 3, 4, 5, 6], default=1, 
                        help="Operation mode: 1=Comprehensive automated testing, 2=AI-powered testing, 3=Simulated manual testing, 4=Individual tool testing, 5=Technical report generation, 6=Exploit search")
    parser.add_argument("--scan-type", choices=["quick", "standard", "comprehensive"], default="standard", 
                        help="Type of scan to perform")
    parser.add_argument("--report-type", choices=["basic", "detailed", "executive", "component", "exploit"], default="detailed", 
                        help="Type of report to generate")
    parser.add_argument("--tool", help="Specific tool to use (for mode 4 only)")
    parser.add_argument("--services-file", help="Path to JSON file with service information (for mode 6 only)")
    
    args = parser.parse_args()
    
    # Create and initialize the interface
    interface = UnifiedSecurityInterface(args.target, args.output_dir)
    
    # Execute the requested mode
    if args.mode == 1:
        # Comprehensive automated testing
        results = interface.mode1_comprehensive_automated_testing()
        
        # Automatically generate a report
        interface.mode5_generate_technical_report(results, args.report_type)
        
    elif args.mode == 2:
        # AI-powered testing
        results = interface.mode2_ai_powered_testing()
        
        # Automatically generate a report
        interface.mode5_generate_technical_report(results, args.report_type)
        
    elif args.mode == 3:
        # Simulated manual testing
        results = interface.mode3_simulated_manual_testing()
        
        # Automatically generate a report
        interface.mode5_generate_technical_report(results, args.report_type)
        
    elif args.mode == 4:
        # Individual tool testing
        results = interface.mode4_individual_tool_testing(args.tool)
        
        # Automatically generate a report
        interface.mode5_generate_technical_report(results, args.report_type)
        
    elif args.mode == 5:
        # Technical report generation
        if args.target:
            # If target is provided, run a scan first
            results = interface.mode1_comprehensive_automated_testing()
        else:
            # Load results from latest report directory
            results_file = interface._find_latest_results_file()
            if results_file:
                with open(results_file, 'r') as f:
                    results = json.load(f)
            else:
                print("Error: No target specified and no previous results found.")
                sys.exit(1)
        
        # Generate technical report
        interface.mode5_generate_technical_report(results, args.report_type)
        
    elif args.mode == 6:
        # Exploit search
        results = interface.mode6_exploit_search(services_file=args.services_file, scan_type=args.scan_type)
        
        # Generate exploit-focused report
        interface.mode5_generate_technical_report(results, "exploit")


if __name__ == "__main__":
    sys.exit(main()) 