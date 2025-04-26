#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import argparse
import datetime
import time
import concurrent.futures
import importlib.util

# Import our system components
from security_integrator import SecurityAPIHandler, SecurityToolIntegrator
from security_platform import SecurityPlatform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("unified_security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("UnifiedSecurity")

class UnifiedSecuritySystem:
    """
    Unified Security System

    This is the main entry point for the security system, providing:
    1. Integration of all security tools and components
    2. Command-line interface for running security assessments
    3. Configuration management
    4. Results storage and reporting
    """
    
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.config = self._load_config()
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialize the main system components
        self.integrator = SecurityToolIntegrator(config_file=config_file)
        self.api = SecurityAPIHandler(self.integrator)
        self.platform = None  # Lazy-loaded when needed
        
        # Set up output directory
        self.output_dir = self.config.get("output_dir", "unified_security_reports")
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info("Unified Security System initialized")
    
    def _load_config(self):
        """Load configuration from file or use defaults"""
        default_config = {
            "output_dir": "unified_security_reports",
            "parallel_execution": True,
            "max_workers": 5,
            "timeout": 600,
            "default_modules": ["network", "osint", "web", "ai"],
            "report_formats": ["json", "html"],
            "save_raw_data": True
        }
        
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                
                # Merge user config with defaults
                for key, value in user_config.items():
                    default_config[key] = value
                
                logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
        
        return default_config
    
    def _get_platform(self, target=None):
        """Get or create the security platform instance"""
        if not self.platform:
            output_dir = os.path.join(self.output_dir, f"assessment_{self.timestamp}")
            self.platform = SecurityPlatform(target=target, output_dir=output_dir)
            
            # Configure the platform based on our config
            platform_config = {
                "modules": {
                    "network_scanning": "network" in self.config["default_modules"],
                    "osint_reconnaissance": "osint" in self.config["default_modules"],
                    "web_vulnerability_scanning": "web" in self.config["default_modules"],
                    "ai_security_analysis": "ai" in self.config["default_modules"],
                    "social_engineering": "social" in self.config["default_modules"],
                    "comprehensive_testing": "comprehensive" in self.config["default_modules"],
                    "client_reporting": "report" in self.config["default_modules"]
                },
                "concurrency": {
                    "max_workers": self.config["max_workers"],
                    "timeout": self.config["timeout"]
                },
                "reporting": {
                    "formats": self.config["report_formats"],
                    "include_raw_data": self.config["save_raw_data"],
                    "include_screenshots": True
                }
            }
            
            self.platform.configure(platform_config)
        
        return self.platform
    
    def list_available_tools(self):
        """List all available security tools in the system"""
        return self.api.get_available_tools()
    
    def list_available_workflows(self):
        """List all available assessment workflows"""
        return self.api.get_available_workflows()
    
    def run_assessment(self, target, assessment_type="full", modules=None, output_format="all"):
        """
        Run a security assessment on the target
        
        Args:
            target: The target URL, domain, or IP to assess
            assessment_type: Type of assessment (full, quick, network, web, osint)
            modules: List of specific modules to enable
            output_format: Output format for reports (json, html, pdf, all)
            
        Returns:
            Dict containing assessment results and report paths
        """
        logger.info(f"Starting {assessment_type} assessment for target: {target}")
        
        # Get the security platform
        platform = self._get_platform(target)
        
        # Configure modules based on assessment type and specified modules
        active_modules = set(self.config["default_modules"])
        
        if assessment_type == "quick":
            # Quick assessment only uses basic modules
            active_modules = {"network", "web"}
        elif assessment_type == "network":
            active_modules = {"network"}
        elif assessment_type == "web":
            active_modules = {"web", "ai"}
        elif assessment_type == "osint":
            active_modules = {"osint", "social"}
        
        # Add user-specified modules
        if modules:
            active_modules.update(modules)
        
        # Configure the platform
        module_config = {
            "network_scanning": "network" in active_modules,
            "osint_reconnaissance": "osint" in active_modules,
            "web_vulnerability_scanning": "web" in active_modules,
            "ai_security_analysis": "ai" in active_modules,
            "social_engineering": "social" in active_modules,
            "comprehensive_testing": "comprehensive" in active_modules,
            "client_reporting": "report" in active_modules
        }
        
        platform.config["modules"].update(module_config)
        
        # Run the assessment
        try:
            start_time = time.time()
            results = platform.run_full_assessment()
            execution_time = time.time() - start_time
            
            logger.info(f"Assessment completed in {execution_time:.2f} seconds")
            
            # Generate reports in requested formats
            report_paths = {}
            
            if output_format in ["json", "all"]:
                json_path = platform.save_results()
                report_paths["json"] = json_path
            
            if output_format in ["html", "all"]:
                html_path = platform.generate_html_report()
                report_paths["html"] = html_path
            
            # Add report paths to results
            results["report_paths"] = report_paths
            results["execution_time"] = execution_time
            
            return results
        except Exception as e:
            logger.error(f"Error during assessment: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": self.timestamp
            }
    
    def run_tool(self, tool_name, method="run", **params):
        """Run a specific security tool"""
        logger.info(f"Running tool {tool_name}.{method}")
        return self.api.execute_tool(tool_name, method, **params)
    
    def run_workflow(self, workflow_id, **params):
        """Run a specific workflow"""
        logger.info(f"Running workflow {workflow_id}")
        return self.api.execute_workflow(workflow_id, **params)

def main():
    """Command line interface for the unified security system"""
    parser = argparse.ArgumentParser(
        description="Unified Security System - Comprehensive Security Assessment Platform"
    )
    
    # Main arguments
    parser.add_argument("target", nargs="?", help="Target URL, domain, or IP address to assess")
    parser.add_argument(
        "--type", choices=["full", "quick", "network", "web", "osint"], 
        default="full", help="Type of assessment to run"
    )
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--output", help="Output directory for reports")
    parser.add_argument(
        "--format", choices=["json", "html", "pdf", "all"], 
        default="all", help="Output format for reports"
    )
    
    # Module selection
    parser.add_argument("--enable", action="append", help="Enable specific modules")
    parser.add_argument("--disable", action="append", help="Disable specific modules")
    
    # Tool and workflow execution
    parser.add_argument("--tool", help="Run a specific security tool")
    parser.add_argument("--method", default="run", help="Method to run on the tool")
    parser.add_argument("--workflow", help="Run a specific workflow")
    
    # Information commands
    parser.add_argument("--list-tools", action="store_true", help="List available security tools")
    parser.add_argument("--list-workflows", action="store_true", help="List available workflows")
    parser.add_argument("--list-modules", action="store_true", help="List available assessment modules")
    
    args = parser.parse_args()
    
    # Initialize the unified security system
    system = UnifiedSecuritySystem(config_file=args.config)
    
    # Override output directory if specified
    if args.output:
        system.output_dir = args.output
        os.makedirs(system.output_dir, exist_ok=True)
    
    # Handle information commands
    if args.list_tools:
        tools = system.list_available_tools()
        print("\n=== Available Security Tools ===\n")
        for i, tool in enumerate(tools, 1):
            print(f"{i}. {tool['name']} ({tool['module']})")
            actions = tool['capabilities'].get('actions', ['unknown'])
            print(f"   Capabilities: {', '.join(actions)}")
            if tool['dependencies']:
                print(f"   Dependencies: {', '.join(tool['dependencies'])}")
            print()
        return
    
    if args.list_workflows:
        workflows = system.list_available_workflows()
        print("\n=== Available Assessment Workflows ===\n")
        for i, workflow in enumerate(workflows, 1):
            print(f"{i}. {workflow['name']} (ID: {workflow['id']})")
            print(f"   {workflow['description']}")
            print(f"   Required parameters: {', '.join(workflow['required_parameters'])}")
            print()
        return
    
    if args.list_modules:
        print("\n=== Available Assessment Modules ===\n")
        print("network       - Network infrastructure scanning")
        print("osint         - Open-source intelligence gathering")
        print("web           - Web application vulnerability scanning")
        print("ai            - AI-powered security analysis")
        print("social        - Social engineering assessment")
        print("comprehensive - Comprehensive security testing")
        print("report        - Client-friendly reporting")
        print()
        return
    
    # Handle tool or workflow execution
    if args.tool:
        params = {}
        if args.target:
            params["target"] = args.target
        
        print(f"\nExecuting tool: {args.tool}.{args.method}\n")
        results = system.run_tool(args.tool, args.method, **params)
        print(json.dumps(results, indent=2))
        return
    
    if args.workflow:
        if not args.target:
            print("Error: Target is required for workflow execution")
            sys.exit(1)
        
        print(f"\nExecuting workflow: {args.workflow} on target: {args.target}\n")
        results = system.run_workflow(args.workflow, target=args.target)
        print(json.dumps(results, indent=2))
        return
    
    # Run assessment if target is provided
    if args.target:
        # Determine which modules to enable/disable
        modules = None
        if args.enable:
            modules = args.enable
        
        print(f"\nStarting {args.type} security assessment for: {args.target}\n")
        results = system.run_assessment(
            target=args.target,
            assessment_type=args.type,
            modules=modules,
            output_format=args.format
        )
        
        # Print completion message with report locations
        if "error" in results:
            print(f"\nAssessment failed: {results['error']}")
        else:
            print("\nAssessment completed successfully!")
            print(f"Execution time: {results['execution_time']:.2f} seconds")
            
            if "report_paths" in results:
                print("\nReport locations:")
                for format_name, path in results["report_paths"].items():
                    print(f"- {format_name.upper()}: {path}")
            
            # Print summary statistics if available
            if "summary" in results:
                print("\nSummary:")
                risk_level = results["summary"].get("risk_level", "Unknown")
                print(f"- Overall risk level: {risk_level}")
                
                vuln_count = 0
                if "web" in results and "vulnerabilities" in results["web"]:
                    vuln_count = len(results["web"]["vulnerabilities"])
                print(f"- Vulnerabilities found: {vuln_count}")
    else:
        # If no specific command was given, show help
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAssessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1) 