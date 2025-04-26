#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified Security Tools System

A comprehensive integration system that combines all security tools into a single unified platform.
This is the main entry point for the integrated security system.

Features:
- Dynamic discovery and loading of all security tools
- Integrated web interface for all tools
- Unified API for programmatic access
- Standardized reporting and data formats
- Parallel execution of security assessments
- AI-powered analysis of combined results
"""

import os
import sys
import json
import logging
import argparse
import datetime
import time
import importlib
import shutil
import tempfile
import concurrent.futures
import threading
import subprocess
import webbrowser
from typing import Dict, List, Any, Optional, Union

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("unified_security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("UnifiedSecurityTools")

# Import core components 
try:
    from security_integrator import SecurityToolIntegrator, SecurityAPIHandler
    INTEGRATOR_AVAILABLE = True
except ImportError:
    logger.error("Unable to import SecurityToolIntegrator. Core functionality will be limited.")
    INTEGRATOR_AVAILABLE = False

try:
    from security_platform import SecurityPlatform
    PLATFORM_AVAILABLE = True
except ImportError:
    logger.warning("Unable to import SecurityPlatform. Some features may be limited.")
    PLATFORM_AVAILABLE = False

# Try to import AI components
try:
    from ai_security_integrator import AISecurityIntegrator
    AI_AVAILABLE = True
except ImportError:
    logger.warning("AI security integration not available.")
    AI_AVAILABLE = False

# Try to import client reporting
try:
    from client_vulnerability_report import ClientVulnerabilityReport
    REPORTING_AVAILABLE = True
except ImportError:
    logger.warning("Client vulnerability reporting not available.")
    REPORTING_AVAILABLE = False

class UnifiedSecuritySystem:
    """
    Unified Security System

    This is the main system that integrates all security tools into a single platform:
    1. Provides a single interface for all security tools
    2. Manages configuration and setup
    3. Orchestrates assessment workflows
    4. Generates comprehensive reports
    5. Provides web, API, and CLI interfaces
    """
    
    def __init__(self, config_file=None):
        """Initialize the unified security system"""
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.config_file = config_file
        self.config = self._load_config()
        
        # Initialize directories
        self.output_dir = self.config.get("output_dir", "unified_security_reports")
        self.data_dir = self.config.get("data_dir", "security_data")
        self.temp_dir = self.config.get("temp_dir", tempfile.gettempdir())
        
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialize core components
        if INTEGRATOR_AVAILABLE:
            self.integrator = SecurityToolIntegrator(config_file=config_file)
            self.api = SecurityAPIHandler(self.integrator)
        else:
            self.integrator = None
            self.api = None
            
        self.platform = None  # Lazy-loaded when needed
        self.ai_integrator = None  # Lazy-loaded when needed
        self.web_server = None  # Will hold web server process if started
        
        # Track running assessments
        self.active_assessments = {}
        self.assessment_lock = threading.Lock()
        
        logger.info("Unified Security System initialized")
    
    def _load_config(self):
        """Load configuration from file or use defaults"""
        default_config = {
            "output_dir": "unified_security_reports",
            "data_dir": "security_data",
            "parallel_execution": True,
            "max_workers": 5,
            "timeout": 1200,
            "default_modules": ["network", "osint", "web", "ai", "social", "comprehensive", "report"],
            "report_formats": ["json", "html", "pdf"],
            "save_raw_data": True,
            "web_interface": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 5000,
                "debug": False,
                "open_browser": True
            },
            "notifications": {
                "enabled": False,
                "email": False,
                "slack": False,
                "webhook": False
            }
        }
        
        # Try loading unified config if it exists
        if os.path.exists("unified_config.json"):
            try:
                with open("unified_config.json", 'r') as f:
                    unified_config = json.load(f)
                # Merge with defaults
                for section, settings in unified_config.items():
                    if isinstance(settings, dict) and section in default_config and isinstance(default_config[section], dict):
                        default_config[section].update(settings)
                    else:
                        default_config[section] = settings
                logger.info("Loaded unified configuration from unified_config.json")
            except Exception as e:
                logger.error(f"Error loading unified configuration: {str(e)}")
        
        # Load user-provided config if specified
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                # Merge with current config
                for section, settings in user_config.items():
                    if isinstance(settings, dict) and section in default_config and isinstance(default_config[section], dict):
                        default_config[section].update(settings)
                    else:
                        default_config[section] = settings
                logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.error(f"Error loading configuration from {self.config_file}: {str(e)}")
        
        return default_config
    
    def save_config(self, config_file="unified_config.json"):
        """Save current configuration to a file"""
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Configuration saved to {config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def _get_platform(self, target=None):
        """Get or create the security platform instance"""
        if not PLATFORM_AVAILABLE:
            raise ImportError("SecurityPlatform module is not available")
            
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
    
    def _get_ai_integrator(self):
        """Get or create the AI security integrator"""
        if not AI_AVAILABLE:
            raise ImportError("AISecurityIntegrator module is not available")
            
        if not self.ai_integrator:
            self.ai_integrator = AISecurityIntegrator()
            
        return self.ai_integrator
    
    def list_available_tools(self):
        """List all available security tools"""
        if not self.integrator:
            return []
            
        return self.api.get_available_tools()
    
    def list_available_workflows(self):
        """List all available security workflows"""
        if not self.integrator:
            return []
            
        return self.api.get_available_workflows()
    
    def start_assessment(self, target, assessment_type="full", modules=None, format="all", 
                         async_execution=True, callback=None):
        """
        Start a security assessment on the target
        
        Args:
            target: URL, IP, or domain to assess
            assessment_type: Type of assessment (full, quick, network, web, osint, etc.)
            modules: List of specific modules to enable
            format: Output format for reports
            async_execution: Whether to run the assessment asynchronously
            callback: Function to call when assessment completes (for async mode)
            
        Returns:
            If async_execution is True: assessment_id
            If async_execution is False: assessment results
        """
        logger.info(f"Starting {assessment_type} assessment for target: {target}")
        
        # Generate a unique assessment ID
        assessment_id = f"assessment_{self.timestamp}_{id(target)}"
        
        # Create assessment record
        assessment = {
            "id": assessment_id,
            "target": target,
            "type": assessment_type,
            "modules": modules or self.config["default_modules"],
            "format": format,
            "status": "initializing",
            "start_time": time.time(),
            "progress": 0,
            "results": None,
            "reports": {},
            "errors": []
        }
        
        # Store assessment record
        with self.assessment_lock:
            self.active_assessments[assessment_id] = assessment
        
        if async_execution:
            # Start assessment in a separate thread
            thread = threading.Thread(
                target=self._run_assessment_thread,
                args=(assessment_id, target, assessment_type, modules, format, callback)
            )
            thread.daemon = True
            thread.start()
            
            return assessment_id
        else:
            # Run assessment synchronously
            results = self._run_assessment(target, assessment_type, modules, format)
            
            # Update assessment record
            with self.assessment_lock:
                assessment = self.active_assessments[assessment_id]
                assessment["status"] = "completed"
                assessment["progress"] = 100
                assessment["results"] = results
                assessment["end_time"] = time.time()
                assessment["duration"] = assessment["end_time"] - assessment["start_time"]
                if "report_paths" in results:
                    assessment["reports"] = results["report_paths"]
            
            return results
    
    def _run_assessment_thread(self, assessment_id, target, assessment_type, modules, format, callback):
        """Thread function to run an assessment"""
        try:
            # Update status
            with self.assessment_lock:
                self.active_assessments[assessment_id]["status"] = "running"
                self.active_assessments[assessment_id]["progress"] = 5
            
            # Run the assessment
            results = self._run_assessment(target, assessment_type, modules, format)
            
            # Update assessment record
            with self.assessment_lock:
                assessment = self.active_assessments[assessment_id]
                assessment["status"] = "completed"
                assessment["progress"] = 100
                assessment["results"] = results
                assessment["end_time"] = time.time()
                assessment["duration"] = assessment["end_time"] - assessment["start_time"]
                if "report_paths" in results:
                    assessment["reports"] = results["report_paths"]
            
            # Call callback if provided
            if callback and callable(callback):
                callback(assessment_id, results)
                
        except Exception as e:
            logger.error(f"Error in assessment {assessment_id}: {str(e)}")
            # Update assessment record with error
            with self.assessment_lock:
                assessment = self.active_assessments[assessment_id]
                assessment["status"] = "error"
                assessment["errors"].append(str(e))
                assessment["end_time"] = time.time()
                assessment["duration"] = assessment["end_time"] - assessment["start_time"]
            
            # Call callback with error if provided
            if callback and callable(callback):
                callback(assessment_id, {"error": str(e)})
    
    def _run_assessment(self, target, assessment_type="full", modules=None, format="all"):
        """
        Internal function to run a security assessment
        """
        # Determine whether to use platform or integrator
        if PLATFORM_AVAILABLE and assessment_type == "full":
            # Use SecurityPlatform for full assessments
            platform = self._get_platform(target)
            
            # Configure modules based on assessment type and specified modules
            active_modules = set(self.config["default_modules"])
            
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
            start_time = time.time()
            results = platform.run_full_assessment()
            execution_time = time.time() - start_time
            
            # Generate reports in requested formats
            report_paths = {}
            
            if format in ["json", "all"]:
                json_path = platform.save_results()
                report_paths["json"] = json_path
            
            if format in ["html", "all"]:
                html_path = platform.generate_html_report()
                report_paths["html"] = html_path
                
            if format in ["pdf", "all"] and hasattr(platform, "generate_pdf_report"):
                pdf_path = platform.generate_pdf_report()
                report_paths["pdf"] = pdf_path
            
            # Add report paths to results
            results["report_paths"] = report_paths
            results["execution_time"] = execution_time
            
            return results
            
        elif INTEGRATOR_AVAILABLE:
            # Use the SecurityToolIntegrator for specific assessment types
            return self.api.run_assessment(target, assessment_type, modules=modules, output_format=format)
        else:
            raise ImportError("Neither SecurityPlatform nor SecurityToolIntegrator are available")
    
    def get_assessment_status(self, assessment_id):
        """Get the status of a running assessment"""
        with self.assessment_lock:
            if assessment_id in self.active_assessments:
                return self.active_assessments[assessment_id]
            else:
                return None
    
    def list_completed_assessments(self):
        """List all completed assessments"""
        completed = []
        with self.assessment_lock:
            for assessment_id, assessment in self.active_assessments.items():
                if assessment["status"] in ["completed", "error"]:
                    completed.append(assessment)
        return completed
    
    def get_assessment_report(self, assessment_id, format="json"):
        """Get a specific report for an assessment"""
        with self.assessment_lock:
            if assessment_id in self.active_assessments:
                assessment = self.active_assessments[assessment_id]
                if assessment["status"] == "completed" and format in assessment["reports"]:
                    report_path = assessment["reports"][format]
                    if os.path.exists(report_path):
                        try:
                            if format == "json":
                                with open(report_path, 'r') as f:
                                    return json.load(f)
                            else:
                                with open(report_path, 'rb') as f:
                                    return f.read()
                        except Exception as e:
                            logger.error(f"Error reading report: {str(e)}")
        return None
    
    def run_specific_tool(self, tool_name, method="run", **params):
        """Run a specific security tool"""
        if not self.integrator:
            raise ImportError("SecurityToolIntegrator is not available")
            
        return self.api.execute_tool(tool_name, method, **params)
    
    def run_specific_workflow(self, workflow_id, **params):
        """Run a specific security workflow"""
        if not self.integrator:
            raise ImportError("SecurityToolIntegrator is not available")
            
        return self.api.execute_workflow(workflow_id, **params)
    
    def start_web_interface(self, host=None, port=None, debug=None, open_browser=None):
        """Start the web interface for the security system"""
        # Check if Flask is available
        try:
            import flask
        except ImportError:
            raise ImportError("Flask is required for the web interface. Install with: pip install flask")
        
        # Use configuration or defaults
        web_config = self.config.get("web_interface", {})
        host = host or web_config.get("host", "127.0.0.1")
        port = port or web_config.get("port", 5000)
        debug = debug if debug is not None else web_config.get("debug", False)
        open_browser = open_browser if open_browser is not None else web_config.get("open_browser", True)
        
        logger.info(f"Starting web interface on http://{host}:{port}")
        
        # Import the app (app.py file assumed to exist)
        try:
            if os.path.exists("app.py"):
                # Start the Flask app as a subprocess
                cmd = [sys.executable, "app.py", "--host", host, "--port", str(port)]
                if debug:
                    cmd.append("--debug")
                    
                # Start the server
                self.web_server = subprocess.Popen(cmd)
                
                # Wait a moment for the server to start
                time.sleep(2)
                
                # Open browser if requested
                if open_browser:
                    url = f"http://{host}:{port}"
                    webbrowser.open(url)
                
                return True
            else:
                logger.error("app.py not found. Web interface cannot be started.")
                return False
        except Exception as e:
            logger.error(f"Error starting web interface: {str(e)}")
            return False
    
    def stop_web_interface(self):
        """Stop the web interface"""
        if self.web_server:
            try:
                self.web_server.terminate()
                self.web_server.wait(timeout=5)
                self.web_server = None
                logger.info("Web interface stopped")
                return True
            except Exception as e:
                logger.error(f"Error stopping web interface: {str(e)}")
                try:
                    self.web_server.kill()
                    self.web_server = None
                except:
                    pass
                return False
        return True
    
    def rebuild_unified_config(self):
        """Rebuild and save the unified configuration"""
        # Combine settings from all tools
        unified_config = self.config.copy()
        
        if self.integrator:
            # Add tool-specific configurations
            tools = self.integrator.list_available_tools()
            tool_configs = {}
            
            for tool in tools:
                tool_name = tool["name"]
                tool_configs[tool_name] = {
                    "enabled": True,
                    "capabilities": tool["capabilities"],
                    "dependencies": tool["dependencies"]
                }
                
            unified_config["tools"] = tool_configs
        
        # Save the unified configuration
        return self.save_config("unified_config.json")
    
    def check_environment(self):
        """Check if the environment has all required components"""
        environment_status = {
            "core_components": {
                "security_integrator": INTEGRATOR_AVAILABLE,
                "security_platform": PLATFORM_AVAILABLE,
                "ai_security": AI_AVAILABLE,
                "client_reporting": REPORTING_AVAILABLE
            },
            "directories": {
                "output_dir": os.path.exists(self.output_dir),
                "data_dir": os.path.exists(self.data_dir)
            },
            "config": {
                "unified_config": os.path.exists("unified_config.json"),
                "env_file": os.path.exists(".env") or os.path.exists(".env.template")
            }
        }
        
        # Check for web interface components
        try:
            import flask
            environment_status["web_interface"] = {"flask": True}
        except ImportError:
            environment_status["web_interface"] = {"flask": False}
        
        # Check for AI components if available
        if AI_AVAILABLE:
            try:
                import torch
                environment_status["ai_components"] = {"torch": True}
            except ImportError:
                environment_status["ai_components"] = {"torch": False}
        
        return environment_status
    
    def setup_environment(self):
        """Set up the environment for the unified security system"""
        # Create required directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, "tools"), exist_ok=True)
        
        # Create .env file if it doesn't exist
        if not os.path.exists(".env") and os.path.exists(".env.template"):
            shutil.copy(".env.template", ".env")
            logger.info("Created .env file from template")
        
        # Create unified config if it doesn't exist
        if not os.path.exists("unified_config.json"):
            self.rebuild_unified_config()
            logger.info("Created unified configuration file")
        
        # Check for required Python packages
        missing_packages = []
        required_packages = ["flask", "requests", "python-dotenv", "pyyaml"]
        
        for package in required_packages:
            try:
                importlib.import_module(package.replace("-", "_"))
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            logger.warning(f"Missing required packages: {', '.join(missing_packages)}")
            logger.info("Install missing packages with: pip install " + " ".join(missing_packages))
        
        return True

def main():
    """Command line interface for the unified security system"""
    parser = argparse.ArgumentParser(
        description="Unified Security Tools - Comprehensive Security Assessment Platform"
    )
    
    # Target argument
    parser.add_argument("target", nargs="?", help="Target URL, domain, or IP address to assess")
    
    # Assessment type and configuration
    parser.add_argument(
        "--type", choices=["full", "quick", "network", "web", "osint", "dns", "exploit", "ai"], 
        default="full", help="Type of assessment to run"
    )
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--output-dir", help="Output directory for reports")
    parser.add_argument(
        "--format", choices=["json", "html", "pdf", "all"], 
        default="all", help="Output format for reports"
    )
    
    # Module selection
    parser.add_argument("--enable", action="append", help="Enable specific modules")
    parser.add_argument("--disable", action="append", help="Disable specific modules")
    
    # Web interface options
    parser.add_argument("--start-web", action="store_true", help="Start the web interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host for web interface")
    parser.add_argument("--port", type=int, default=5000, help="Port for web interface")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser when starting web interface")
    
    # Tool and workflow execution
    parser.add_argument("--tool", help="Run a specific security tool")
    parser.add_argument("--method", default="run", help="Method to run on the tool")
    parser.add_argument("--workflow", help="Run a specific workflow")
    parser.add_argument("--async", dest="async_mode", action="store_true", help="Run assessment asynchronously")
    
    # Information commands
    parser.add_argument("--list-tools", action="store_true", help="List available security tools")
    parser.add_argument("--list-workflows", action="store_true", help="List available workflows")
    parser.add_argument("--list-modules", action="store_true", help="List available assessment modules")
    parser.add_argument("--list-assessments", action="store_true", help="List completed assessments")
    parser.add_argument("--show-assessment", help="Show details of a specific assessment by ID")
    parser.add_argument("--check-env", action="store_true", help="Check environment setup")
    parser.add_argument("--setup", action="store_true", help="Set up the environment")
    
    args = parser.parse_args()
    
    # Initialize the unified security system
    system = UnifiedSecuritySystem(config_file=args.config)
    
    # Override output directory if specified
    if args.output_dir:
        system.config["output_dir"] = args.output_dir
        system.output_dir = args.output_dir
        os.makedirs(args.output_dir, exist_ok=True)
    
    # Set up environment if requested
    if args.setup:
        print("Setting up the environment...")
        system.setup_environment()
        print("Environment setup complete.")
        return
    
    # Check environment if requested
    if args.check_env:
        env_status = system.check_environment()
        print("\n=== Environment Status ===\n")
        
        print("Core Components:")
        for component, status in env_status["core_components"].items():
            print(f"  {component}: {'Available' if status else 'Not Available'}")
        
        print("\nDirectories:")
        for directory, status in env_status["directories"].items():
            print(f"  {directory}: {'Exists' if status else 'Missing'}")
        
        print("\nConfiguration:")
        for config, status in env_status["config"].items():
            print(f"  {config}: {'Found' if status else 'Missing'}")
        
        if "web_interface" in env_status:
            print("\nWeb Interface:")
            for component, status in env_status["web_interface"].items():
                print(f"  {component}: {'Available' if status else 'Not Available'}")
        
        if "ai_components" in env_status:
            print("\nAI Components:")
            for component, status in env_status["ai_components"].items():
                print(f"  {component}: {'Available' if status else 'Not Available'}")
        
        print()
        return
    
    # Start web interface if requested
    if args.start_web:
        if system.start_web_interface(args.host, args.port, debug=False, open_browser=not args.no_browser):
            print(f"Web interface started at http://{args.host}:{args.port}")
            print("Press Ctrl+C to stop the web interface")
            try:
                # Keep the main thread alive
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping web interface...")
                system.stop_web_interface()
                print("Web interface stopped")
        else:
            print("Failed to start web interface")
        return
    
    # Handle information commands
    if args.list_tools:
        tools = system.list_available_tools()
        print("\n=== Available Security Tools ===\n")
        if not tools:
            print("No security tools available. Make sure the SecurityToolIntegrator is properly set up.")
            return
            
        for i, tool in enumerate(tools, 1):
            print(f"{i}. {tool['name']} ({tool['module']})")
            if "description" in tool["capabilities"]:
                print(f"   {tool['capabilities']['description']}")
            actions = tool['capabilities'].get('actions', ['unknown'])
            print(f"   Capabilities: {', '.join(actions)}")
            if tool['dependencies']:
                print(f"   Dependencies: {', '.join(tool['dependencies'])}")
            print()
        return
    
    if args.list_workflows:
        workflows = system.list_available_workflows()
        print("\n=== Available Assessment Workflows ===\n")
        if not workflows:
            print("No workflows available. Make sure the SecurityToolIntegrator is properly set up.")
            return
            
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
        print("dns           - DNS spoofing and security testing")
        print("exploit       - Exploitation frameworks and vulnerability testing")
        print("comprehensive - Comprehensive security testing")
        print("report        - Client-friendly reporting")
        print()
        return
    
    if args.list_assessments:
        assessments = system.list_completed_assessments()
        print("\n=== Completed Assessments ===\n")
        if not assessments:
            print("No completed assessments found.")
            return
            
        for i, assessment in enumerate(assessments, 1):
            print(f"{i}. ID: {assessment['id']}")
            print(f"   Target: {assessment['target']}")
            print(f"   Type: {assessment['type']}")
            print(f"   Status: {assessment['status']}")
            if "duration" in assessment:
                print(f"   Duration: {assessment['duration']:.2f} seconds")
            if assessment["reports"]:
                print(f"   Reports: {', '.join(assessment['reports'].keys())}")
            print()
        return
    
    if args.show_assessment:
        assessment = system.get_assessment_status(args.show_assessment)
        if not assessment:
            print(f"Assessment not found: {args.show_assessment}")
            return
            
        print("\n=== Assessment Details ===\n")
        print(f"ID: {assessment['id']}")
        print(f"Target: {assessment['target']}")
        print(f"Type: {assessment['type']}")
        print(f"Status: {assessment['status']}")
        print(f"Progress: {assessment['progress']}%")
        
        if "start_time" in assessment:
            start_time = datetime.datetime.fromtimestamp(assessment['start_time'])
            print(f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
        if "end_time" in assessment:
            end_time = datetime.datetime.fromtimestamp(assessment['end_time'])
            print(f"Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Duration: {assessment['duration']:.2f} seconds")
            
        if assessment["reports"]:
            print("\nReports:")
            for format_name, path in assessment["reports"].items():
                print(f"- {format_name.upper()}: {path}")
                
        if assessment["errors"]:
            print("\nErrors:")
            for error in assessment["errors"]:
                print(f"- {error}")
                
        print()
        return
    
    # Handle tool or workflow execution
    if args.tool:
        if not args.target:
            print("Error: Target is required for tool execution")
            sys.exit(1)
        
        print(f"\nExecuting tool: {args.tool}.{args.method} on target: {args.target}\n")
        results = system.run_specific_tool(args.tool, args.method, target=args.target)
        print(json.dumps(results, indent=2))
        return
    
    if args.workflow:
        if not args.target:
            print("Error: Target is required for workflow execution")
            sys.exit(1)
        
        print(f"\nExecuting workflow: {args.workflow} on target: {args.target}\n")
        results = system.run_specific_workflow(args.workflow, target=args.target)
        print(json.dumps(results, indent=2))
        return
    
    # Run assessment if target is provided
    if args.target:
        # Determine which modules to enable/disable
        modules = None
        if args.enable:
            modules = args.enable
        
        print(f"\nStarting {args.type} security assessment for: {args.target}\n")
        
        # Translate assessment type if needed
        assessment_type = args.type
        if args.type == "dns":
            assessment_type = "dns_spoofing"
        elif args.type == "exploit":
            assessment_type = "exploitation"
        elif args.type == "ai":
            assessment_type = "ai_security_analysis"
            
        if args.async_mode:
            # Run asynchronously
            assessment_id = system.start_assessment(
                target=args.target,
                assessment_type=assessment_type,
                modules=modules,
                format=args.format,
                async_execution=True
            )
            print(f"Assessment started with ID: {assessment_id}")
            print(f"Run with --show-assessment {assessment_id} to check status")
        else:
            # Run synchronously
            results = system.start_assessment(
                target=args.target,
                assessment_type=assessment_type,
                modules=modules,
                format=args.format,
                async_execution=False
            )
            
            # Print completion message with report locations
            if "error" in results:
                print(f"\nAssessment failed: {results['error']}")
            else:
                print("\nAssessment completed successfully!")
                if "execution_time" in results:
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
                    if "web_vulnerability_scan" in results and "vulnerabilities" in results["web_vulnerability_scan"]:
                        vuln_count = len(results["web_vulnerability_scan"]["vulnerabilities"])
                    print(f"- Vulnerabilities found: {vuln_count}")
    else:
        # If no specific command was given, show help
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1) 