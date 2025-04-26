#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import datetime
import time
import importlib
import inspect
import concurrent.futures
from typing import Dict, List, Any, Optional, Union
import dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_integrator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecurityIntegrator")

# Load environment variables
dotenv.load_dotenv()
if os.path.exists(".env.template"):
    dotenv.load_dotenv(".env.template", override=True)
if os.path.exists(".env.security_ai.template"):
    dotenv.load_dotenv(".env.security_ai.template", override=True)

class SecurityToolIntegrator:
    """
    Security Tool Integrator
    
    Provides a unified API for all security tools in the system:
    1. Dynamically discovers available security tools
    2. Standardizes interfaces for all tools
    3. Provides consistent error handling and logging
    4. Manages dependencies between tools
    5. Provides a single entry point for all security operations
    """
    
    def __init__(self, tools_directory=".", config_file=None):
        self.tools_directory = tools_directory
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Load configuration if provided
        self.config = self._load_config(config_file)
        
        # Storage for discovered tools
        self.tools = {}
        self.tool_instances = {}
        self.tool_capabilities = {}
        self.tool_dependencies = {}
        
        # Discover available tools
        self._discover_tools()
        
        logger.info(f"Initialized SecurityToolIntegrator with {len(self.tools)} tools")
    
    def _load_config(self, config_file=None):
        """Load configuration from file or use defaults"""
        default_config = {
            "tool_discovery": {
                "scan_subfolders": True,
                "exclude_patterns": ["__pycache__", "venv", ".git"],
                "require_capability_method": True
            },
            "execution": {
                "parallel_execution": True,
                "max_workers": 5,
                "timeout": 600
            },
            "reporting": {
                "save_results": True,
                "results_dir": "security_results",
                "formats": ["json", "html"]
            },
            "integration": {
                "web_interface": True,
                "api_interface": True,
                "cli_interface": True,
                "notifications": True
            }
        }
        
        # Try loading the unified config if exists
        if os.path.exists("unified_config.json"):
            try:
                with open("unified_config.json", 'r') as f:
                    unified_config = json.load(f)
                # Merge unified config with defaults
                for section, settings in unified_config.items():
                    if section in default_config and isinstance(settings, dict):
                        default_config[section].update(settings)
                    else:
                        default_config[section] = settings
                logger.info("Loaded unified configuration from unified_config.json")
            except Exception as e:
                logger.error(f"Error loading unified configuration: {str(e)}")
        
        # Load user config if provided
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                
                # Merge user config with defaults
                for section, settings in user_config.items():
                    if section in default_config and isinstance(settings, dict):
                        default_config[section].update(settings)
                    else:
                        default_config[section] = settings
                
                logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
        
        return default_config
    
    def _discover_tools(self):
        """Discover available security tools in the directory"""
        logger.info(f"Discovering security tools in {self.tools_directory}")
        
        # Get all Python files in the directory
        python_files = self._get_python_files()
        
        # Directly check for known integration modules first
        known_integration_modules = [
            "vulnerability_scanner.py",
            "exploit_documenter.py",
            "client_vulnerability_report.py",
            "security_framework.py",
            "dns_spoof_integration.py",
            "ai_vulnerability_scanner.py",
            "comprehensive_pentesting.py",
            "security_platform.py",
            "ai_security_integrator.py"
        ]
        
        # Process known integration modules first
        priority_files = []
        standard_files = []
        
        for file_path in python_files:
            file_name = os.path.basename(file_path)
            if file_name in known_integration_modules:
                priority_files.append(file_path)
            else:
                standard_files.append(file_path)
        
        # Process all files, with priority files first
        for file_path in priority_files + standard_files:
            try:
                # Skip files based on exclude patterns
                if any(pattern in file_path for pattern in self.config["tool_discovery"]["exclude_patterns"]):
                    continue
                
                # Convert file path to module name
                module_name = os.path.basename(file_path).replace(".py", "")
                
                # Try to import the module
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if not spec or not spec.loader:
                    continue
                    
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                
                # Look for security tool classes in the module
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and self._is_security_tool(obj):
                        # Register the tool
                        self.tools[name] = {
                            "class": obj,
                            "module": module_name,
                            "file_path": file_path,
                            "capabilities": self._get_tool_capabilities(obj)
                        }
                        logger.debug(f"Discovered security tool: {name}")
            except Exception as e:
                logger.warning(f"Error inspecting {file_path}: {str(e)}")
        
        # Build dependency graph
        self._build_dependency_graph()
        
        logger.info(f"Discovered {len(self.tools)} security tools")
    
    def _get_python_files(self):
        """Get all Python files in the directory and subdirectories"""
        python_files = []
        
        if self.config["tool_discovery"]["scan_subfolders"]:
            # Recursive scan
            for root, dirs, files in os.walk(self.tools_directory):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if d not in self.config["tool_discovery"]["exclude_patterns"]]
                
                # Add Python files
                for file in files:
                    if file.endswith(".py"):
                        python_files.append(os.path.join(root, file))
        else:
            # Scan only the main directory
            for file in os.listdir(self.tools_directory):
                if file.endswith(".py"):
                    python_files.append(os.path.join(self.tools_directory, file))
        
        return python_files
    
    def _is_security_tool(self, cls):
        """Check if a class is a security tool"""
        # Check if class has a get_capabilities method
        if self.config["tool_discovery"]["require_capability_method"]:
            if hasattr(cls, "get_capabilities") and callable(getattr(cls, "get_capabilities")):
                return True
        
        # Check if class name contains security-related keywords
        security_keywords = ["security", "scanner", "vulnerability", "assessment", "test", 
                             "osint", "network", "analyzer", "report", "social", "tool",
                             "exploit", "penetration", "pentest", "recon", "reconnaissance",
                             "monitoring", "firewall", "protection", "defense", "attack"]
        
        cls_name = cls.__name__.lower()
        if any(keyword in cls_name for keyword in security_keywords):
            return True
        
        # Check if class has security-related methods
        security_method_names = ["scan", "test", "analyze", "detect", "exploit", "report",
                                "check_vulnerability", "assess", "attack", "defend"]
        
        for method_name in security_method_names:
            if hasattr(cls, method_name) and callable(getattr(cls, method_name)):
                return True
        
        return False
    
    def _get_tool_capabilities(self, cls):
        """Get the capabilities of a security tool"""
        capabilities = {}
        
        # Try to call get_capabilities class method
        if hasattr(cls, "get_capabilities") and callable(getattr(cls, "get_capabilities")):
            try:
                capabilities = cls.get_capabilities()
            except Exception as e:
                logger.warning(f"Error getting capabilities for {cls.__name__}: {str(e)}")
        
        # Fallback to inspecting methods
        if not capabilities:
            capabilities = {
                "name": cls.__name__,
                "description": cls.__doc__.strip() if cls.__doc__ else f"{cls.__name__} security tool",
                "actions": [],
                "target_types": ["unknown"],
                "output_formats": ["unknown"],
                "dependencies": []
            }
            
            # Check for common methods
            common_methods = {
                "scan": "scanning",
                "test": "testing",
                "analyze": "analysis",
                "report": "reporting",
                "check": "checking",
                "assess": "assessment",
                "exploit": "exploitation",
                "detect": "detection",
                "monitor": "monitoring"
            }
            
            for method_name, action in common_methods.items():
                if hasattr(cls, method_name) and callable(getattr(cls, method_name)):
                    capabilities["actions"].append(action)
        
        # Store capabilities for this tool
        self.tool_capabilities[cls.__name__] = capabilities
        
        return capabilities
    
    def _build_dependency_graph(self):
        """Build a dependency graph for tools"""
        for tool_name, tool_info in self.tools.items():
            dependencies = []
            
            # Get declared dependencies
            if "dependencies" in tool_info["capabilities"]:
                dependencies = tool_info["capabilities"]["dependencies"]
            
            # Check for import dependencies
            try:
                cls = tool_info["class"]
                source = inspect.getsource(cls)
                
                # Check for imports of other tools
                for other_tool in self.tools:
                    if other_tool != tool_name and f"import {other_tool}" in source:
                        if other_tool not in dependencies:
                            dependencies.append(other_tool)
            except Exception:
                pass
            
            self.tool_dependencies[tool_name] = dependencies
    
    def get_tool_instance(self, tool_name, **kwargs):
        """Get an instance of a security tool"""
        if tool_name not in self.tools:
            raise ValueError(f"Tool not found: {tool_name}")
        
        # Check if we already have an instance
        if tool_name in self.tool_instances:
            return self.tool_instances[tool_name]
        
        # Create a new instance
        tool_class = self.tools[tool_name]["class"]
        
        try:
            # Get required dependencies
            for dependency in self.tool_dependencies.get(tool_name, []):
                # Recursively get dependency instances
                if dependency in self.tools and dependency not in kwargs:
                    kwargs[dependency.lower()] = self.get_tool_instance(dependency)
            
            # Create the instance
            instance = tool_class(**kwargs)
            self.tool_instances[tool_name] = instance
            return instance
        except Exception as e:
            logger.error(f"Error creating instance of {tool_name}: {str(e)}")
            raise
    
    def list_available_tools(self):
        """List all available security tools and their capabilities"""
        tools_list = []
        
        for name, info in self.tools.items():
            tools_list.append({
                "name": name,
                "module": info["module"],
                "capabilities": info["capabilities"],
                "dependencies": self.tool_dependencies.get(name, [])
            })
        
        return tools_list
    
    def execute_tool(self, tool_name, method_name="run", **kwargs):
        """Execute a method on a security tool"""
        instance = self.get_tool_instance(tool_name, **kwargs)
        
        if not hasattr(instance, method_name) or not callable(getattr(instance, method_name)):
            raise ValueError(f"Method not found: {method_name} on tool {tool_name}")
        
        logger.info(f"Executing {tool_name}.{method_name}")
        try:
            # Get the method
            method = getattr(instance, method_name)
            
            # Call the method with the provided arguments
            start_time = time.time()
            result = method(**kwargs)
            execution_time = time.time() - start_time
            
            logger.info(f"Executed {tool_name}.{method_name} in {execution_time:.2f} seconds")
            
            # Save results if configured
            if self.config["reporting"]["save_results"]:
                self._save_tool_results(tool_name, method_name, result)
            
            return result
        except Exception as e:
            logger.error(f"Error executing {tool_name}.{method_name}: {str(e)}")
            raise
    
    def execute_tools_parallel(self, tool_executions):
        """
        Execute multiple tools in parallel
        
        Args:
            tool_executions: List of dicts containing tool_name, method_name, and kwargs
        """
        logger.info(f"Executing {len(tool_executions)} tools in parallel")
        
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["execution"]["max_workers"]) as executor:
            future_to_tool = {}
            
            for tool_info in tool_executions:
                tool_name = tool_info["tool_name"]
                method_name = tool_info.get("method_name", "run")
                kwargs = tool_info.get("kwargs", {})
                
                future = executor.submit(self.execute_tool, tool_name, method_name, **kwargs)
                future_to_tool[future] = f"{tool_name}.{method_name}"
            
            for future in concurrent.futures.as_completed(future_to_tool):
                tool_key = future_to_tool[future]
                try:
                    results[tool_key] = future.result()
                except Exception as e:
                    logger.error(f"Error executing {tool_key}: {str(e)}")
                    results[tool_key] = {"error": str(e)}
        
        return results
    
    def _save_tool_results(self, tool_name, method_name, results):
        """Save tool execution results to file"""
        results_dir = self.config["reporting"]["results_dir"]
        os.makedirs(results_dir, exist_ok=True)
        
        # Determine if results can be JSON serialized
        try:
            # Test JSON serialization
            json.dumps(results)
            serializable = True
        except (TypeError, OverflowError):
            serializable = False
        
        if serializable:
            filename = os.path.join(results_dir, f"{tool_name}_{method_name}_{self.timestamp}.json")
            try:
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=4)
                logger.debug(f"Saved results to {filename}")
            except Exception as e:
                logger.warning(f"Error saving results: {str(e)}")
        else:
            # For non-serializable results, save basic information
            filename = os.path.join(results_dir, f"{tool_name}_{method_name}_{self.timestamp}.txt")
            try:
                with open(filename, 'w') as f:
                    f.write(f"Results from {tool_name}.{method_name} at {self.timestamp}\n")
                    f.write(f"Results type: {type(results)}\n")
                    f.write(f"Results summary: {str(results)[:1000]}")
                logger.debug(f"Saved non-serializable results summary to {filename}")
            except Exception as e:
                logger.warning(f"Error saving results summary: {str(e)}")
    
    def execute_workflow(self, workflow, target, **kwargs):
        """Execute a predefined workflow of security tools"""
        logger.info(f"Executing workflow: {workflow}")
        
        if workflow == "network_scan":
            return self._execute_network_scan_workflow(target, **kwargs)
        elif workflow == "web_vulnerability_scan":
            return self._execute_web_vulnerability_workflow(target, **kwargs)
        elif workflow == "osint_reconnaissance":
            return self._execute_osint_workflow(target, **kwargs)
        elif workflow == "full_assessment":
            return self._execute_full_assessment_workflow(target, **kwargs)
        elif workflow == "dns_spoofing":
            return self._execute_dns_spoofing_workflow(target, **kwargs)
        elif workflow == "exploitation":
            return self._execute_exploitation_workflow(target, **kwargs)
        elif workflow == "ai_security_analysis":
            return self._execute_ai_security_workflow(target, **kwargs)
        else:
            raise ValueError(f"Unknown workflow: {workflow}")
    
    def _execute_network_scan_workflow(self, target, **kwargs):
        """Execute a network scanning workflow"""
        results = {}
        
        # Try to use the AdvancedNetworkTools if available
        if "AdvancedNetworkTools" in self.tools:
            tool = "AdvancedNetworkTools"
            instance = self.get_tool_instance(tool, target=target)
            results["advanced_scan"] = instance.run_all_scans()
        elif "NetworkTools" in self.tools:
            tool = "NetworkTools"
            instance = self.get_tool_instance(tool)
            results["port_scan"] = instance.port_scan(target)
            results["service_detection"] = instance.detect_services(target)
        # Try to use Nmap scanner if available
        elif "NmapScanner" in self.tools:
            tool = "NmapScanner"
            instance = self.get_tool_instance(tool)
            results["comprehensive_scan"] = instance.comprehensive_scan(target)
        else:
            logger.warning("No network scanning tools available")
        
        return results
    
    def _execute_web_vulnerability_workflow(self, target, **kwargs):
        """Execute a web vulnerability scanning workflow"""
        results = {}
        
        # Try different available vulnerability scanners
        if "VulnerabilityScanner" in self.tools:
            scanner_instance = self.get_tool_instance("VulnerabilityScanner")
            scanner_instance.scan(target)
            results["vulnerabilities"] = scanner_instance.get_results()
        
        # Add AI vulnerability scan if available
        if "AIVulnerabilityScanner" in self.tools:
            ai_scanner = self.get_tool_instance("AIVulnerabilityScanner")
            results["ai_scan"] = ai_scanner.start_scan(target)
        
        # Try OWASP ZAP if available
        if "OwaspZAP" in self.tools:
            zap = self.get_tool_instance("OwaspZAP")
            results["zap_scan"] = zap.scan(target, scan_type="all")
        
        # Try W3af if available
        if "W3afScanner" in self.tools:
            w3af = self.get_tool_instance("W3afScanner")
            results["w3af_scan"] = w3af.scan(target)
        
        # Try Nikto if available
        if "NiktoScanner" in self.tools:
            nikto = self.get_tool_instance("NiktoScanner")
            results["nikto_scan"] = nikto.scan(target)
            
        return results
    
    def _execute_osint_workflow(self, target, **kwargs):
        """Execute an OSINT reconnaissance workflow"""
        results = {}
        
        # Try to use OSINTTools if available
        if "OSINTTools" in self.tools:
            tool = "OSINTTools"
            instance = self.get_tool_instance(tool, target=target)
            results = instance.run_all_osint()
        elif "OsintScanner" in self.tools:
            tool = "OsintScanner"
            instance = self.get_tool_instance(tool)
            results = instance.gather_intelligence(target)
        
        return results
    
    def _execute_dns_spoofing_workflow(self, target, **kwargs):
        """Execute DNS spoofing tools workflow"""
        results = {}
        
        if "dns_spoof_integration" in sys.modules:
            dns_spoof = self.get_tool_instance("DNSSpoofingTools")
            results["dns_spoofing"] = dns_spoof.run_dns_tools(target)
        
        return results
    
    def _execute_exploitation_workflow(self, target, **kwargs):
        """Execute exploitation tools workflow"""
        results = {}
        
        # Try to use Metasploit if available
        if "MetasploitFramework" in self.tools:
            metasploit = self.get_tool_instance("MetasploitFramework")
            results["vulnerability_scan"] = metasploit.db_scan(target)
            
        # Try to use ExploitDB if available
        if "ExploitDB" in self.tools:
            exploit_db = self.get_tool_instance("ExploitDB")
            results["exploit_search"] = exploit_db.search_exploits(target)
            
        return results
    
    def _execute_ai_security_workflow(self, target, **kwargs):
        """Execute AI-powered security analysis workflow"""
        results = {}
        
        # Try to use AI security tools if available
        if "AISecurityIntegrator" in self.tools:
            ai_security = self.get_tool_instance("AISecurityIntegrator")
            results["ai_security_analysis"] = ai_security.analyze_target(target)
            
        # Try to use IBM Watson integration if available
        if "IBMWatsonSecurity" in self.tools:
            watson = self.get_tool_instance("IBMWatsonSecurity")
            results["watson_analysis"] = watson.analyze_vulnerabilities(target)
            
        return results
    
    def _execute_full_assessment_workflow(self, target, **kwargs):
        """Execute a full security assessment workflow"""
        # Use our SecurityPlatform for full assessment if available
        if "SecurityPlatform" in self.tools:
            tool = "SecurityPlatform"
            instance = self.get_tool_instance(tool, target=target)
            return instance.run_full_assessment()
        
        # Otherwise, execute individual workflows and combine results
        results = {
            "timestamp": self.timestamp,
            "target": target
        }
        
        # Run all workflows in parallel if configured
        if self.config["execution"]["parallel_execution"]:
            workflow_tools = [
                {"workflow": "network_scan", "name": "Network Scanning"},
                {"workflow": "web_vulnerability_scan", "name": "Web Vulnerability Scanning"},
                {"workflow": "osint_reconnaissance", "name": "OSINT Reconnaissance"},
                {"workflow": "dns_spoofing", "name": "DNS Spoofing Tools"},
                {"workflow": "exploitation", "name": "Exploitation Tools"},
                {"workflow": "ai_security_analysis", "name": "AI Security Analysis"}
            ]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config["execution"]["max_workers"]) as executor:
                future_to_workflow = {}
                
                for wf in workflow_tools:
                    future = executor.submit(self.execute_workflow, wf["workflow"], target, **kwargs)
                    future_to_workflow[future] = wf
                
                for future in concurrent.futures.as_completed(future_to_workflow):
                    wf = future_to_workflow[future]
                    try:
                        results[wf["workflow"]] = future.result()
                        logger.info(f"Completed {wf['name']} workflow")
                    except Exception as e:
                        logger.error(f"Error in {wf['name']} workflow: {str(e)}")
                        results[wf["workflow"]] = {"error": str(e)}
        else:
            # Run network scan
            results["network_scan"] = self._execute_network_scan_workflow(target, **kwargs)
            
            # Run web vulnerability scan
            results["web_vulnerability_scan"] = self._execute_web_vulnerability_workflow(target, **kwargs)
            
            # Run OSINT reconnaissance
            results["osint_reconnaissance"] = self._execute_osint_workflow(target, **kwargs)
            
            # Run DNS spoofing tools
            results["dns_spoofing"] = self._execute_dns_spoofing_workflow(target, **kwargs)
            
            # Run exploitation tools
            results["exploitation"] = self._execute_exploitation_workflow(target, **kwargs)
            
            # Run AI security analysis
            results["ai_security_analysis"] = self._execute_ai_security_workflow(target, **kwargs)
        
        # Try to use AI analysis if available to provide integrated analysis
        if "AISecurityIntegrator" in self.tools:
            tool = "AISecurityIntegrator"
            instance = self.get_tool_instance(tool)
            
            # Analyze vulnerabilities
            combined_vulns = []
            if "web_vulnerability_scan" in results and "vulnerabilities" in results["web_vulnerability_scan"]:
                combined_vulns.extend(results["web_vulnerability_scan"]["vulnerabilities"])
                
            results["ai_analysis"] = instance.analyze_vulnerabilities(combined_vulns)
            results["remediation"] = instance.generate_remediation_recommendations(combined_vulns)
        
        # Generate client report if available
        if "ClientVulnerabilityReport" in self.tools:
            tool = "ClientVulnerabilityReport"
            instance = self.get_tool_instance(tool)
            
            # Extract vulnerabilities from results
            all_vulnerabilities = []
            if "web_vulnerability_scan" in results and "vulnerabilities" in results["web_vulnerability_scan"]:
                all_vulnerabilities.extend(results["web_vulnerability_scan"]["vulnerabilities"])
            
            results["client_report"] = {
                "report_path": instance.generate_report(
                    target=target,
                    vulnerabilities=all_vulnerabilities,
                    remediation=results.get("remediation", {}),
                    executive_summary=""
                )
            }
        
        return results
    
    def generate_integrated_report(self, assessment_results, output_formats=None):
        """
        Generate a comprehensive integrated report from assessment results
        """
        if not output_formats:
            output_formats = self.config["reporting"]["formats"]
            
        report_paths = {}
        output_dir = self.config["reporting"]["results_dir"]
        os.makedirs(output_dir, exist_ok=True)
        
        # Use ClientVulnerabilityReport if available
        if "ClientVulnerabilityReport" in self.tools:
            try:
                report_generator = self.get_tool_instance("ClientVulnerabilityReport")
                
                # Process and extract data
                target = assessment_results.get("target", "Unknown")
                vulnerabilities = []
                
                # Extract all vulnerabilities from different scanners
                if "web_vulnerability_scan" in assessment_results:
                    if "vulnerabilities" in assessment_results["web_vulnerability_scan"]:
                        vulnerabilities.extend(assessment_results["web_vulnerability_scan"]["vulnerabilities"])
                    if "zap_scan" in assessment_results["web_vulnerability_scan"]:
                        zap_results = assessment_results["web_vulnerability_scan"]["zap_scan"]
                        if "alerts" in zap_results:
                            for alert in zap_results["alerts"]:
                                vulnerabilities.append({
                                    "type": alert.get("name", "Unknown"),
                                    "severity": alert.get("risk", "Medium"),
                                    "details": alert.get("description", "")
                                })
                
                # Extract AI analysis if available
                remediation = {}
                if "ai_analysis" in assessment_results:
                    remediation = assessment_results.get("remediation", {})
                
                # Generate reports in all requested formats
                for format_name in output_formats:
                    report_path = report_generator.generate_report(
                        target=target,
                        vulnerabilities=vulnerabilities,
                        remediation=remediation,
                        output_format=format_name
                    )
                    report_paths[format_name] = report_path
                
                return report_paths
            
            except Exception as e:
                logger.error(f"Error generating integrated report: {str(e)}")
        
        # Fallback to basic JSON report if ClientVulnerabilityReport not available
        if "json" in output_formats:
            try:
                report_path = os.path.join(output_dir, f"integrated_report_{self.timestamp}.json")
                with open(report_path, 'w') as f:
                    json.dump(assessment_results, f, indent=4)
                report_paths["json"] = report_path
            except Exception as e:
                logger.error(f"Error generating JSON report: {str(e)}")
        
        return report_paths

class SecurityAPIHandler:
    """
    Provides a standardized API interface to the security tools integrator
    """
    
    def __init__(self, integrator=None, config_file=None):
        self.integrator = integrator or SecurityToolIntegrator(config_file=config_file)
    
    def get_available_tools(self):
        """Get a list of all available security tools"""
        return self.integrator.list_available_tools()
    
    def get_available_workflows(self):
        """Get a list of all available workflows"""
        return [
            {
                "id": "network_scan",
                "name": "Network Scanning",
                "description": "Scan network infrastructure for open ports and services",
                "required_parameters": ["target"]
            },
            {
                "id": "web_vulnerability_scan",
                "name": "Web Vulnerability Scanning",
                "description": "Scan web applications for common vulnerabilities",
                "required_parameters": ["target"]
            },
            {
                "id": "osint_reconnaissance",
                "name": "OSINT Reconnaissance",
                "description": "Gather intelligence from open sources",
                "required_parameters": ["target"]
            },
            {
                "id": "dns_spoofing",
                "name": "DNS Spoofing Tools",
                "description": "Test DNS spoofing vulnerabilities",
                "required_parameters": ["target"]
            },
            {
                "id": "exploitation",
                "name": "Exploitation Tools",
                "description": "Test using exploitation frameworks and databases",
                "required_parameters": ["target"]
            },
            {
                "id": "ai_security_analysis",
                "name": "AI Security Analysis",
                "description": "Use AI-powered tools for security analysis",
                "required_parameters": ["target"]
            },
            {
                "id": "full_assessment",
                "name": "Full Security Assessment",
                "description": "Complete security assessment including all available tools",
                "required_parameters": ["target"]
            }
        ]
    
    def execute_tool(self, tool_name, method_name="run", **params):
        """Execute a specific security tool"""
        try:
            return {
                "status": "success",
                "tool": tool_name,
                "method": method_name,
                "timestamp": datetime.datetime.now().isoformat(),
                "results": self.integrator.execute_tool(tool_name, method_name, **params)
            }
        except Exception as e:
            return {
                "status": "error",
                "tool": tool_name,
                "method": method_name,
                "timestamp": datetime.datetime.now().isoformat(),
                "error": str(e)
            }
    
    def execute_workflow(self, workflow_id, **params):
        """Execute a predefined workflow"""
        try:
            if "target" not in params:
                return {
                    "status": "error",
                    "workflow": workflow_id,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "error": "Target parameter is required"
                }
                
            results = self.integrator.execute_workflow(workflow_id, params["target"], **params)
            
            return {
                "status": "success",
                "workflow": workflow_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "results": results
            }
        except Exception as e:
            return {
                "status": "error",
                "workflow": workflow_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "error": str(e)
            }
    
    def run_assessment(self, target, assessment_type="full", **params):
        """Run a complete security assessment"""
        try:
            if assessment_type == "full":
                results = self.integrator.execute_workflow("full_assessment", target, **params)
            else:
                results = self.integrator.execute_workflow(assessment_type, target, **params)
                
            # Generate integrated report
            report_paths = self.integrator.generate_integrated_report(results)
            
            return {
                "status": "success",
                "assessment_type": assessment_type,
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "results": results,
                "report_paths": report_paths
            }
        except Exception as e:
            return {
                "status": "error",
                "assessment_type": assessment_type,
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "error": str(e)
            }

def main():
    """Command line interface for the security integrator"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Tools Integrator")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--list-tools", action="store_true", help="List all available security tools")
    parser.add_argument("--list-workflows", action="store_true", help="List all available workflows")
    parser.add_argument("--workflow", help="Execute a specific workflow")
    parser.add_argument("--tool", help="Execute a specific tool")
    parser.add_argument("--method", default="run", help="Method to execute on the tool")
    parser.add_argument("--target", help="Target URL, domain or IP address")
    parser.add_argument("--output-format", choices=["json", "html", "all"], default="all", help="Output format for reports")
    
    args = parser.parse_args()
    
    # Initialize the integrator
    integrator = SecurityToolIntegrator(config_file=args.config)
    api = SecurityAPIHandler(integrator)
    
    if args.list_tools:
        # List all available tools
        tools = api.get_available_tools()
        print("\nAvailable Security Tools:")
        print("========================")
        for i, tool in enumerate(tools, 1):
            print(f"{i}. {tool['name']}")
            if "description" in tool["capabilities"]:
                print(f"   {tool['capabilities']['description']}")
            if "actions" in tool["capabilities"]:
                print(f"   Actions: {', '.join(tool['capabilities']['actions'])}")
            print()
    
    elif args.list_workflows:
        # List all available workflows
        workflows = api.get_available_workflows()
        print("\nAvailable Workflows:")
        print("===================")
        for i, workflow in enumerate(workflows, 1):
            print(f"{i}. {workflow['name']}")
            print(f"   {workflow['description']}")
            print(f"   Required parameters: {', '.join(workflow['required_parameters'])}")
            print()
    
    elif args.workflow:
        # Execute a workflow
        if not args.target:
            print("Error: Target parameter is required for executing a workflow")
            sys.exit(1)
            
        print(f"Executing workflow '{args.workflow}' on target {args.target}")
        result = api.execute_workflow(args.workflow, target=args.target)
        
        if result["status"] == "success":
            print("Workflow executed successfully!")
            
            # Generate report in requested format
            report_formats = ["json"]
            if args.output_format == "html":
                report_formats = ["html"]
            elif args.output_format == "all":
                report_formats = ["json", "html"]
                
            report_paths = integrator.generate_integrated_report(result["results"], report_formats)
            
            print("\nReport generated at:")
            for format_name, path in report_paths.items():
                print(f"- {format_name.upper()}: {path}")
        else:
            print(f"Error executing workflow: {result['error']}")
    
    elif args.tool:
        # Execute a specific tool
        if not args.target:
            print("Error: Target parameter is required for executing a tool")
            sys.exit(1)
            
        print(f"Executing tool '{args.tool}.{args.method}' on target {args.target}")
        result = api.execute_tool(args.tool, args.method, target=args.target)
        
        if result["status"] == "success":
            print("Tool executed successfully!")
            print(f"Results: {result['results']}")
        else:
            print(f"Error executing tool: {result['error']}")
    
    else:
        # Show help
        parser.print_help()

if __name__ == "__main__":
    main()