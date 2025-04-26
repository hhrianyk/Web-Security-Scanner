#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import subprocess
import json
import tempfile
import time
import datetime
from typing import Dict, List, Any, Optional, Union

# Import base class from security_tools_integration.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, security_tools_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bandit_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BanditIntegration")

@register_tool
class Bandit(SecurityToolBase):
    """
    Bandit - A tool designed to find common security issues in Python code
    
    Features:
    - Static code analysis for Python applications
    - Detection of common security vulnerabilities
    - Multiple report formats
    - Configurable tests and policies
    - Integration with CI/CD pipelines
    """
    
    def __init__(self):
        self.bandit_bin = "bandit"
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Bandit",
            "description": "Python security linter and static code analyzer",
            "actions": ["static_analysis", "vulnerability_scan", "code_review"],
            "target_types": ["python_code", "python_file", "python_project"],
            "output_formats": ["json", "yaml", "xml", "html", "txt"],
            "dependencies": ["python", "pip"]
        }
        
    def check_installation(self):
        """Check if Bandit is installed"""
        try:
            # Try to run bandit --version
            result = self.run_command([self.bandit_bin, "--version"])
            return result["returncode"] == 0
        except:
            return False
        
    def install(self):
        """Install Bandit using pip"""
        logger.info("Installing Bandit...")
        result = self.run_command([sys.executable, "-m", "pip", "install", "bandit"])
        
        if result["returncode"] != 0:
            raise Exception(f"Failed to install Bandit: {result['stderr']}")
            
        return self.check_installation()
        
    def scan(self, target_path, output_format="json", output_file=None, severity_level="LOW", confidence_level="LOW", tests=None, skips=None):
        """Run a Bandit scan on Python code"""
        if not self.check_installation():
            raise Exception("Bandit is not installed")
            
        # Create output file if not specified
        if not output_file and output_format != "txt":
            output_file = os.path.join(tempfile.gettempdir(), f"bandit_report_{int(time.time())}.{output_format}")
            
        # Build command
        cmd = [self.bandit_bin, "-r", target_path]
        
        # Add severity level
        if severity_level:
            cmd.extend(["-l", severity_level])
            
        # Add confidence level
        if confidence_level:
            cmd.extend(["-c", confidence_level])
            
        # Add output format
        if output_format:
            cmd.extend(["-f", output_format])
            
        # Add output file
        if output_file:
            cmd.extend(["-o", output_file])
            
        # Add specific tests
        if tests:
            if isinstance(tests, list):
                tests = ",".join(tests)
            cmd.extend(["-t", tests])
            
        # Add skipped tests
        if skips:
            if isinstance(skips, list):
                skips = ",".join(skips)
            cmd.extend(["-s", skips])
            
        # Run scan
        logger.info(f"Running Bandit scan on {target_path}")
        result = self.run_command(cmd)
        
        # Parse and return results
        if output_format == "json" and output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    scan_results = json.load(f)
                    
                return {
                    "target": target_path,
                    "scan_time": datetime.datetime.now().isoformat(),
                    "output_file": output_file,
                    "results": scan_results,
                    "return_code": result["returncode"]
                }
            except Exception as e:
                logger.error(f"Error parsing Bandit output: {str(e)}")
                
        return {
            "target": target_path,
            "scan_time": datetime.datetime.now().isoformat(),
            "output_file": output_file if output_file and os.path.exists(output_file) else None,
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "return_code": result["returncode"]
        }
        
    def get_tests(self):
        """Get the list of available Bandit tests"""
        if not self.check_installation():
            raise Exception("Bandit is not installed")
            
        result = self.run_command([self.bandit_bin, "--help"])
        
        # Parse tests from help output
        tests = []
        capture = False
        
        for line in result["stdout"].splitlines():
            if "Available tests:" in line:
                capture = True
                continue
            elif capture and not line.strip():
                capture = False
                break
                
            if capture and line.strip():
                tests.append(line.strip())
                
        return tests

if __name__ == "__main__":
    try:
        # Initialize Bandit tool
        bandit = security_tools_manager.get_tool("Bandit")
        
        # Run a test if requested
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            # Run a simple test on current directory
            print("Running test scan on current directory")
            result = bandit.scan(os.getcwd())
            print(f"Test scan completed.")
            if isinstance(result.get("results"), dict) and "results" in result["results"]:
                issues = result["results"]["results"]
                print(f"Found {len(issues)} security issues.")
                for issue in issues[:5]:  # Print first 5 issues
                    print(f"- {issue.get('issue_text')} in {issue.get('filename')}:{issue.get('line_number')}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 