#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import subprocess
import shutil
import requests
import json
import zipfile
import tempfile
import time
import datetime
from typing import Dict, List, Any, Optional, Union

# Try to import from security_tools_integration, fall back to security_framework if that fails
try:
    from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, download_file, security_tools_manager
except ImportError:
    from security_framework import SecurityToolBase, register_tool, get_tools_directory, download_file, security_tools_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sonarqube_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SonarQubeIntegration")

@register_tool
class SonarQubeCommunity(SecurityToolBase):
    """
    SonarQube Community Edition - An open-source platform for continuous inspection of code quality
    
    Features:
    - Static code analysis
    - Security vulnerability detection
    - Code quality metrics
    - Multi-language support
    - Continuous integration capabilities
    """
    
    def __init__(self):
        self.sonarqube_path = os.path.join(get_tools_directory(), "sonarqube")
        self.sonar_scanner_path = os.path.join(get_tools_directory(), "sonar-scanner")
        
        # Platform-specific paths
        system = self._get_system()
        if system == "windows":
            self.sonarqube_start_script = os.path.join(self.sonarqube_path, "bin", "windows-x86-64", "StartSonar.bat")
            self.scanner_bin = os.path.join(self.sonar_scanner_path, "bin", "sonar-scanner.bat")
        else:  # Linux/Mac
            self.sonarqube_start_script = os.path.join(self.sonarqube_path, "bin", "linux-x86-64", "sonar.sh")
            self.scanner_bin = os.path.join(self.sonar_scanner_path, "bin", "sonar-scanner")
            
        # SonarQube server settings
        self.server_url = "http://localhost:9000"
        self.admin_username = "admin"
        self.admin_password = "admin"
        self.server_process = None
        
    def _get_system(self):
        """Get the current operating system"""
        system = sys.platform.lower()
        if system.startswith("win"):
            return "windows"
        elif system.startswith("darwin"):
            return "mac"
        else:
            return "linux"
            
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "SonarQube Community",
            "description": "Open-source platform for continuous inspection of code quality",
            "actions": ["code_analysis", "vulnerability_scan", "quality_gate", "multi_language_scan"],
            "target_types": ["source_code", "project", "repository"],
            "output_formats": ["json", "html", "pdf"],
            "dependencies": ["java"]
        }
        
    def check_installation(self):
        """Check if SonarQube Community and SonarScanner are installed"""
        sonarqube_installed = os.path.exists(self.sonarqube_start_script)
        scanner_installed = os.path.exists(self.scanner_bin)
        
        return sonarqube_installed and scanner_installed
        
    def install(self):
        """Install SonarQube Community and SonarScanner"""
        # Check if Java is installed
        java_path = shutil.which("java")
        if not java_path:
            raise Exception("Java is required but not installed")
            
        # Create directories
        os.makedirs(self.sonarqube_path, exist_ok=True)
        os.makedirs(self.sonar_scanner_path, exist_ok=True)
        
        # Install SonarQube
        logger.info("Downloading SonarQube Community Edition...")
        sonarqube_url = "https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-9.9.1.69595.zip"
        sonarqube_zip = os.path.join(tempfile.gettempdir(), "sonarqube.zip")
        
        if not download_file(sonarqube_url, sonarqube_zip):
            raise Exception("Failed to download SonarQube")
            
        logger.info("Extracting SonarQube...")
        with zipfile.ZipFile(sonarqube_zip, 'r') as zip_ref:
            zip_ref.extractall(get_tools_directory())
            
        # Find the extracted directory and move it
        for item in os.listdir(get_tools_directory()):
            item_path = os.path.join(get_tools_directory(), item)
            if os.path.isdir(item_path) and "sonarqube" in item.lower() and item_path != self.sonarqube_path:
                # Move all contents to sonarqube_path
                for subitem in os.listdir(item_path):
                    src = os.path.join(item_path, subitem)
                    dst = os.path.join(self.sonarqube_path, subitem)
                    shutil.move(src, dst)
                os.rmdir(item_path)
                
        # Install SonarScanner
        logger.info("Downloading SonarScanner...")
        system = self._get_system()
        if system == "windows":
            scanner_url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-windows.zip"
        elif system == "mac":
            scanner_url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-macosx.zip"
        else:  # Linux
            scanner_url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.8.0.2856-linux.zip"
            
        scanner_zip = os.path.join(tempfile.gettempdir(), "sonar-scanner.zip")
        
        if not download_file(scanner_url, scanner_zip):
            raise Exception("Failed to download SonarScanner")
            
        logger.info("Extracting SonarScanner...")
        with zipfile.ZipFile(scanner_zip, 'r') as zip_ref:
            zip_ref.extractall(get_tools_directory())
            
        # Find the extracted directory and move it
        for item in os.listdir(get_tools_directory()):
            item_path = os.path.join(get_tools_directory(), item)
            if os.path.isdir(item_path) and "sonar-scanner" in item.lower() and item_path != self.sonar_scanner_path:
                # Move all contents to sonar_scanner_path
                for subitem in os.listdir(item_path):
                    src = os.path.join(item_path, subitem)
                    dst = os.path.join(self.sonar_scanner_path, subitem)
                    shutil.move(src, dst)
                os.rmdir(item_path)
                
        # Make scripts executable on Linux/Mac
        if system != "windows":
            os.chmod(self.sonarqube_start_script, 0o755)
            os.chmod(self.scanner_bin, 0o755)
            
        # Clean up
        try:
            os.remove(sonarqube_zip)
            os.remove(scanner_zip)
        except:
            pass
            
        return self.check_installation()
        
    def start_server(self):
        """Start the SonarQube server"""
        if not self.check_installation():
            raise Exception("SonarQube is not installed")
            
        if self.is_server_running():
            logger.info("SonarQube server is already running")
            return True
            
        logger.info("Starting SonarQube server...")
        
        system = self._get_system()
        if system == "windows":
            self.server_process = subprocess.Popen([self.sonarqube_start_script])
        else:
            self.server_process = subprocess.Popen([self.sonarqube_start_script, "start"])
            
        # Wait for server to start
        max_attempts = 30
        for i in range(max_attempts):
            logger.info(f"Waiting for SonarQube server to start ({i+1}/{max_attempts})...")
            time.sleep(10)
            if self.is_server_running():
                logger.info("SonarQube server started successfully")
                return True
                
        logger.error("Failed to start SonarQube server")
        return False
        
    def stop_server(self):
        """Stop the SonarQube server"""
        if not self.is_server_running():
            logger.info("SonarQube server is not running")
            return True
            
        logger.info("Stopping SonarQube server...")
        
        system = self._get_system()
        if system == "windows":
            # On Windows, we need to kill the process
            if self.server_process:
                self.server_process.terminate()
                try:
                    self.server_process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.server_process.kill()
        else:
            # On Linux/Mac, use the stop command
            subprocess.run([self.sonarqube_start_script, "stop"])
            
        # Wait for server to stop
        max_attempts = 10
        for i in range(max_attempts):
            time.sleep(3)
            if not self.is_server_running():
                logger.info("SonarQube server stopped successfully")
                return True
                
        logger.warning("Failed to stop SonarQube server gracefully")
        return False
        
    def is_server_running(self):
        """Check if the SonarQube server is running"""
        try:
            response = requests.get(f"{self.server_url}/api/system/status", timeout=5)
            return response.status_code == 200 and response.json().get("status") == "UP"
        except:
            return False
            
    def scan(self, project_path, project_key=None, project_name=None, sources=None, java_binaries=None, additional_params=None):
        """Run a SonarQube scan on a project"""
        if not self.check_installation():
            raise Exception("SonarQube is not installed")
            
        # Ensure server is running
        if not self.is_server_running():
            logger.warning("SonarQube server is not running. Attempting to start it...")
            if not self.start_server():
                raise Exception("Failed to start SonarQube server")
                
        # Generate default project key and name if not provided
        if not project_key:
            project_key = f"project-{int(time.time())}"
            
        if not project_name:
            project_name = os.path.basename(os.path.abspath(project_path))
            
        # Create properties file
        properties_file = os.path.join(project_path, "sonar-project.properties")
        with open(properties_file, 'w') as f:
            f.write(f"sonar.projectKey={project_key}\n")
            f.write(f"sonar.projectName={project_name}\n")
            f.write(f"sonar.host.url={self.server_url}\n")
            f.write(f"sonar.login={self.admin_username}\n")
            f.write(f"sonar.password={self.admin_password}\n")
            
            # Set sources path if provided
            if sources:
                f.write(f"sonar.sources={sources}\n")
                
            # Set Java binaries path if provided
            if java_binaries:
                f.write(f"sonar.java.binaries={java_binaries}\n")
                
            # Add additional parameters
            if additional_params:
                for key, value in additional_params.items():
                    f.write(f"{key}={value}\n")
                    
        # Run scan
        logger.info(f"Running SonarQube scan on {project_path}")
        
        # Build command
        cmd = [self.scanner_bin]
        
        # Run scanner
        result = self.run_command(cmd, cwd=project_path, timeout=3600)  # 1-hour timeout
        
        # Clean up properties file
        try:
            os.remove(properties_file)
        except:
            pass
            
        if result["returncode"] != 0:
            logger.error(f"SonarQube scan failed: {result['stderr']}")
            return {
                "error": "Scan failed",
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
            
        # Get scan results from API
        try:
            issues_response = requests.get(
                f"{self.server_url}/api/issues/search",
                params={"projectKeys": project_key},
                auth=(self.admin_username, self.admin_password)
            )
            
            measures_response = requests.get(
                f"{self.server_url}/api/measures/component",
                params={
                    "component": project_key,
                    "metricKeys": "ncloc,coverage,duplicated_lines_density,bugs,vulnerabilities,code_smells"
                },
                auth=(self.admin_username, self.admin_password)
            )
            
            issues = issues_response.json() if issues_response.status_code == 200 else {}
            measures = measures_response.json() if measures_response.status_code == 200 else {}
            
            return {
                "project_key": project_key,
                "project_name": project_name,
                "scan_time": datetime.datetime.now().isoformat(),
                "issues": issues,
                "measures": measures,
                "dashboard_url": f"{self.server_url}/dashboard?id={project_key}"
            }
            
        except Exception as e:
            logger.error(f"Error retrieving scan results: {str(e)}")
            return {
                "project_key": project_key,
                "project_name": project_name,
                "scan_time": datetime.datetime.now().isoformat(),
                "error": f"Error retrieving scan results: {str(e)}",
                "stdout": result["stdout"],
                "dashboard_url": f"{self.server_url}/dashboard?id={project_key}"
            }

if __name__ == "__main__":
    try:
        # Initialize SonarQube tool
        sonarqube = security_tools_manager.get_tool("SonarQubeCommunity")
        
        # Process command-line arguments
        if len(sys.argv) > 1:
            if sys.argv[1] == "--start":
                sonarqube.start_server()
                print(f"SonarQube server started. Access the web interface at {sonarqube.server_url}")
                print("Default credentials: admin/admin")
                
            elif sys.argv[1] == "--stop":
                sonarqube.stop_server()
                print("SonarQube server stopped")
                
            elif sys.argv[1] == "--scan" and len(sys.argv) > 2:
                project_path = sys.argv[2]
                result = sonarqube.scan(project_path)
                print(f"Scan completed for {result.get('project_name')}")
                print(f"Dashboard URL: {result.get('dashboard_url')}")
                
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 