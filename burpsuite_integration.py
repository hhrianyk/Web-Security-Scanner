#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import subprocess
import shutil
import requests
import zipfile
import tempfile
import time
import datetime
import platform
import json
from typing import Dict, List, Any, Optional, Union

# Import base class from security_tools_integration.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, download_file, security_tools_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("burpsuite_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BurpSuiteIntegration")

@register_tool
class BurpSuiteCommunity(SecurityToolBase):
    """
    Burp Suite Community - A leading web vulnerability scanner and manual testing tool
    
    Features:
    - Web vulnerability scanning
    - HTTP proxy intercept and modify
    - Spider/crawler functionality
    - Manual testing tools
    - Extension support
    """
    
    def __init__(self):
        self.burp_path = os.path.join(get_tools_directory(), "burpsuite")
        self.burp_jar = os.path.join(self.burp_path, "burpsuite_community.jar")
        self.burp_config = os.path.join(self.burp_path, "burp_config.json")
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Burp Suite Community",
            "description": "Web application security testing platform",
            "actions": ["intercept", "crawl", "scan", "manual_testing"],
            "target_types": ["web_application", "api", "http_traffic"],
            "output_formats": ["html", "xml"],
            "dependencies": ["java"]
        }
        
    def check_installation(self):
        """Check if Burp Suite Community is installed"""
        return os.path.exists(self.burp_jar)
        
    def install(self):
        """Install Burp Suite Community"""
        # Check if Java is installed
        java_path = shutil.which("java")
        if not java_path:
            raise Exception("Java is required but not installed")
            
        # Create directory
        os.makedirs(self.burp_path, exist_ok=True)
        
        # Download Burp Suite Community
        system = platform.system().lower()
        
        if system == "windows":
            download_url = "https://portswigger.net/burp/releases/download?product=community&version=latest&type=WindowsX64"
            installer_path = os.path.join(self.burp_path, "burpsuite_community_windows-x64.exe")
        elif system == "darwin":  # macOS
            download_url = "https://portswigger.net/burp/releases/download?product=community&version=latest&type=MacOsx"
            installer_path = os.path.join(self.burp_path, "burpsuite_community_macos.dmg")
        else:  # Linux
            download_url = "https://portswigger.net/burp/releases/download?product=community&version=latest&type=jar"
            installer_path = self.burp_jar
            
        logger.info(f"Downloading Burp Suite Community from {download_url}")
        if not download_file(download_url, installer_path):
            raise Exception("Failed to download Burp Suite Community")
            
        # For JAR version, we're done
        if system == "linux" or installer_path.endswith(".jar"):
            return self.check_installation()
            
        # For Windows and macOS, we need to extract/install
        if system == "windows":
            logger.info("Please run the installer manually: " + installer_path)
            logger.info("After installation, copy the JAR file to: " + self.burp_jar)
        elif system == "darwin":
            logger.info("Please mount the DMG file and install manually: " + installer_path)
            logger.info("After installation, copy the JAR file to: " + self.burp_jar)
            
        return self.check_installation()
        
    def start_gui(self, project_file=None, config_file=None):
        """Start Burp Suite GUI"""
        if not self.check_installation():
            raise Exception("Burp Suite Community is not installed")
            
        # Build command
        cmd = ["java", "-jar", self.burp_jar]
        
        # Add project file if specified
        if project_file:
            cmd.extend(["--project-file", project_file])
            
        # Add config file if specified
        if config_file:
            cmd.extend(["--config-file", config_file])
            
        logger.info("Starting Burp Suite Community GUI")
        subprocess.Popen(cmd)
        
        return {
            "status": "started",
            "message": "Burp Suite Community GUI launched"
        }
        
    def start_headless(self, target_url, project_file=None, config_file=None, output_file=None):
        """Start Burp Suite in headless mode (limited in Community Edition)"""
        if not self.check_installation():
            raise Exception("Burp Suite Community is not installed")
            
        # Create default project file if not specified
        if not project_file:
            project_file = os.path.join(tempfile.gettempdir(), f"burp_project_{int(time.time())}.burp")
            
        # Create default output file if not specified
        if not output_file:
            output_file = os.path.join(tempfile.gettempdir(), f"burp_report_{int(time.time())}.html")
            
        # Create config file if not specified
        if not config_file:
            config_file = self._create_config_file(target_url, output_file)
            
        # Build command (Burp Community has limited headless capabilities)
        cmd = [
            "java", "-jar", self.burp_jar, 
            "--project-file", project_file,
            "--config-file", config_file,
            "--unpause-spider-and-scanner"
        ]
        
        logger.info(f"Starting Burp Suite Community in headless mode for {target_url}")
        logger.warning("Note: Burp Suite Community has limited headless capabilities")
        
        # Run Burp (this will likely require user interaction in Community Edition)
        process = subprocess.Popen(cmd)
        
        return {
            "status": "started",
            "message": "Burp Suite Community headless scan initiated (may require user interaction)",
            "process_id": process.pid,
            "target_url": target_url,
            "project_file": project_file,
            "output_file": output_file
        }
        
    def _create_config_file(self, target_url, output_file):
        """Create a Burp Suite configuration file for headless scanning"""
        config = {
            "target": {
                "scope": {
                    "advanced_mode": False,
                    "include": [
                        {
                            "enabled": True,
                            "host": target_url.replace("https://", "").replace("http://", "").split("/")[0],
                            "protocol": "any",
                            "port": "any"
                        }
                    ]
                }
            },
            "scanner": {
                "active_scanning_engine": {
                    "sensitivity": "normal"
                }
            },
            "misc": {
                "auto_save": True,
                "save_on_exit": True
            }
        }
        
        config_file = os.path.join(tempfile.gettempdir(), f"burp_config_{int(time.time())}.json")
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        return config_file
        
    def configure_proxy(self, host="127.0.0.1", port=8080):
        """Configure Burp proxy and print instructions for browser setup"""
        proxy_instructions = f"""
Burp Suite Proxy Configuration Instructions
==========================================

1. Configure Burp Suite proxy:
   - Open Burp Suite
   - Go to Proxy -> Options
   - Ensure listener is running on {host}:{port}

2. Configure your browser to use proxy:
   - Host: {host}
   - Port: {port}
   - No proxy for: localhost,127.0.0.1

3. Install the Burp CA certificate:
   - In Burp Suite, go to Proxy -> Options -> Import/Export CA certificate
   - Export the certificate in DER format
   - Import the certificate into your browser's trusted root certificates

4. Testing the proxy:
   - Visit https://example.com and check if traffic appears in Burp's Proxy -> HTTP history

Proxy Settings for Different Browsers:
-------------------------------------
* Chrome/Edge: Settings -> Advanced -> System -> Proxy settings
* Firefox: Settings -> Network Settings -> Configure Proxy Access
* Safari: System Preferences -> Network -> Advanced -> Proxies

For Mobile Devices:
------------------
1. Connect to the same network as your Burp proxy
2. Configure proxy settings (typically in WiFi settings)
3. Visit http://{host}:{port} to download and install the certificate
"""
        
        print(proxy_instructions)
        return {
            "status": "success",
            "proxy_host": host,
            "proxy_port": port,
            "instructions": proxy_instructions
        }
        
    def create_project(self, project_file, target_url=None):
        """Create a new Burp Suite project file"""
        if not self.check_installation():
            raise Exception("Burp Suite Community is not installed")
            
        # Ensure directory exists
        project_dir = os.path.dirname(project_file)
        if project_dir and not os.path.exists(project_dir):
            os.makedirs(project_dir, exist_ok=True)
            
        # Build command
        cmd = [
            "java", "-jar", self.burp_jar,
            "--project-file", project_file,
            "--fresh-project"
        ]
        
        if target_url:
            # Create a temporary config file with the target
            config_file = self._create_config_file(target_url, None)
            cmd.extend(["--config-file", config_file])
            
        logger.info(f"Creating new Burp Suite project: {project_file}")
        
        # Start Burp to create the project (user will need to save it)
        subprocess.Popen(cmd)
        
        return {
            "status": "started",
            "message": "Burp Suite launched to create project. Please save the project file.",
            "project_file": project_file
        }
        
    def export_certificate(self, output_file=None):
        """Export the Burp CA certificate"""
        if not self.check_installation():
            raise Exception("Burp Suite Community is not installed")
            
        if not output_file:
            output_file = os.path.join(os.getcwd(), "burp_ca_cert.der")
            
        # Ensure directory exists
        cert_dir = os.path.dirname(output_file)
        if cert_dir and not os.path.exists(cert_dir):
            os.makedirs(cert_dir, exist_ok=True)
            
        logger.info("Please use the following steps to export the Burp CA certificate:")
        certificate_instructions = f"""
Burp Suite CA Certificate Export Instructions
===========================================

1. Open Burp Suite Community
2. Go to Proxy -> Options -> Import/Export CA certificate
3. Select "Certificate in DER format" 
4. Save the certificate to: {output_file}
5. Install this certificate in your browser or system's trusted root certificates
"""
        
        print(certificate_instructions)
        return {
            "status": "instructions_provided",
            "output_file": output_file,
            "instructions": certificate_instructions
        }
        
    def install_extensions(self):
        """Print instructions for installing Burp extensions"""
        extensions_instructions = """
Burp Suite Extensions Installation Instructions
=============================================

1. Open Burp Suite Community
2. Go to the Extensions tab
3. Click on "BApp Store" to browse official extensions
4. Recommended security extensions:
   - Active Scan++
   - AuthMatrix
   - Backslash Powered Scanner
   - Collaborator Everywhere
   - CSP Auditor
   - CSRF Scanner
   - Decoder Improved
   - Detect Dynamic JS
   - GATHER Contacts
   - J2EEScan
   - JavaScript Security
   - Param Miner
   - Retire.js
   - Software Version Reporter
   - Turbo Intruder
   - VulnersFinder

5. To install custom extensions (JAR files):
   - Go to Extensions -> Extensions Settings
   - Click "Add" under "Java Environment"
   - Enter required details and select your JAR file
"""
        
        print(extensions_instructions)
        return {
            "status": "instructions_provided",
            "instructions": extensions_instructions
        }

if __name__ == "__main__":
    try:
        # Initialize Burp Suite tool
        burpsuite = security_tools_manager.get_tool("BurpSuiteCommunity")
        
        # Process command-line arguments
        if len(sys.argv) > 1:
            if sys.argv[1] == "--start":
                burpsuite.start_gui()
                
            elif sys.argv[1] == "--proxy":
                burpsuite.configure_proxy()
                
            elif sys.argv[1] == "--certificate":
                output_file = sys.argv[2] if len(sys.argv) > 2 else None
                burpsuite.export_certificate(output_file)
                
            elif sys.argv[1] == "--extensions":
                burpsuite.install_extensions()
                
            elif sys.argv[1] == "--project" and len(sys.argv) > 2:
                project_file = sys.argv[2]
                target_url = sys.argv[3] if len(sys.argv) > 3 else None
                burpsuite.create_project(project_file, target_url)
                
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 