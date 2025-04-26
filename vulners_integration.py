#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import subprocess
import shutil
import requests
import tempfile
import time
import platform
import re
from typing import Dict, List, Any, Optional, Union

# Add the parent directory to the path to import security_tools_integration
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try to import from security_tools_integration, fall back to security_framework if that fails
try:
    from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, download_file
except ImportError:
    from security_framework import SecurityToolBase, register_tool, get_tools_directory, download_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("vulners_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("VulnersIntegration")


@register_tool
class VulnersScanner(SecurityToolBase):
    """
    Vulners Scanner - A vulnerability scanner with a comprehensive vulnerability database
    
    Features:
    - Software version detection
    - CVE identification
    - Exploit availability information
    - Detailed vulnerability reports
    - Risk scoring
    """
    
    def __init__(self):
        self.api_key = os.environ.get("VULNERS_API_KEY", "")
        self.api_url = "https://vulners.com/api/v3"
        self.scanner_path = os.path.join(get_tools_directory(), "vulners-scanner")
        self.agent_script = os.path.join(self.scanner_path, "vulners-agent.py")
        
        # Python package import check
        try:
            import vulners
            self.vulners_module_available = True
        except ImportError:
            self.vulners_module_available = False
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Vulners Scanner",
            "description": "A vulnerability scanner with a comprehensive vulnerability database",
            "actions": ["scan_host", "search_cve", "get_exploit", "search_vulnerability", "scan_software"],
            "target_types": ["host", "application", "cve", "software"],
            "output_formats": ["json", "text", "html"],
            "dependencies": ["python", "pip"]
        }
        
    def check_installation(self):
        """Check if Vulners Scanner is installed"""
        # Check for Python API
        if self.vulners_module_available:
            return True
            
        # Check for agent script
        if os.path.exists(self.agent_script):
            return True
            
        return False
        
    def install(self):
        """Install Vulners Scanner"""
        # Install Python API
        logger.info("Installing Vulners Python API...")
        api_result = self.run_command([sys.executable, "-m", "pip", "install", "vulners"])
        
        if api_result["returncode"] != 0:
            logger.warning(f"Failed to install Vulners Python API: {api_result['stderr']}")
            
        # Clone the agent repository
        os.makedirs(self.scanner_path, exist_ok=True)
        
        logger.info("Cloning Vulners Scanner repository...")
        result = self.run_command(["git", "clone", "https://github.com/vulnersCom/vulners-scanner.git", self.scanner_path])
        
        if result["returncode"] != 0:
            # Try downloading as zip if git fails
            logger.info("Git clone failed, trying direct download...")
            download_url = "https://github.com/vulnersCom/vulners-scanner/archive/master.zip"
            zip_path = os.path.join(self.scanner_path, "vulners-scanner.zip")
            
            if not download_file(download_url, zip_path):
                raise Exception("Failed to download Vulners Scanner")
                
            # Extract the zip file
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.scanner_path)
                
            # Find the extracted directory
            for item in os.listdir(self.scanner_path):
                item_path = os.path.join(self.scanner_path, item)
                if os.path.isdir(item_path) and "vulners-scanner" in item.lower():
                    # Move contents up one level
                    for subitem in os.listdir(item_path):
                        shutil.move(
                            os.path.join(item_path, subitem),
                            os.path.join(self.scanner_path, subitem)
                        )
                    # Remove the now-empty directory
                    try:
                        os.rmdir(item_path)
                    except:
                        pass
                        
            # Clean up zip file
            try:
                os.remove(zip_path)
            except:
                pass
                
        # Install agent dependencies
        logger.info("Installing Vulners Scanner dependencies...")
        requirements_file = os.path.join(self.scanner_path, "requirements.txt")
        if os.path.exists(requirements_file):
            self.run_command([sys.executable, "-m", "pip", "install", "-r", requirements_file])
            
        # Try import again to check installation
        try:
            import vulners
            self.vulners_module_available = True
        except ImportError:
            self.vulners_module_available = False
            
        return self.check_installation()
        
    def api_request(self, endpoint, method="GET", params=None, data=None):
        """Make a request to the Vulners API"""
        url = f"{self.api_url}/{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=params, headers=headers)
            else:
                response = requests.post(url, json=data, headers=headers)
                
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"API request error: {str(e)}")
            return {"error": str(e)}
            
    def search_cve(self, cve_id):
        """Search for a specific CVE"""
        # Validate CVE ID format
        if not re.match(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
            raise ValueError(f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
            
        # Try using Python API first
        if self.vulners_module_available:
            try:
                import vulners
                vulners_api = vulners.Vulners(api_key=self.api_key)
                cve_data = vulners_api.document(cve_id)
                return cve_data
            except Exception as e:
                logger.warning(f"Vulners API error: {str(e)}")
                
        # Fallback to direct API call
        return self.api_request("search/id", method="POST", data={"id": cve_id})
        
    def search_vulnerability(self, query, limit=10):
        """Search for vulnerabilities by keywords"""
        # Try using Python API first
        if self.vulners_module_available:
            try:
                import vulners
                vulners_api = vulners.Vulners(api_key=self.api_key)
                results = vulners_api.search(query, limit=limit)
                return results
            except Exception as e:
                logger.warning(f"Vulners API error: {str(e)}")
                
        # Fallback to direct API call
        return self.api_request("search/keywords", method="POST", 
                               data={"keywords": query, "size": limit})
        
    def get_exploit(self, bulletin_id):
        """Get exploit details by ID"""
        # Try using Python API first
        if self.vulners_module_available:
            try:
                import vulners
                vulners_api = vulners.Vulners(api_key=self.api_key)
                exploit_data = vulners_api.document(bulletin_id)
                return exploit_data
            except Exception as e:
                logger.warning(f"Vulners API error: {str(e)}")
                
        # Fallback to direct API call
        return self.api_request("search/id", method="POST", data={"id": bulletin_id})
        
    def scan_software(self, name, version):
        """Check vulnerabilities for a specific software version"""
        # Try using Python API first
        if self.vulners_module_available:
            try:
                import vulners
                vulners_api = vulners.Vulners(api_key=self.api_key)
                results = vulners_api.softwareVersion(name, version)
                return results
            except Exception as e:
                logger.warning(f"Vulners API error: {str(e)}")
                
        # Fallback to direct API call
        return self.api_request("burp/software", method="POST", 
                               data={"software": name, "version": version, "type": "software"})
        
    def scan_host(self, target=None, scan_type="fast"):
        """Run a vulnerability scan against a host"""
        if not os.path.exists(self.agent_script):
            raise Exception("Vulners Scanner agent not installed")
            
        # Default to local host if no target specified
        if not target:
            target = "127.0.0.1"
            
        # Create output file
        output_file = os.path.join(tempfile.gettempdir(), f"vulners_scan_{int(time.time())}.json")
        
        # Prepare scan command
        cmd = [
            sys.executable, 
            self.agent_script, 
            "--host", target,
            "--output", output_file
        ]
        
        # Add API key if available
        if self.api_key:
            cmd.extend(["--api-key", self.api_key])
            
        # Add scan type
        if scan_type == "fast":
            cmd.append("--fast")
        elif scan_type == "full":
            cmd.append("--full")
            
        logger.info(f"Running Vulners Scanner against {target}")
        result = self.run_command(cmd)
        
        if result["returncode"] != 0:
            logger.warning(f"Vulners scan failed: {result['stderr']}")
            return {
                "error": "Scan failed",
                "stderr": result["stderr"],
                "stdout": result["stdout"]
            }
            
        # Read output file
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                    
                # Clean up
                os.remove(output_file)
                    
                return {
                    "target": target,
                    "scan_type": scan_type,
                    "results": scan_data
                }
            except Exception as e:
                return {
                    "error": f"Failed to parse scan results: {str(e)}",
                    "stderr": result["stderr"],
                    "stdout": result["stdout"]
                }
        else:
            return {
                "error": "Scan output file not found",
                "stderr": result["stderr"],
                "stdout": result["stdout"]
            }
            
    def search_exploits_for_cve(self, cve_id):
        """Search for exploits related to a specific CVE"""
        # Validate CVE ID format
        if not re.match(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
            raise ValueError(f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
            
        # Try using Python API first
        if self.vulners_module_available:
            try:
                import vulners
                vulners_api = vulners.Vulners(api_key=self.api_key)
                exploits = vulners_api.searchExploit(cve_id)
                return {
                    "cve_id": cve_id,
                    "exploits": exploits,
                    "count": len(exploits)
                }
            except Exception as e:
                logger.warning(f"Vulners API error: {str(e)}")
                
        # Fallback to direct API call
        exploits_data = self.api_request("search/id", method="POST", data={
            "id": cve_id,
            "references": True,
            "fields": ["bulletinFamily", "title", "description", "published", "type", "sourceHref"]
        })
        
        if "data" in exploits_data and "documents" in exploits_data["data"]:
            documents = exploits_data["data"]["documents"]
            
            # Filter for exploit-type documents
            exploits = [doc for doc in documents.values() 
                       if doc.get("bulletinFamily") in ["exploit", "metasploit"]]
            
            return {
                "cve_id": cve_id,
                "exploits": exploits,
                "count": len(exploits)
            }
        
        return {
            "cve_id": cve_id,
            "exploits": [],
            "count": 0,
            "error": "No exploits found or API error"
        }
        
    def audit_package(self, package_name, package_version=None, os_name=None, os_version=None):
        """Check vulnerabilities for a specific package"""
        # Try using Python API first
        if self.vulners_module_available:
            try:
                import vulners
                vulners_api = vulners.Vulners(api_key=self.api_key)
                
                if os_name and os_version:
                    # OS package audit
                    results = vulners_api.audit(os=os_name, version=os_version, 
                                              package=package_name, packageVersion=package_version)
                else:
                    # Generic package audit
                    results = vulners_api.softwareVersion(package_name, package_version)
                    
                return {
                    "package": package_name,
                    "version": package_version,
                    "os": os_name,
                    "os_version": os_version,
                    "results": results
                }
            except Exception as e:
                logger.warning(f"Vulners API error: {str(e)}")
                
        # Fallback to direct API call
        data = {
            "software": package_name,
            "version": package_version or ""
        }
        
        if os_name and os_version:
            data["os"] = os_name
            data["osVersion"] = os_version
            endpoint = "audit/audit"
        else:
            endpoint = "burp/software"
            
        api_results = self.api_request(endpoint, method="POST", data=data)
        
        return {
            "package": package_name,
            "version": package_version,
            "os": os_name,
            "os_version": os_version,
            "results": api_results
        }
        
    def scan_multi_packages(self, packages):
        """Check vulnerabilities for multiple packages at once"""
        # packages should be a list of dicts with name, version, os, os_version
        results = {}
        
        for package in packages:
            name = package.get("name")
            version = package.get("version")
            os_name = package.get("os")
            os_version = package.get("os_version")
            
            if name:
                results[name] = self.audit_package(name, version, os_name, os_version)
                
        return results 