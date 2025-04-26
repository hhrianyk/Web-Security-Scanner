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
import re
import platform
from typing import Dict, List, Any, Optional, Union

# Add the parent directory to the path to import security_tools_integration
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from the security tools integration
from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nessus_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NessusIntegration")


@register_tool
class NessusScanner(SecurityToolBase):
    """
    Nessus - Professional vulnerability scanner with an extensive database of checks
    
    Features:
    - Comprehensive vulnerability scanning
    - Service detection
    - Compliance auditing
    - Web application scanning
    - Detailed reporting
    """
    
    def __init__(self):
        self.api_url = os.environ.get("NESSUS_API_URL", "https://localhost:8834")
        self.access_key = os.environ.get("NESSUS_ACCESS_KEY", "")
        self.secret_key = os.environ.get("NESSUS_SECRET_KEY", "")
        self.username = os.environ.get("NESSUS_USERNAME", "")
        self.password = os.environ.get("NESSUS_PASSWORD", "")
        self.verify_ssl = os.environ.get("NESSUS_VERIFY_SSL", "False").lower() in ("true", "1", "yes")
        self.token = None
        
        # Nessus paths
        self.nessus_bin = None
        self.nessus_service = None
        self.nessuscli_bin = None
        
        # Detect platform-specific paths
        if platform.system() == "Windows":
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            self.nessus_bin = os.path.join(program_files, "Tenable\\Nessus", "nessus.exe")
            self.nessus_service = "Tenable Nessus"
            self.nessuscli_bin = os.path.join(program_files, "Tenable\\Nessus", "nessuscli.exe")
        elif platform.system() == "Darwin":  # macOS
            self.nessus_bin = "/Applications/Nessus/run/sbin/nessusd"
            self.nessus_service = "com.tenablesecurity.nessusd"
            self.nessuscli_bin = "/Applications/Nessus/run/sbin/nessuscli"
        else:  # Linux and others
            self.nessus_bin = "/opt/nessus/sbin/nessusd"
            self.nessus_service = "nessusd"
            self.nessuscli_bin = "/opt/nessus/sbin/nessuscli"
            
        # Check if binaries exist, otherwise try to find them in PATH
        if not os.path.exists(self.nessuscli_bin):
            self.nessuscli_bin = shutil.which("nessuscli")
            
        if not os.path.exists(self.nessus_bin):
            self.nessus_bin = shutil.which("nessusd")
            
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Nessus Scanner",
            "description": "Professional vulnerability scanner with an extensive database of checks",
            "actions": ["scan", "get_scan_results", "list_plugins", "list_policies", "create_scan"],
            "target_types": ["host", "network", "web_application"],
            "output_formats": ["json", "html", "pdf", "csv", "nessus"],
            "dependencies": []
        }
        
    def check_installation(self):
        """Check if Nessus is installed"""
        # Check for the Nessus binary
        if self.nessuscli_bin and os.path.exists(self.nessuscli_bin):
            return True
            
        # Check if the service exists
        if platform.system() == "Windows":
            try:
                result = self.run_command(["sc", "query", self.nessus_service])
                return result["returncode"] == 0 and "STATE" in result["stdout"]
            except:
                pass
        elif platform.system() == "Darwin":  # macOS
            try:
                result = self.run_command(["launchctl", "list", self.nessus_service])
                return result["returncode"] == 0
            except:
                pass
        else:  # Linux
            try:
                result = self.run_command(["systemctl", "status", self.nessus_service])
                return result["returncode"] == 0
            except:
                try:
                    result = self.run_command(["service", self.nessus_service, "status"])
                    return result["returncode"] == 0
                except:
                    pass
                    
        return False
        
    def install(self):
        """Install Nessus - only provides instructions as this requires manual download"""
        logger.info("Nessus installation requires manual download from Tenable website")
        logger.info("Please visit: https://www.tenable.com/downloads/nessus")
        logger.info("After installation, set the following environment variables:")
        logger.info("  NESSUS_API_URL - URL to the Nessus server (default: https://localhost:8834)")
        logger.info("  NESSUS_USERNAME - Nessus username")
        logger.info("  NESSUS_PASSWORD - Nessus password")
        logger.info("  Or use API keys:")
        logger.info("  NESSUS_ACCESS_KEY - Nessus API access key")
        logger.info("  NESSUS_SECRET_KEY - Nessus API secret key")
        
        return False  # Cannot automatically install
        
    def api_request(self, endpoint, method="GET", params=None, data=None, files=None):
        """Make a request to the Nessus API"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        headers = {"Accept": "application/json"}
        
        # Add auth headers
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key}; secretKey={self.secret_key}"
        elif self.token:
            headers["X-Cookie"] = f"token={self.token}"
            
        try:
            # Make the request
            if method.upper() == "GET":
                response = requests.get(url, params=params, headers=headers, verify=self.verify_ssl)
            elif method.upper() == "POST":
                headers["Content-Type"] = "application/json"
                response = requests.post(url, params=params, json=data, headers=headers, files=files, verify=self.verify_ssl)
            elif method.upper() == "PUT":
                headers["Content-Type"] = "application/json"
                response = requests.put(url, params=params, json=data, headers=headers, verify=self.verify_ssl)
            elif method.upper() == "DELETE":
                response = requests.delete(url, params=params, headers=headers, verify=self.verify_ssl)
            else:
                return {"error": f"Unsupported method: {method}"}
                
            response.raise_for_status()
            
            # Handle empty responses
            if not response.content:
                return {"status": "success"}
                
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return {"error": str(e)}
            
    def login(self):
        """Authenticate with the Nessus API"""
        # Skip if using API keys
        if self.access_key and self.secret_key:
            return True
            
        # Check if we have credentials
        if not self.username or not self.password:
            logger.error("Nessus username and password not provided")
            return False
            
        try:
            # Authenticate with the API
            response = self.api_request("session", method="POST", data={
                "username": self.username,
                "password": self.password
            })
            
            if "token" in response:
                self.token = response["token"]
                return True
            else:
                logger.error(f"Authentication failed: {response.get('error', 'Unknown error')}")
                return False
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
            
    def get_server_status(self):
        """Get the status of the Nessus server"""
        return self.api_request("server/status")
        
    def list_scans(self):
        """List all scans"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        return self.api_request("scans")
        
    def get_scan_details(self, scan_id):
        """Get details for a specific scan"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        return self.api_request(f"scans/{scan_id}")
        
    def create_scan(self, name, targets, policy_id=None, folder_id=None, description=None):
        """Create a new scan"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        # Build scan settings
        scan_data = {
            "uuid": policy_id or "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66",  # Default to basic network scan
            "settings": {
                "name": name,
                "text_targets": targets
            }
        }
        
        if folder_id:
            scan_data["folder_id"] = folder_id
            
        if description:
            scan_data["description"] = description
            
        return self.api_request("scans", method="POST", data=scan_data)
        
    def launch_scan(self, scan_id, targets=None):
        """Launch an existing scan, optionally with new targets"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        data = {}
        if targets:
            data["alt_targets"] = targets.split(",")
            
        return self.api_request(f"scans/{scan_id}/launch", method="POST", data=data)
        
    def get_scan_status(self, scan_id):
        """Check the status of a scan"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        details = self.get_scan_details(scan_id)
        
        if "info" in details and "status" in details["info"]:
            status = details["info"]["status"]
            return {
                "scan_id": scan_id,
                "status": status,
                "is_running": status in ["running", "processing"],
                "details": details
            }
        else:
            return {"error": "Failed to get scan status", "details": details}
            
    def stop_scan(self, scan_id):
        """Stop a running scan"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        return self.api_request(f"scans/{scan_id}/stop", method="POST")
        
    def export_scan_results(self, scan_id, format="nessus", chapters="vuln_hosts_summary"):
        """Export scan results in the specified format"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        # Validate format
        valid_formats = ["nessus", "html", "pdf", "csv", "db"]
        if format not in valid_formats:
            return {"error": f"Invalid format. Must be one of: {', '.join(valid_formats)}"}
            
        # Request export
        response = self.api_request(f"scans/{scan_id}/export", method="POST", data={
            "format": format,
            "chapters": chapters
        })
        
        if "error" in response:
            return response
            
        # Get file ID
        if "file" not in response:
            return {"error": "Export failed, no file ID returned"}
            
        file_id = response["file"]
        
        # Wait for export to complete
        for _ in range(60):  # Wait up to 5 minutes
            status = self.api_request(f"scans/{scan_id}/export/{file_id}/status")
            
            if "status" in status and status["status"] == "ready":
                break
                
            time.sleep(5)
        else:
            return {"error": "Export timed out"}
            
        # Download the exported file
        temp_file = os.path.join(tempfile.gettempdir(), f"nessus_export_{scan_id}_{int(time.time())}.{format}")
        
        download = self.api_request(f"scans/{scan_id}/export/{file_id}/download", params={"token": self.token})
        
        # Write to file
        try:
            if "content" in download:
                with open(temp_file, "wb") as f:
                    f.write(download["content"])
            else:
                # Try direct download
                response = requests.get(f"{self.api_url}/scans/{scan_id}/export/{file_id}/download",
                                     headers={"X-Cookie": f"token={self.token}"}, verify=self.verify_ssl)
                response.raise_for_status()
                
                with open(temp_file, "wb") as f:
                    f.write(response.content)
                    
            return {"file_path": temp_file, "status": "success"}
        except Exception as e:
            logger.error(f"Export download error: {str(e)}")
            return {"error": f"Failed to download export: {str(e)}"}
            
    def list_plugins(self, family_id=None):
        """List available plugins, optionally filtered by family"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        if family_id:
            return self.api_request(f"plugins/families/{family_id}")
        else:
            return self.api_request("plugins/families")
            
    def get_plugin_details(self, plugin_id):
        """Get detailed information about a specific plugin"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        return self.api_request(f"plugins/plugin/{plugin_id}")
        
    def list_policies(self):
        """List available scan policies"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        return self.api_request("policies")
        
    def get_policy_details(self, policy_id):
        """Get detailed information about a scan policy"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        return self.api_request(f"policies/{policy_id}")
        
    def search_vulnerabilities(self, query):
        """Search for vulnerabilities in the Nessus database"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        # This is a limited feature - Nessus doesn't have a dedicated vulnerability search API
        # This attempts to use the plugin search functionality as a proxy
        return self.api_request("plugins/search", params={"q": query})
        
    def start_service(self):
        """Start the Nessus service"""
        if not self.check_installation():
            return {"error": "Nessus is not installed"}
            
        if platform.system() == "Windows":
            result = self.run_command(["sc", "start", self.nessus_service])
        elif platform.system() == "Darwin":  # macOS
            result = self.run_command(["launchctl", "load", f"/Library/LaunchDaemons/{self.nessus_service}.plist"])
        else:  # Linux
            if os.path.exists("/bin/systemctl"):
                result = self.run_command(["systemctl", "start", self.nessus_service])
            else:
                result = self.run_command(["service", self.nessus_service, "start"])
                
        return {
            "status": "success" if result["returncode"] == 0 else "error",
            "message": "Service started" if result["returncode"] == 0 else "Failed to start service",
            "output": result["stdout"],
            "error": result["stderr"]
        }
        
    def stop_service(self):
        """Stop the Nessus service"""
        if not self.check_installation():
            return {"error": "Nessus is not installed"}
            
        if platform.system() == "Windows":
            result = self.run_command(["sc", "stop", self.nessus_service])
        elif platform.system() == "Darwin":  # macOS
            result = self.run_command(["launchctl", "unload", f"/Library/LaunchDaemons/{self.nessus_service}.plist"])
        else:  # Linux
            if os.path.exists("/bin/systemctl"):
                result = self.run_command(["systemctl", "stop", self.nessus_service])
            else:
                result = self.run_command(["service", self.nessus_service, "stop"])
                
        return {
            "status": "success" if result["returncode"] == 0 else "error",
            "message": "Service stopped" if result["returncode"] == 0 else "Failed to stop service",
            "output": result["stdout"],
            "error": result["stderr"]
        }
        
    def scan(self, targets, name=None, wait_for_completion=False, policy_id=None):
        """Run a vulnerability scan against the specified targets"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        # Create a descriptive name if not provided
        if not name:
            name = f"Scan of {targets} - {time.strftime('%Y-%m-%d %H:%M:%S')}"
            
        # Create the scan
        scan_result = self.create_scan(name, targets, policy_id)
        
        if "error" in scan_result:
            return scan_result
            
        # Extract scan ID
        if "scan" not in scan_result or "id" not in scan_result["scan"]:
            return {"error": "Failed to create scan", "details": scan_result}
            
        scan_id = scan_result["scan"]["id"]
        
        # Launch the scan
        launch_result = self.launch_scan(scan_id)
        
        if "error" in launch_result:
            return launch_result
            
        # Get initial status
        status = self.get_scan_status(scan_id)
        
        # Wait for completion if requested
        if wait_for_completion:
            while status.get("is_running", False):
                logger.info(f"Scan {scan_id} is still running. Waiting...")
                time.sleep(30)
                status = self.get_scan_status(scan_id)
                
            # Export results
            export_result = self.export_scan_results(scan_id, format="json")
            status["export"] = export_result
            
        return {
            "scan_id": scan_id,
            "name": name,
            "targets": targets,
            "status": status,
            "message": "Scan launched successfully"
        }
        
    def get_scan_results(self, scan_id, format="json"):
        """Get the results of a completed scan"""
        if not self.login():
            return {"error": "Authentication failed"}
            
        # Check if scan is complete
        status = self.get_scan_status(scan_id)
        
        if status.get("is_running", False):
            return {"error": "Scan is still running", "status": status}
            
        # Export and download results
        export_result = self.export_scan_results(scan_id, format=format)
        
        if "error" in export_result:
            return export_result
            
        # If JSON format, parse the file and return the content
        if format == "json" and "file_path" in export_result:
            try:
                with open(export_result["file_path"], 'r') as f:
                    results = json.load(f)
                    
                return {
                    "scan_id": scan_id,
                    "status": "success",
                    "results": results
                }
            except Exception as e:
                return {"error": f"Failed to parse results: {str(e)}"}
        
        # For other formats, just return the file path
        return {
            "scan_id": scan_id,
            "status": "success",
            "file_path": export_result.get("file_path"),
            "format": format
        } 