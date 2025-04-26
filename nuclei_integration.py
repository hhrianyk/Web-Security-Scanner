#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import subprocess
import shutil
import platform
import tempfile
import time
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
        logging.FileHandler("nuclei_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NucleiIntegration")


@register_tool
class NucleiScanner(SecurityToolBase):
    """
    Nuclei - Fast and customizable vulnerability scanner with a vast template library
    
    Features:
    - Fast, template-based scanning
    - Extensive vulnerability template collection
    - Custom template support
    - Highly configurable scanning options
    - Low false positive rate
    """
    
    def __init__(self):
        self.nuclei_bin = shutil.which("nuclei")
        self.nuclei_path = os.path.join(get_tools_directory(), "nuclei")
        self.templates_path = os.path.join(self.nuclei_path, "templates")
        
        # Detect platform for binary download
        self.system = platform.system().lower()
        self.machine = platform.machine().lower()
        
        # Map architecture to GitHub release naming
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "i386": "386",
            "i686": "386",
            "arm64": "arm64",
            "armv8": "arm64",
            "armv7": "arm",
            "armv6": "arm"
        }
        
        self.arch = arch_map.get(self.machine, self.machine)
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Nuclei Scanner",
            "description": "Fast and customizable vulnerability scanner with a vast template library",
            "actions": ["scan", "list_templates", "update_templates", "info", "scan_with_templates"],
            "target_types": ["host", "network", "web_application", "api"],
            "output_formats": ["json", "text", "markdown", "csv", "html"],
            "dependencies": []
        }
        
    def check_installation(self):
        """Check if Nuclei is installed"""
        if self.nuclei_bin:
            return True
            
        # Check custom installation path
        nuclei_bin_path = os.path.join(self.nuclei_path, "nuclei")
        if platform.system() == "Windows":
            nuclei_bin_path += ".exe"
            
        if os.path.exists(nuclei_bin_path):
            self.nuclei_bin = nuclei_bin_path
            return True
            
        return False
        
    def install(self):
        """Install Nuclei"""
        os.makedirs(self.nuclei_path, exist_ok=True)
        
        # Determine download URL based on system and architecture
        if self.system == "windows":
            binary_name = "nuclei_windows_{}.zip".format(self.arch)
        elif self.system == "darwin":  # macOS
            binary_name = "nuclei_darwin_{}.zip".format(self.arch)
        else:  # Linux and others
            binary_name = "nuclei_linux_{}.tar.gz".format(self.arch)
            
        # Get latest release information from GitHub
        logger.info("Finding latest Nuclei release...")
        try:
            import requests
            response = requests.get("https://api.github.com/repos/projectdiscovery/nuclei/releases/latest")
            response.raise_for_status()
            
            release_data = response.json()
            version = release_data["tag_name"]
            
            # Find the correct asset
            download_url = None
            for asset in release_data["assets"]:
                if asset["name"] == binary_name:
                    download_url = asset["browser_download_url"]
                    break
                    
            if not download_url:
                raise Exception(f"Could not find download for {binary_name} in release {version}")
                
        except Exception as e:
            logger.error(f"Failed to get latest release info: {str(e)}")
            logger.info("Using hardcoded download URL for Nuclei...")
            
            # Fallback to a hardcoded version if GitHub API fails
            version = "v2.9.4"  # Update this as needed
            download_url = f"https://github.com/projectdiscovery/nuclei/releases/download/{version}/{binary_name}"
            
        # Download the binary
        logger.info(f"Downloading Nuclei {version} from {download_url}")
        downloaded_file = os.path.join(self.nuclei_path, binary_name)
        
        if not download_file(download_url, downloaded_file):
            raise Exception("Failed to download Nuclei")
            
        # Extract the archive
        logger.info("Extracting Nuclei binary...")
        if self.system == "windows" or self.system == "darwin":
            import zipfile
            with zipfile.ZipFile(downloaded_file, 'r') as zip_ref:
                zip_ref.extractall(self.nuclei_path)
        else:
            import tarfile
            with tarfile.open(downloaded_file, 'r:gz') as tar_ref:
                tar_ref.extractall(self.nuclei_path)
                
        # Make the binary executable on Unix systems
        nuclei_bin_path = os.path.join(self.nuclei_path, "nuclei")
        if self.system == "windows":
            nuclei_bin_path += ".exe"
            
        if self.system != "windows":
            os.chmod(nuclei_bin_path, 0o755)
            
        self.nuclei_bin = nuclei_bin_path
        
        # Download templates
        logger.info("Updating Nuclei templates...")
        self.update_templates()
        
        # Clean up the downloaded archive
        try:
            os.remove(downloaded_file)
        except:
            pass
            
        return self.check_installation()
        
    def update_templates(self):
        """Update Nuclei templates"""
        if not self.check_installation():
            raise Exception("Nuclei is not installed")
            
        logger.info("Updating Nuclei templates...")
        
        result = self.run_command([self.nuclei_bin, "-update-templates"])
        
        return {
            "success": result["returncode"] == 0,
            "output": result["stdout"],
            "error": result["stderr"]
        }
        
    def list_templates(self, tags=None, authors=None, severities=None):
        """List available Nuclei templates"""
        if not self.check_installation():
            raise Exception("Nuclei is not installed")
            
        cmd = [self.nuclei_bin, "-tl"]
        
        if tags:
            cmd.extend(["-tags", tags])
            
        if authors:
            cmd.extend(["-author", authors])
            
        if severities:
            cmd.extend(["-severity", severities])
            
        result = self.run_command(cmd)
        
        if result["returncode"] != 0:
            logger.warning(f"Template listing failed: {result['stderr']}")
            
        # Parse the output to extract template information
        templates = []
        current_template = {}
        
        for line in result["stdout"].splitlines():
            line = line.strip()
            
            if line.startswith("Template ID:"):
                # Start of a new template
                if current_template:
                    templates.append(current_template)
                    
                current_template = {"id": line.split("Template ID:")[1].strip()}
            elif ":" in line and current_template:
                # Template attributes
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                
                if key in ["tags", "authors"]:
                    # Split comma-separated values
                    current_template[key] = [tag.strip() for tag in value.split(",")]
                else:
                    current_template[key] = value
                    
        # Add the last template
        if current_template:
            templates.append(current_template)
            
        return {
            "templates": templates,
            "count": len(templates)
        }
        
    def info(self):
        """Get information about Nuclei installation"""
        if not self.check_installation():
            raise Exception("Nuclei is not installed")
            
        # Get version information
        version_result = self.run_command([self.nuclei_bin, "-version"])
        version = "unknown"
        
        if version_result["returncode"] == 0:
            version_match = re.search(r"version (\S+)", version_result["stdout"])
            if version_match:
                version = version_match.group(1)
                
        # Get template statistics
        stats_result = self.run_command([self.nuclei_bin, "-template-stats"])
        stats = {}
        
        if stats_result["returncode"] == 0:
            # Parse the template statistics output
            for line in stats_result["stdout"].splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    stats[key.strip().lower().replace(" ", "_")] = value.strip()
                    
        return {
            "version": version,
            "binary_path": self.nuclei_bin,
            "templates_path": self.templates_path,
            "template_stats": stats,
            "system": self.system,
            "architecture": self.arch
        }
        
    def scan(self, targets, options=None, output_file=None, output_format="json"):
        """Run a Nuclei scan with specified options"""
        if not self.check_installation():
            raise Exception("Nuclei is not installed")
            
        # Prepare targets
        if isinstance(targets, list):
            targets_file = os.path.join(tempfile.gettempdir(), f"nuclei_targets_{int(time.time())}.txt")
            with open(targets_file, 'w') as f:
                f.write("\n".join(targets))
            target_arg = ["-l", targets_file]
        else:
            target_arg = ["-u", targets]
            targets_file = None
            
        # Prepare output file
        if not output_file:
            output_file = os.path.join(tempfile.gettempdir(), f"nuclei_scan_{int(time.time())}.{output_format}")
            
        # Prepare command
        cmd = [self.nuclei_bin] + target_arg + ["-o", output_file]
        
        # Add output format
        if output_format == "json":
            cmd.append("-json")
        elif output_format == "markdown":
            cmd.append("-markdown")
        elif output_format == "csv":
            cmd.append("-csv")
        elif output_format == "html":
            cmd.append("-html")
            
        # Add additional options
        if options:
            for option, value in options.items():
                if option.startswith('-'):
                    option_name = option
                else:
                    option_name = f"-{option}"
                    
                if isinstance(value, bool):
                    if value:
                        cmd.append(option_name)
                elif value is not None:
                    cmd.append(option_name)
                    cmd.append(str(value))
                    
        # Run the scan
        logger.info(f"Running Nuclei scan against {targets}")
        result = self.run_command(cmd)
        
        # Clean up targets file if created
        if targets_file:
            try:
                os.remove(targets_file)
            except:
                pass
                
        # Parse the output file
        scan_results = {"targets": targets}
        
        if result["returncode"] != 0:
            logger.warning(f"Nuclei scan failed: {result['stderr']}")
            scan_results["error"] = result["stderr"]
            scan_results["stdout"] = result["stdout"]
            scan_results["status"] = "error"
        else:
            scan_results["status"] = "success"
            scan_results["output_file"] = output_file
            scan_results["output_format"] = output_format
            
            # Parse JSON output if available
            if output_format == "json" and os.path.exists(output_file):
                try:
                    vulnerabilities = []
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                vuln = json.loads(line)
                                vulnerabilities.append(vuln)
                            except:
                                continue
                                
                    scan_results["vulnerabilities"] = vulnerabilities
                    scan_results["vulnerability_count"] = len(vulnerabilities)
                    
                except Exception as e:
                    logger.error(f"Failed to parse JSON output: {str(e)}")
                    scan_results["error"] = f"Failed to parse results: {str(e)}"
                    
        return scan_results
        
    def scan_with_templates(self, targets, templates=None, severities=None, tags=None, exclude_tags=None, output_format="json"):
        """Run a Nuclei scan with specific templates or tags"""
        options = {}
        
        if templates:
            if isinstance(templates, list):
                options["t"] = ",".join(templates)
            else:
                options["t"] = templates
                
        if severities:
            if isinstance(severities, list):
                options["severity"] = ",".join(severities)
            else:
                options["severity"] = severities
                
        if tags:
            if isinstance(tags, list):
                options["tags"] = ",".join(tags)
            else:
                options["tags"] = tags
                
        if exclude_tags:
            if isinstance(exclude_tags, list):
                options["exclude-tags"] = ",".join(exclude_tags)
            else:
                options["exclude-tags"] = exclude_tags
                
        return self.scan(targets, options, output_format=output_format)
        
    def find_vulnerabilities(self, target, severity="medium,high,critical", rate_limit=100):
        """Find vulnerabilities in a target with specified severity"""
        options = {
            "severity": severity,
            "rate-limit": rate_limit,
            "stats": True,
            "silent": True
        }
        
        return self.scan(target, options)
        
    def extract_vulnerabilities(self, scan_results):
        """Extract vulnerability details from scan results"""
        vulnerabilities = []
        
        if "vulnerabilities" in scan_results:
            for vuln in scan_results["vulnerabilities"]:
                vulnerability = {
                    "name": vuln.get("info", {}).get("name"),
                    "severity": vuln.get("info", {}).get("severity"),
                    "type": vuln.get("type"),
                    "host": vuln.get("host"),
                    "ip": vuln.get("ip"),
                    "url": vuln.get("matched", ""),
                    "description": vuln.get("info", {}).get("description", ""),
                    "tags": vuln.get("info", {}).get("tags", []),
                    "timestamp": vuln.get("timestamp", "")
                }
                
                vulnerabilities.append(vulnerability)
                
        return vulnerabilities 