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
        logging.FileHandler("metasploit_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MetasploitIntegration")


@register_tool
class MetasploitExploitDB(SecurityToolBase):
    """
    Metasploit Framework - An exploitation framework with an extensive database of public exploits
    
    Features:
    - Comprehensive exploit collection
    - Automated exploitation
    - Exploit development tools
    - Vulnerability verification
    - Post-exploitation modules
    """
    
    def __init__(self):
        self.msf_path = None  # Path to Metasploit installation
        self.msfconsole_path = shutil.which("msfconsole")
        self.msfvenom_path = shutil.which("msfvenom")
        self.msfdb_path = shutil.which("msfdb")
        
        # If msfconsole found in PATH, determine the installation directory
        if self.msfconsole_path:
            self.msf_path = os.path.dirname(os.path.dirname(self.msfconsole_path))
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Metasploit Framework",
            "description": "A framework for developing, testing, and using exploit code",
            "actions": ["exploit_search", "run_exploit", "list_modules", "vulnerability_verification", "payload_generation"],
            "target_types": ["host", "network", "application", "os", "service"],
            "output_formats": ["json", "xml", "text"],
            "dependencies": ["ruby"]
        }
        
    def check_installation(self):
        """Check if Metasploit is installed"""
        return self.msfconsole_path is not None and self.msfvenom_path is not None
        
    def install(self):
        """Install Metasploit"""
        system = platform.system().lower()
        
        # Metasploit installation varies significantly by platform
        if system == "windows":
            logger.info("Please install Metasploit for Windows from https://windows.metasploit.com/")
            return False
        elif system == "darwin":  # macOS
            logger.info("Installing Metasploit on macOS...")
            return self.run_command(["brew", "install", "metasploit"])["returncode"] == 0
        else:  # Linux
            logger.info("Installing Metasploit on Linux...")
            
            # Try the installer script
            installer_cmd = "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
            
            install_result = self.run_command(installer_cmd, shell=True, timeout=1800)
            
            if install_result["returncode"] == 0:
                # Update paths after installation
                self.msfconsole_path = shutil.which("msfconsole")
                self.msfvenom_path = shutil.which("msfvenom")
                self.msfdb_path = shutil.which("msfdb")
                
                if self.msfconsole_path:
                    self.msf_path = os.path.dirname(os.path.dirname(self.msfconsole_path))
                    
                # Initialize the database
                self.run_command([self.msfdb_path, "init"])
                    
                return True
                
            # Try apt for Debian/Ubuntu
            apt_result = self.run_command(["apt-get", "update", "&&", "apt-get", "install", "-y", "metasploit-framework"], shell=True)
            if apt_result["returncode"] == 0:
                self.msfconsole_path = shutil.which("msfconsole")
                self.msfvenom_path = shutil.which("msfvenom")
                self.msfdb_path = shutil.which("msfdb")
                
                if self.msfconsole_path:
                    self.msf_path = os.path.dirname(os.path.dirname(self.msfconsole_path))
                    
                # Initialize the database
                self.run_command([self.msfdb_path, "init"])
                    
                return True
                
            return False
    
    def run_rc_script(self, script_content, output_file=None):
        """Run a Metasploit resource script"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Create temporary resource script
        script_file = os.path.join(tempfile.gettempdir(), f"msf_script_{int(time.time())}.rc")
        with open(script_file, 'w') as f:
            f.write(script_content)
            
        # Create output file if specified
        output_redirect = ""
        if output_file:
            output_redirect = f" > {output_file} 2>&1"
            
        # Run the resource script
        cmd = f"{self.msfconsole_path} -q -r {script_file}{output_redirect}"
        
        logger.info(f"Running Metasploit resource script")
        result = self.run_command(cmd, shell=True, timeout=1800)  # 30-minute timeout
        
        # Clean up script file
        try:
            os.remove(script_file)
        except:
            pass
            
        # Read output file if created
        output = None
        if output_file and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()
                
        return {
            "returncode": result["returncode"],
            "output": output or result["stdout"],
            "error": result["stderr"]
        }
    
    def search_exploits(self, search_term, type_filter=None):
        """Search Metasploit's exploit database"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Prepare search command
        search_cmd = f"search {search_term}"
        if type_filter:
            search_cmd += f" type:{type_filter}"
            
        # Create resource script for search
        script_content = f"""
        {search_cmd}
        exit
        """
        
        output_file = os.path.join(tempfile.gettempdir(), f"msf_search_{int(time.time())}.txt")
        
        result = self.run_rc_script(script_content, output_file)
        
        # Parse search results
        modules = []
        if "output" in result and result["output"]:
            for line in result["output"].splitlines():
                if " - " in line:
                    try:
                        # Parse module name and description
                        parts = line.split(" - ", 1)
                        if len(parts) == 2:
                            module_path = parts[0].strip()
                            module_desc = parts[1].strip()
                            
                            # Skip non-module lines
                            if module_path.startswith("#") or module_path.startswith("="):
                                continue
                                
                            modules.append({
                                "path": module_path,
                                "description": module_desc
                            })
                    except:
                        pass
        
        return {
            "search_term": search_term,
            "type_filter": type_filter,
            "modules": modules,
            "count": len(modules)
        }
    
    def search_cve(self, cve_id):
        """Search Metasploit's exploit database for a specific CVE"""
        return self.search_exploits(cve_id, "exploit")
    
    def get_exploit_info(self, exploit_path):
        """Get detailed information about a specific exploit"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Create resource script to get info about the exploit
        script_content = f"""
        use {exploit_path}
        info
        exit
        """
        
        output_file = os.path.join(tempfile.gettempdir(), f"msf_info_{int(time.time())}.txt")
        
        result = self.run_rc_script(script_content, output_file)
        
        # Parse exploit info
        info = {}
        if "output" in result and result["output"]:
            current_section = "general"
            info["general"] = []
            
            for line in result["output"].splitlines():
                line = line.strip()
                
                # Skip empty lines and dividers
                if not line or line.startswith("="):
                    continue
                    
                # Check for section headers
                if line.endswith(":") and line[0].isupper():
                    current_section = line.rstrip(":").lower()
                    info[current_section] = []
                else:
                    # Add line to current section
                    if current_section in info:
                        info[current_section].append(line)
                        
            # Process sections that contain key-value pairs
            for section, lines in info.items():
                if section in ["options", "required", "advanced", "evasion"]:
                    options = []
                    headers = None
                    
                    for line in lines:
                        if "Name" in line and "Current Setting" in line and "Required" in line:
                            headers = [h.strip() for h in line.split("  ") if h.strip()]
                        elif headers and line:
                            # Split line based on whitespace, preserving at least the number of headers
                            parts = []
                            remaining = line
                            for i in range(len(headers)-1):
                                if "  " in remaining:
                                    part, remaining = remaining.split("  ", 1)
                                    parts.append(part.strip())
                                else:
                                    parts.append(remaining.strip())
                                    remaining = ""
                            if remaining:
                                parts.append(remaining.strip())
                                
                            if len(parts) >= len(headers):
                                option = {headers[i]: parts[i] for i in range(len(headers))}
                                options.append(option)
                                
                    info[section] = options
        
        return {
            "exploit_path": exploit_path,
            "info": info
        }
    
    def run_exploit(self, exploit_path, options=None, payload=None, target_host=None):
        """Run a Metasploit exploit module"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Create options string
        options_str = ""
        if options:
            for option, value in options.items():
                options_str += f"set {option} {value}\n"
                
        # Set the target host if provided
        if target_host:
            options_str += f"set RHOSTS {target_host}\n"
            
        # Set the payload if provided
        payload_str = ""
        if payload:
            payload_str = f"set PAYLOAD {payload}\n"
            
        # Create resource script for exploit
        script_content = f"""
        use {exploit_path}
        {options_str}
        {payload_str}
        check
        exploit
        """
        
        output_file = os.path.join(tempfile.gettempdir(), f"msf_exploit_{int(time.time())}.txt")
        
        return self.run_rc_script(script_content, output_file)
    
    def list_compatible_payloads(self, exploit_path):
        """List payloads compatible with a specific exploit"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Create resource script to list compatible payloads
        script_content = f"""
        use {exploit_path}
        show payloads
        exit
        """
        
        output_file = os.path.join(tempfile.gettempdir(), f"msf_payloads_{int(time.time())}.txt")
        
        result = self.run_rc_script(script_content, output_file)
        
        # Parse payload list
        payloads = []
        if "output" in result and result["output"]:
            in_payload_section = False
            
            for line in result["output"].splitlines():
                line = line.strip()
                
                # Check if we're in the payload listing section
                if "Compatible Payloads" in line:
                    in_payload_section = True
                    continue
                    
                if in_payload_section:
                    if not line or line.startswith("="):
                        continue
                    
                    if "Name" in line and "Description" in line:
                        # Header line, skip
                        continue
                    
                    if " - " in line:
                        parts = line.split(" - ", 1)
                        if len(parts) == 2:
                            payload_path = parts[0].strip()
                            payload_desc = parts[1].strip()
                            
                            payloads.append({
                                "path": payload_path,
                                "description": payload_desc
                            })
        
        return {
            "exploit_path": exploit_path,
            "compatible_payloads": payloads,
            "count": len(payloads)
        }
    
    def db_status(self):
        """Check the status of the Metasploit database"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Create resource script to check database status
        script_content = """
        db_status
        exit
        """
        
        output_file = os.path.join(tempfile.gettempdir(), f"msf_db_status_{int(time.time())}.txt")
        
        result = self.run_rc_script(script_content, output_file)
        
        # Check if database is connected
        db_connected = False
        if "output" in result and result["output"]:
            if "database connected" in result["output"].lower():
                db_connected = True
                
        return {
            "db_connected": db_connected,
            "output": result.get("output", "")
        }
    
    def update_database(self):
        """Update the Metasploit exploit database"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        logger.info("Updating Metasploit Framework...")
        
        # Use msfupdate if available
        msfupdate_path = shutil.which("msfupdate")
        if msfupdate_path:
            result = self.run_command([msfupdate_path])
            if result["returncode"] != 0:
                logger.warning(f"Metasploit update failed: {result['stderr']}")
                return False
        else:
            # Try apt update for Debian/Ubuntu systems
            apt_result = self.run_command(["apt-get", "update", "&&", "apt-get", "install", "--only-upgrade", "metasploit-framework"], shell=True)
            if apt_result["returncode"] != 0:
                logger.warning(f"Metasploit update failed: {apt_result['stderr']}")
                return False
                
        return True
    
    def find_exploitable_services(self, host):
        """Scan a host for services and find matching exploits"""
        if not self.check_installation():
            raise Exception("Metasploit is not installed")
            
        # Check if database is connected
        db_status = self.db_status()
        if not db_status["db_connected"]:
            logger.warning("Metasploit database is not connected. Initialize it with 'msfdb init'.")
            # Try to initialize the database
            if self.msfdb_path:
                self.run_command([self.msfdb_path, "init"])
                # Check again
                db_status = self.db_status()
                if not db_status["db_connected"]:
                    logger.error("Failed to connect to Metasploit database")
                    return {
                        "error": "Database not connected",
                        "status": "error"
                    }
        
        # Create a new workspace
        workspace_name = f"scan_{int(time.time())}"
        
        # Create resource script for scanning and finding exploits
        script_content = f"""
        workspace -a {workspace_name}
        db_nmap -sV -O {host}
        analyze
        vulns
        exit
        """
        
        output_file = os.path.join(tempfile.gettempdir(), f"msf_scan_{int(time.time())}.txt")
        
        result = self.run_rc_script(script_content, output_file)
        
        return {
            "host": host,
            "workspace": workspace_name,
            "output": result.get("output", ""),
            "status": "success" if result["returncode"] == 0 else "error"
        } 