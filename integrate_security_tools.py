#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import importlib
import argparse
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("integrate_security_tools.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("IntegrateSecurityTools")

# Path to the main security tools integration module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the security tools manager
from security_tools_integration import security_tools_manager

# List of tool integration modules to import
TOOL_MODULES = [
    "dirbuster_integration",
    "bandit_integration",
    "sonarqube_integration",
    "mitmproxy_integration",
    "burpsuite_integration",
    # Exploit databases and vulnerability scanners
    "exploitdb_integration",
    "metasploit_integration",
    "vulners_integration",
    "nvd_integration",
    "rapid7_integration",
    "nessus_integration",
    "nuclei_integration",
    # DNS spoofing tools
    "dns_spoof_integration",
    # Add additional modules as they are created
]

# List of tools to be integrated
TOOLS = [
    "DirBuster",
    "Bandit",
    "SonarQubeCommunity",
    "Mitmproxy",
    "BurpSuiteCommunity",
    "JohnTheRipper",
    "HashCat",
    "Fierce",
    "SocialEngineerToolkit",
    "AircrackNg",
    "Kismet",
    "FaradayCommunity",
    "DradisCE",
    "Postman",
    "SoapUIOpenSource",
    "RIPS",
    "FindSecBugs",
    "Clair",
    "Trivy",
    "OSSEC",
    "Wazuh",
    # DNS Spoofing Tools
    "DNSChef",
    "Ettercap",
    "Responder",
    # Exploit Databases and Vulnerability Scanners
    "ExploitDB",
    "MetasploitExploitDB",
    "VulnersScanner",
    "NVDDatabase",
    "Rapid7Database",
    "NessusScanner",
    "NucleiScanner"
]

def import_tool_modules():
    """Import all tool integration modules"""
    imported_modules = []
    
    for module_name in TOOL_MODULES:
        try:
            module = importlib.import_module(module_name)
            imported_modules.append(module)
            logger.info(f"Successfully imported module: {module_name}")
        except ImportError as e:
            logger.warning(f"Failed to import module {module_name}: {str(e)}")
            
    return imported_modules

def list_available_tools():
    """List all available security tools"""
    tools = security_tools_manager.list_tools()
    
    print("\nAvailable Security Tools:")
    print("=======================")
    
    for name, info in tools.items():
        print(f"\n{name}")
        print("-" * len(name))
        print(f"Description: {info.get('description', 'No description')}")
        print(f"Actions: {', '.join(info.get('actions', []))}")
        print(f"Target Types: {', '.join(info.get('target_types', []))}")
        print(f"Output Formats: {', '.join(info.get('output_formats', []))}")
        
    # List tools that are planned but not yet implemented
    available_tools = set(tools.keys())
    planned_tools = set(TOOLS) - available_tools
    
    if planned_tools:
        print("\nPlanned Tools (Not Yet Implemented):")
        print("==================================")
        for tool in sorted(planned_tools):
            print(f"- {tool}")
            
    return tools

def initialize_tool(tool_name):
    """Initialize a specific security tool"""
    try:
        tool = security_tools_manager.get_tool(tool_name)
        is_installed = tool.check_installation()
        
        print(f"\n{tool_name}")
        print("-" * len(tool_name))
        
        if is_installed:
            print("Status: Installed")
        else:
            print("Status: Not installed")
            install = input("Do you want to install this tool? (y/n): ")
            if install.lower() == 'y':
                print(f"Installing {tool_name}...")
                tool.install()
                print(f"{tool_name} installation completed.")
                
        return tool
    except Exception as e:
        logger.error(f"Error initializing {tool_name}: {str(e)}")
        print(f"Error: {str(e)}")
        return None

def install_all_tools():
    """Install all available security tools"""
    tools = security_tools_manager.list_tools()
    
    for name in tools:
        try:
            print(f"\nInitializing {name}...")
            tool = security_tools_manager.get_tool(name)
            
            if not tool.check_installation():
                print(f"Installing {name}...")
                tool.install()
                print(f"{name} installation completed.")
            else:
                print(f"{name} is already installed.")
                
        except Exception as e:
            logger.error(f"Error installing {name}: {str(e)}")
            print(f"Error installing {name}: {str(e)}")
            
def test_tools():
    """Run basic tests for all available tools"""
    tools = security_tools_manager.list_tools()
    
    for name in tools:
        try:
            print(f"\nTesting {name}...")
            tool = security_tools_manager.get_tool(name)
            
            # Check installation
            is_installed = tool.check_installation()
            print(f"Installation status: {'Installed' if is_installed else 'Not installed'}")
            
            if not is_installed:
                continue
                
            # Get capabilities
            capabilities = tool.get_capabilities()
            print(f"Actions: {', '.join(capabilities.get('actions', []))}")
            
        except Exception as e:
            logger.error(f"Error testing {name}: {str(e)}")
            print(f"Error testing {name}: {str(e)}")

def update_requirements():
    """Update the requirements_security_tools.txt file"""
    # Define the requirements for each tool
    tool_requirements = {
        "DirBuster": [],  # Java-based
        "Bandit": ["bandit>=1.7.5"],
        "SonarQubeCommunity": ["requests>=2.25.1"],
        "Mitmproxy": ["mitmproxy>=9.0.1"],
        "BurpSuiteCommunity": [],  # Java-based
        "JohnTheRipper": [],  # External binary
        "HashCat": [],  # External binary
        "Fierce": ["fierce>=1.5.0"],
        "SocialEngineerToolkit": [],  # External tool
        "AircrackNg": [],  # External binary
        "Kismet": [],  # External binary
        "FaradayCommunity": ["faradaysec>=4.0.0"],
        "DradisCE": [],  # Ruby-based
        "Postman": [],  # Desktop application
        "SoapUIOpenSource": [],  # Java-based
        "RIPS": [],  # PHP-based
        "FindSecBugs": [],  # Java-based
        "Clair": [],  # Go-based
        "Trivy": [],  # Go-based
        "OSSEC": [],  # C-based
        "Wazuh": [],  # C-based
        # DNS Spoofing Tools
        "DNSChef": ["dnschef>=0.4"],
        "Ettercap": [],  # External binary
        "Responder": [],  # External binary/Python script
        # Exploit Databases and Vulnerability Scanners
        "ExploitDB": [],  # Uses git and basic Python libraries
        "MetasploitExploitDB": ["pymetasploit3>=1.0.3"],
        "VulnersScanner": ["vulners>=1.7.0"],
        "NVDDatabase": [],  # Uses requests already included
        "Rapid7Database": [],  # Uses requests already included
        "NessusScanner": [],  # Uses requests already included
        "NucleiScanner": []  # Uses requests already included
    }
    
    # Core requirements
    core_requirements = [
        "# Security Tools Integration Requirements",
        "",
        "# Core dependencies",
        "requests>=2.25.1",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0",
        "xmltodict>=0.13.0",
        "",
        "# DNS spoofing tools dependencies",
        "scapy>=2.5.0",
        "netifaces>=0.11.0",
        "netfilterqueue>=1.0.0",
        "",
        "# Security tool specific dependencies"
    ]
    
    # Combine all requirements
    all_requirements = core_requirements.copy()
    for tool, reqs in tool_requirements.items():
        if reqs:
            all_requirements.append(f"# {tool} requirements")
            all_requirements.extend(reqs)
            all_requirements.append("")
            
    # Write to file
    with open("requirements_security_tools.txt", "w") as f:
        f.write("\n".join(all_requirements))
        
    print("Updated requirements_security_tools.txt")
    
def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Security Tools Integration Utility")
    parser.add_argument("--list", action="store_true", help="List all available security tools")
    parser.add_argument("--install-all", action="store_true", help="Install all available security tools")
    parser.add_argument("--install", help="Install a specific security tool")
    parser.add_argument("--test", action="store_true", help="Test all installed security tools")
    parser.add_argument("--update-requirements", action="store_true", help="Update requirements file")
    
    args = parser.parse_args()
    
    # Import all tool modules
    import_tool_modules()
    
    if args.list:
        list_available_tools()
    elif args.install_all:
        install_all_tools()
    elif args.install:
        initialize_tool(args.install)
    elif args.test:
        test_tools()
    elif args.update_requirements:
        update_requirements()
    else:
        parser.print_help()
        
if __name__ == "__main__":
    main() 