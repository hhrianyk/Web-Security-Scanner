#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import json
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is sufficient."""
    print("Checking Python version...")
    required_version = (3, 7)
    current_version = sys.version_info[:2]
    
    if current_version < required_version:
        print(f"Error: Python {required_version[0]}.{required_version[1]} or higher is required. You have {current_version[0]}.{current_version[1]}.")
        sys.exit(1)
    
    print(f"Python version {current_version[0]}.{current_version[1]} detected. ✓")
    return True

def create_directories():
    """Create necessary directories."""
    print("Creating directories...")
    directories = [
        "unified_security_reports",
        "security_data",
        "security_data/tools",
        "security_data/temp",
        "templates",
        "static"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")
    
    return True

def install_dependencies():
    """Install Python dependencies."""
    print("Installing Python dependencies...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Dependencies installed successfully. ✓")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def check_optional_dependencies():
    """Check for optional dependencies."""
    print("\nChecking optional dependencies...")
    
    # Check for MongoDB
    try:
        subprocess.check_call([sys.executable, "-c", "import pymongo"], stderr=subprocess.DEVNULL)
        print("MongoDB Python client (pymongo) is installed. ✓")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("MongoDB Python client is not installed. Some database features may not work.")
        print("To install: pip install pymongo")
    
    # Check for AI dependencies
    try:
        subprocess.check_call([sys.executable, "-c", "import torch"], stderr=subprocess.DEVNULL)
        print("PyTorch is installed. AI features will be available. ✓")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("PyTorch is not installed. AI features will be limited.")
        print("To install AI components: pip install torch transformers nltk")
    
    return True

def check_external_tools():
    """Check for external security tools."""
    print("\nChecking for external security tools...")
    
    # Check for Nmap
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Nmap is installed: {result.stdout.split('(')[0].strip()} ✓")
        else:
            print("Nmap may not be installed properly.")
    except FileNotFoundError:
        print("Nmap is not installed. Network scanning features will be limited.")
        if sys.platform == "win32":
            print("Download and install from: https://nmap.org/download.html")
        elif sys.platform == "darwin":
            print("Install with: brew install nmap")
        else:
            print("Install with: sudo apt-get install nmap")
    
    return True

def create_env_template():
    """Create .env.template file with default configurations."""
    print("\nCreating environment template file...")
    
    env_template = """# Unified Security System Environment Configuration

# API Keys (replace with your actual keys)
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SECURITY_TRAILS_API_KEY=your_securitytrails_api_key

# Web Interface Settings
FLASK_SECRET_KEY=replace_with_random_secret_key
FLASK_DEBUG=False
FLASK_HOST=127.0.0.1
FLASK_PORT=5000

# Database Configuration (optional)
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=security_platform

# AI Integration Settings (optional)
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key

# Security Scanner Settings
NMAP_ARGUMENTS=-sV -sC -O
MAX_THREADS=8
SCAN_TIMEOUT=1800
DEFAULT_PORT_RANGE=1-1000

# Report Generation
COMPANY_NAME=Security Assessment Team
REPORT_TITLE=Security Assessment Report
INCLUDE_EXECUTIVE_SUMMARY=True
INCLUDE_TECHNICAL_DETAILS=True
INCLUDE_REMEDIATION=True
"""
    
    with open(".env.template", "w") as f:
        f.write(env_template)
    
    if not os.path.exists(".env"):
        shutil.copy(".env.template", ".env")
        print("Created .env file with default settings. Please edit with your API keys. ✓")
    else:
        print(".env file already exists. Template updated but existing .env preserved. ✓")
    
    return True

def check_unified_config():
    """Check if unified_config.json exists and is valid."""
    print("\nChecking configuration...")
    
    if os.path.exists("unified_config.json"):
        try:
            with open("unified_config.json", "r") as f:
                config = json.load(f)
            print("Unified configuration file exists and is valid. ✓")
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error reading unified_config.json: {e}")
            print("Creating a new default configuration file...")
            create_unified_config()
    else:
        print("Configuration file not found. Creating default configuration...")
        create_unified_config()
    
    return True

def create_unified_config():
    """Create a default unified_config.json file."""
    config = {
        "output_dir": "unified_security_reports",
        "data_dir": "security_data",
        "temp_dir": "security_data/temp",
        "parallel_execution": True,
        "max_workers": 8,
        "timeout": 1800,
        "default_modules": [
            "network",
            "osint",
            "web",
            "ai",
            "social",
            "comprehensive",
            "report"
        ],
        "report_formats": [
            "json",
            "html",
            "pdf"
        ],
        "save_raw_data": True,
        "web_interface": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 5000,
            "debug": False,
            "open_browser": True
        },
        "modules": {
            "network_scanning": {
                "enabled": True,
                "port_range": "1-1000",
                "scan_speed": "normal",
                "detect_os": True,
                "service_detection": True
            },
            "web_vulnerability_scanning": {
                "enabled": True,
                "scan_depth": "standard",
                "active_scanning": True,
                "passive_scanning": True,
                "authenticated_scan": False
            }
        }
    }
    
    try:
        with open("unified_config.json", "w") as f:
            json.dump(config, f, indent=2)
        print("Created unified_config.json with default settings. ✓")
        return True
    except IOError as e:
        print(f"Error creating unified_config.json: {e}")
        return False

def check_executable_permissions():
    """Ensure scripts have executable permissions."""
    print("\nChecking script permissions...")
    
    scripts = [
        "unified_security_tools.py",
        "run_unified_security.sh"
    ]
    
    if sys.platform != "win32":  # Skip on Windows
        for script in scripts:
            if os.path.exists(script):
                try:
                    os.chmod(script, 0o755)  # rwxr-xr-x
                    print(f"Set executable permissions for {script}. ✓")
                except OSError as e:
                    print(f"Error setting permissions for {script}: {e}")
    else:
        print("Running on Windows, skipping executable permissions.")
    
    return True

def main():
    """Main setup function."""
    print("=" * 60)
    print("  Unified Security System - Setup")
    print("=" * 60)
    
    steps = [
        ("Checking Python version", check_python_version),
        ("Creating directories", create_directories),
        ("Installing dependencies", install_dependencies),
        ("Checking optional dependencies", check_optional_dependencies),
        ("Checking external tools", check_external_tools),
        ("Creating environment template", create_env_template),
        ("Checking configuration", check_unified_config),
        ("Setting executable permissions", check_executable_permissions)
    ]
    
    success = True
    for name, func in steps:
        print(f"\n{name}...")
        try:
            if not func():
                print(f"Warning: Step '{name}' had issues.")
                success = False
        except Exception as e:
            print(f"Error during '{name}': {e}")
            success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✓ Setup completed successfully!")
        print("\nTo run the unified security system:")
        if sys.platform == "win32":
            print("  - Double-click run_unified_security.bat")
            print("  - Or run: python unified_security_tools.py --help")
        else:
            print("  - Run: ./run_unified_security.sh")
            print("  - Or run: python3 unified_security_tools.py --help")
    else:
        print("⚠ Setup completed with some warnings.")
        print("Please address the issues mentioned above and try again if needed.")
    
    print("\nFor more information, see UNIFIED_SYSTEM_README.md")
    print("=" * 60)

if __name__ == "__main__":
    main() 