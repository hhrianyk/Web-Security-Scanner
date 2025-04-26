#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nmap Installation Verification Script
-------------------------------------
This script verifies if Nmap is properly installed and configured.
It checks for:
1. Nmap binary in PATH
2. Python-nmap library
3. Ability to run a basic scan
4. System integration with security_tools_integration.py
"""

import os
import sys
import subprocess
import shutil
import platform
import time

def print_status(message, status):
    """Print colored status message."""
    if status == "success":
        print(f"✅ {message}")
    elif status == "warning":
        print(f"⚠️ {message}")
    elif status == "error":
        print(f"❌ {message}")
    else:
        print(f"   {message}")

def check_nmap_binary():
    """Check if Nmap binary is installed and in PATH."""
    print("\nChecking Nmap binary installation...")
    
    # Check if nmap is in PATH
    nmap_path = shutil.which("nmap")
    if nmap_path:
        try:
            result = subprocess.run([nmap_path, "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0]
                print_status(f"Nmap found in PATH: {nmap_path}", "success")
                print_status(f"Version: {version}", "info")
                return True, nmap_path, version
        except Exception as e:
            print_status(f"Error running Nmap: {str(e)}", "error")
    
    # Check common installation paths on Windows
    if platform.system().lower() == "windows":
        common_paths = [
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Nmap", "nmap.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Nmap", "nmap.exe")
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                try:
                    result = subprocess.run([path, "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if result.returncode == 0:
                        version = result.stdout.strip().split("\n")[0]
                        print_status(f"Nmap found at: {path}", "success")
                        print_status(f"Version: {version}", "info")
                        print_status("Nmap is installed but not in PATH", "warning")
                        print_status("Run fix_nmap_detection.py to fix PATH issues", "info")
                        return True, path, version
                except Exception as e:
                    print_status(f"Error running Nmap at {path}: {str(e)}", "error")
    
    print_status("Nmap not found in system", "error")
    print_status("Please install Nmap using install_nmap.bat or Install-Nmap.ps1", "info")
    return False, None, None

def check_python_nmap():
    """Check if python-nmap library is installed and working."""
    print("\nChecking python-nmap library...")
    
    try:
        import nmap
        scanner = nmap.PortScanner()
        print_status("Python-nmap library is installed and imported successfully", "success")
        return True
    except ImportError:
        print_status("Python-nmap library is not installed", "error")
        print_status("Install it using: pip install python-nmap", "info")
        return False
    except Exception as e:
        print_status(f"Error importing python-nmap: {str(e)}", "error")
        return False

def run_basic_scan(nmap_path):
    """Run a basic Nmap scan."""
    if not nmap_path:
        print_status("Skipping scan test, Nmap binary not found", "warning")
        return False
    
    print("\nTesting basic Nmap scan...")
    try:
        # Run a simple scan on localhost, only a few well-known ports
        result = subprocess.run(
            [nmap_path, "-F", "-T4", "127.0.0.1"], 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print_status("Basic scan completed successfully", "success")
            print("\n--- Scan output ---")
            print(result.stdout)
            print("--- End of output ---\n")
            return True
        else:
            print_status(f"Scan failed with error: {result.stderr}", "error")
            return False
    except subprocess.TimeoutExpired:
        print_status("Scan timed out after 30 seconds", "error")
        return False
    except Exception as e:
        print_status(f"Error during scan: {str(e)}", "error")
        return False

def check_security_integration():
    """Check if security_tools_integration.py is configured correctly."""
    print("\nChecking security integration...")
    
    # Check if the file exists
    if not os.path.exists("security_tools_integration.py"):
        print_status("security_tools_integration.py not found", "warning")
        print_status("Security integration check skipped", "info")
        return False
    
    # Check if the file has been modified by fix_nmap_detection.py
    if os.path.exists("security_tools_integration.py.bak"):
        print_status("Backup file found, indicating fix_nmap_detection.py has been run", "success")
    else:
        print_status("No backup file found, fix_nmap_detection.py may not have been run", "warning")
        print_status("Run fix_nmap_detection.py to improve Nmap detection", "info")
    
    # Basic content check
    try:
        with open("security_tools_integration.py", "r", encoding="utf-8") as f:
            content = f.read()
            
            if "if platform.system().lower() == \"windows\":" in content and "common_paths =" in content:
                print_status("Enhanced Nmap detection code found in security_tools_integration.py", "success")
                return True
            else:
                print_status("Enhanced Nmap detection code not found", "warning")
                print_status("Run fix_nmap_detection.py to add enhanced detection", "info")
                return False
    except Exception as e:
        print_status(f"Error checking security_tools_integration.py: {str(e)}", "error")
        return False

def main():
    """Main function."""
    print("="*60)
    print("Nmap Installation Verification")
    print("="*60)
    
    # Check Nmap binary
    nmap_installed, nmap_path, nmap_version = check_nmap_binary()
    
    # Check python-nmap library
    python_nmap_installed = check_python_nmap()
    
    # Run basic scan
    if nmap_installed:
        scan_success = run_basic_scan(nmap_path)
    else:
        scan_success = False
    
    # Check security integration
    security_integration_ok = check_security_integration()
    
    # Print summary
    print("\n" + "="*60)
    print("VERIFICATION SUMMARY")
    print("="*60)
    print(f"Nmap binary:            {'✅ Installed' if nmap_installed else '❌ Not installed'}")
    print(f"Nmap in PATH:           {'✅ Yes' if shutil.which('nmap') else '❌ No'}")
    print(f"Python-nmap library:    {'✅ Installed' if python_nmap_installed else '❌ Not installed'}")
    print(f"Basic scan:             {'✅ Working' if scan_success else '❌ Failed'}")
    print(f"Security integration:   {'✅ Configured' if security_integration_ok else '⚠️ Needs configuration'}")
    
    # Final verdict
    print("\nFINAL VERDICT:")
    if nmap_installed and python_nmap_installed and scan_success:
        print("✅ Nmap is properly installed and working!")
        if not shutil.which('nmap'):
            print("⚠️ Nmap is not in PATH. Run fix_nmap_detection.py to add it to PATH.")
        if not security_integration_ok:
            print("⚠️ Security integration may need configuration. Run fix_nmap_detection.py.")
    else:
        print("❌ Nmap installation is incomplete or not working properly.")
        print("\nRECOMMENDED ACTIONS:")
        if not nmap_installed:
            print("1. Install Nmap using Install-Nmap.ps1 or install_nmap.bat")
        if not python_nmap_installed:
            print("2. Install python-nmap using: pip install python-nmap")
        if nmap_installed and not shutil.which('nmap'):
            print("3. Add Nmap to PATH by running fix_nmap_detection.py")
        if not security_integration_ok:
            print("4. Configure security integration by running fix_nmap_detection.py")
        print("5. Restart your computer after making changes")
    
    print("\nNote: If you've just installed Nmap or modified PATH, you may need to restart your computer.")
    
    # Wait before exit on Windows
    if platform.system().lower() == "windows":
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main() 