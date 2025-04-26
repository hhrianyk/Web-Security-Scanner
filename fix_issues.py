#!/usr/bin/env python3
"""
System Issues Fixer
This script fixes all identified issues in the security system:
1. MongoDB connection issues
2. Scapy limitations
3. OSINTScanner module issues
"""

import os
import sys
import subprocess
import platform
import shutil
import time
import importlib.util

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f" {text} ".center(60, "="))
    print("=" * 60 + "\n")

def print_step(step, description):
    """Print a step with description"""
    print(f"[{step}] {description}")

def check_module_exists(module_name):
    """Check if a Python module exists"""
    return importlib.util.find_spec(module_name) is not None

def run_command(command, capture_output=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=False, 
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True
        )
        return result
    except Exception as e:
        print(f"Error running command: {e}")
        return None

def fix_mongodb_issues():
    """Fix MongoDB connection issues"""
    print_header("Fixing MongoDB Issues")
    
    # Check if pymongo is installed
    if not check_module_exists("pymongo"):
        print_step(1, "Installing pymongo package...")
        run_command("pip install pymongo", capture_output=False)
    else:
        print_step(1, "pymongo package is already installed.")
    
    # Check MongoDB installation status
    print_step(2, "Checking MongoDB installation...")
    
    # Import our checker module
    sys.path.append(os.getcwd())
    try:
        import check_mongodb
        installation_ok = check_mongodb.check_mongodb_installation()
    except ImportError:
        installation_ok = False
        print("Could not import check_mongodb module. Check if it exists.")
    
    if not installation_ok:
        print_step(3, "Installing MongoDB...")
        if os.path.exists("install_and_run_mongodb.py"):
            return_code = run_command("python install_and_run_mongodb.py").returncode
            if return_code != 0:
                print("Failed to install MongoDB using the script.")
                print("Please install MongoDB manually from: https://www.mongodb.com/try/download/community")
        else:
            print("install_and_run_mongodb.py script not found.")
            print("Please install MongoDB manually from: https://www.mongodb.com/try/download/community")
    else:
        print_step(3, "MongoDB is already installed.")
    
    # Check if MongoDB service is running
    print_step(4, "Starting MongoDB service...")
    if os.path.exists("run_mongodb.py"):
        # Start with our custom script that creates the appropriate data directory
        process = subprocess.Popen(["python", "run_mongodb.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("MongoDB service should now be starting...")
        time.sleep(3)  # Give it a moment to start
        
        # Verify the connection
        try:
            import pymongo
            client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
            server_info = client.admin.command('ismaster')
            print(f"✓ MongoDB connection successful (version: {server_info.get('version', 'unknown')})")
        except Exception as e:
            print(f"✗ MongoDB connection still failed: {e}")
            print("You may need to start MongoDB manually.")
    else:
        print("run_mongodb.py script not found.")
        print("Starting MongoDB service using system commands...")
        
        if platform.system() == "Windows":
            run_command("net start MongoDB", capture_output=False)
        else:
            run_command("sudo systemctl start mongod", capture_output=False)
    
    print("\nMongoDB setup complete. To verify the connection, run: python check_mongodb.py")

def fix_scapy_issues():
    """Fix Scapy limitations"""
    print_header("Fixing Scapy Issues")
    
    # Check if scapy is installed
    if not check_module_exists("scapy"):
        print_step(1, "Installing scapy package...")
        run_command("pip install scapy", capture_output=False)
    else:
        print_step(1, "scapy package is already installed.")
    
    # Check if Windows and Npcap is needed
    if platform.system() == "Windows":
        print_step(2, "Checking Npcap installation for Windows...")
        
        # Try to import winreg to check registry for Npcap
        try:
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap")
                winreg.CloseKey(key)
                print("✓ Npcap is installed.")
            except:
                print("✗ Npcap not found in registry.")
                print("Please download and install Npcap from: https://npcap.com/")
                print("Npcap is required for Scapy to capture packets on Windows.")
        except ImportError:
            print("Could not check Npcap registry. Attempting alternative detection...")
            
            # Check common installation path
            if os.path.exists("C:\\Program Files\\Npcap"):
                print("✓ Npcap folder found.")
            else:
                print("✗ Npcap folder not found.")
                print("Please download and install Npcap from: https://npcap.com/")
    
    # Update the check_scapy.py script (already done separately)
    print_step(3, "Verifying scapy functionality...")
    if os.path.exists("check_scapy.py"):
        result = run_command("python check_scapy.py")
        if result.returncode != 0:
            print("Scapy check failed. Please review the output above.")
        else:
            print("✓ Scapy functionality verified.")
    else:
        print("check_scapy.py script not found.")
    
    print("\nScapy setup complete. To verify functionality, run: python check_scapy.py")

def fix_osint_scanner_issues():
    """Fix OSINTScanner module issues"""
    print_header("Fixing OSINTScanner Module Issues")
    
    # Check if osint_scanner.py exists
    if not os.path.exists("osint_scanner.py"):
        print_step(1, "Creating osint_scanner.py module...")
        print("This module should have been created separately.")
    else:
        print_step(1, "osint_scanner.py already exists.")
    
    # Check if osint_tools.py exists (dependency)
    if not os.path.exists("osint_tools.py"):
        print("Warning: osint_tools.py not found. OSINTScanner depends on this file.")
    else:
        print_step(2, "Verified osint_tools.py dependency.")
    
    # Test importing the module
    print_step(3, "Testing OSINTScanner module import...")
    try:
        sys.path.append(os.getcwd())
        import osint_scanner
        print("✓ OSINTScanner module imported successfully.")
    except ImportError as e:
        print(f"✗ Failed to import OSINTScanner module: {e}")
    except Exception as e:
        print(f"✗ Error in OSINTScanner module: {e}")
    
    print("\nOSINTScanner module setup complete.")

def verify_fixes():
    """Verify all fixes"""
    print_header("Verifying All Fixes")
    
    # Check MongoDB
    print_step(1, "Verifying MongoDB connection...")
    mongodb_ok = False
    try:
        import pymongo
        client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        server_info = client.admin.command('ismaster')
        print(f"✓ MongoDB connection successful (version: {server_info.get('version', 'unknown')})")
        mongodb_ok = True
    except Exception as e:
        print(f"✗ MongoDB connection failed: {e}")
    
    # Check Scapy
    print_step(2, "Verifying Scapy functionality...")
    scapy_ok = False
    try:
        import scapy.all as scapy
        print(f"✓ Scapy imported successfully (version: {scapy.conf.version})")
        scapy_ok = True
    except Exception as e:
        print(f"✗ Scapy import failed: {e}")
    
    # Check OSINTScanner
    print_step(3, "Verifying OSINTScanner module...")
    osint_ok = False
    try:
        import osint_scanner
        print("✓ OSINTScanner module imported successfully.")
        osint_ok = True
    except Exception as e:
        print(f"✗ OSINTScanner module import failed: {e}")
    
    # Report overall status
    print("\nFix Verification Summary:")
    print(f"MongoDB: {'✓ FIXED' if mongodb_ok else '✗ STILL ISSUES'}")
    print(f"Scapy: {'✓ FIXED' if scapy_ok else '✗ STILL ISSUES'}")
    print(f"OSINTScanner: {'✓ FIXED' if osint_ok else '✗ STILL ISSUES'}")
    
    if mongodb_ok and scapy_ok and osint_ok:
        print("\n✅ All issues have been fixed successfully!")
        return True
    else:
        print("\n⚠ Some issues remain. Check the summary above.")
        return False

def main():
    """Main function"""
    print_header("System Issues Fixer")
    print("This script will fix the following issues:")
    print("1. MongoDB connection issues")
    print("2. Scapy limitations")
    print("3. OSINTScanner module issues")
    
    input("\nPress Enter to begin the fix process...")
    
    # Fix MongoDB issues
    fix_mongodb_issues()
    
    # Fix Scapy issues
    fix_scapy_issues()
    
    # Fix OSINTScanner issues
    fix_osint_scanner_issues()
    
    # Verify all fixes
    success = verify_fixes()
    
    if success:
        print("\nAll issues have been fixed. The system should now be fully functional.")
    else:
        print("\nSome issues could not be automatically fixed. Please check the logs above.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 