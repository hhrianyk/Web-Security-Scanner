#!/usr/bin/env python3
"""
MongoDB Installation and Starter Script
This script downloads, installs, and starts MongoDB on Windows.
"""

import os
import sys
import time
import subprocess
import platform
import tempfile
import urllib.request
import zipfile
import shutil
import ctypes

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def download_mongodb():
    """Download MongoDB zip file."""
    mongodb_url = "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-6.0.8.zip"
    temp_dir = tempfile.gettempdir()
    zip_path = os.path.join(temp_dir, "mongodb.zip")
    
    print(f"Downloading MongoDB from {mongodb_url}...")
    print("This may take a few minutes...")
    
    try:
        urllib.request.urlretrieve(mongodb_url, zip_path)
        print("✓ MongoDB downloaded successfully!")
        return zip_path
    except Exception as e:
        print(f"✗ Failed to download MongoDB: {e}")
        return None

def extract_mongodb(zip_path):
    """Extract MongoDB zip file."""
    extract_dir = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "MongoDB")
    
    print(f"Extracting MongoDB to {extract_dir}...")
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(extract_dir, exist_ok=True)
        
        # Extract ZIP file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Get the name of the extracted directory (first directory in the ZIP)
        extracted_dirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
        if not extracted_dirs:
            print("✗ No directories found after extraction!")
            return None
            
        mongodb_dir = os.path.join(extract_dir, extracted_dirs[0])
        bin_dir = os.path.join(mongodb_dir, "bin")
        
        print(f"✓ MongoDB extracted to {mongodb_dir}")
        return bin_dir
    except Exception as e:
        print(f"✗ Failed to extract MongoDB: {e}")
        return None

def ensure_data_directory():
    """Create the MongoDB data directory if it doesn't exist."""
    data_dir = "C:\\data\\db"
    if not os.path.exists(data_dir):
        print(f"Creating data directory: {data_dir}")
        os.makedirs(data_dir, exist_ok=True)
    return data_dir

def start_mongodb(bin_dir=None):
    """Start MongoDB server process."""
    data_dir = ensure_data_directory()
    
    # If bin_dir is provided, use the mongod from there
    mongod_path = "mongod"
    if bin_dir:
        mongod_path = os.path.join(bin_dir, "mongod.exe")
    
    print("Starting MongoDB server...")
    # Start MongoDB as a subprocess
    try:
        if platform.system() == "Windows":
            process = subprocess.Popen(
                [mongod_path, "--dbpath", data_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            process = subprocess.Popen(
                [mongod_path, "--dbpath", data_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
        # Wait a moment to see if the process starts successfully
        time.sleep(3)
        
        # Check if process is still running
        if process.poll() is None:
            print("✓ MongoDB started successfully!")
            print(f"✓ Data directory: {data_dir}")
            print("\nMongoDB is now running. You can now run your application.")
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"✗ MongoDB failed to start: {stderr.decode()}")
            return False
            
    except FileNotFoundError:
        print(f"✗ MongoDB executable not found at {mongod_path}")
        return False
    except Exception as e:
        print(f"✗ Error starting MongoDB: {e}")
        return False

def main():
    """Main function."""
    print("=== MongoDB Installer and Starter ===\n")
    
    # Check if running on Windows
    if platform.system() != "Windows":
        print("This script is designed for Windows only.")
        return False
    
    # Check if MongoDB is already in PATH
    try:
        subprocess.run(["mongod", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("✓ MongoDB is already installed!")
        
        # Try to start MongoDB directly
        return start_mongodb()
    except (subprocess.SubprocessError, FileNotFoundError):
        print("MongoDB not found in PATH. Will attempt to install...")
    
    # Download and install MongoDB
    zip_path = download_mongodb()
    if not zip_path:
        return False
    
    bin_dir = extract_mongodb(zip_path)
    if not bin_dir:
        return False
    
    # Start MongoDB
    return start_mongodb(bin_dir)

if __name__ == "__main__":
    # Check if running as admin
    if not is_admin():
        print("This script requires administrator privileges to install MongoDB properly.")
        print("Please run this script as an administrator.")
        sys.exit(1)
        
    success = main()
    print("\nPress Enter to exit...")
    input()
    sys.exit(0 if success else 1) 