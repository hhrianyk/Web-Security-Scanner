#!/usr/bin/env python3
"""
MongoDB Starter Script
This script starts MongoDB server and verifies it's running properly.
"""

import os
import sys
import time
import subprocess
import platform
import shutil
import zipfile
import urllib.request

def ensure_mongodb_exists():
    """Ensure MongoDB executable exists, downloading if needed"""
    mongodb_dir = os.path.join(os.getcwd(), "mongodb")
    bin_dir = os.path.join(mongodb_dir, "bin")
    mongod_path = os.path.join(bin_dir, "mongod.exe") if platform.system() == "Windows" else os.path.join(bin_dir, "mongod")
    
    # Check if mongod exists in our local directory
    if os.path.exists(mongod_path):
        print(f"✓ Found MongoDB executable at: {mongod_path}")
        return bin_dir
    
    # Check if MongoDB ZIP exists
    mongodb_zip = os.path.join(os.getcwd(), "mongodb.zip")
    if os.path.exists(mongodb_zip):
        print(f"Found MongoDB ZIP file: {mongodb_zip}")
        print("Extracting MongoDB...")
        
        # Extract MongoDB if needed
        if not os.path.exists(mongodb_dir):
            os.makedirs(mongodb_dir, exist_ok=True)
            
        with zipfile.ZipFile(mongodb_zip, 'r') as zip_ref:
            zip_ref.extractall(mongodb_dir)
        
        # MongoDB ZIP could have nested directory, find the bin directory
        for root, dirs, files in os.walk(mongodb_dir):
            if "bin" in dirs:
                bin_dir = os.path.join(root, "bin")
                if os.path.exists(os.path.join(bin_dir, "mongod.exe" if platform.system() == "Windows" else "mongod")):
                    print(f"✓ MongoDB extracted to: {bin_dir}")
                    return bin_dir
        
        print("✗ Could not find MongoDB binaries in the extracted files.")
        return None
    
    # No MongoDB found locally, try system PATH
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["where", "mongod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        else:
            result = subprocess.run(["which", "mongod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            
        if result.returncode == 0:
            mongod_path = result.stdout.decode('utf-8').strip()
            print(f"✓ Found MongoDB in system PATH: {mongod_path}")
            return os.path.dirname(mongod_path)
    except Exception:
        pass
    
    print("✗ MongoDB executable not found.")
    print("Please install MongoDB or download mongodb.zip to this directory.")
    return None

def ensure_data_directory():
    """Create the MongoDB data directory if it doesn't exist."""
    if platform.system() == "Windows":
        data_dir = os.path.join("C:\\", "data", "db")
    else:
        data_dir = os.path.join(os.getcwd(), "data", "db")
        
    if not os.path.exists(data_dir):
        print(f"Creating data directory: {data_dir}")
        os.makedirs(data_dir, exist_ok=True)
    return data_dir

def start_mongodb():
    """Start MongoDB server process."""
    # Get MongoDB bin directory
    bin_dir = ensure_mongodb_exists()
    if not bin_dir:
        return False
        
    # Get data directory
    data_dir = ensure_data_directory()
    
    # Determine the path to mongod
    if platform.system() == "Windows":
        mongod_path = os.path.join(bin_dir, "mongod.exe")
    else:
        mongod_path = os.path.join(bin_dir, "mongod")
    
    if not os.path.exists(mongod_path):
        mongod_path = os.path.join(bin_dir, "mongod.exe") if platform.system() == "Windows" else os.path.join(bin_dir, "mongod")
        if not os.path.exists(mongod_path):
            # Try just using 'mongod' command
            mongod_path = "mongod"
    
    print("Starting MongoDB server...")
    print(f"MongoDB executable: {mongod_path}")
    print(f"Data directory: {data_dir}")
    
    # Start MongoDB as a subprocess
    try:
        # Check if MongoDB is already running
        try:
            import pymongo
            client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
            client.admin.command('ismaster')
            print("✓ MongoDB is already running.")
            return True
        except Exception:
            pass  # Not running, continue to start it
            
        # Start MongoDB server
        if platform.system() == "Windows":
            # Use subprocess.Popen to start MongoDB in the background
            process = subprocess.Popen(
                [mongod_path, "--dbpath", data_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            # For Unix-like systems
            process = subprocess.Popen(
                [mongod_path, "--dbpath", data_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
        # Wait a moment to see if the process starts successfully
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is None:
            print("✓ MongoDB started successfully!")
            
            # Import check_mongodb module if available
            try:
                sys.path.append(os.getcwd())
                import check_mongodb
                print("\nVerifying MongoDB connection...")
                check_mongodb.check_mongodb_connection()
            except ImportError:
                print("\nUnable to verify MongoDB connection (check_mongodb.py not found).")
                
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"✗ MongoDB failed to start: {stderr.decode()}")
            return False
            
    except FileNotFoundError:
        print(f"✗ MongoDB executable not found at {mongod_path}.")
        print("\nPlease ensure MongoDB is installed and added to your system PATH.")
        print("Download MongoDB from: https://www.mongodb.com/try/download/community")
        return False
    except Exception as e:
        print(f"✗ Error starting MongoDB: {e}")
        return False

if __name__ == "__main__":
    print("=== MongoDB Starter ===\n")
    success = start_mongodb()
    
    if success:
        print("\nMongoDB is now running.")
        print("Press Ctrl+C in the MongoDB console window to stop it.")
        
    sys.exit(0 if success else 1) 