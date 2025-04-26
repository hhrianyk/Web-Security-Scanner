#!/usr/bin/env python3
"""
MongoDB Connection Checker
This script checks if MongoDB is properly installed and running.
"""

import sys
import time
import os
import platform
import subprocess

def check_mongodb_installation():
    """Check if MongoDB is installed on the system"""
    try:
        # Check for mongod executable in path
        if platform.system() == "Windows":
            mongod_installed = subprocess.run(["where", "mongod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False).returncode == 0
        else:
            mongod_installed = subprocess.run(["which", "mongod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False).returncode == 0
        
        if mongod_installed:
            print("✓ MongoDB is installed and in the system PATH.")
            # Get version
            try:
                result = subprocess.run(["mongod", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                first_line = result.stdout.split('\n')[0]
                print(f"✓ {first_line}")
                return True
            except:
                print("✓ MongoDB is installed, but version check failed.")
                return True
        else:
            print("✗ MongoDB executable not found in PATH.")
            return False
    except Exception as e:
        print(f"✗ Error checking MongoDB installation: {e}")
        return False

def check_mongodb_service():
    """Check if MongoDB service is running"""
    try:
        # Different commands based on OS
        if platform.system() == "Windows":
            result = subprocess.run(["sc", "query", "MongoDB"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            service_running = "RUNNING" in result.stdout
        else:
            result = subprocess.run(["systemctl", "status", "mongod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            service_running = "active (running)" in result.stdout
        
        if service_running:
            print("✓ MongoDB service is running.")
            return True
        else:
            print("✗ MongoDB service is not running.")
            return False
    except Exception as e:
        print(f"⚠ Could not check MongoDB service status: {e}")
        print("  This may be normal if MongoDB is not installed as a service.")
        return None

def check_mongodb_connection():
    """Check connection to MongoDB database"""
    try:
        import pymongo
        print("✓ pymongo is installed.")
        
        # Try to connect to MongoDB
        print("Attempting to connect to MongoDB...")
        client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        
        # The ismaster command is cheap and does not require auth
        server_info = client.admin.command('ismaster')
        
        print("✓ Successfully connected to MongoDB!")
        print(f"✓ MongoDB version: {server_info.get('version', 'unknown')}")
        
        # Try to create a test database and collection
        try:
            db = client["test_security_db"]
            collection = db["test_collection"]
            
            # Insert a test document
            test_id = collection.insert_one({"test": "document", "timestamp": time.time()}).inserted_id
            print(f"✓ Test document inserted with ID: {test_id}")
            
            # Find the document
            result = collection.find_one({"test": "document"})
            if result:
                print("✓ Successfully retrieved test document")
            
            # Clean up
            collection.delete_one({"_id": test_id})
            print("✓ Test document removed")
            
            print("\nMongoDB is correctly installed and functioning!\n")
            return True
            
        except Exception as e:
            print(f"✗ Error during database operations: {e}")
            return False
            
    except ImportError:
        print("✗ pymongo is not installed.")
        print("  Please install it using: pip install pymongo")
        return False
    except pymongo.errors.ServerSelectionTimeoutError:
        print("✗ Could not connect to MongoDB server.")
        print("\nPossible reasons:")
        print("1. MongoDB service is not running")
        print("2. MongoDB is running on a different port")
        print("\nTry starting the MongoDB service:")
        if platform.system() == "Windows":
            print("  - Run: net start MongoDB")
            print("  - Or use: python run_mongodb.py")
        else:
            print("  - Run: sudo systemctl start mongod")
        return False
    except Exception as e:
        print(f"✗ MongoDB connection failed: {e}")
        print("\nPossible reasons for connection failure:")
        print("1. MongoDB service is not running")
        print("2. MongoDB is not installed")
        print("3. MongoDB is running on a different port")
        print("\nInstallation instructions:")
        print("- Windows: https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-windows/")
        print("- Linux: https://www.mongodb.com/docs/manual/administration/install-on-linux/")
        print("- macOS: https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x/")
        print("\nOr use the provided scripts:")
        print("- install_and_run_mongodb.py (for installation and running)")
        print("- run_mongodb.py (if already installed)")
        return False

def check_mongodb():
    """Run all MongoDB checks"""
    print("\n=== MongoDB Connection Checker ===\n")
    
    # Check if MongoDB is installed
    installation_ok = check_mongodb_installation()
    
    # Check if service is running
    if installation_ok:
        service_ok = check_mongodb_service()
    else:
        print("\nSkipping service check as MongoDB is not installed.")
        service_ok = False
    
    # Check connection
    print("\nChecking MongoDB connection:")
    connection_ok = check_mongodb_connection()
    
    # Summary
    print("\n=== MongoDB Check Summary ===")
    print(f"Installation: {'✓ OK' if installation_ok else '✗ Not installed'}")
    print(f"Service: {'✓ Running' if service_ok else '✗ Not running' if service_ok is not None else '- Unknown'}")
    print(f"Connection: {'✓ Successful' if connection_ok else '✗ Failed'}")
    
    if not installation_ok:
        print("\nRecommendation: Install MongoDB first")
        print("  - Run: python install_and_run_mongodb.py")
    elif not connection_ok:
        print("\nRecommendation: Start MongoDB service")
        print("  - Run: python run_mongodb.py")
    
    return connection_ok

if __name__ == "__main__":
    success = check_mongodb()
    sys.exit(0 if success else 1) 