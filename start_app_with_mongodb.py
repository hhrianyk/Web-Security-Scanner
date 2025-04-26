#!/usr/bin/env python3
"""
Start Application with MongoDB
This script ensures MongoDB is running before starting the application.
"""

import os
import sys
import time
import subprocess
import platform
import atexit

def ensure_data_directory():
    """Create the MongoDB data directory if it doesn't exist."""
    data_dir = "C:\\data\\db"
    if not os.path.exists(data_dir):
        print(f"Creating data directory: {data_dir}")
        os.makedirs(data_dir, exist_ok=True)
    return data_dir

def start_mongodb():
    """Start MongoDB server process."""
    data_dir = ensure_data_directory()
    
    print("Starting MongoDB server...")
    # Try common MongoDB installation locations
    possible_mongod_paths = [
        "mongod",
        "mongod.exe",
        "C:\\Program Files\\MongoDB\\Server\\6.0\\bin\\mongod.exe",
        "C:\\Program Files\\MongoDB\\Server\\5.0\\bin\\mongod.exe",
        "C:\\Program Files\\MongoDB\\Server\\4.4\\bin\\mongod.exe",
        "C:\\MongoDB\\bin\\mongod.exe",
    ]
    
    # Try each possible path
    for mongod_path in possible_mongod_paths:
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
                print(f"✓ MongoDB started successfully using {mongod_path}!")
                return process
            
        except (FileNotFoundError, PermissionError):
            continue
        except Exception as e:
            print(f"Error with {mongod_path}: {e}")
            continue
    
    # If we get here, all attempts failed
    print("✗ Failed to start MongoDB. Please install MongoDB or run the install_and_run_mongodb.py script first.")
    return None

def check_mongodb_connection():
    """Check if MongoDB is running and accessible."""
    try:
        # Try to import pymongo
        import pymongo
        
        # Try to connect
        client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        server_info = client.admin.command('ismaster')
        
        print("✓ MongoDB connection successful!")
        return True
    except ImportError:
        print("✗ pymongo module not installed.")
        return False
    except Exception as e:
        print(f"✗ MongoDB connection check failed: {e}")
        return False

def start_application():
    """Start the main application."""
    print("\nStarting application...")
    try:
        app_process = subprocess.Popen(
            ["python", "app.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("✓ Application started!")
        return app_process
    except Exception as e:
        print(f"✗ Failed to start application: {e}")
        return None

def cleanup_processes(processes):
    """Clean up processes on exit."""
    for process in processes:
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                if process.poll() is None:
                    process.kill()

def main():
    """Main function."""
    print("=== Starting Application with MongoDB ===\n")
    
    processes = []
    
    # First check if MongoDB is already running
    if not check_mongodb_connection():
        # If not, try to start it
        mongodb_process = start_mongodb()
        if mongodb_process:
            processes.append(mongodb_process)
            # Check again if the connection works
            if not check_mongodb_connection():
                print("✗ MongoDB started but connection failed. Please check your MongoDB installation.")
                return False
        else:
            print("✗ Could not start MongoDB. Application will not work correctly.")
            return False
    else:
        print("✓ MongoDB is already running!")
    
    # Start the application
    app_process = start_application()
    if app_process:
        processes.append(app_process)
        
        # Register cleanup function
        atexit.register(cleanup_processes, processes)
        
        # Wait for the app to finish
        try:
            return_code = app_process.wait()
            print(f"\nApplication exited with code {return_code}")
            return return_code == 0
        except KeyboardInterrupt:
            print("\nReceived keyboard interrupt. Stopping processes...")
            return False
    
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 