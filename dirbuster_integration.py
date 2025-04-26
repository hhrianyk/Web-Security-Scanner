#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import subprocess
import shutil
import requests
from typing import Dict, List, Any, Optional, Union
import platform
import tempfile
import zipfile
import time
import datetime

# Import base class from security_tools_integration.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, download_file, security_tools_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dirbuster_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DirBusterIntegration")

@register_tool
class DirBuster(SecurityToolBase):
    """
    DirBuster - A multi-threaded Java application designed to brute force directories and files on web/application servers
    
    Features:
    - Directory and file enumeration
    - Multi-threaded scanning
    - Custom wordlist support
    - Recursive scanning
    - Comprehensive reporting
    """
    
    def __init__(self):
        self.dirbuster_path = os.path.join(get_tools_directory(), "dirbuster")
        self.dirbuster_jar = os.path.join(self.dirbuster_path, "DirBuster-1.0-RC1.jar")
        self.wordlists_dir = os.path.join(self.dirbuster_path, "wordlists")
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "DirBuster",
            "description": "Web directory enumeration and brute force tool",
            "actions": ["directory_brute_force", "file_brute_force", "web_enumeration"],
            "target_types": ["web_application", "web_server"],
            "output_formats": ["text", "xml", "csv"],
            "dependencies": ["java"]
        }
        
    def check_installation(self):
        """Check if DirBuster is installed"""
        return os.path.exists(self.dirbuster_jar)
        
    def install(self):
        """Install DirBuster"""
        os.makedirs(self.dirbuster_path, exist_ok=True)
        os.makedirs(self.wordlists_dir, exist_ok=True)
        
        # Check if Java is installed
        java_path = shutil.which("java")
        if not java_path:
            raise Exception("Java is required but not installed")
            
        # Download DirBuster
        download_url = "https://sourceforge.net/projects/dirbuster/files/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.zip"
        zip_path = os.path.join(self.dirbuster_path, "dirbuster.zip")
        
        if not download_file(download_url, zip_path):
            raise Exception("Failed to download DirBuster")
            
        # Extract the zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(self.dirbuster_path)
            
        # Find and move the JAR file if necessary
        for root, dirs, files in os.walk(self.dirbuster_path):
            for file in files:
                if file.endswith(".jar") and "dirbuster" in file.lower():
                    src_path = os.path.join(root, file)
                    if src_path != self.dirbuster_jar:
                        shutil.move(src_path, self.dirbuster_jar)
                        
        # Move wordlists to the wordlists directory
        for root, dirs, files in os.walk(self.dirbuster_path):
            for file in files:
                if file.endswith(".txt") and root != self.wordlists_dir:
                    src_path = os.path.join(root, file)
                    dst_path = os.path.join(self.wordlists_dir, file)
                    shutil.move(src_path, dst_path)
                    
        # Clean up zip file
        try:
            os.remove(zip_path)
        except:
            pass
            
        return self.check_installation()
        
    def run_headless(self, target_url, wordlist=None, file_extensions=None, threads=10, recursive=True, output_file=None):
        """Run DirBuster in headless mode"""
        if not self.check_installation():
            raise Exception("DirBuster is not installed")
            
        # Prepare target URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"http://{target_url}"
            
        # Find default wordlist if not specified
        if not wordlist:
            # Use the medium wordlist if available
            default_wordlist = os.path.join(self.wordlists_dir, "directory-list-2.3-medium.txt")
            if not os.path.exists(default_wordlist):
                # Try to find any wordlist
                for file in os.listdir(self.wordlists_dir):
                    if file.endswith(".txt"):
                        default_wordlist = os.path.join(self.wordlists_dir, file)
                        break
            wordlist = default_wordlist
            
        # Ensure wordlist exists
        if not os.path.exists(wordlist):
            raise Exception(f"Wordlist not found: {wordlist}")
            
        # Set default output file if not specified
        if not output_file:
            output_file = os.path.join(tempfile.gettempdir(), f"dirbuster_report_{int(time.time())}.txt")
            
        # Build command
        cmd = [
            "java", "-jar", self.dirbuster_jar,
            "-u", target_url,
            "-l", wordlist,
            "-t", str(threads),
            "-r", str(recursive).lower(),
            "-o", output_file
        ]
        
        # Add file extensions if specified
        if file_extensions:
            if isinstance(file_extensions, list):
                file_extensions = ",".join(file_extensions)
            cmd.extend(["-e", file_extensions])
            
        # Run DirBuster
        logger.info(f"Running DirBuster against {target_url}")
        result = self.run_command(cmd, timeout=3600)  # 1-hour timeout
        
        if result["returncode"] != 0:
            logger.warning(f"DirBuster scan ended with non-zero exit code: {result['returncode']}")
            
        # Check if output file was created
        if not os.path.exists(output_file):
            logger.error("DirBuster did not generate an output file")
            return {
                "error": "No output file was generated",
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
            
        # Read output file
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse results (simple parsing for text output)
            directories = []
            files = []
            
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.endswith("/"):
                        directories.append(line)
                    else:
                        files.append(line)
                        
            return {
                "target": target_url,
                "scan_time": datetime.datetime.now().isoformat(),
                "wordlist": wordlist,
                "directories": directories,
                "files": files,
                "total_directories": len(directories),
                "total_files": len(files),
                "output_file": output_file
            }
            
        except Exception as e:
            logger.error(f"Error parsing DirBuster output: {str(e)}")
            return {
                "error": str(e),
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
        
    def run_gui(self):
        """Launch DirBuster GUI"""
        if not self.check_installation():
            raise Exception("DirBuster is not installed")
            
        # Build command
        cmd = ["java", "-jar", self.dirbuster_jar]
        
        # Run DirBuster GUI
        logger.info("Launching DirBuster GUI")
        subprocess.Popen(cmd)
        
        return {
            "status": "launched",
            "message": "DirBuster GUI launched successfully"
        }

if __name__ == "__main__":
    try:
        # Initialize DirBuster tool
        dirbuster = security_tools_manager.get_tool("DirBuster")
        
        # Run a test if requested
        if len(sys.argv) > 1 and sys.argv[1] == "--test":
            # Run a simple test
            test_url = "example.com"
            print(f"Running test scan against {test_url}")
            result = dirbuster.run_headless(test_url, threads=5, recursive=False)
            print(f"Test scan completed. Found {result.get('total_directories', 0)} directories and {result.get('total_files', 0)} files.")
            
        # Launch GUI if requested
        elif len(sys.argv) > 1 and sys.argv[1] == "--gui":
            dirbuster.run_gui()
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 