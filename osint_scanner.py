#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSINTScanner Module - Open Source Intelligence Scanner
Provides functionality for gathering intelligence from various open sources.
"""

import os
import sys
import logging
import socket
import json
import datetime
from osint_tools import OSINTTools

# Configure logging
log_file = 'osint_scanner.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('OSINTScanner')

class OSINTScanner:
    """
    OSINT Scanner for gathering information about hosts and domains
    from various public sources.
    """
    
    def __init__(self, target=None, output_dir="security_reports/osint"):
        self.target = target
        self.output_dir = output_dir
        self.tools = None
        self.results = {}
        self.scan_time = None
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Initialized OSINTScanner for target: {target}")
    
    def initialize_tools(self, api_keys=None):
        """Initialize the OSINT tools with API keys if provided"""
        try:
            self.tools = OSINTTools(self.target, self.output_dir, api_keys)
            logger.info("OSINT tools initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize OSINT tools: {str(e)}")
            return False
    
    def scan(self, target=None):
        """
        Perform a complete OSINT scan on the target
        
        Args:
            target: Target domain or IP to analyze (overrides the one set at initialization)
            
        Returns:
            dict: Complete OSINT results
        """
        if target:
            self.target = target
        
        if not self.target:
            logger.error("No target specified for OSINT scanning")
            return {"error": "No target specified"}
        
        logger.info(f"Starting OSINT scan for {self.target}")
        self.scan_time = datetime.datetime.now()
        
        # Initialize tools if not already done
        if not self.tools:
            self.initialize_tools()
        
        # Run all OSINT gathering methods
        try:
            self.results = self.tools.run_all_osint(self.target)
            logger.info(f"OSINT scan completed for {self.target}")
            self.save_report()
            return self.results
        except Exception as e:
            error_msg = f"Error during OSINT scan: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def save_report(self, filename=None):
        """
        Save scan results to a report file
        
        Args:
            filename: Custom filename (default: osint_scan_TARGET_TIMESTAMP.json)
            
        Returns:
            str: Path to saved file
        """
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self.target.replace(".", "_") if self.target else "unknown"
            filename = f"osint_scan_{target_name}_{timestamp}.json"
            
        file_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(file_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Saved OSINT scan report to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error saving scan report: {str(e)}")
            return None
    
    def get_summary(self):
        """
        Get a summary of the scan results
        
        Returns:
            dict: Summary of key findings
        """
        if not self.results:
            return {"error": "No scan results available"}
        
        summary = {
            "target": self.target,
            "scan_time": self.scan_time.strftime("%Y-%m-%d %H:%M:%S") if self.scan_time else None,
            "ip_addresses": self.results.get("domain_info", {}).get("ip_addresses", []),
            "whois": {
                "registrar": self.results.get("whois_data", {}).get("registrar"),
                "creation_date": self.results.get("whois_data", {}).get("creation_date"),
                "expiration_date": self.results.get("whois_data", {}).get("expiration_date")
            },
            "technologies": self.results.get("web_technologies", {}).get("technologies", []),
            "open_ports": self.results.get("shodan_data", {}).get("ports", []),
            "email_count": len(self.results.get("email_harvesting", {}).get("emails", [])),
            "geolocation": {
                "country": self.results.get("geolocation", {}).get("country"),
                "city": self.results.get("geolocation", {}).get("city")
            }
        }
        
        return summary

if __name__ == "__main__":
    # Simple command line interface
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scanner = OSINTScanner(target)
        results = scanner.scan()
        print(json.dumps(scanner.get_summary(), indent=2))
    else:
        print("Usage: python osint_scanner.py [target_domain_or_ip]") 