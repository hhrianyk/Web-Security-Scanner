#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import subprocess
import shutil
import requests
import tempfile
import time
import re
import datetime
from typing import Dict, List, Any, Optional, Union

# Add the parent directory to the path to import security_tools_integration
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from the security tools integration
from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nvd_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDIntegration")


@register_tool
class NVDDatabase(SecurityToolBase):
    """
    NIST National Vulnerability Database (NVD) - Comprehensive vulnerability database maintained by NIST
    
    Features:
    - Standardized vulnerability information
    - CVE details and summaries
    - CVSS scoring and metrics
    - CPE product matching
    - References to advisories and solutions
    """
    
    def __init__(self):
        self.api_key = os.environ.get("NVD_API_KEY", "")
        self.api_url = "https://services.nvd.nist.gov/rest/json"
        self.database_path = os.path.join(get_tools_directory(), "nvd-data")
        self.data_feeds = {
            "cve": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz",
            "cpe": "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
        }
        os.makedirs(self.database_path, exist_ok=True)
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "NIST NVD Database",
            "description": "National Vulnerability Database maintained by NIST",
            "actions": ["search_cve", "cve_details", "cpe_match", "search_by_product", "get_cvss_score"],
            "target_types": ["cve", "product", "vendor", "keyword"],
            "output_formats": ["json"],
            "dependencies": []
        }
        
    def check_installation(self):
        """Check if NVD database files are downloaded"""
        # NVD is a web API, so we just check if we have the data directory
        return os.path.exists(self.database_path)
        
    def install(self):
        """Set up the NVD integration"""
        # Create database directory
        os.makedirs(self.database_path, exist_ok=True)
        
        # Download latest data feed (optional)
        self.update_database()
        
        return True
    
    def api_request(self, endpoint, params=None):
        """Make a request to the NVD API"""
        url = f"{self.api_url}/{endpoint}"
        headers = {}
        
        # Add API key if available for higher rate limits
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        try:
            # Add delay to respect rate limits
            time.sleep(0.6)  # NVD requires at least 0.6s between requests without API key
            
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"NVD API request error: {str(e)}")
            return {"error": str(e)}
            
    def update_database(self):
        """Update the local NVD data feeds"""
        import gzip
        
        current_year = datetime.datetime.now().year
        
        # Download CVE data for recent years
        for year in range(current_year - 2, current_year + 1):
            feed_url = self.data_feeds["cve"].format(year)
            output_file = os.path.join(self.database_path, f"nvdcve-1.1-{year}.json.gz")
            json_file = os.path.join(self.database_path, f"nvdcve-1.1-{year}.json")
            
            try:
                logger.info(f"Downloading NVD CVE data for {year}...")
                response = requests.get(feed_url, stream=True)
                response.raise_for_status()
                
                with open(output_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        
                # Extract the gzipped file
                with gzip.open(output_file, 'rb') as f_in:
                    with open(json_file, 'wb') as f_out:
                        f_out.write(f_in.read())
                        
                logger.info(f"Successfully downloaded and extracted NVD CVE data for {year}")
            except Exception as e:
                logger.error(f"Failed to download NVD CVE data for {year}: {str(e)}")
                
        # Download CPE match data
        try:
            cpe_url = self.data_feeds["cpe"]
            cpe_output_file = os.path.join(self.database_path, "nvdcpematch-1.0.json.gz")
            cpe_json_file = os.path.join(self.database_path, "nvdcpematch-1.0.json")
            
            logger.info("Downloading NVD CPE match data...")
            response = requests.get(cpe_url, stream=True)
            response.raise_for_status()
            
            with open(cpe_output_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            # Extract the gzipped file
            with gzip.open(cpe_output_file, 'rb') as f_in:
                with open(cpe_json_file, 'wb') as f_out:
                    f_out.write(f_in.read())
                    
            logger.info("Successfully downloaded and extracted NVD CPE match data")
        except Exception as e:
            logger.error(f"Failed to download NVD CPE match data: {str(e)}")
            
        return True
        
    def search_cve(self, cve_id=None, keyword=None, start_index=0, results_per_page=20):
        """Search for CVEs by ID or keyword"""
        if cve_id:
            # Validate CVE ID format
            if not re.match(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
                raise ValueError(f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
                
            # Query specific CVE
            return self.api_request("cve/2.0", params={"cveId": cve_id})
        elif keyword:
            # Search by keyword
            return self.api_request("cve/2.0", params={
                "keyword": keyword,
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            })
        else:
            raise ValueError("Either cve_id or keyword must be provided")
            
    def search_by_product(self, product, vendor=None, cpe_version=None, start_index=0, results_per_page=20):
        """Search for vulnerabilities by product name"""
        params = {
            "keyword": product,
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }
        
        if vendor:
            params["keyword"] = f"{vendor} {product}"
            
        return self.api_request("cve/2.0", params=params)
        
    def get_cvss_score(self, cve_id):
        """Get CVSS score for a specific CVE"""
        # Validate CVE ID format
        if not re.match(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
            raise ValueError(f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
            
        cve_data = self.search_cve(cve_id=cve_id)
        
        if "error" in cve_data:
            return cve_data
            
        try:
            # Extract CVSS data
            cvss_data = {}
            
            if "vulnerabilities" in cve_data and len(cve_data["vulnerabilities"]) > 0:
                vuln = cve_data["vulnerabilities"][0]["cve"]
                
                # CVSS v3.x
                if "metrics" in vuln and "cvssMetricV30" in vuln["metrics"]:
                    cvss3 = vuln["metrics"]["cvssMetricV30"][0]["cvssData"]
                    cvss_data["v3"] = {
                        "version": cvss3.get("version"),
                        "baseScore": cvss3.get("baseScore"),
                        "baseSeverity": cvss3.get("baseSeverity"),
                        "vectorString": cvss3.get("vectorString")
                    }
                    
                # CVSS v2.0
                if "metrics" in vuln and "cvssMetricV2" in vuln["metrics"]:
                    cvss2 = vuln["metrics"]["cvssMetricV2"][0]["cvssData"]
                    cvss_data["v2"] = {
                        "version": cvss2.get("version"),
                        "baseScore": cvss2.get("baseScore"),
                        "vectorString": cvss2.get("vectorString")
                    }
                    
                # Add description
                if "descriptions" in vuln:
                    for desc in vuln["descriptions"]:
                        if desc.get("lang") == "en":
                            cvss_data["description"] = desc.get("value")
                            break
                            
                # Add references
                if "references" in vuln:
                    cvss_data["references"] = []
                    for ref in vuln["references"]:
                        cvss_data["references"].append({
                            "url": ref.get("url"),
                            "source": ref.get("source")
                        })
                        
            return {
                "cve_id": cve_id,
                "cvss": cvss_data
            }
        except Exception as e:
            logger.error(f"Error extracting CVSS data: {str(e)}")
            return {
                "cve_id": cve_id,
                "error": f"Error extracting CVSS data: {str(e)}"
            }
            
    def search_local_database(self, term, year=None):
        """Search the local NVD database files"""
        results = []
        
        # Determine which years to search
        if year:
            years_to_search = [year]
        else:
            current_year = datetime.datetime.now().year
            years_to_search = range(current_year - 2, current_year + 1)
            
        # Search each year's database
        for year in years_to_search:
            json_file = os.path.join(self.database_path, f"nvdcve-1.1-{year}.json")
            
            if not os.path.exists(json_file):
                continue
                
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    
                # Search through CVE items
                if "CVE_Items" in data:
                    for item in data["CVE_Items"]:
                        found = False
                        
                        # Check CVE ID
                        if "cve" in item and "CVE_data_meta" in item["cve"]:
                            cve_id = item["cve"]["CVE_data_meta"].get("ID", "")
                            if term.lower() in cve_id.lower():
                                found = True
                                
                        # Check description
                        if not found and "cve" in item and "description" in item["cve"]:
                            descriptions = item["cve"]["description"].get("description_data", [])
                            for desc in descriptions:
                                if "value" in desc and term.lower() in desc["value"].lower():
                                    found = True
                                    break
                                    
                        # If found, add to results
                        if found:
                            results.append(item)
                            
            except Exception as e:
                logger.error(f"Error searching local database for year {year}: {str(e)}")
                
        return {
            "search_term": term,
            "count": len(results),
            "results": results
        }
        
    def get_recent_cves(self, days=30, start_index=0, results_per_page=20):
        """Get recently added CVEs"""
        # Calculate date range
        today = datetime.datetime.now()
        start_date = today - datetime.timedelta(days=days)
        
        # Format dates for API
        pub_start_date = start_date.strftime("%Y-%m-%dT00:00:00.000")
        pub_end_date = today.strftime("%Y-%m-%dT23:59:59.999")
        
        # Query API
        return self.api_request("cve/2.0", params={
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        })
        
    def get_cve_details(self, cve_id):
        """Get comprehensive details about a specific CVE"""
        # Validate CVE ID format
        if not re.match(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
            raise ValueError(f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN")
            
        cve_data = self.search_cve(cve_id=cve_id)
        
        if "error" in cve_data:
            return cve_data
            
        try:
            # Create a simplified and better organized structure
            details = {"cve_id": cve_id}
            
            if "vulnerabilities" in cve_data and len(cve_data["vulnerabilities"]) > 0:
                vuln = cve_data["vulnerabilities"][0]["cve"]
                
                # Basic information
                details["published"] = vuln.get("published")
                details["lastModified"] = vuln.get("lastModified")
                
                # Description
                if "descriptions" in vuln:
                    for desc in vuln["descriptions"]:
                        if desc.get("lang") == "en":
                            details["description"] = desc.get("value")
                            break
                            
                # CVSS scores
                details["cvss"] = {}
                
                if "metrics" in vuln:
                    # CVSS v3.x
                    if "cvssMetricV30" in vuln["metrics"]:
                        cvss3 = vuln["metrics"]["cvssMetricV30"][0]["cvssData"]
                        details["cvss"]["v3"] = {
                            "baseScore": cvss3.get("baseScore"),
                            "baseSeverity": cvss3.get("baseSeverity"),
                            "vectorString": cvss3.get("vectorString")
                        }
                        
                    # CVSS v2.0
                    if "cvssMetricV2" in vuln["metrics"]:
                        cvss2 = vuln["metrics"]["cvssMetricV2"][0]["cvssData"]
                        details["cvss"]["v2"] = {
                            "baseScore": cvss2.get("baseScore"),
                            "vectorString": cvss2.get("vectorString")
                        }
                        
                # References
                if "references" in vuln:
                    details["references"] = []
                    for ref in vuln["references"]:
                        details["references"].append({
                            "url": ref.get("url"),
                            "source": ref.get("source"),
                            "tags": ref.get("tags", [])
                        })
                        
                # Configurations
                if "configurations" in cve_data["vulnerabilities"][0]:
                    configs = cve_data["vulnerabilities"][0]["configurations"]
                    details["affected_products"] = []
                    
                    for config in configs:
                        if "nodes" in config:
                            for node in config["nodes"]:
                                if "cpeMatch" in node:
                                    for cpe in node["cpeMatch"]:
                                        if "criteria" in cpe:
                                            details["affected_products"].append({
                                                "cpe": cpe.get("criteria"),
                                                "vulnerable": cpe.get("vulnerable", False)
                                            })
            
            return details
        except Exception as e:
            logger.error(f"Error extracting CVE details: {str(e)}")
            return {
                "cve_id": cve_id,
                "error": f"Error extracting CVE details: {str(e)}"
            }
            
    def search_by_cpe(self, cpe_string, start_index=0, results_per_page=20):
        """Search for vulnerabilities by CPE identifier"""
        # Clean and validate CPE string
        cpe_string = cpe_string.strip()
        if not cpe_string.startswith("cpe:"):
            raise ValueError(f"Invalid CPE format: {cpe_string}. Expected format: cpe:2.3:part:vendor:product:version")
            
        return self.api_request("cve/2.0", params={
            "cpeName": cpe_string,
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        })
        
    def get_security_advisory(self, cve_id):
        """Get security advisory information for a CVE"""
        cve_details = self.get_cve_details(cve_id)
        
        if "error" in cve_details:
            return cve_details
            
        # Extract references with advisory tags
        advisories = []
        if "references" in cve_details:
            for ref in cve_details["references"]:
                if "tags" in ref and any(tag in ["Vendor Advisory", "Patch", "Mitigation"] for tag in ref.get("tags", [])):
                    advisories.append(ref)
                    
        return {
            "cve_id": cve_id,
            "advisories": advisories,
            "count": len(advisories)
        } 