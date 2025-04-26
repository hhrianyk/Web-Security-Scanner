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
        logging.FileHandler("rapid7_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Rapid7Integration")


@register_tool
class Rapid7Database(SecurityToolBase):
    """
    Rapid7 Vulnerability & Exploit Database - Professional database of vulnerabilities and exploits
    
    Features:
    - Detailed vulnerability information
    - Exploit availability checks
    - Attack vector analysis
    - References to patches and mitigations
    - Integration with Metasploit modules
    """
    
    def __init__(self):
        self.api_key = os.environ.get("RAPID7_API_KEY", "")
        self.vm_api_url = "https://us.api.insight.rapid7.com/vm"
        self.insight_api_url = "https://insight.rapid7.com/api/3"
        self.metasploit_path = shutil.which("msfconsole")
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Rapid7 Vulnerability Database",
            "description": "Professional database of vulnerabilities and exploits",
            "actions": ["search_vulnerabilities", "get_vulnerability", "search_exploits", "get_metasploit_modules"],
            "target_types": ["cve", "product", "exploit"],
            "output_formats": ["json"],
            "dependencies": []
        }
        
    def check_installation(self):
        """Check if Rapid7 API is accessible"""
        # For API-based services, we just check if we can configure it
        return True
        
    def install(self):
        """Configure the Rapid7 API integration"""
        if not self.api_key:
            logger.warning("Rapid7 API key not set. Set RAPID7_API_KEY environment variable for full access.")
            
        return True
    
    def api_request(self, endpoint, method="GET", params=None, data=None, insight=False):
        """Make a request to the Rapid7 API"""
        # Select the appropriate base URL
        base_url = self.insight_api_url if insight else self.vm_api_url
        url = f"{base_url}/{endpoint.lstrip('/')}"
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        if self.api_key:
            headers["X-Api-Key"] = self.api_key
            
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=params, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, headers=headers)
            else:
                response = requests.request(method, url, json=data, params=params, headers=headers)
                
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"API request error: {str(e)}")
            # Return simplified error response
            return {"error": str(e)}
    
    def web_scrape_vulnerability(self, vulnerability_id):
        """Scrape vulnerability details from Rapid7 website (fallback method)"""
        # This is a fallback method when API key is not available
        # It uses web scraping to get public information from the Rapid7 website
        
        # Normalize ID (CVE or Rapid7 ID)
        if vulnerability_id.startswith("CVE-"):
            url = f"https://www.rapid7.com/db/vulnerabilities/{vulnerability_id}"
        else:
            url = f"https://www.rapid7.com/db/vulnerabilities/rapid7-{vulnerability_id}"
            
        try:
            logger.info(f"Scraping vulnerability details from {url}")
            response = requests.get(url)
            response.raise_for_status()
            
            # Simple HTML parsing to extract basic information
            html = response.text
            data = {}
            
            # Extract title
            title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
            if title_match:
                data["title"] = title_match.group(1).strip()
                
            # Extract description
            desc_match = re.search(r'<div[^>]*class="[^"]*vulnerability-description[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            if desc_match:
                desc_html = desc_match.group(1)
                # Simple HTML to text conversion
                desc_text = re.sub(r'<[^>]+>', ' ', desc_html)
                desc_text = re.sub(r'\s+', ' ', desc_text).strip()
                data["description"] = desc_text
                
            # Extract severity
            severity_match = re.search(r'CVSS Score:\s*([0-9.]+)', html)
            if severity_match:
                data["cvss_score"] = float(severity_match.group(1))
                
            # Extract references
            references = []
            ref_matches = re.finditer(r'<a[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', html)
            for match in ref_matches:
                href = match.group(1)
                text = match.group(2).strip()
                if "rapid7.com/db" not in href and text and len(text) > 5:
                    references.append({"url": href, "title": text})
                    
            data["references"] = references
            
            # Extract solutions if available
            solution_match = re.search(r'<div[^>]*class="[^"]*solution-description[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            if solution_match:
                solution_html = solution_match.group(1)
                solution_text = re.sub(r'<[^>]+>', ' ', solution_html)
                solution_text = re.sub(r'\s+', ' ', solution_text).strip()
                data["solution"] = solution_text
                
            return {
                "vulnerability_id": vulnerability_id,
                "data": data,
                "source": "web_scrape"
            }
            
        except Exception as e:
            logger.error(f"Web scraping error: {str(e)}")
            return {"error": str(e), "vulnerability_id": vulnerability_id}
    
    def search_vulnerabilities(self, query=None, cve_id=None, product=None, limit=20):
        """Search for vulnerabilities in the Rapid7 database"""
        if self.api_key:
            # Use API if key is available
            endpoint = "/vulnerabilities"
            params = {"size": limit}
            
            if query:
                params["search"] = query
            if cve_id:
                params["vulnerability_id"] = cve_id
            if product:
                params["product"] = product
                
            return self.api_request(endpoint, params=params)
        else:
            # Fallback to web scraping
            logger.info("No API key available, using web scraping fallback")
            
            # If we have a CVE ID, we can directly fetch that
            if cve_id:
                return self.web_scrape_vulnerability(cve_id)
                
            # For keyword search, scrape the search results page
            url = "https://www.rapid7.com/db/search"
            params = {"utf8": "✓", "type": "nexpose", "q": query or product or ""}
            
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                
                html = response.text
                results = []
                
                # Extract vulnerability links
                vuln_matches = re.finditer(r'<a[^>]*href="(/db/vulnerabilities/[^"]+)"[^>]*>([^<]+)</a>', html)
                for match in vuln_matches:
                    href = match.group(1)
                    title = match.group(2).strip()
                    vuln_id = href.split('/')[-1]
                    
                    results.append({
                        "id": vuln_id,
                        "title": title,
                        "url": f"https://www.rapid7.com{href}"
                    })
                    
                    if len(results) >= limit:
                        break
                        
                return {
                    "query": query or product or "",
                    "results": results,
                    "count": len(results),
                    "source": "web_scrape"
                }
                
            except Exception as e:
                logger.error(f"Web scraping error: {str(e)}")
                return {"error": str(e)}
    
    def get_vulnerability(self, vulnerability_id):
        """Get detailed information about a specific vulnerability"""
        if self.api_key:
            # Use API if key is available
            endpoint = f"/vulnerabilities/{vulnerability_id}"
            return self.api_request(endpoint)
        else:
            # Fallback to web scraping
            return self.web_scrape_vulnerability(vulnerability_id)
    
    def search_exploits(self, query=None, cve_id=None, msf_module=None, limit=20):
        """Search for exploits in the Rapid7 database"""
        if self.api_key:
            # Use API if key is available
            endpoint = "/exploits"
            params = {"size": limit}
            
            if query:
                params["search"] = query
            if cve_id:
                params["cve"] = cve_id
            if msf_module:
                params["module"] = msf_module
                
            return self.api_request(endpoint, params=params, insight=True)
        else:
            # Fallback to web scraping
            logger.info("No API key available, using web scraping fallback")
            
            # Build search URL
            url = "https://www.rapid7.com/db/search"
            params = {"utf8": "✓", "type": "metasploit", "q": query or cve_id or msf_module or ""}
            
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                
                html = response.text
                results = []
                
                # Extract exploit links
                exploit_matches = re.finditer(r'<a[^>]*href="(/db/modules/[^"]+)"[^>]*>([^<]+)</a>', html)
                for match in exploit_matches:
                    href = match.group(1)
                    title = match.group(2).strip()
                    module_id = href.split('/')[-1]
                    
                    results.append({
                        "id": module_id,
                        "title": title,
                        "url": f"https://www.rapid7.com{href}"
                    })
                    
                    if len(results) >= limit:
                        break
                        
                return {
                    "query": query or cve_id or msf_module or "",
                    "results": results,
                    "count": len(results),
                    "source": "web_scrape"
                }
                
            except Exception as e:
                logger.error(f"Web scraping error: {str(e)}")
                return {"error": str(e)}
    
    def get_metasploit_modules(self, vulnerability_id=None, keyword=None):
        """Get Metasploit modules related to a vulnerability or keyword"""
        # Check if metasploit is installed
        if not self.metasploit_path:
            self.metasploit_path = shutil.which("msfconsole")
            
        if not self.metasploit_path:
            return {"error": "Metasploit not found in PATH"}
            
        # Create temporary script file
        script_file = os.path.join(tempfile.gettempdir(), f"msf_search_{int(time.time())}.rc")
        output_file = os.path.join(tempfile.gettempdir(), f"msf_output_{int(time.time())}.txt")
        
        # Prepare search command
        search_term = keyword or vulnerability_id or ""
        
        with open(script_file, 'w') as f:
            f.write(f"search {search_term}\n")
            f.write("exit\n")
            
        # Run Metasploit search
        try:
            cmd = f"{self.metasploit_path} -q -r {script_file} > {output_file} 2>&1"
            
            logger.info(f"Running Metasploit search for: {search_term}")
            result = subprocess.run(cmd, shell=True, timeout=60)
            
            if result.returncode != 0:
                logger.warning(f"Metasploit search returned non-zero exit code: {result.returncode}")
                
            # Parse output
            modules = []
            if os.path.exists(output_file):
                with open(output_file, 'r', errors='ignore') as f:
                    output = f.read()
                    
                # Extract module information
                for line in output.splitlines():
                    if " - " in line:
                        try:
                            # Parse module name and description
                            parts = line.split(" - ", 1)
                            if len(parts) == 2:
                                module_path = parts[0].strip()
                                module_desc = parts[1].strip()
                                
                                # Skip non-module lines
                                if module_path.startswith("#") or module_path.startswith("="):
                                    continue
                                    
                                # Extract type (exploit, auxiliary, etc)
                                module_type = module_path.split("/")[0] if "/" in module_path else "unknown"
                                
                                modules.append({
                                    "path": module_path,
                                    "description": module_desc,
                                    "type": module_type
                                })
                        except:
                            pass
                            
            # Clean up temp files
            try:
                os.remove(script_file)
                os.remove(output_file)
            except:
                pass
                
            return {
                "search_term": search_term,
                "modules": modules,
                "count": len(modules)
            }
            
        except Exception as e:
            logger.error(f"Metasploit search error: {str(e)}")
            
            # Clean up temp files
            try:
                os.remove(script_file)
                os.remove(output_file)
            except:
                pass
                
            return {"error": str(e)}
    
    def get_vulnerability_details_and_exploits(self, vulnerability_id):
        """Combined method to get both vulnerability details and available exploits"""
        # Get vulnerability details
        vuln_details = self.get_vulnerability(vulnerability_id)
        
        # Get related exploits if Metasploit is available
        exploits = self.get_metasploit_modules(vulnerability_id)
        
        # Combine results
        return {
            "vulnerability": vuln_details,
            "exploits": exploits
        }
        
    def web_scrape_exploit(self, module_id):
        """Scrape exploit details from Rapid7 website (fallback method)"""
        # This is a fallback method when API key is not available
        url = f"https://www.rapid7.com/db/modules/{module_id}"
            
        try:
            logger.info(f"Scraping exploit details from {url}")
            response = requests.get(url)
            response.raise_for_status()
            
            # Simple HTML parsing to extract basic information
            html = response.text
            data = {}
            
            # Extract title
            title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
            if title_match:
                data["title"] = title_match.group(1).strip()
                
            # Extract description
            desc_match = re.search(r'<div[^>]*class="[^"]*description-body[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            if desc_match:
                desc_html = desc_match.group(1)
                # Simple HTML to text conversion
                desc_text = re.sub(r'<[^>]+>', ' ', desc_html)
                desc_text = re.sub(r'\s+', ' ', desc_text).strip()
                data["description"] = desc_text
                
            # Extract module path
            path_match = re.search(r'Module Name:.*?<code>([^<]+)</code>', html, re.DOTALL)
            if path_match:
                data["module_path"] = path_match.group(1).strip()
                
            # Extract references
            references = []
            ref_matches = re.finditer(r'<a[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', html)
            for match in ref_matches:
                href = match.group(1)
                text = match.group(2).strip()
                if "rapid7.com/db" not in href and text and len(text) > 5:
                    references.append({"url": href, "title": text})
                    
            data["references"] = references
            
            # Extract CVEs
            cves = []
            cve_matches = re.finditer(r'>(CVE-\d{4}-\d{4,})<', html)
            for match in cve_matches:
                cve_id = match.group(1)
                if cve_id not in cves:
                    cves.append(cve_id)
                    
            data["cves"] = cves
            
            return {
                "module_id": module_id,
                "data": data,
                "source": "web_scrape"
            }
            
        except Exception as e:
            logger.error(f"Web scraping error: {str(e)}")
            return {"error": str(e), "module_id": module_id}
            
    def get_exploit(self, module_id):
        """Get detailed information about a specific Metasploit module/exploit"""
        if self.api_key:
            # Use API if key is available
            endpoint = f"/modules/{module_id}"
            return self.api_request(endpoint, insight=True)
        else:
            # Fallback to web scraping
            return self.web_scrape_exploit(module_id) 