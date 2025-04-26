#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import requests
import re
import socket
import dns.resolver
import whois
import shodan
import censys.search
import time
import argparse
import logging
from bs4 import BeautifulSoup
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('OSINTTools')

class OSINTTools:
    """
    OSINT (Open Source Intelligence) tools for gathering information 
    from publicly available sources about targets
    """
    
    def __init__(self, target=None, output_dir="results", api_keys=None):
        self.target = target
        self.output_dir = output_dir
        self.api_keys = api_keys or {}
        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "domain_info": {},
            "whois_data": {},
            "dns_records": {},
            "web_technologies": {},
            "email_harvesting": {},
            "social_media_presence": {},
            "data_breaches": {},
            "geolocation": {},
            "shodan_data": {},
            "censys_data": {}
        }
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        logger.info(f"Initialized OSINTTools for target: {target}")
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def gather_domain_info(self, domain=None):
        """
        Gather basic information about a domain
        
        Args:
            domain: Target domain name
            
        Returns:
            dict: Domain information results
        """
        domain = domain or self.target
        if not domain:
            logger.error("No domain specified for domain info gathering")
            return {"error": "No domain specified"}
        
        logger.info(f"Gathering domain information for {domain}")
        
        try:
            parsed_domain = urlparse(domain)
            if not parsed_domain.scheme:
                domain = f"http://{domain}"
                parsed_domain = urlparse(domain)
            
            clean_domain = parsed_domain.netloc or parsed_domain.path
            
            result = {
                "domain": clean_domain,
                "ip_addresses": [],
                "http_status": None,
                "https_status": None,
                "redirects_to": None
            }
            
            # Get IP address
            try:
                result["ip_addresses"] = socket.gethostbyname_ex(clean_domain)[2]
            except socket.gaierror:
                pass
                
            # Check HTTP/HTTPS status
            for protocol in ["http", "https"]:
                url = f"{protocol}://{clean_domain}"
                try:
                    response = self.session.get(url, timeout=5, allow_redirects=False)
                    result[f"{protocol}_status"] = response.status_code
                    
                    if 300 <= response.status_code < 400 and 'Location' in response.headers:
                        result["redirects_to"] = response.headers['Location']
                except requests.RequestException:
                    pass
            
            self.results["domain_info"] = result
            logger.info(f"Completed domain information gathering for {domain}")
            return result
            
        except Exception as e:
            error_msg = f"Error gathering domain info: {str(e)}"
            logger.error(error_msg)
            self.results["domain_info"] = {"error": error_msg}
            return {"error": error_msg}
    
    def _find_subdomains(self, domain, use_apis=True):
        """
        Find subdomains using various techniques
        
        Args:
            domain: Target domain
            use_apis: Whether to use third-party APIs
            
        Returns:
            list: Discovered subdomains
        """
        subdomains = set()
        
        # Basic DNS enumeration
        for prefix in ["www", "mail", "ftp", "webmail", "login", "admin", "test", 
                      "dev", "staging", "api", "cdn", "shop", "blog"]:
            subdomain = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
            except socket.gaierror:
                pass
        
        # Use SecurityTrails API for subdomain discovery if key available
        if use_apis and "securitytrails" in self.api_keys:
            try:
                headers = {"apikey": self.api_keys["securitytrails"]}
                response = requests.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for subdomain in data.get("subdomains", []):
                        subdomains.add(f"{subdomain}.{domain}")
            except Exception as e:
                logger.warning(f"Error using SecurityTrails API: {str(e)}")
        
        # Use Certificate Transparency logs
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(ct_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "").lower()
                    # Extract valid subdomains
                    if name.endswith(f".{domain}") and name != f"*.{domain}":
                        subdomains.add(name)
        except Exception as e:
            logger.warning(f"Error using Certificate Transparency logs: {str(e)}")
        
        return list(subdomains)
    
    def perform_whois_lookup(self, domain=None):
        """
        Perform WHOIS lookup for domain registration information
        
        Args:
            domain: Target domain name
            
        Returns:
            dict: WHOIS data
        """
        domain = domain or self.target
        if not domain:
            logger.error("No domain specified for WHOIS lookup")
            return {"error": "No domain specified"}
        
        logger.info(f"Performing WHOIS lookup for {domain}")
        
        try:
            whois_data = whois.whois(domain)
            
            # Extract relevant data
            result = {
                "domain": domain,
                "registrar": whois_data.registrar,
                "creation_date": self._format_date(whois_data.creation_date),
                "expiration_date": self._format_date(whois_data.expiration_date),
                "updated_date": self._format_date(whois_data.updated_date),
                "name_servers": whois_data.name_servers,
                "status": whois_data.status,
                "emails": whois_data.emails,
                "dnssec": whois_data.dnssec,
                "registrant": {
                    "name": whois_data.get("registrant_name", None),
                    "organization": whois_data.get("registrant_org", None),
                    "country": whois_data.get("registrant_country", None)
                },
                "admin": {
                    "name": whois_data.get("admin_name", None),
                    "organization": whois_data.get("admin_org", None),
                    "country": whois_data.get("admin_country", None),
                    "email": whois_data.get("admin_email", None)
                },
                "tech": {
                    "name": whois_data.get("tech_name", None),
                    "organization": whois_data.get("tech_org", None),
                    "country": whois_data.get("tech_country", None),
                    "email": whois_data.get("tech_email", None)
                }
            }
            
            # Clean up None values
            result = self._clean_dict(result)
            
            self.results["whois_data"] = result
            logger.info(f"Completed WHOIS lookup for {domain}")
            return result
            
        except Exception as e:
            error_msg = f"Error during WHOIS lookup: {str(e)}"
            logger.error(error_msg)
            self.results["whois_data"] = {"error": error_msg}
            return {"error": error_msg}
    
    def _format_date(self, date_obj):
        """Format datetime objects for JSON serialization"""
        if date_obj is None:
            return None
        if isinstance(date_obj, list):
            return [d.strftime("%Y-%m-%d %H:%M:%S") if hasattr(d, 'strftime') else str(d) for d in date_obj]
        return date_obj.strftime("%Y-%m-%d %H:%M:%S") if hasattr(date_obj, 'strftime') else str(date_obj)
    
    def _clean_dict(self, d):
        """Remove None values from dictionary for cleaner output"""
        if isinstance(d, dict):
            return {k: self._clean_dict(v) for k, v in d.items() if v is not None}
        return d
    
    def query_dns_records(self, domain=None, record_types=None):
        """
        Query various DNS record types for a domain
        
        Args:
            domain: Target domain name
            record_types: List of DNS record types to query
            
        Returns:
            dict: DNS records by type
        """
        domain = domain or self.target
        if not domain:
            logger.error("No domain specified for DNS records query")
            return {"error": "No domain specified"}
        
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA']
            
        logger.info(f"Querying DNS records for {domain}")
        
        results = {"domain": domain}
        
        try:
            resolver = dns.resolver.Resolver()
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    results[record_type] = [str(answer) for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    results[record_type] = []
                except Exception as e:
                    results[record_type] = [f"Error: {str(e)}"]
            
            # SPF record special handling (typically in TXT records)
            spf_records = []
            if 'TXT' in results:
                for txt in results['TXT']:
                    if txt.startswith('"v=spf1') or txt.startswith('v=spf1'):
                        spf_records.append(txt)
            results['SPF'] = spf_records
            
            # DMARC record
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
                results['DMARC'] = [str(answer) for answer in dmarc_answers 
                                  if 'v=DMARC1' in str(answer)]
            except Exception:
                results['DMARC'] = []
            
            self.results["dns_records"] = results
            logger.info(f"Completed DNS records query for {domain}")
            return results
            
        except Exception as e:
            error_msg = f"Error querying DNS records: {str(e)}"
            logger.error(error_msg)
            self.results["dns_records"] = {"error": error_msg}
            return {"error": error_msg}
    
    def detect_web_technologies(self, url=None):
        """
        Detect technologies used on a website
        
        Args:
            url: Target URL (with protocol)
            
        Returns:
            dict: Detected web technologies
        """
        domain = self.target
        url = url or (f"https://{domain}" if domain else None)
        if not url:
            logger.error("No URL specified for web technology detection")
            return {"error": "No URL specified"}
        
        logger.info(f"Detecting web technologies for {url}")
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            
            technologies = {
                "server": response.headers.get('Server', 'Unknown'),
                "x_powered_by": response.headers.get('X-Powered-By', None),
                "technologies": [],
                "javascript_libraries": [],
                "analytics": [],
                "cms": None,
                "headers": dict(response.headers)
            }
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for common technologies based on HTML patterns
            
            # JavaScript libraries
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script['src'].lower()
                if 'jquery' in src:
                    technologies["javascript_libraries"].append("jQuery")
                elif 'react' in src:
                    technologies["javascript_libraries"].append("React")
                elif 'angular' in src:
                    technologies["javascript_libraries"].append("Angular")
                elif 'vue' in src:
                    technologies["javascript_libraries"].append("Vue.js")
                elif 'bootstrap' in src:
                    technologies["javascript_libraries"].append("Bootstrap")
            
            # Analytics
            if "google-analytics.com" in response.text or "gtag" in response.text:
                technologies["analytics"].append("Google Analytics")
            if "googletagmanager" in response.text:
                technologies["analytics"].append("Google Tag Manager")
            
            # CMS detection
            if soup.select('meta[name="generator"]'):
                generator = soup.select_one('meta[name="generator"]')['content']
                technologies["cms"] = generator
            elif "wp-content" in response.text:
                technologies["cms"] = "WordPress"
            elif "drupal" in response.text:
                technologies["cms"] = "Drupal"
            elif "joomla" in response.text:
                technologies["cms"] = "Joomla"
            
            # Remove duplicate entries and clean up
            technologies["javascript_libraries"] = list(set(technologies["javascript_libraries"]))
            technologies["analytics"] = list(set(technologies["analytics"]))
            
            # Clean up None values
            technologies = self._clean_dict(technologies)
            
            self.results["web_technologies"] = technologies
            logger.info(f"Completed web technology detection for {url}")
            return technologies
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error requesting {url}: {str(e)}"
            logger.error(error_msg)
            self.results["web_technologies"] = {"error": error_msg}
            return {"error": error_msg}
        except Exception as e:
            error_msg = f"Error detecting web technologies: {str(e)}"
            logger.error(error_msg)
            self.results["web_technologies"] = {"error": error_msg}
            return {"error": error_msg}
    
    def harvest_email_addresses(self, domain=None, search_depth=1):
        """
        Harvest email addresses related to a domain from various sources
        
        Args:
            domain: Target domain name
            search_depth: How deep to search (1-3)
            
        Returns:
            dict: Harvested email addresses
        """
        domain = domain or self.target
        if not domain:
            logger.error("No domain specified for email harvesting")
            return {"error": "No domain specified"}
        
        logger.info(f"Harvesting email addresses for {domain} with depth {search_depth}")
        
        results = {
            "domain": domain,
            "emails": [],
            "sources": {}
        }
        
        try:
            # Collect pages to scan
            pages_to_scan = [f"https://{domain}"]
            
            # Add common contact pages
            for path in ['/contact', '/about', '/about-us', '/team', '/staff', '/support']:
                pages_to_scan.append(f"https://{domain}{path}")
            
            # Process pages for emails
            all_emails = set()
            page_emails = {}
            
            for page_url in pages_to_scan:
                try:
                    emails = self._extract_emails_from_page(page_url)
                    if emails:
                        page_emails[page_url] = list(emails)
                        all_emails.update(emails)
                except Exception as e:
                    logger.warning(f"Error processing {page_url}: {str(e)}")
            
            # Process WHOIS data if available
            if self.results["whois_data"] and "error" not in self.results["whois_data"]:
                whois_emails = []
                whois_data = self.results["whois_data"]
                
                if "emails" in whois_data and whois_data["emails"]:
                    if isinstance(whois_data["emails"], list):
                        whois_emails.extend(whois_data["emails"])
                    else:
                        whois_emails.append(whois_data["emails"])
                
                for contact_type in ["registrant", "admin", "tech"]:
                    if contact_type in whois_data and "email" in whois_data[contact_type]:
                        email = whois_data[contact_type]["email"]
                        if email:
                            whois_emails.append(email)
                
                if whois_emails:
                    page_emails["WHOIS Data"] = whois_emails
                    all_emails.update(whois_emails)
            
            # Only search Google if we have API key and deeper search is requested
            if search_depth > 1 and "google_api" in self.api_keys:
                google_emails = self._search_emails_google(domain)
                if google_emails:
                    page_emails["Google Search"] = list(google_emails)
                    all_emails.update(google_emails)
            
            # Format the results
            results["emails"] = sorted(list(all_emails))
            results["sources"] = page_emails
            results["count"] = len(results["emails"])
            
            self.results["email_harvesting"] = results
            logger.info(f"Completed email harvesting, found {len(results['emails'])} addresses")
            return results
            
        except Exception as e:
            error_msg = f"Error during email harvesting: {str(e)}"
            logger.error(error_msg)
            self.results["email_harvesting"] = {"error": error_msg}
            return {"error": error_msg}
    
    def _extract_emails_from_page(self, url):
        """Extract email addresses from a web page"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                return set()
            
            # Regular expression for email extraction
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = set(re.findall(email_pattern, response.text))
            
            # Filter out common false positives
            emails = {e for e in emails if not e.endswith(('.png', '.jpg', '.gif'))}
            
            return emails
        except requests.exceptions.RequestException:
            return set()
    
    def _search_emails_google(self, domain):
        """Search for emails using Google Custom Search API"""
        try:
            api_key = self.api_keys.get("google_api", {}).get("api_key")
            cx = self.api_keys.get("google_api", {}).get("cx")
            
            if not api_key or not cx:
                return set()
            
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": api_key,
                "cx": cx,
                "q": f"\"@{domain}\" email contact",
                "num": 10
            }
            
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            emails = set()
            if "items" in data:
                for item in data["items"]:
                    snippet = item.get("snippet", "")
                    found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), snippet)
                    emails.update(found)
            
            return emails
        except Exception:
            return set()
    
    def check_social_media_presence(self, company_name=None):
        """
        Check for presence on social media platforms
        
        Args:
            company_name: Name of the company/organization to check
            
        Returns:
            dict: Social media presence information
        """
        company_name = company_name or self.target.split('.')[0]
        if not company_name:
            logger.error("No company name specified for social media check")
            return {"error": "No company name specified"}
        
        logger.info(f"Checking social media presence for '{company_name}'")
        
        platforms = {
            "facebook": f"https://www.facebook.com/{company_name}",
            "twitter": f"https://www.twitter.com/{company_name}",
            "linkedin": f"https://www.linkedin.com/company/{company_name}",
            "instagram": f"https://www.instagram.com/{company_name}",
            "youtube": f"https://www.youtube.com/c/{company_name}",
            "github": f"https://github.com/{company_name}"
        }
        
        results = {
            "company_name": company_name,
            "platforms": {}
        }
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            for platform, url in platforms.items():
                try:
                    response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                    
                    # Different platforms have different indicators of existence
                    if platform == "linkedin":
                        exists = response.status_code == 200 and "Page not found" not in response.text
                    elif platform == "twitter":
                        exists = response.status_code == 200 and "This account doesn't exist" not in response.text
                    else:
                        exists = response.status_code == 200
                    
                    results["platforms"][platform] = {
                        "url": url,
                        "exists": exists,
                        "status_code": response.status_code
                    }
                    
                except Exception as e:
                    results["platforms"][platform] = {
                        "url": url,
                        "exists": False,
                        "error": str(e)
                    }
                
                # Be nice to servers - don't hit them too quickly
                time.sleep(1)
            
            self.results["social_media_presence"] = results
            logger.info(f"Completed social media presence check for '{company_name}'")
            return results
            
        except Exception as e:
            error_msg = f"Error checking social media presence: {str(e)}"
            logger.error(error_msg)
            self.results["social_media_presence"] = {"error": error_msg}
            return {"error": error_msg}
    
    def check_data_breaches(self, domain=None):
        """
        Check if the domain or associated email addresses appear in known data breaches
        
        Args:
            domain: Target domain name
            
        Returns:
            dict: Data breach information
        """
        domain = domain or self.target
        if not domain:
            logger.error("No domain specified for data breach check")
            return {"error": "No domain specified"}
        
        logger.info(f"Checking data breaches for {domain}")
        
        results = {
            "domain": domain,
            "breach_data": [],
            "api_used": None
        }
        
        try:
            if "hibp" in self.api_keys:
                # Have I Been Pwned API integration
                hibp_key = self.api_keys["hibp"]
                results["api_used"] = "haveibeenpwned"
                
                headers = {
                    "hibp-api-key": hibp_key,
                    "User-Agent": "OSINT Security Scanner"
                }
                
                # Query HIBP for the domain
                response = requests.get(
                    f"https://haveibeenpwned.com/api/v3/breaches",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    all_breaches = response.json()
                    domain_breaches = [b for b in all_breaches if domain in b.get("Domain", "")]
                    
                    for breach in domain_breaches:
                        results["breach_data"].append({
                            "name": breach["Name"],
                            "title": breach["Title"],
                            "domain": breach["Domain"],
                            "breach_date": breach["BreachDate"],
                            "pwn_count": breach["PwnCount"],
                            "data_classes": breach["DataClasses"],
                            "description": breach["Description"]
                        })
            else:
                # No API key - simulate a search with dummy data and disclaimer
                results["api_used"] = "simulation"
                results["note"] = "No breach API key provided - this is simulated data for demonstration purposes only"
                
                results["breach_data"].append({
                    "name": "ExampleBreach",
                    "title": "Example Breach (SIMULATED)",
                    "domain": domain,
                    "breach_date": "2021-01-01",
                    "pwn_count": 1000,
                    "data_classes": ["Email addresses", "Passwords"],
                    "description": "This is a simulated breach entry for demonstration purposes only."
                })
            
            self.results["data_breaches"] = results
            logger.info(f"Completed data breach check for {domain}, found {len(results['breach_data'])} breaches")
            return results
            
        except Exception as e:
            error_msg = f"Error checking data breaches: {str(e)}"
            logger.error(error_msg)
            self.results["data_breaches"] = {"error": error_msg}
            return {"error": error_msg}
    
    def find_geolocation(self, ip_address=None):
        """
        Find geolocation information for an IP address
        
        Args:
            ip_address: Target IP address
            
        Returns:
            dict: Geolocation information
        """
        if not ip_address:
            # Try to get IP from domain info results
            if self.results["domain_info"] and "ip_addresses" in self.results["domain_info"]:
                ip_address = self.results["domain_info"]["ip_addresses"][0]
            else:
                try:
                    ip_address = socket.gethostbyname(self.target)
                except Exception:
                    logger.error("No IP address available for geolocation")
                    return {"error": "No IP address available"}
        
        logger.info(f"Finding geolocation for IP {ip_address}")
        
        try:
            # Use ipinfo.io API (doesn't require API key for basic usage)
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if "bogon" in data and data["bogon"]:
                    return {
                        "ip": ip_address,
                        "is_bogon": True,
                        "note": "This is a reserved/private IP address and does not have public geolocation information"
                    }
                
                # Format coordinates
                if "loc" in data and data["loc"]:
                    lat, lon = data["loc"].split(",")
                    coordinates = {"latitude": lat, "longitude": lon}
                else:
                    coordinates = None
                
                geo_data = {
                    "ip": ip_address,
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "coordinates": coordinates,
                    "isp": data.get("org"),
                    "hostname": data.get("hostname"),
                    "timezone": data.get("timezone")
                }
                
                # Clean up None values
                geo_data = self._clean_dict(geo_data)
                
                self.results["geolocation"] = geo_data
                logger.info(f"Completed geolocation lookup for {ip_address}")
                return geo_data
            else:
                error_msg = f"Error from geolocation API: {response.status_code}"
                logger.error(error_msg)
                self.results["geolocation"] = {"error": error_msg}
                return {"error": error_msg}
                
        except Exception as e:
            error_msg = f"Error finding geolocation: {str(e)}"
            logger.error(error_msg)
            self.results["geolocation"] = {"error": error_msg}
            return {"error": error_msg}
    
    def query_shodan(self, target=None):
        """
        Query Shodan for information about a host
        
        Args:
            target: IP address or hostname
            
        Returns:
            dict: Shodan information
        """
        target = target or self.target
        if not target:
            logger.error("No target specified for Shodan query")
            return {"error": "No target specified"}
        
        # Try to resolve hostname to IP if needed
        try:
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
                ip_address = socket.gethostbyname(target)
            else:
                ip_address = target
        except socket.gaierror:
            error_msg = f"Could not resolve hostname {target}"
            logger.error(error_msg)
            self.results["shodan_data"] = {"error": error_msg}
            return {"error": error_msg}
        
        logger.info(f"Querying Shodan for {ip_address}")
        
        if "shodan" not in self.api_keys:
            error_msg = "No Shodan API key provided"
            logger.error(error_msg)
            self.results["shodan_data"] = {
                "error": error_msg,
                "note": "This is simulated Shodan data for demonstration",
                "ip": ip_address,
                "simulation": True,
                "ports": [80, 443, 22],
                "hostnames": [target if target != ip_address else "example.com"],
                "country": "Unknown"
            }
            return self.results["shodan_data"]
        
        try:
            api = shodan.Shodan(self.api_keys["shodan"])
            results = api.host(ip_address)
            
            shodan_data = {
                "ip": ip_address,
                "hostnames": results.get("hostnames", []),
                "domains": results.get("domains", []),
                "country": results.get("country_name", "Unknown"),
                "city": results.get("city", "Unknown"),
                "organization": results.get("org", "Unknown"),
                "isp": results.get("isp", "Unknown"),
                "last_update": results.get("last_update", "Unknown"),
                "ports": results.get("ports", []),
                "vulnerabilities": results.get("vulns", []),
                "services": []
            }
            
            # Process services/banners
            for service in results.get("data", []):
                service_info = {
                    "port": service.get("port"),
                    "protocol": service.get("transport", "Unknown"),
                    "product": service.get("product", "Unknown"),
                    "version": service.get("version", "Unknown"),
                    "cpe": service.get("cpe", []),
                    "module": service.get("_shodan", {}).get("module")
                }
                shodan_data["services"].append(service_info)
            
            self.results["shodan_data"] = shodan_data
            logger.info(f"Completed Shodan query for {ip_address}, found {len(shodan_data['ports'])} ports")
            return shodan_data
            
        except shodan.APIError as e:
            error_msg = f"Shodan API Error: {str(e)}"
            logger.error(error_msg)
            self.results["shodan_data"] = {"error": error_msg}
            return {"error": error_msg}
        except Exception as e:
            error_msg = f"Error during Shodan query: {str(e)}"
            logger.error(error_msg)
            self.results["shodan_data"] = {"error": error_msg}
            return {"error": error_msg}
    
    def query_censys(self, target=None):
        """
        Query Censys for host information
        
        Args:
            target: IP address or hostname
            
        Returns:
            dict: Censys information
        """
        target = target or self.target
        if not target:
            logger.error("No target specified for Censys query")
            return {"error": "No target specified"}
        
        # Try to resolve hostname to IP if needed
        try:
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
                ip_address = socket.gethostbyname(target)
            else:
                ip_address = target
        except socket.gaierror:
            error_msg = f"Could not resolve hostname {target}"
            logger.error(error_msg)
            self.results["censys_data"] = {"error": error_msg}
            return {"error": error_msg}
        
        logger.info(f"Querying Censys for {ip_address}")
        
        if "censys" not in self.api_keys or not isinstance(self.api_keys["censys"], dict):
            error_msg = "No Censys API credentials provided"
            logger.error(error_msg)
            self.results["censys_data"] = {
                "error": error_msg,
                "note": "This is simulated Censys data for demonstration",
                "ip": ip_address,
                "simulation": True,
                "ports": [80, 443],
                "protocols": ["https", "http"]
            }
            return self.results["censys_data"]
        
        try:
            api_id = self.api_keys["censys"].get("api_id")
            api_secret = self.api_keys["censys"].get("api_secret")
            
            if not api_id or not api_secret:
                raise ValueError("Incomplete Censys API credentials")
            
            # Initialize Censys API
            censys_api = censys.search.CensysIPv4(api_id=api_id, api_secret=api_secret)
            result = censys_api.view(ip_address)
            
            censys_data = {
                "ip": ip_address,
                "location": {
                    "country": result.get("location", {}).get("country", "Unknown"),
                    "continent": result.get("location", {}).get("continent", "Unknown"),
                    "timezone": result.get("location", {}).get("timezone", "Unknown")
                },
                "autonomous_system": {
                    "name": result.get("autonomous_system", {}).get("name"),
                    "asn": result.get("autonomous_system", {}).get("asn")
                },
                "ports": result.get("ports", []),
                "protocols": result.get("protocols", []),
                "services": {}
            }
            
            # Process services by port
            for protocol in result.get("protocols", []):
                if "." in protocol:
                    proto_name, port = protocol.split(".")
                    service_data = result.get(proto_name, {}).get(port, {})
                    
                    if service_data:
                        censys_data["services"][port] = {
                            "protocol": proto_name,
                            "service_name": service_data.get("service_name", "Unknown"),
                            "banner": service_data.get("banner", "")
                        }
                        
                        # Add TLS data if available
                        if "tls" in service_data:
                            censys_data["services"][port]["tls"] = {
                                "certificate": {
                                    "issuer": service_data["tls"].get("certificate", {}).get("issuer", {}),
                                    "subject": service_data["tls"].get("certificate", {}).get("subject", {}),
                                    "validity": service_data["tls"].get("certificate", {}).get("validity", {})
                                },
                                "cipher": service_data["tls"].get("cipher", {}).get("name", "Unknown"),
                                "version": service_data["tls"].get("version", "Unknown")
                            }
            
            self.results["censys_data"] = censys_data
            logger.info(f"Completed Censys query for {ip_address}")
            return censys_data
            
        except Exception as e:
            error_msg = f"Error during Censys query: {str(e)}"
            logger.error(error_msg)
            self.results["censys_data"] = {"error": error_msg}
            return {"error": error_msg}
    
    def run_all_osint(self, target=None):
        """
        Run all OSINT gathering methods in sequence
        
        Args:
            target: Target domain or IP to analyze
            
        Returns:
            dict: Complete OSINT results
        """
        if target:
            self.target = target
            self.results["target"] = target
            
        if not self.target:
            logger.error("No target specified for OSINT gathering")
            return {"error": "No target specified"}
            
        logger.info(f"Starting comprehensive OSINT gathering for {self.target}")
        
        # Basic domain-related info
        self.gather_domain_info()
        self.perform_whois_lookup()
        self.query_dns_records()
        
        # Web and services analysis
        if self.results["domain_info"] and "error" not in self.results["domain_info"]:
            if "http_status" in self.results["domain_info"] and self.results["domain_info"]["http_status"]:
                url = f"https://{self.target}" if self.results["domain_info"]["https_status"] else f"http://{self.target}"
                self.detect_web_technologies(url)
        
        # Additional intelligence gathering
        self.harvest_email_addresses()
        company_name = self.target.split('.')[0] if self.target else None
        if company_name:
            self.check_social_media_presence(company_name)
        self.check_data_breaches()
        
        # Network intelligence
        if self.results["domain_info"] and "ip_addresses" in self.results["domain_info"]:
            ip = self.results["domain_info"]["ip_addresses"][0]
            self.find_geolocation(ip)
            self.query_shodan(ip)
            self.query_censys(ip)
        
        # Save results to file
        self.save_results()
        
        logger.info(f"Completed all OSINT gathering for {self.target}")
        return self.results
    
    def save_results(self, filename=None):
        """
        Save OSINT results to JSON file
        
        Args:
            filename: Custom filename (default: target_osint_TIMESTAMP.json)
            
        Returns:
            str: Path to saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self.target.replace(".", "_") if self.target else "unknown"
            filename = f"{target_name}_osint_{timestamp}.json"
            
        file_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(file_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Saved OSINT results to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
            return None

# Add OSINTScanner class that imports the OSINTTools class
class OSINTScanner:
    """
    Wrapper around OSINTTools to provide compatibility with modules 
    that expect an OSINTScanner class.
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
        self.scan_time = datetime.now()
        
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
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
        print("Usage: python osint_tools.py [target_domain_or_ip]") 