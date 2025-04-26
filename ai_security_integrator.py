#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import time
import datetime
import requests
from urllib.parse import urlparse
import dotenv
import random  # For simulation

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ai_security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AISecurityIntegrator")

# Load environment variables for API keys
dotenv.load_dotenv(".env")

class AISecurityIntegrator:
    """
    AI Security Integrator
    
    Enhances vulnerability scanning with AI-powered analysis:
    1. Analyzes vulnerabilities discovered by other tools
    2. Determines exploitation conditions and paths
    3. Assesses potential impact and damage
    4. Generates detailed remediation strategies
    5. Creates comprehensive reports
    """
    
    def __init__(self, target, output_dir="ai_security_reports"):
        self.target_url = target
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get API keys from environment variables
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        
        # Additional security tool API keys
        self.owasp_ai_scanner_key = os.getenv("OWASP_AI_SCANNER_KEY")
        self.arachni_ai_key = os.getenv("ARACHNI_AI_KEY")
        self.deep_exploit_key = os.getenv("DEEP_EXPLOIT_KEY")
        self.seclists_ai_key = os.getenv("SECLISTS_AI_KEY")
        self.ai_fuzzer_key = os.getenv("AI_FUZZER_KEY")
        self.neural_recon_key = os.getenv("NEURAL_RECON_KEY")
        self.ai_security_key = os.getenv("AI_SECURITY_API_KEY")
        
        logger.info(f"Initialized AISecurityIntegrator for target: {target}")
        
        # Check if we have required API keys
        self.ai_providers = []
        if self.openai_api_key:
            self.ai_providers.append("openai")
        if self.anthropic_api_key:
            self.ai_providers.append("anthropic")
        if self.gemini_api_key:
            self.ai_providers.append("gemini")
            
        if not self.ai_providers:
            logger.warning("No AI API keys provided. Operating in simulation mode.")
        else:
            logger.info(f"Using AI providers: {', '.join(self.ai_providers)}")
    
    def _get_ai_client(self, provider=None):
        """Get an AI client for the specified provider or a random available provider"""
        if not provider and self.ai_providers:
            provider = random.choice(self.ai_providers)
        
        if provider == "openai" and self.openai_api_key:
            try:
                import openai
                openai.api_key = self.openai_api_key
                return openai
            except ImportError:
                logger.error("OpenAI package not installed")
        
        elif provider == "anthropic" and self.anthropic_api_key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=self.anthropic_api_key)
                return client
            except ImportError:
                logger.error("Anthropic package not installed")
        
        elif provider == "gemini" and self.gemini_api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_api_key)
                return genai
            except ImportError:
                logger.error("Google Generative AI package not installed")
        
        logger.warning(f"AI provider {provider} not available, using simulation mode")
        return None
    
    def _ai_request(self, prompt, provider=None, temperature=0.1):
        """Make a request to the AI provider with the given prompt"""
        client = self._get_ai_client(provider)
        
        if not client:
            # Simulate AI response for testing
            return self._simulate_ai_response(prompt)
        
        try:
            if provider == "openai":
                response = client.ChatCompletion.create(
                    model="gpt-4-turbo",
                    messages=[{"role": "system", "content": "You are a cybersecurity expert analyzing web vulnerabilities."},
                              {"role": "user", "content": prompt}],
                    temperature=temperature
                )
                return response.choices[0].message.content
            
            elif provider == "anthropic":
                response = client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=2000,
                    temperature=temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            
            elif provider == "gemini":
                response = client.generate_text(
                    model="gemini-pro",
                    prompt=prompt,
                    temperature=temperature
                )
                return response.text
            
            return self._simulate_ai_response(prompt)
            
        except Exception as e:
            logger.error(f"Error making AI request: {str(e)}")
            return self._simulate_ai_response(prompt)
    
    def _simulate_ai_response(self, prompt):
        """Simulate an AI response for testing without API keys"""
        logger.info("Simulating AI response")
        
        # Extract key words from prompt to generate contextual responses
        
        if "analyze" in prompt.lower() and "vulnerabilities" in prompt.lower():
            return """
Based on the identified vulnerabilities, I've conducted a detailed analysis:

1. SQL Injection vulnerabilities appear to be exploitable under standard conditions. The application does not properly sanitize user input in query parameters, allowing attackers to modify SQL query logic.

2. XSS vulnerabilities manifest when user input is reflected in the response without proper encoding. These can be exploited in any modern browser that executes JavaScript.

3. Authentication weaknesses suggest improper session management and potentially weak password policies. These become exploitable when attackers can make multiple authentication attempts without rate limiting.

These vulnerabilities represent significant security risks that should be addressed immediately.
            """
        
        elif "exploitation" in prompt.lower() and "path" in prompt.lower():
            return """
Exploitation paths for the identified vulnerabilities:

1. SQL Injection:
   - Attacker enters malicious input like `' OR 1=1 --` in the login form
   - The application constructs an SQL query without sanitization
   - The database executes the modified query, bypassing authentication
   - Attacker gains unauthorized access to the application

2. XSS (Reflected):
   - Attacker crafts a URL with malicious script tags
   - Victim is socially engineered to click on the link
   - When loaded, the malicious script executes in the victim's browser
   - Script can steal cookies, session tokens, or redirect to phishing sites

3. Authentication Bypass:
   - Attacker identifies weak password reset functionality
   - Through predictable tokens or insufficient validation, attacker initiates password reset
   - Attacker gains unauthorized access to user accounts
   
Each path represents how these vulnerabilities could be chained for maximum impact on the system.
            """
        
        elif "remediation" in prompt.lower() or "recommendation" in prompt.lower():
            return """
Recommended remediation strategies:

1. SQL Injection:
   - Implement parameterized queries/prepared statements
   - Apply input validation with strict type checking
   - Use ORM frameworks that handle SQL escaping
   - Apply principle of least privilege to database users
   - Code example: Replace `"SELECT * FROM users WHERE username='" + username + "'"` with parameterized version

2. XSS:
   - Implement context-specific output encoding
   - Use Content-Security-Policy headers
   - Validate all user input on the server-side
   - Consider using modern frameworks with built-in XSS protection
   - Example fix: Use `htmlspecialchars()` in PHP or equivalent in your framework

3. Authentication:
   - Implement multi-factor authentication
   - Use strong password policies
   - Implement proper session management
   - Add rate-limiting and account lockout mechanisms
   - Use secure, HttpOnly, SameSite cookies

Additional recommendations include regular security testing, developer security training, and implementing a web application firewall as an extra layer of protection.
            """
        
        # Default response
        return """
Based on the vulnerability data, I've analyzed the security posture of the application.
The findings indicate several critical vulnerabilities that require immediate attention.
These issues could potentially allow unauthorized access, data theft, or service disruption if exploited.
Implementing the recommended fixes should significantly improve the application's security posture.
            """
    
    def analyze_vulnerabilities(self, vulnerabilities):
        """Analyze vulnerabilities to determine their conditions and impact"""
        logger.info("Analyzing vulnerabilities with AI")
        
        if not vulnerabilities:
            return {"analysis": "No vulnerabilities found to analyze"}
        
        # Prepare data for AI analysis
        vulnerabilities_json = json.dumps(vulnerabilities, indent=2)
        
        prompt = f"""
As a cybersecurity expert, analyze the following vulnerabilities found in a web application:

{vulnerabilities_json}

For each vulnerability type:
1. Explain the conditions under which this vulnerability can be exploited
2. Describe the potential impact if exploited
3. Rate the severity and exploitability
4. Explain how this vulnerability could be combined with others for a more severe attack

Provide a detailed technical analysis in JSON format with the following structure:
{{
  "vulnerability_types": [
    {{
      "type": "...",
      "exploitation_conditions": "...",
      "impact": "...",
      "severity": "...",
      "exploitability": "...",
      "potential_chains": "..."
    }}
  ],
  "overall_assessment": "..."
}}
"""
        
        # Get AI analysis
        ai_response = self._ai_request(prompt)
        
        try:
            # Try to extract JSON from the response
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                analysis = json.loads(json_str)
                return analysis
            else:
                # If we can't parse JSON, return the raw response
                return {"analysis": ai_response}
        except Exception as e:
            logger.error(f"Error parsing AI analysis: {str(e)}")
            return {"analysis": ai_response, "error": str(e)}
    
    def determine_exploitation_paths(self, vulnerabilities):
        """Determine detailed exploitation paths for the identified vulnerabilities"""
        logger.info("Determining exploitation paths with AI")
        
        if not vulnerabilities:
            return {"paths": "No vulnerabilities found to analyze"}
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln["type"]
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Create a prompt for AI
        prompt = f"""
As a penetration tester, I need a detailed explanation of how to exploit these vulnerabilities found in a web application:

{json.dumps(vuln_types, indent=2)}

For each vulnerability type, provide:
1. Step-by-step exploitation procedure
2. Tools that could be used to exploit it
3. Conditions required for successful exploitation
4. How an attacker could escalate privileges or combine with other vulnerabilities
5. Sample attack payloads or code that would work against this vulnerability

Format your response as JSON with the following structure:
{{
  "vulnerability_paths": [
    {{
      "type": "...",
      "exploitation_steps": ["step1", "step2", ...],
      "tools": ["tool1", "tool2", ...],
      "required_conditions": "...",
      "escalation_paths": "...",
      "sample_payloads": "..."
    }}
  ]
}}
"""
        
        # Get AI response
        ai_response = self._ai_request(prompt)
        
        try:
            # Try to extract JSON from the response
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                paths = json.loads(json_str)
                return paths
            else:
                # If we can't parse JSON, return the raw response
                return {"paths": ai_response}
        except Exception as e:
            logger.error(f"Error parsing exploitation paths: {str(e)}")
            return {"paths": ai_response, "error": str(e)}
    
    def generate_remediation_recommendations(self, vulnerabilities):
        """Generate detailed remediation recommendations for the identified vulnerabilities"""
        logger.info("Generating remediation recommendations with AI")
        
        if not vulnerabilities:
            return {"remediation": "No vulnerabilities found to analyze"}
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln["type"]
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Create a prompt for AI
        prompt = f"""
As a security expert, provide detailed remediation recommendations for these vulnerabilities found in a web application:

{json.dumps(vuln_types, indent=2)}

For each vulnerability type, provide:
1. Step-by-step remediation procedures
2. Code examples showing vulnerable code and fixed code
3. Configuration changes needed
4. Security frameworks or libraries that could help
5. Testing procedures to verify the fix

Format your response as JSON with the following structure:
{{
  "remediation_strategies": [
    {{
      "type": "...",
      "remediation_steps": ["step1", "step2", ...],
      "code_examples": {{
        "vulnerable": "...",
        "fixed": "..."
      }},
      "configuration_changes": "...",
      "recommended_tools": ["tool1", "tool2", ...],
      "verification_testing": "..."
    }}
  ],
  "overall_security_improvements": "..."
}}
"""
        
        # Get AI response
        ai_response = self._ai_request(prompt)
        
        try:
            # Try to extract JSON from the response
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                remediation = json.loads(json_str)
                return remediation
            else:
                # If we can't parse JSON, return the raw response
                return {"remediation": ai_response}
        except Exception as e:
            logger.error(f"Error parsing remediation recommendations: {str(e)}")
            return {"remediation": ai_response, "error": str(e)}
    
    def analyze_attack_surface(self, target_url, scan_results):
        """Analyze the attack surface of the application"""
        logger.info(f"Analyzing attack surface for {target_url}")
        
        # Create a prompt for AI
        prompt = f"""
Analyze the attack surface of this web application based on the scan results:

{json.dumps(scan_results, indent=2)}

Provide:
1. A map of all potential entry points
2. Most vulnerable components
3. Most likely attack vectors
4. Recommendations for reducing the attack surface

Format your response as a detailed analysis that could be included in a security report.
"""
        
        # Get AI response
        return self._ai_request(prompt)
    
    def generate_executive_summary(self, scan_results):
        """Generate an executive summary of the security assessment"""
        logger.info("Generating executive summary")
        
        # Create a prompt for AI
        prompt = f"""
As a cybersecurity consultant, create an executive summary of this security assessment:

{json.dumps(scan_results, indent=2)}

The summary should:
1. Briefly explain the scope of the assessment
2. Summarize the most critical findings
3. Provide a clear risk assessment
4. Outline prioritized recommendations
5. Include a conclusion on the overall security posture

Format your response as a professional executive summary suitable for senior management.
"""
        
        # Get AI response
        return self._ai_request(prompt)
    
    def save_results(self, results, filename=None):
        """Save the AI analysis results to a file"""
        if not filename:
            filename = os.path.join(self.output_dir, f"ai_security_analysis_{self.timestamp}.json")
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        logger.info(f"AI security analysis saved to {filename}")
        return filename

def main():
    """Main function for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI-powered Security Analysis")
    parser.add_argument("target", help="Target URL to analyze")
    parser.add_argument("--vuln-file", help="JSON file containing vulnerability data")
    
    args = parser.parse_args()
    
    ai_integrator = AISecurityIntegrator(args.target)
    
    if args.vuln_file:
        with open(args.vuln_file, 'r') as f:
            vulnerabilities = json.load(f)
        
        analysis = ai_integrator.analyze_vulnerabilities(vulnerabilities)
        paths = ai_integrator.determine_exploitation_paths(vulnerabilities)
        remediation = ai_integrator.generate_remediation_recommendations(vulnerabilities)
        
        results = {
            "target": args.target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": vulnerabilities,
            "analysis": analysis,
            "exploitation_paths": paths,
            "remediation": remediation
        }
        
        ai_integrator.save_results(results)
        print(f"Analysis completed and saved to {ai_integrator.output_dir}")
    else:
        print("No vulnerability data provided. Use --vuln-file to specify a JSON file.")

if __name__ == "__main__":
    main() 