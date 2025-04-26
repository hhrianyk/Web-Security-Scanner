#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import subprocess
import json
import tempfile
import time
import datetime
import platform
from typing import Dict, List, Any, Optional, Union

# Import base class from security_tools_integration.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from security_tools_integration import SecurityToolBase, register_tool, get_tools_directory, security_tools_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("mitmproxy_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MitmproxyIntegration")

@register_tool
class Mitmproxy(SecurityToolBase):
    """
    Mitmproxy - An interactive HTTPS proxy for penetration testers and security researchers
    
    Features:
    - Man-in-the-middle proxy
    - SSL/TLS interception
    - Traffic modification
    - HTTP/2 support
    - WebSocket support
    - Command-line, Web UI, and Python API interfaces
    """
    
    def __init__(self):
        self.mitmproxy_bin = "mitmproxy"
        self.mitmdump_bin = "mitmdump"
        self.mitmweb_bin = "mitmweb"
        
    @classmethod
    def get_capabilities(cls):
        """Return the capabilities of this security tool"""
        return {
            "name": "Mitmproxy",
            "description": "Interactive HTTPS proxy for penetration testing",
            "actions": ["intercept", "modify", "record", "replay", "analyze"],
            "target_types": ["http_traffic", "https_traffic", "websocket"],
            "output_formats": ["flow", "har", "curl", "httpie", "raw"],
            "dependencies": ["python"]
        }
        
    def check_installation(self):
        """Check if Mitmproxy is installed"""
        try:
            # Try to run mitmproxy --version
            result = self.run_command([self.mitmdump_bin, "--version"])
            return result["returncode"] == 0
        except:
            return False
        
    def install(self):
        """Install Mitmproxy using pip"""
        logger.info("Installing Mitmproxy...")
        result = self.run_command([sys.executable, "-m", "pip", "install", "mitmproxy"])
        
        if result["returncode"] != 0:
            raise Exception(f"Failed to install Mitmproxy: {result['stderr']}")
            
        return self.check_installation()
        
    def start_interactive(self):
        """Start the interactive Mitmproxy console"""
        if not self.check_installation():
            raise Exception("Mitmproxy is not installed")
            
        logger.info("Starting Mitmproxy interactive console...")
        subprocess.Popen([self.mitmproxy_bin])
        
        return {
            "status": "started",
            "message": "Mitmproxy interactive console started"
        }
        
    def start_web_interface(self, port=8081, web_port=8080, host="127.0.0.1"):
        """Start the Mitmproxy web interface"""
        if not self.check_installation():
            raise Exception("Mitmproxy is not installed")
            
        logger.info(f"Starting Mitmproxy web interface on port {web_port}...")
        
        cmd = [
            self.mitmweb_bin,
            "--listen-port", str(port),
            "--web-port", str(web_port),
            "--web-host", host
        ]
        
        subprocess.Popen(cmd)
        
        return {
            "status": "started",
            "message": f"Mitmproxy web interface started at http://{host}:{web_port}",
            "proxy_address": f"{host}:{port}"
        }
        
    def record_traffic(self, output_file, port=8080, host="127.0.0.1", filters=None, timeout=None):
        """Record HTTP/HTTPS traffic to a file"""
        if not self.check_installation():
            raise Exception("Mitmproxy is not installed")
            
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        # Build command
        cmd = [
            self.mitmdump_bin,
            "--listen-port", str(port),
            "--listen-host", host,
            "-w", output_file
        ]
        
        # Add filters if specified
        if filters:
            cmd.extend(["-f", filters])
            
        logger.info(f"Recording traffic to {output_file} (proxy on {host}:{port})")
        
        if timeout:
            # Run with timeout
            process = subprocess.Popen(cmd)
            try:
                print(f"Recording traffic for {timeout} seconds. Press Ctrl+C to stop earlier.")
                time.sleep(timeout)
                process.terminate()
                process.wait(timeout=5)
            except KeyboardInterrupt:
                print("Recording stopped by user.")
                process.terminate()
                process.wait(timeout=5)
        else:
            # Run indefinitely until user interrupts
            process = subprocess.Popen(cmd)
            print("Recording traffic. Press Ctrl+C to stop.")
            try:
                process.wait()
            except KeyboardInterrupt:
                print("Recording stopped by user.")
                process.terminate()
                process.wait(timeout=5)
                
        return {
            "status": "completed",
            "output_file": output_file,
            "proxy_address": f"{host}:{port}"
        }
        
    def replay_traffic(self, input_file, server=None, port=8080, host="127.0.0.1", filters=None):
        """Replay recorded traffic"""
        if not self.check_installation():
            raise Exception("Mitmproxy is not installed")
            
        if not os.path.exists(input_file):
            raise Exception(f"Input file not found: {input_file}")
            
        # Build command
        cmd = [
            self.mitmdump_bin,
            "--listen-port", str(port),
            "--listen-host", host,
            "-r", input_file
        ]
        
        # Add server if specified
        if server:
            cmd.extend(["-S", server])
            
        # Add filters if specified
        if filters:
            cmd.extend(["-f", filters])
            
        logger.info(f"Replaying traffic from {input_file}")
        
        process = subprocess.Popen(cmd)
        print("Replaying traffic. Press Ctrl+C to stop.")
        try:
            process.wait()
        except KeyboardInterrupt:
            print("Replay stopped by user.")
            process.terminate()
            process.wait(timeout=5)
            
        return {
            "status": "completed",
            "input_file": input_file,
            "proxy_address": f"{host}:{port}"
        }
        
    def convert_to_har(self, input_file, output_file=None):
        """Convert a mitmproxy flow file to HAR format"""
        if not self.check_installation():
            raise Exception("Mitmproxy is not installed")
            
        if not os.path.exists(input_file):
            raise Exception(f"Input file not found: {input_file}")
            
        # Create default output file if not specified
        if not output_file:
            output_file = os.path.splitext(input_file)[0] + ".har"
            
        # Build command
        cmd = [
            self.mitmdump_bin,
            "-r", input_file,
            "--set", f"hardump={output_file}"
        ]
        
        logger.info(f"Converting {input_file} to HAR format")
        result = self.run_command(cmd)
        
        if result["returncode"] != 0:
            logger.error(f"Failed to convert file: {result['stderr']}")
            return {
                "status": "error",
                "message": f"Failed to convert file: {result['stderr']}"
            }
            
        return {
            "status": "completed",
            "input_file": input_file,
            "output_file": output_file
        }
        
    def analyze_traffic(self, input_file):
        """Analyze recorded traffic and extract key information"""
        if not self.check_installation():
            raise Exception("Mitmproxy is not installed")
            
        if not os.path.exists(input_file):
            raise Exception(f"Input file not found: {input_file}")
            
        # Create a temporary Python script to analyze the traffic
        script_content = """
import json
import sys
from mitmproxy import io, http

def analyze_flow(flow):
    if not isinstance(flow, http.HTTPFlow):
        return None
        
    result = {
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "status_code": flow.response.status_code if flow.response else None,
        "request_headers": dict(flow.request.headers),
        "request_content_length": len(flow.request.content) if flow.request.content else 0,
        "response_headers": dict(flow.response.headers) if flow.response else {},
        "response_content_length": len(flow.response.content) if flow.response and flow.response.content else 0,
        "duration": (flow.response.timestamp_end - flow.request.timestamp_start) if flow.response else None,
    }
    
    # Add content type information
    if flow.response and "content-type" in flow.response.headers:
        result["content_type"] = flow.response.headers["content-type"]
        
    return result

results = []
with open(sys.argv[1], "rb") as logfile:
    freader = io.FlowReader(logfile)
    for flow in freader.stream():
        analysis = analyze_flow(flow)
        if analysis:
            results.append(analysis)

stats = {
    "total_requests": len(results),
    "methods": {},
    "status_codes": {},
    "content_types": {},
    "total_request_size": 0,
    "total_response_size": 0,
    "avg_duration": 0
}

duration_sum = 0
duration_count = 0

for r in results:
    # Count methods
    method = r["method"]
    stats["methods"][method] = stats["methods"].get(method, 0) + 1
    
    # Count status codes
    if r["status_code"]:
        status = r["status_code"]
        stats["status_codes"][str(status)] = stats["status_codes"].get(str(status), 0) + 1
    
    # Count content types
    if "content_type" in r:
        ct = r["content_type"].split(";")[0].strip()
        stats["content_types"][ct] = stats["content_types"].get(ct, 0) + 1
    
    # Sum sizes
    stats["total_request_size"] += r["request_content_length"]
    stats["total_response_size"] += r["response_content_length"]
    
    # Calculate average duration
    if r["duration"]:
        duration_sum += r["duration"]
        duration_count += 1

if duration_count > 0:
    stats["avg_duration"] = duration_sum / duration_count

output = {
    "stats": stats,
    "requests": results
}

print(json.dumps(output))
"""
        
        script_file = os.path.join(tempfile.gettempdir(), f"analyze_traffic_{int(time.time())}.py")
        with open(script_file, 'w') as f:
            f.write(script_content)
            
        try:
            # Run the analysis script
            cmd = [sys.executable, script_file, input_file]
            result = self.run_command(cmd)
            
            if result["returncode"] != 0:
                logger.error(f"Failed to analyze traffic: {result['stderr']}")
                return {
                    "status": "error",
                    "message": f"Failed to analyze traffic: {result['stderr']}"
                }
                
            # Parse JSON output
            analysis = json.loads(result["stdout"])
            
            return {
                "status": "completed",
                "input_file": input_file,
                "analysis": analysis
            }
            
        finally:
            # Clean up the temporary script
            try:
                os.remove(script_file)
            except:
                pass
                
    def configure_browser_proxy(self):
        """Print instructions for configuring browsers to use the proxy"""
        proxy_host = "127.0.0.1"
        proxy_port = 8080
        
        instructions = f"""
Mitmproxy Configuration Instructions
===================================

1. Configure your browser to use proxy:
   - Host: {proxy_host}
   - Port: {proxy_port}
   - No proxy for: localhost,127.0.0.1

2. Install the mitmproxy CA certificate:
   - Visit http://mitm.it in your browser
   - Follow the instructions for your operating system/browser

3. Testing the proxy:
   - Visit https://example.com and check if traffic is visible in mitmproxy

Proxy Settings for Different Browsers:
-------------------------------------
* Chrome/Edge: Settings -> Advanced -> System -> Proxy settings
* Firefox: Settings -> Network Settings -> Configure Proxy Access
* Safari: System Preferences -> Network -> Advanced -> Proxies

For Mobile Devices:
------------------
1. Connect to the same network as your proxy
2. Configure proxy settings (typically in WiFi settings)
3. Visit http://mitm.it to install the certificate
"""
        
        print(instructions)
        return {
            "status": "success",
            "proxy_host": proxy_host,
            "proxy_port": proxy_port,
            "instructions": instructions
        }

if __name__ == "__main__":
    try:
        # Initialize Mitmproxy tool
        mitmproxy = security_tools_manager.get_tool("Mitmproxy")
        
        # Process command-line arguments
        if len(sys.argv) > 1:
            if sys.argv[1] == "--interactive":
                mitmproxy.start_interactive()
                
            elif sys.argv[1] == "--web":
                result = mitmproxy.start_web_interface()
                print(f"Mitmproxy web interface started. Access at {result['message']}")
                print(f"Configure your browser to use proxy: {result['proxy_address']}")
                
            elif sys.argv[1] == "--record" and len(sys.argv) > 2:
                output_file = sys.argv[2]
                timeout = int(sys.argv[3]) if len(sys.argv) > 3 else None
                result = mitmproxy.record_traffic(output_file, timeout=timeout)
                print(f"Traffic recorded to {result['output_file']}")
                
            elif sys.argv[1] == "--replay" and len(sys.argv) > 2:
                input_file = sys.argv[2]
                result = mitmproxy.replay_traffic(input_file)
                
            elif sys.argv[1] == "--analyze" and len(sys.argv) > 2:
                input_file = sys.argv[2]
                result = mitmproxy.analyze_traffic(input_file)
                print(json.dumps(result["analysis"]["stats"], indent=2))
                
            elif sys.argv[1] == "--configure":
                mitmproxy.configure_browser_proxy()
                
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1) 