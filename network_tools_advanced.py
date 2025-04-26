#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import nmap
import json
import subprocess
import ssl
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AdvancedNetworkTools')

class AdvancedNetworkTools:
    """
    Enhanced network analysis tools for comprehensive security assessment
    with improved capabilities for vulnerability detection and analysis.
    """
    
    def __init__(self, target=None, output_dir="results"):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "port_scan": {},
            "ssl_analysis": {},
            "network_devices": {},
            "traffic_analysis": {},
            "firewall_detection": {},
            "vulnerability_correlation": {}
        }
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        logger.info(f"Initialized AdvancedNetworkTools for target: {target}")
    
    def enhanced_port_scan(self, target=None, ports="1-1000", scan_type="-sS"):
        """
        Perform enhanced port scanning with service detection and OS fingerprinting
        
        Args:
            target: Target IP or hostname
            ports: Port range to scan (default: 1-1000)
            scan_type: Nmap scan type (default: SYN scan)
            
        Returns:
            dict: Port scanning results with service details
        """
        target = target or self.target
        if not target:
            logger.error("No target specified for port scan")
            return {"error": "No target specified"}
        
        logger.info(f"Starting enhanced port scan on {target} (ports: {ports})")
        
        try:
            nm = nmap.PortScanner()
            # Run advanced scan with service detection and OS detection
            arguments = f"{scan_type} -sV -O -T4 -A --version-all"
            nm.scan(target, ports, arguments=arguments)
            
            scan_results = {}
            
            for host in nm.all_hosts():
                scan_results[host] = {
                    "status": nm[host].state(),
                    "os_detection": nm[host].get('osmatch', []),
                    "ports": {}
                }
                
                for proto in nm[host].all_protocols():
                    scan_results[host]["ports"][proto] = {}
                    lport = list(nm[host][proto].keys())
                    lport.sort()
                    
                    for port in lport:
                        port_info = nm[host][proto][port]
                        scan_results[host]["ports"][proto][port] = {
                            "state": port_info["state"],
                            "service": port_info.get("name", "unknown"),
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "extrainfo": port_info.get("extrainfo", ""),
                            "reason": port_info.get("reason", ""),
                            "cpe": port_info.get("cpe", "")
                        }
            
            self.results["port_scan"] = scan_results
            logger.info(f"Completed enhanced port scan with {len(lport) if 'lport' in locals() else 0} ports found")
            return scan_results
            
        except Exception as e:
            error_msg = f"Error during port scan: {str(e)}"
            logger.error(error_msg)
            self.results["port_scan"] = {"error": error_msg}
            return {"error": error_msg}
    
    def ssl_tls_analysis(self, target=None, port=443):
        """
        Perform comprehensive SSL/TLS security analysis
        
        Args:
            target: Target hostname
            port: HTTPS port (default: 443)
            
        Returns:
            dict: SSL/TLS security analysis results
        """
        target = target or self.target
        if not target:
            logger.error("No target specified for SSL/TLS analysis")
            return {"error": "No target specified"}
            
        logger.info(f"Starting SSL/TLS analysis for {target}:{port}")
        
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=target
            )
            conn.settimeout(10)
            conn.connect((target, port))
            
            cert = conn.getpeercert()
            cipher = conn.cipher()
            protocol_version = conn.version()
            
            # Get certificate details
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            not_before = cert['notBefore']
            not_after = cert['notAfter']
            
            # Check for weak ciphers and protocols
            is_secure_protocol = protocol_version not in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
            
            ssl_results = {
                "certificate": {
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "san": cert.get('subjectAltName', [])
                },
                "connection": {
                    "protocol": protocol_version,
                    "cipher_suite": cipher[0],
                    "encryption_method": cipher[1],
                    "bits": cipher[2]
                },
                "security_assessment": {
                    "is_secure_protocol": is_secure_protocol,
                    "recommendations": []
                }
            }
            
            # Generate security recommendations
            if not is_secure_protocol:
                ssl_results["security_assessment"]["recommendations"].append(
                    "Upgrade to TLSv1.2 or TLSv1.3 and disable older protocols"
                )
                
            conn.close()
            
            # Additional SSL tests using external tools
            try:
                # Run testssl.sh if available
                ssl_command = f"testssl.sh --quiet --color 0 {target}:{port}"
                process = subprocess.Popen(
                    ssl_command.split(), 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    shell=True
                )
                output, error = process.communicate(timeout=120)
                
                if output:
                    ssl_results["detailed_analysis"] = output.decode('utf-8', errors='ignore')
            except (subprocess.SubprocessError, FileNotFoundError) as se:
                logger.warning(f"Detailed SSL analysis unavailable: {str(se)}")
                
            self.results["ssl_analysis"] = ssl_results
            logger.info(f"Completed SSL/TLS analysis for {target}:{port}")
            return ssl_results
            
        except ssl.SSLError as ssl_err:
            error_msg = f"SSL Error: {str(ssl_err)}"
            logger.error(error_msg)
            self.results["ssl_analysis"] = {"error": error_msg}
            return {"error": error_msg}
        except socket.error as sock_err:
            error_msg = f"Socket Error: {str(sock_err)}"
            logger.error(error_msg)
            self.results["ssl_analysis"] = {"error": error_msg}
            return {"error": error_msg}
        except Exception as e:
            error_msg = f"Error during SSL/TLS analysis: {str(e)}"
            logger.error(error_msg)
            self.results["ssl_analysis"] = {"error": error_msg}
            return {"error": error_msg}
    
    def discover_network_devices(self, target_range=None):
        """
        Discover network devices in the specified IP range using ARP
        
        Args:
            target_range: IP range in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            dict: Discovered network devices
        """
        target_range = target_range or f"{self.target}/24" if self.target else None
        if not target_range:
            logger.error("No target range specified for network device discovery")
            return {"error": "No target range specified"}
            
        logger.info(f"Starting network device discovery on range: {target_range}")
        
        try:
            # Create ARP request
            arp = ARP(pdst=target_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._get_mac_vendor(received.hwsrc)
                })
                
            self.results["network_devices"] = {
                "range_scanned": target_range,
                "devices_found": len(devices),
                "devices": devices
            }
            
            logger.info(f"Discovered {len(devices)} network devices in range {target_range}")
            return self.results["network_devices"]
            
        except Exception as e:
            error_msg = f"Error during network device discovery: {str(e)}"
            logger.error(error_msg)
            self.results["network_devices"] = {"error": error_msg}
            return {"error": error_msg}
    
    def _get_mac_vendor(self, mac_address):
        """
        Get vendor information from MAC address
        
        Args:
            mac_address: MAC address string
            
        Returns:
            str: Vendor name or Unknown
        """
        try:
            # Use first 3 bytes (OUI) to identify vendor
            oui = mac_address.replace(':', '').replace('-', '').upper()[0:6]
            url = f"https://api.macvendors.com/{oui}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def analyze_traffic_pattern(self, interface=None, duration=30, packet_count=1000):
        """
        Analyze network traffic patterns
        
        Args:
            interface: Network interface to monitor
            duration: Capture duration in seconds
            packet_count: Maximum number of packets to capture
            
        Returns:
            dict: Traffic analysis results
        """
        logger.info(f"Starting traffic analysis on interface {interface} for {duration}s")
        
        try:
            # Run tcpdump to capture traffic
            cmd = [
                "tcpdump", "-i", interface or "any",
                "-c", str(packet_count),
                "-G", str(duration),
                "-w", f"{self.output_dir}/traffic_capture.pcap",
                "-n"  # Don't resolve hostnames
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            _, stderr = process.communicate()
            
            # Analyze captured file with tshark
            analysis_cmd = [
                "tshark", "-r", f"{self.output_dir}/traffic_capture.pcap",
                "-q", "-z", "io,stat,0", "-z", "conv,ip",
                "-z", "http,tree", "-z", "dns,tree"
            ]
            
            analysis = subprocess.run(
                analysis_cmd,
                capture_output=True,
                text=True
            )
            
            traffic_results = {
                "capture_info": {
                    "interface": interface or "any",
                    "duration": duration,
                    "packet_count": packet_count
                },
                "analysis": {
                    "summary": analysis.stdout,
                    "protocols": self._extract_protocol_stats(analysis.stdout),
                    "connections": self._extract_connections(analysis.stdout)
                },
                "pcap_location": f"{self.output_dir}/traffic_capture.pcap"
            }
            
            self.results["traffic_analysis"] = traffic_results
            logger.info("Completed traffic analysis")
            return traffic_results
            
        except Exception as e:
            error_msg = f"Error during traffic analysis: {str(e)}"
            logger.error(error_msg)
            self.results["traffic_analysis"] = {"error": error_msg}
            return {"error": error_msg}
    
    def _extract_protocol_stats(self, analysis_output):
        """Extract protocol statistics from tshark output"""
        # Simplified implementation
        protocols = {}
        return protocols
    
    def _extract_connections(self, analysis_output):
        """Extract connection information from tshark output"""
        # Simplified implementation
        connections = []
        return connections
    
    def detect_firewall_rules(self, target=None, probe_ports=[21, 22, 25, 80, 443, 3306, 3389]):
        """
        Detect firewall rules by analyzing packet responses
        
        Args:
            target: Target IP or hostname
            probe_ports: List of ports to probe
            
        Returns:
            dict: Firewall detection results
        """
        target = target or self.target
        if not target:
            logger.error("No target specified for firewall detection")
            return {"error": "No target specified"}
            
        logger.info(f"Starting firewall detection on {target}")
        
        try:
            results = {
                "target": target,
                "firewall_detected": False,
                "firewall_type": "Unknown",
                "port_responses": {},
                "behavior_analysis": {}
            }
            
            # Test ports with different TCP flags
            for port in probe_ports:
                # Test with SYN
                syn_result = self._tcp_probe(target, port, flags="S")
                
                # Test with ACK (may behave differently with firewalls)
                ack_result = self._tcp_probe(target, port, flags="A")
                
                # Test with FIN, PSH, URG flags
                fpf_result = self._tcp_probe(target, port, flags="FPU")
                
                results["port_responses"][port] = {
                    "syn_response": syn_result,
                    "ack_response": ack_result,
                    "fin_psh_urg_response": fpf_result
                }
                
                # Analyze inconsistencies that indicate firewalls
                if self._is_firewall_behavior(syn_result, ack_result, fpf_result):
                    results["firewall_detected"] = True
                    results["behavior_analysis"][port] = "Anomalous response pattern suggesting firewall presence"
            
            # Additional tests for firewall fingerprinting
            if results["firewall_detected"]:
                results["firewall_type"] = self._determine_firewall_type(results["port_responses"])
            
            self.results["firewall_detection"] = results
            logger.info(f"Completed firewall detection: {'Detected' if results['firewall_detected'] else 'Not detected'}")
            return results
            
        except Exception as e:
            error_msg = f"Error during firewall detection: {str(e)}"
            logger.error(error_msg)
            self.results["firewall_detection"] = {"error": error_msg}
            return {"error": error_msg}
    
    def _tcp_probe(self, target, port, flags="S", timeout=2):
        """Send a TCP probe with specific flags and analyze response"""
        try:
            # Implementation would use raw sockets or scapy
            # This is a simplified version
            return {"status": "simulated", "response_type": "RST-ACK"}
        except Exception:
            return {"status": "error", "response_type": None}
    
    def _is_firewall_behavior(self, syn_result, ack_result, fpf_result):
        """Analyze TCP probe results to detect firewall behavior"""
        # Actual implementation would look for inconsistencies indicating filtering
        # Simplified version
        return False
    
    def _determine_firewall_type(self, port_responses):
        """Try to fingerprint the firewall type based on behavior patterns"""
        # Simplified implementation
        return "Unknown"
    
    def correlate_vulnerabilities(self):
        """
        Correlate findings from all scans to identify potential vulnerabilities
        
        Returns:
            dict: Correlated vulnerability findings
        """
        logger.info("Starting vulnerability correlation analysis")
        
        vulnerabilities = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        # Check open ports against known vulnerable services
        if "port_scan" in self.results and isinstance(self.results["port_scan"], dict):
            for host, host_data in self.results["port_scan"].items():
                if "ports" not in host_data:
                    continue
                    
                for proto, ports in host_data["ports"].items():
                    for port, port_data in ports.items():
                        # Check for vulnerable services and versions
                        service = port_data.get("service", "")
                        product = port_data.get("product", "")
                        version = port_data.get("version", "")
                        
                        if service and product:
                            vuln = self._check_service_vulnerability(service, product, version)
                            if vuln:
                                vuln["host"] = host
                                vuln["port"] = port
                                vuln["protocol"] = proto
                                vulnerabilities.append(vuln)
                                severity_counts[vuln["severity"]] += 1
        
        # Check SSL/TLS vulnerabilities
        if "ssl_analysis" in self.results and isinstance(self.results["ssl_analysis"], dict):
            ssl_data = self.results["ssl_analysis"]
            if "security_assessment" in ssl_data:
                if not ssl_data["security_assessment"].get("is_secure_protocol", True):
                    vulnerabilities.append({
                        "type": "ssl_vulnerability",
                        "name": "Insecure SSL/TLS Protocol",
                        "description": f"Server is using {ssl_data.get('connection', {}).get('protocol', 'unknown')} which is considered insecure",
                        "severity": "high",
                        "remediation": "Upgrade to TLSv1.2 or TLSv1.3 and disable older protocols"
                    })
                    severity_counts["high"] += 1
        
        correlation_results = {
            "vulnerabilities_found": len(vulnerabilities),
            "severity_summary": severity_counts,
            "vulnerabilities": vulnerabilities,
            "correlation_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.results["vulnerability_correlation"] = correlation_results
        logger.info(f"Completed vulnerability correlation, found {len(vulnerabilities)} issues")
        return correlation_results
    
    def _check_service_vulnerability(self, service, product, version):
        """Check if service/version has known vulnerabilities"""
        # This would normally query a vulnerability database
        # Simplified example implementation
        if service == "http" and product == "Apache" and version.startswith("2.4."):
            return {
                "type": "cve",
                "name": "CVE-EXAMPLE-2023",
                "description": "Example Apache vulnerability",
                "severity": "high",
                "remediation": "Update to latest version"
            }
        return None
    
    def run_all_scans(self, target=None):
        """
        Run all network analysis scans in sequence
        
        Args:
            target: Target to scan (overrides instance target)
            
        Returns:
            dict: Complete scan results
        """
        if target:
            self.target = target
            self.results["target"] = target
            
        if not self.target:
            logger.error("No target specified for scanning")
            return {"error": "No target specified"}
            
        logger.info(f"Starting comprehensive network scan on {self.target}")
        
        # Run all scans with proper exception handling
        try:
            # Run enhanced port scan
            self.enhanced_port_scan()
            
            # SSL/TLS analysis if target has HTTPS
            try:
                socket.getaddrinfo(self.target, 443)
                self.ssl_tls_analysis()
            except socket.gaierror:
                logger.info(f"Target {self.target} doesn't support HTTPS on port 443, skipping SSL/TLS analysis")
            
            # Run firewall detection
            self.detect_firewall_rules()
            
            # Correlate findings
            self.correlate_vulnerabilities()
            
            # Save results to file
            self.save_results()
            
            logger.info(f"Completed all network scans for {self.target}")
            return self.results
            
        except Exception as e:
            error_msg = f"Error during comprehensive scan: {str(e)}"
            logger.error(error_msg)
            self.results["error"] = error_msg
            self.save_results()  # Save partial results
            return {"error": error_msg, "partial_results": self.results}
    
    def save_results(self, filename=None):
        """
        Save scan results to JSON file
        
        Args:
            filename: Custom filename (default: target_network_scan_TIMESTAMP.json)
            
        Returns:
            str: Path to saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self.target.replace(".", "_") if self.target else "unknown"
            filename = f"{target_name}_network_scan_{timestamp}.json"
            
        file_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(file_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Saved scan results to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
            return None

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Network Security Analysis Tools")
    parser.add_argument("target", help="Target IP, hostname, or network range")
    parser.add_argument("--output", "-o", help="Output directory for results", default="results")
    parser.add_argument("--ports", "-p", help="Port range to scan (default: 1-1000)", default="1-1000")
    parser.add_argument("--scan-type", "-s", help="Scan type (default: SYN scan)", default="-sS")
    args = parser.parse_args()
    
    scanner = AdvancedNetworkTools(args.target, args.output)
    results = scanner.run_all_scans()
    
    print(f"\nScan completed. Results saved to: {scanner.output_dir}") 