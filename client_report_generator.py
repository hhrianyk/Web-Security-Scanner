#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import argparse
import logging
from datetime import datetime

# Import our vulnerability scanning components
try:
    from app import start_scan
    from ai_vulnerability_scanner import start_scan as ai_start_scan
    from vulnerability_scanner import VulnerabilityScanner
    from client_vulnerability_report import ClientVulnerabilityReporter
except ImportError as e:
    print(f"Warning: Some modules couldn't be imported: {e}")
    print("Please ensure all dependencies are installed.")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client_report.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ClientReportGenerator")

def get_client_info():
    """Gather client information for the report"""
    print("\n--- Client Information ---")
    client_name = input("Client name: ")
    client_website = input("Client website: ")
    client_contact = input("Client contact person: ")
    client_contact_email = input("Client contact email: ")
    client_logo = input("Path to client logo (optional): ")
    
    client_info = {
        "name": client_name,
        "website": client_website,
        "contact": client_contact,
        "contact_email": client_contact_email
    }
    
    if client_logo and os.path.exists(client_logo):
        client_info["logo_path"] = os.path.abspath(client_logo)
    
    return client_info

def generate_full_client_report(target_url, output_dir="client_reports", use_ai=True):
    """
    Generate a complete client vulnerability report by:
    1. Running a vulnerability scan
    2. Analyzing the results
    3. Generating a detailed client report
    
    Args:
        target_url: The URL to scan
        output_dir: Directory to store the report
        use_ai: Whether to use AI-enhanced scanning
    
    Returns:
        Path to the generated report
    """
    logger.info(f"Starting client vulnerability assessment for {target_url}")
    print(f"\nStarting comprehensive vulnerability assessment for {target_url}")
    print("This process involves multiple phases and may take some time...")
    
    # Step 1: Get client information
    client_info = get_client_info()
    
    # Step 2: Run the vulnerability scan
    print("\nPhase 1: Running vulnerability scan...")
    scan_data = None
    
    try:
        if use_ai and 'ai_start_scan' in globals():
            print("Using AI-enhanced vulnerability scanner")
            scanner = ai_start_scan(target_url)
            scan_id = scanner.scan_id
            
            # Wait for scan to complete
            print("Scan initiated. Please wait for results (this may take several minutes)...")
            print("You can check the scan progress in the web interface.")
            
            # In a real implementation, we would poll for scan completion
            # For this example, we'll ask the user to provide the scan results file
            scan_results_file = input("\nEnter path to AI scan results JSON file when scan completes: ")
            
            if os.path.exists(scan_results_file):
                with open(scan_results_file, 'r') as f:
                    scan_data = json.load(f)
            else:
                print(f"Error: Could not find scan results file at {scan_results_file}")
        else:
            print("Using standard vulnerability scanner")
            scanner = VulnerabilityScanner(output_dir="temp_scan_results")
            scan_data = scanner.scan_target(target_url)
    except Exception as e:
        logger.error(f"Error during vulnerability scanning: {str(e)}")
        print(f"Error during vulnerability scanning: {str(e)}")
        
        # Ask if user wants to provide a scan results file instead
        use_file = input("Would you like to use an existing scan results file instead? (y/n): ")
        if use_file.lower() == 'y':
            scan_results_file = input("Enter path to scan results JSON file: ")
            if os.path.exists(scan_results_file):
                with open(scan_results_file, 'r') as f:
                    scan_data = json.load(f)
    
    if not scan_data:
        logger.error("No scan data available. Exiting.")
        print("Error: No scan data available. Exiting.")
        return None
    
    # Step 3: Enhance the scan results with detailed exploitation and business impact data
    print("\nPhase 2: Analyzing vulnerability details...")
    
    # Ensure scan data has target information
    if "target" not in scan_data and "target_url" in locals():
        scan_data["target"] = target_url
    
    # Add scan ID if not present
    if "scan_id" not in scan_data:
        scan_data["scan_id"] = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Step 4: Generate the client report
    print("\nPhase 3: Generating comprehensive client report...")
    reporter = ClientVulnerabilityReporter(report_dir=output_dir)
    report_files = reporter.generate_report(scan_data, client_info, "all")
    
    if not report_files:
        logger.error("Failed to generate client report")
        print("Error: Failed to generate client report")
        return None
    
    # Step 5: Return the report paths
    print("\nClient vulnerability report generated successfully!")
    print("Report files:")
    for format_type, file_path in report_files.items():
        print(f"- {format_type.upper()}: {file_path}")
    
    return report_files

def main():
    """Main function when running as a script"""
    parser = argparse.ArgumentParser(description="Generate comprehensive client vulnerability reports")
    parser.add_argument("target", help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("--output-dir", "-o", default="client_reports", help="Directory to store reports")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI-enhanced scanning")
    parser.add_argument("--scan-file", "-f", help="Use existing scan results file instead of performing a new scan")
    
    args = parser.parse_args()
    
    if args.scan_file:
        # Use existing scan results
        if not os.path.exists(args.scan_file):
            print(f"Error: Scan results file not found: {args.scan_file}")
            return 1
        
        try:
            # Get client information
            client_info = get_client_info()
            
            # Load scan data
            with open(args.scan_file, 'r') as f:
                scan_data = json.load(f)
            
            # Generate report
            reporter = ClientVulnerabilityReporter(report_dir=args.output_dir)
            report_files = reporter.generate_report(scan_data, client_info, "all")
            
            if report_files:
                print("\nClient vulnerability report generated successfully!")
                print("Report files:")
                for format_type, file_path in report_files.items():
                    print(f"- {format_type.upper()}: {file_path}")
                return 0
            else:
                print("Error: Failed to generate client report")
                return 1
        except Exception as e:
            print(f"Error: {str(e)}")
            return 1
    else:
        # Run full scan and report generation
        report_files = generate_full_client_report(
            args.target,
            args.output_dir,
            not args.no_ai
        )
        
        return 0 if report_files else 1

if __name__ == "__main__":
    sys.exit(main()) 