#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Standalone module for NmapScanner

import sys
import os
import json
import argparse
import time
import inspect

# Add the parent directory to sys.path if running as standalone script
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import the tool class
try:
    from security_tools_integration import NmapScanner, security_tools_manager
except ImportError:
    print("Error: Could not import NmapScanner from security_tools_integration")
    sys.exit(1)

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="Network exploration and security auditing tool")
    
    # Add common arguments
    parser.add_argument("--target", help="Target URL, IP, or domain")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--format", choices=['normal', 'xml', 'json', 'grepable'], default="normal", help="Output format")
    parser.add_argument("--action", choices=['port_scan', 'os_detection', 'service_detection', 'script_scan', 'version_detection'], help="Action to perform")
    
    # Add additional common options
    parser.add_argument("--timeout", type=int, help="Timeout for operations in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create tool instance
    try:
        tool = security_tools_manager.get_tool("NmapScanner")
    except Exception as e:
        print(f"Error creating NmapScanner instance: {str(e)}")
        return 1
    
    # Check if tool is installed
    if not tool.check_installation():
        print("NmapScanner is not installed. Attempting to install...")
        try:
            if not tool.install():
                print("Failed to install NmapScanner. Please install it manually.")
                return 1
        except Exception as e:
            print(f"Error installing NmapScanner: {str(e)}")
            return 1
    
    # Execute action based on arguments
    result = None
    
    try:
        # If no action matched or no action provided
        else:
            print("Available actions for NmapScanner:")
            print("  - port_scan")
            print("  - os_detection")
            print("  - service_detection")
            print("  - script_scan")
            print("  - version_detection")
            return 1
            
    except Exception as e:
        print(f"Error executing tool: {str(e)}")
        return 1
    
    # Handle results
    if result:
        # Save to output file if specified
        if args.output:
            try:
                # Check if result is JSON serializable
                json_str = json.dumps(result, indent=4, default=str)
                
                with open(args.output, 'w') as f:
                    f.write(json_str)
                    
                print(f"Results saved to {args.output}")
            except Exception as e:
                print(f"Error saving results to {args.output}: {str(e)}")
                # Try to save as text
                try:
                    with open(args.output, 'w') as f:
                        f.write(str(result))
                    print(f"Results saved as text to {args.output}")
                except:
                    print("Could not save results to file")
        else:
            # Print to console
            print("\nResults:")
            try:
                print(json.dumps(result, indent=4, default=str))
            except:
                print(result)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
