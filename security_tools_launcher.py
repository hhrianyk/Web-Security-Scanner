#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import json
import importlib.util

def get_tools_info():
    """Get information about available tools"""
    try:
        from security_tools_integration import security_tools_manager
        return security_tools_manager.list_tools()
    except ImportError:
        print("Error: Could not import security_tools_manager from security_tools_integration")
        return {}

def main():
    """Main function for unified security tools launcher"""
    # Get available tools
    tools_info = get_tools_info()
    
    if not tools_info:
        print("No security tools available")
        return 1
    
    # Create main parser
    parser = argparse.ArgumentParser(description="Unified Security Tools Launcher")
    subparsers = parser.add_subparsers(dest="tool", help="Security tool to run")
    
    # Add a subparser for each tool
    for tool_name, capabilities in tools_info.items():
        tool_parser = subparsers.add_parser(tool_name.lower(), help=capabilities.get('description', ''))
        
        # Add common arguments
        tool_parser.add_argument("--target", help="Target URL, IP, or domain")
        tool_parser.add_argument("--output", help="Output file path")
        tool_parser.add_argument("--format", choices=capabilities.get('output_formats', ['json']), 
                              default=capabilities.get('output_formats', ['json'])[0], 
                              help="Output format")
        
        # Add tool-specific arguments based on capabilities
        actions = capabilities.get('actions', [])
        if actions:
            tool_parser.add_argument("--action", choices=actions, help="Action to perform")
            
        # Add common options
        tool_parser.add_argument("--timeout", type=int, help="Timeout for operations in seconds")
        tool_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Add general commands
    list_parser = subparsers.add_parser("list", help="List available tools")
    install_parser = subparsers.add_parser("install", help="Install a specific tool")
    install_parser.add_argument("tool_name", help="Name of the tool to install")
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.tool:
        parser.print_help()
        return 0
    
    if args.tool == "list":
        print("Available Security Tools:")
        print("========================")
        for i, (name, capabilities) in enumerate(sorted(tools_info.items()), 1):
            print(f"{i}. {name} - {capabilities.get('description', 'No description')}")
            actions = capabilities.get('actions', [])
            if actions:
                print(f"   Actions: {', '.join(actions)}")
            print()
        return 0
    
    if args.tool == "install":
        try:
            from security_tools_integration import security_tools_manager
            tool = security_tools_manager.get_tool(args.tool_name, initialize=False)
            if tool.check_installation():
                print(f"{args.tool_name} is already installed")
                return 0
            
            print(f"Installing {args.tool_name}...")
            if tool.install():
                print(f"{args.tool_name} installed successfully")
                return 0
            else:
                print(f"Failed to install {args.tool_name}")
                return 1
        except Exception as e:
            print(f"Error installing {args.tool_name}: {e}")
            return 1
    
    # Run the specified tool
    tool_name = next((name for name in tools_info.keys() if name.lower() == args.tool.lower()), None)
    
    if not tool_name:
        print(f"Tool '{args.tool}' not found")
        return 1
    
    try:
        # Import the tool module
        standalone_module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                           "standalone_tools", f"{tool_name.lower()}.py")
        
        if os.path.exists(standalone_module_path):
            # Use the standalone module if available
            spec = importlib.util.spec_from_file_location(f"{tool_name.lower()}_module", standalone_module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Pass all arguments to the module's main function
            old_argv = sys.argv
            sys.argv = [standalone_module_path] + [arg for arg in old_argv[2:] if arg != args.tool]
            
            try:
                result = module.main()
                sys.argv = old_argv
                return result
            except Exception as e:
                sys.argv = old_argv
                print(f"Error running {tool_name}: {e}")
                return 1
        else:
            # Directly use the security tools manager
            from security_tools_integration import security_tools_manager
            
            # Get tool instance
            tool = security_tools_manager.get_tool(tool_name)
            
            # Check if tool is installed
            if not tool.check_installation():
                print(f"{tool_name} is not installed. Attempting to install...")
                if not tool.install():
                    print(f"Failed to install {tool_name}. Please install it manually.")
                    return 1
            
            # Handle different actions based on the tool type
            result = None
            
            if hasattr(tool, 'scan') and (not hasattr(args, 'action') or not args.action or args.action in ['scan', 'web_scan']):
                if not args.target:
                    print("Error: --target is required for scanning")
                    return 1
                
                print(f"Running scan against {args.target}...")
                result = tool.scan(args.target, output_format=args.format)
                
            elif hasattr(tool, 'analyze') and args.action == 'analyze':
                if not args.target:
                    print("Error: --target is required for analysis")
                    return 1
                
                print(f"Analyzing {args.target}...")
                result = tool.analyze(args.target, output_format=args.format)
                
            elif hasattr(tool, 'comprehensive_scan') and (not args.action or args.action == 'comprehensive_scan'):
                if not args.target:
                    print("Error: --target is required for scanning")
                    return 1
                
                print(f"Running comprehensive scan against {args.target}...")
                result = tool.comprehensive_scan(args.target)
                
            else:
                print(f"No suitable action found for {tool_name}")
                return 1
            
            # Handle results
            if result:
                if args.output:
                    try:
                        with open(args.output, 'w') as f:
                            json.dump(result, f, indent=4, default=str)
                        print(f"Results saved to {args.output}")
                    except:
                        print(f"Error saving results to {args.output}")
                else:
                    print("\nResults:")
                    print(json.dumps(result, indent=4, default=str))
            
            return 0
            
    except Exception as e:
        print(f"Error running {tool_name}: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 