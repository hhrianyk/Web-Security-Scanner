#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import argparse

def list_tools():
    """List all available standalone tools"""
    tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "standalone_tools")
    
    if not os.path.exists(tools_dir):
        print("Standalone tools directory not found")
        return 1
    
    tools = []
    for file in os.listdir(tools_dir):
        if file.endswith(".py") and file != "__init__.py":
            tool_name = file[:-3]
            tools.append(tool_name)
    
    if not tools:
        print("No standalone tools found")
        return 1
    
    print("\nAvailable Standalone Security Tools:")
    print("==================================")
    
    for i, tool in enumerate(sorted(tools), 1):
        # Try to get description from module docstring
        try:
            module_path = os.path.join(tools_dir, f"{tool}.py")
            with open(module_path, 'r') as f:
                content = f.read()
                desc_start = content.find('description="')
                if desc_start >= 0:
                    desc_start += 13  # Length of 'description="'
                    desc_end = content.find('"', desc_start)
                    if desc_end > desc_start:
                        description = content[desc_start:desc_end]
                        print(f"{i}. {tool} - {description}")
                        continue
        except:
            pass
        
        # Fallback if description not found
        print(f"{i}. {tool}")
    
    print("\nRun a tool with: python run_tool.py TOOL_NAME [ARGUMENTS]")
    print("Example: python run_tool.py nmapscanner --target example.com")
    print("\nGet help for a specific tool: python run_tool.py TOOL_NAME --help")
    
    return 0

def main():
    """Main function for standalone tools launcher"""
    parser = argparse.ArgumentParser(description="Standalone Security Tools Launcher")
    parser.add_argument("tool", nargs="?", help="Tool to run")
    parser.add_argument("--list", action="store_true", help="List all available tools")
    parser.add_argument("--update", action="store_true", help="Update standalone tool modules")
    
    # Split arguments for the launcher and for the tool
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        launcher_args = parser.parse_args([sys.argv[1]])
        tool_args = sys.argv[2:] if len(sys.argv) > 2 else []
    else:
        launcher_args, tool_args = parser.parse_known_args()
    
    if launcher_args.list:
        return list_tools()
    
    if launcher_args.update:
        try:
            from standalone_security_tools import StandaloneToolsManager
            manager = StandaloneToolsManager()
            if manager.create_standalone_modules():
                print("Standalone tools updated successfully")
                return 0
            else:
                print("Failed to update standalone tools")
                return 1
        except ImportError:
            print("Could not import StandaloneToolsManager. Make sure standalone_security_tools.py is available.")
            return 1
    
    if launcher_args.tool:
        # Run the specified tool
        tool_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                               "standalone_tools", f"{launcher_args.tool.lower()}.py")
        
        if not os.path.exists(tool_script):
            print(f"Tool '{launcher_args.tool}' not found")
            print("Use --list to see available tools")
            return 1
        
        # Run the tool with the provided arguments
        return subprocess.call([sys.executable, tool_script] + tool_args)
    
    # If no arguments provided, show help
    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main()) 