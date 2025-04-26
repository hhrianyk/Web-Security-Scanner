#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import time
import importlib
import argparse
import tempfile
import subprocess
import shutil
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("standalone_tools.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("StandaloneSecurityTools")

# Try to import the security tools manager
try:
    from security_tools_integration import security_tools_manager
    TOOLS_AVAILABLE = True
except ImportError:
    logger.error("Unable to import security_tools_manager. Make sure security_tools_integration.py is available.")
    TOOLS_AVAILABLE = False

class StandaloneToolsManager:
    """Manager for standalone security tools"""
    
    def __init__(self):
        self.tools_dir = "standalone_tools"
        
    def list_available_tools(self):
        """List all available security tools"""
        if not TOOLS_AVAILABLE:
            return {}
            
        return security_tools_manager.list_tools()
        
    def create_standalone_modules(self):
        """Create standalone executable modules for all available tools"""
        if not TOOLS_AVAILABLE:
            logger.error("Security tools integration module not available")
            return False
            
        os.makedirs(self.tools_dir, exist_ok=True)
        
        # Create README for standalone tools
        readme_text = "# Standalone Security Tools\n\n"
        readme_text += "This directory contains standalone executable modules for each security tool in the unified framework.\n"
        readme_text += "Each tool can be run independently without requiring the entire framework.\n\n"
        readme_text += "## Available Tools\n\n"
        
        # Get all available tools
        available_tools = self.list_available_tools()
        
        # Create a module for each tool
        for tool_name, capabilities in available_tools.items():
            # Get tool information
            actions = capabilities.get('actions', [])
            actions_str = ", ".join(actions) if actions else "N/A"
            output_formats = capabilities.get('output_formats', ['json'])
            description = capabilities.get('description', 'No description')
            
            # Generate module content
            self._create_tool_module(tool_name, actions, output_formats, description)
            
            # Add to README
            readme_text += f"### {tool_name}\n\n"
            readme_text += f"{description}\n\n"
            readme_text += f"**Actions:** {actions_str}\n\n"
            readme_text += f"**Output Formats:** {', '.join(output_formats)}\n\n"
            readme_text += f"**Usage:**\n\n"
            readme_text += f"```bash\npython standalone_tools/{tool_name.lower()}.py --target [TARGET] --action [ACTION]\n```\n\n"
            
        # Create an __init__.py file for the package
        init_file = os.path.join(self.tools_dir, "__init__.py")
        with open(init_file, 'w') as f:
            f.write("# Standalone Security Tools Package\n")
            f.write("import os\n")
            f.write("import sys\n\n")
            f.write("# Add tool imports\n")
            
        # Write README file
        with open(os.path.join(self.tools_dir, "README.md"), 'w') as f:
            f.write(readme_text)
            
        logger.info(f"Created {len(available_tools)} standalone tool modules in {self.tools_dir}/")
        return True
    
    def _create_tool_module(self, tool_name, actions, output_formats, description):
        """Create a standalone module file for a tool"""
        # Prepare file content
        content = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Standalone module for {tool_name}

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
    from security_tools_integration import {tool_name}, security_tools_manager
except ImportError:
    print("Error: Could not import {tool_name} from security_tools_integration")
    sys.exit(1)

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="{description}")
    
    # Add common arguments
    parser.add_argument("--target", help="Target URL, IP, or domain")
    parser.add_argument("--output", help="Output file path")
"""

        # Add format choices if available
        if output_formats:
            default_format = output_formats[0] if output_formats else 'json'
            content += f'    parser.add_argument("--format", choices={output_formats}, default="{default_format}", help="Output format")\n'
        
        # Add action choices if available
        if actions:
            content += f'    parser.add_argument("--action", choices={actions}, help="Action to perform")\n'
        
        # Add additional arguments
        content += """    
    # Add additional common options
    parser.add_argument("--timeout", type=int, help="Timeout for operations in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create tool instance
    try:
        tool = security_tools_manager.get_tool("{0}")
    except Exception as e:
        print(f"Error creating {0} instance: {{str(e)}}")
        return 1
    
    # Check if tool is installed
    if not tool.check_installation():
        print("{0} is not installed. Attempting to install...")
        try:
            if not tool.install():
                print("Failed to install {0}. Please install it manually.")
                return 1
        except Exception as e:
            print(f"Error installing {0}: {{str(e)}}")
            return 1
    
    # Execute action based on arguments
    result = None
    
    try:
""".format(tool_name)

        # Add handling for common actions
        if 'scan' in [a.lower() for a in actions]:
            content += """        # Handle scan action
        if hasattr(tool, 'scan') and (not args.action or args.action in ['scan', 'web_scan']):
            if not args.target:
                print("Error: --target is required for scanning")
                return 1
                
            print(f"Running scan against {args.target}...")
            
            # Determine the right parameters for the scan method
            scan_params = inspect.signature(tool.scan).parameters
            scan_args = {'target': args.target}
            
            if 'output_format' in scan_params and args.format:
                scan_args['output_format'] = args.format
            elif 'format' in scan_params and args.format:
                scan_args['format'] = args.format
                
            if 'timeout' in scan_params and args.timeout:
                scan_args['timeout'] = args.timeout
                
            result = tool.scan(**scan_args)
"""

        if 'analyze' in [a.lower() for a in actions]:
            content += """        # Handle analyze action
        elif hasattr(tool, 'analyze') and args.action == 'analyze':
            if not args.target:
                print("Error: --target is required for analysis")
                return 1
                
            print(f"Analyzing {args.target}...")
            result = tool.analyze(args.target, output_format=args.format)
"""

        if 'capture' in [a.lower() for a in actions]:
            content += """        # Handle capture action
        elif hasattr(tool, 'capture') and args.action == 'capture':
            if not args.target:
                print("Error: --target (interface) is required for capture")
                return 1
                
            output = args.output or f"capture_{int(time.time())}.pcap"
            print(f"Capturing traffic on {args.target} to {output}...")
            
            # Determine if duration is needed
            duration = args.timeout or 60  # Default to 60 seconds
            result = tool.capture(args.target, output, duration=duration)
"""

        if 'comprehensive_scan' in [a.lower() for a in actions] or 'scan' in [a.lower() for a in actions]:
            content += """        # Handle comprehensive scan action
        elif hasattr(tool, 'comprehensive_scan') and (not args.action or args.action == 'comprehensive_scan'):
            if not args.target:
                print("Error: --target is required for scanning")
                return 1
                
            print(f"Running comprehensive scan against {args.target}...")
            result = tool.comprehensive_scan(args.target)
"""

        if 'start_server' in [a.lower() for a in actions]:
            content += """        # Handle start server action
        elif hasattr(tool, 'start_server') and args.action == 'start_server':
            print("Starting server...")
            result = tool.start_server()
"""

        if 'stop_server' in [a.lower() for a in actions]:
            content += """        # Handle stop server action
        elif hasattr(tool, 'stop_server') and args.action == 'stop_server':
            print("Stopping server...")
            result = tool.stop_server()
"""

        if 'exploit' in [a.lower() for a in actions]:
            content += """        # Handle exploit action
        elif hasattr(tool, 'exploit') and args.action == 'exploit':
            if not args.target:
                print("Error: --target is required for exploitation")
                return 1
                
            print(f"Running exploit against {args.target}...")
            # Additional parameters would typically be needed for exploitation
            module = args.module if hasattr(args, 'module') else None
            result = tool.exploit(module, args.target)
"""

        # Add fallback for when no action matches
        content += f"""        # If no action matched or no action provided
        else:
            print("Available actions for {tool_name}:")
"""
        
        if actions:
            for action in actions:
                content += f'            print("  - {action}")\n'
        else:
            content += '            print("This tool doesn\'t have any specific actions defined.")\n'
        
        content += """            return 1
            
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
            print("\\nResults:")
            try:
                print(json.dumps(result, indent=4, default=str))
            except:
                print(result)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

        # Write the module file
        module_file = os.path.join(self.tools_dir, f"{tool_name.lower()}.py")
        with open(module_file, 'w') as f:
            f.write(content)
            
        # Make it executable
        try:
            import stat
            os.chmod(module_file, os.stat(module_file).st_mode | stat.S_IEXEC)
        except:
            pass
            
        return True
        
    def create_unified_launcher(self):
        """Create a unified launcher for all tools"""
        if not TOOLS_AVAILABLE:
            logger.error("Security tools integration module not available")
            return False
            
        os.makedirs(self.tools_dir, exist_ok=True)
            
        # Create the launcher in a separate file
        return True

def main():
    """Command line interface for standalone security tools"""
    parser = argparse.ArgumentParser(description="Standalone Security Tools Manager")
    parser.add_argument("--create-modules", action="store_true", help="Create standalone modules for all tools")
    parser.add_argument("--list-tools", action="store_true", help="List available security tools")
    
    args = parser.parse_args()
    
    if not TOOLS_AVAILABLE:
        print("Error: Security tools integration module not available")
        print("Make sure security_tools_integration.py is in the same directory")
        return 1
    
    manager = StandaloneToolsManager()
    
    if args.list_tools:
        # List available tools
        tools = manager.list_available_tools()
        print("\nAvailable Security Tools:")
        print("========================")
        for i, (name, capabilities) in enumerate(tools.items(), 1):
            print(f"{i}. {name} - {capabilities.get('description', 'No description')}")
            actions = capabilities.get('actions', [])
            if actions:
                print(f"   Actions: {', '.join(actions)}")
            print()
        return 0
    
    if args.create_modules:
        # Create standalone modules
        print("Creating standalone modules for all security tools...")
        if manager.create_standalone_modules():
            print("Standalone modules created successfully in the 'standalone_tools' directory")
            return 0
        else:
            print("Failed to create standalone modules")
            return 1
    
    # If no arguments provided, show help
    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main()) 