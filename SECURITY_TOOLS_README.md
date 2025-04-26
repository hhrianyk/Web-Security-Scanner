# Security Tools Framework

This framework provides a comprehensive collection of security tools for vulnerability scanning, network analysis, penetration testing, and more. You can use all the tools together through the unified security system or use each tool independently.

## Using the Unified Security System

The unified security system integrates all tools into a single platform with consistent interfaces. To use the unified system:

```bash
# Run a full security assessment
python unified_security_tools.py --target example.com

# Run a specific workflow
python unified_security_tools.py --workflow network_scan --target 192.168.1.0/24

# List available tools
python unified_security_tools.py --list-tools

# Use the web interface
python unified_security_tools.py --start-web
```

## Using Individual Security Tools

You can use each security tool independently without requiring the entire framework. This allows you to:

1. Run specific tools without loading the entire system
2. Integrate individual tools into your own scripts or workflows
3. Use tools separately in resource-constrained environments

### Setting Up Individual Tools

Run the following command to generate standalone modules for all tools:

```bash
python standalone_security_tools.py --create-modules
```

This will create a `standalone_tools` directory with individual modules for each tool.

### Running Individual Tools

You can run each tool directly:

```bash
# Run a specific tool
python standalone_tools/nmapscanner.py --target 192.168.1.1

# Run a Nikto scan
python standalone_tools/niktoscanner.py --target example.com --action scan

# Start a BeEF server
python standalone_tools/beefframework.py --action start_server
```

Or use the launcher script:

```bash
# List all available tools
python run_tool.py --list

# Run a specific tool
python run_tool.py nmapscanner --target 192.168.1.1
```

### Available Tools

Here are some of the key security tools available individually:

- **NmapScanner**: Network exploration and security auditing
- **OwaspZAP**: Web application security scanner
- **NiktoScanner**: Web server vulnerability scanner
- **MetasploitFramework**: Penetration testing framework
- **WiresharkAnalyzer**: Network protocol analyzer
- **W3afScanner**: Web application attack and audit framework
- **BeEFFramework**: Browser exploitation framework

Each tool supports different actions and parameters. Use the `--help` flag to see available options:

```bash
python standalone_tools/nmapscanner.py --help
```

## Common Tool Options

Most individual tools support these common options:

- `--target`: Target URL, IP, or domain
- `--action`: Specific action to perform
- `--output`: File to save results to
- `--format`: Output format (json, xml, etc.)
- `--timeout`: Timeout for operations in seconds
- `--verbose`: Enable verbose output

## Integration Guide

To use individual tools in your own Python scripts:

```python
# Import a specific tool
from security_tools_integration import NmapScanner, security_tools_manager

# Create a tool instance
scanner = security_tools_manager.get_tool("NmapScanner")

# Check if tool is installed
if not scanner.check_installation():
    scanner.install()

# Use the tool
results = scanner.comprehensive_scan("192.168.1.0/24")
print(results)
```

## Reporting Issues

If you encounter issues with individual tools or the unified system, please report them with details about:

1. Which tool you were using
2. Command or action you were trying to run
3. The error message or unexpected behavior
4. Your environment (OS, Python version) 