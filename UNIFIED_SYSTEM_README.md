# Unified Security Assessment Platform

A comprehensive, integrated security assessment platform that combines multiple security tools into a single unified system.

## Overview

The Unified Security Assessment Platform integrates various security tools and modules into a single coherent system that allows for:

1. **Comprehensive Security Assessments** - Automated security testing covering network scanning, web vulnerability assessment, OSINT reconnaissance, exploitation, and more
2. **Centralized Configuration** - Single configuration file to control all security tools
3. **Unified Reporting** - Standardized reports that combine results from multiple tools
4. **Multiple Interfaces** - Command-line, API, and web interfaces for access
5. **AI-Powered Analysis** - Integrated AI components for advanced security analysis

## System Components

The unified security platform integrates the following components:

1. **unified_security_tools.py** - Main integration point and primary interface for all security tools
2. **security_integrator.py** - Dynamic tool discovery and integration system
3. **security_platform.py** - Core platform for running security assessments
4. **unified_config.json** - Centralized configuration for all components

### Security Modules

- **Network Security** - Port scanning, service detection, and network infrastructure assessment
- **Web Security** - Web application vulnerability scanning and testing
- **OSINT Reconnaissance** - Open Source Intelligence gathering and analysis
- **DNS Security** - DNS spoofing and related security testing
- **Exploitation** - Safe exploitation testing using various frameworks
- **AI Security Analysis** - AI-powered vulnerability assessment and remediation
- **Comprehensive Testing** - Full security testing including all modules
- **Client Reporting** - Professional vulnerability reporting

## Getting Started

### Prerequisites

- Python 3.7+
- Required Python packages (install via `pip install -r requirements.txt`)

### Quick Start

#### On Windows:

```
run_unified_security.bat
```

#### On Linux/Mac:

```
chmod +x run_unified_security.sh
./run_unified_security.sh
```

### Running a Security Assessment

#### Command Line

```bash
# Full assessment
python unified_security_tools.py example.com

# Quick assessment
python unified_security_tools.py example.com --type quick

# Network-focused assessment
python unified_security_tools.py example.com --type network

# Web vulnerability assessment
python unified_security_tools.py example.com --type web

# OSINT reconnaissance
python unified_security_tools.py example.com --type osint

# DNS security assessment
python unified_security_tools.py example.com --type dns

# Exploitation testing
python unified_security_tools.py example.com --type exploit

# AI security analysis
python unified_security_tools.py example.com --type ai
```

#### Web Interface

To start the web interface:

```bash
python unified_security_tools.py --start-web
```

This will start a web server at http://127.0.0.1:5000 by default. You can customize the host and port:

```bash
python unified_security_tools.py --start-web --host 0.0.0.0 --port 8080
```

### Output Formats

The system supports multiple output formats:

```bash
python unified_security_tools.py example.com --format json
python unified_security_tools.py example.com --format html
python unified_security_tools.py example.com --format pdf
python unified_security_tools.py example.com --format all  # Default
```

### Enabling Specific Modules

```bash
python unified_security_tools.py example.com --enable network --enable web
```

### Asynchronous Assessment

For long-running assessments, you can run them asynchronously:

```bash
python unified_security_tools.py example.com --async
```

This will return an assessment ID that you can use to check the status later:

```bash
python unified_security_tools.py --show-assessment assessment_20230401_123456_12345678
```

### Listing Available Tools and Workflows

```bash
python unified_security_tools.py --list-tools
python unified_security_tools.py --list-workflows
python unified_security_tools.py --list-modules
```

## Configuration

The system uses a unified configuration file (`unified_config.json`) to control all aspects of the system. You can also provide a custom configuration file:

```bash
python unified_security_tools.py example.com --config my_config.json
```

### Configuration Structure

```json
{
  "output_dir": "unified_security_reports",
  "parallel_execution": true,
  "max_workers": 8,
  "default_modules": ["network", "web", "osint", "ai", "report"],
  "report_formats": ["json", "html", "pdf"],
  "web_interface": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 5000
  },
  "modules": {
    "network_scanning": {
      "enabled": true,
      "port_range": "1-1000"
    },
    "web_vulnerability_scanning": {
      "enabled": true,
      "scan_depth": "deep"
    }
  }
}
```

## Architecture

### System Architecture

The unified security system follows a modular design:

1. **Tool Discovery Layer** - Dynamically discovers and loads security tools
2. **Integration Layer** - Standardizes interfaces and data formats across tools
3. **Orchestration Layer** - Manages execution of security assessments
4. **Reporting Layer** - Standardizes and combines results into reports
5. **Interface Layer** - Provides CLI, API, and web interfaces

### Data Flow

1. User requests a security assessment through one of the interfaces
2. The system identifies and configures the appropriate security tools
3. The orchestration layer executes tools in the correct order
4. Results are collected, normalized, and stored
5. The reporting layer generates standardized reports
6. Results are presented to the user through the selected interface

## Extending the System

The security system is designed to be easily extensible:

1. Create a new security tool Python module
2. Implement the `get_capabilities()` class method to describe the tool's functionality
3. The tool will be automatically discovered and integrated into the system

### Example Tool Module

```python
class MySecurityTool:
    """My custom security tool for XYZ testing"""
    
    @classmethod
    def get_capabilities(cls):
        return {
            "name": "My Security Tool",
            "description": "Custom security tool for XYZ testing",
            "actions": ["scan", "analyze", "report"],
            "target_types": ["web_application", "network"],
            "output_formats": ["json", "html"],
            "dependencies": []
        }
        
    def scan(self, target, **kwargs):
        # Implement scanning logic
        return results
```

## Additional Information

### Directory Structure

- `unified_security_reports/` - Default output directory for reports
- `security_data/` - Directory for storing security data
- `templates/` - Report templates
- `static/` - Static assets for web interface

### Log Files

- `unified_security.log` - Main system log
- `security_integrator.log` - Tool integration log
- `vulnerability_scanner.log` - Vulnerability scanning log
- `security_platform.log` - Security platform log

## License

This project is licensed under the MIT License

## Acknowledgments

This integrated security system combines various open-source security tools and libraries to provide a comprehensive security assessment platform. 