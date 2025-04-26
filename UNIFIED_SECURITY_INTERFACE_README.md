# Unified Security Interface

A comprehensive security testing interface that provides multiple testing modes and detailed reporting capabilities.

## Overview

The Unified Security Interface integrates all security tools and services into a single system with five major operational modes:

1. **Comprehensive Automated Testing** - Full automated testing through all connected services and tools
2. **AI-Powered Testing** - Vulnerability assessment using advanced AI capabilities
3. **AI-Simulated Manual Testing** - Testing that simulates manual penetration testing methodologies with AI
4. **Individual Tool Testing** - Testing using each connected tool and service separately
5. **Detailed Technical Reporting** - Comprehensive technical reports on vulnerabilities, exploits, and remediation

Each mode generates detailed technical reports with extensive information about vulnerabilities, exploitation methods, attack vectors, and recommended fixes.

## Requirements

- Python 3.8 or higher
- All dependencies listed in `requirements.txt`
- Connected security tools and services (see Setup section)

## Setup

1. **Install required packages**:

   ```
   pip install -r requirements.txt
   ```

2. **Ensure all security tools are available**:

   The unified interface will dynamically discover and integrate available security tools. For full functionality, ensure the following key components are available:

   - `security_integrator.py` - Core integrator for all security tools
   - `unified_security_tools.py` - Unified security assessment system
   - `comprehensive_tester.py` - In-depth security testing module
   - `ai_vulnerability_scanner.py` - AI-powered vulnerability scanner
   - `vulnerability_reporter.py` - Comprehensive vulnerability reporting

3. **Configure API keys** (for AI-powered testing):

   Copy `.env.template` to `.env` and add your API keys:

   ```
   cp .env.template .env
   ```

   The file should include keys for OpenAI, Anthropic, or Google Gemini (for AI analysis).

## Usage

### Command Line Interface

The unified security interface can be used from the command line:

```
python unified_security_interface.py <target> [options]
```

#### Basic Examples:

```
# Comprehensive automated testing
python unified_security_interface.py example.com

# AI-powered testing
python unified_security_interface.py example.com --mode 2

# AI-simulated manual testing
python unified_security_interface.py example.com --mode 3

# Individual tool testing (all tools)
python unified_security_interface.py example.com --mode 4

# Individual tool testing (specific tool)
python unified_security_interface.py example.com --mode 4 --tool vulnerability_scanner

# Run all testing modes
python unified_security_interface.py example.com --all-modes

# List available security tools
python unified_security_interface.py --list-tools
```

#### Options:

- `--mode <1-5>` - Specify testing mode:
  1. Comprehensive automated testing
  2. AI-powered testing
  3. AI-simulated manual testing
  4. Individual tool testing
  5. Generate technical report (requires previous test results)
  
- `--tool <tool_name>` - Specific tool to use in mode 4
- `--output-dir <directory>` - Output directory for reports (default: "security_reports")
- `--report-type <basic|detailed|executive>` - Type of report to generate (default: "detailed")
- `--all-modes` - Run all testing modes
- `--list-tools` - List all available security tools

### Windows Batch Script

For Windows users, a batch script is provided for easier execution:

```
run_unified_security.bat example.com
```

The batch script provides an interactive menu for selecting the testing mode.

## Testing Modes

### Mode 1: Comprehensive Automated Testing

This mode runs a full automated security assessment using all available security tools. It provides the most thorough analysis of the target system, including:

- Network scanning
- Web vulnerability assessment
- OSINT reconnaissance
- Infrastructure analysis
- API security testing
- Authentication testing
- Injection vulnerability detection
- and more...

### Mode 2: AI-Powered Testing

This mode leverages AI capabilities to enhance security testing by:

- Using AI to analyze possible vulnerability conditions
- Determining potential exploitation paths
- Generating detailed remediation recommendations
- Providing AI-enhanced vulnerability analysis
- Simulating attacker thought processes

### Mode 3: AI-Simulated Manual Testing

This mode simulates how a human security tester would approach the target, using AI to:

- Replicate manual penetration testing methodologies
- Discover context-aware vulnerabilities
- Identify business logic flaws
- Generate exploitation scenarios
- Provide detailed attack narratives

### Mode 4: Individual Tool Testing

This mode allows running each security tool or service individually, giving you:

- Focused testing with specific tools
- Granular control over the testing process
- Ability to validate findings from specific tools
- Detailed outputs from each tool

### Mode 5: Detailed Technical Reporting

This mode generates comprehensive technical reports with:

- Detailed vulnerability descriptions
- Exploitation methods and examples
- Impact assessments
- Code-level remediation recommendations
- Proof-of-concept exploit details
- References to relevant CVEs and security standards

## Output Reports

The system generates detailed reports in multiple formats:

- **JSON** - Machine-readable data format
- **HTML** - User-friendly web-based report
- **PDF** - Printable documentation format (when available)
- **Markdown** - Text-based technical documentation

Reports include:

- Executive summary
- Vulnerability list with severity ratings
- Detailed technical descriptions
- Exploitation steps and examples
- Code samples for vulnerabilities
- Remediation recommendations
- References to security standards

## Security Considerations

- Only use this tool on systems you own or have explicit permission to test
- Review and comply with all relevant laws and regulations
- Unauthorized security testing can be illegal
- Handle vulnerability information responsibly
- Avoid running exploits against production systems

## Extending the System

The unified security interface is designed to be extensible:

1. To add a new security tool, create a Python module that follows the standard interface
2. Tools will be automatically discovered and integrated
3. New reporting formats can be added to the mode5_generate_technical_report method
4. Additional testing modes can be implemented by extending the UnifiedSecurityInterface class

## Troubleshooting

If you encounter issues:

1. Check the log file: `unified_security_interface.log`
2. Verify that required security tools are available
3. Check API keys in the `.env` file for AI-powered features
4. Ensure all required dependencies are installed
5. Verify target URL format and connectivity

## License

This system is for educational and professional security assessment purposes only. Use responsibly and ethically.

## Disclaimer

This tool is provided for legitimate security testing only. The authors are not responsible for misuse or damage caused by this tool. 