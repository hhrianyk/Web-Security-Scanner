# AI-Powered Comprehensive Vulnerability Scanner

This system is an advanced web vulnerability scanning platform that integrates multiple security testing tools with AI-powered analysis to provide comprehensive vulnerability detection, exploitation path analysis, and detailed remediation recommendations.

## Features

- **Multi-layered vulnerability scanning** using various security testing tools
- **AI-enhanced vulnerability analysis** to determine exploitation conditions and impact
- **Detailed exploitation path analysis** showing how vulnerabilities can be chained together
- **Comprehensive remediation recommendations** with code examples
- **Detailed reporting** on discovered vulnerabilities
- **User-friendly web interface** for initiating scans and viewing reports

## System Architecture

The system follows a conceptual model that:
1. Receives a website URL for vulnerability testing
2. Processes it through a comprehensive scanning pipeline
3. Studies the site in detail to find vulnerabilities
4. Analyzes under what conditions these vulnerabilities appear
5. Investigates how the vulnerabilities could be exploited
6. Determines what each vulnerability provides to an attacker
7. Generates detailed reports with exploitation methods and remediation steps

## Components

- **Web Interface** - Flask-based frontend for submitting URLs and viewing reports
- **Core Scanner** - Basic vulnerability scanner for essential checks
- **Comprehensive Tester** - Advanced reconnaissance and testing module
- **Specialized Testing Modules** - Individual modules for specific vulnerability types:
  - Injection attacks (SQL, NoSQL, Command)
  - XSS vulnerabilities (Reflected, Stored, DOM-based)
  - Authentication weaknesses
  - And more
- **AI Security Integrator** - Enhances detection and analysis with AI capabilities

## Setup

### Requirements

- Python 3.8 or higher
- Required Python packages listed in `requirements.txt`
- MongoDB (required for storing scan results and vulnerability data)
- Scapy (required for network analysis)
- For AI capabilities: API keys for OpenAI, Anthropic, or Google Gemini (optional)

### Installation

#### Automated Setup (Recommended)

The easiest way to set up the system is using the provided setup script:

```
python setup.py
```

This script will:
1. Check if your Python version is compatible
2. Install all required dependencies
3. Set up the .env file from the template (if it doesn't exist)
4. Check MongoDB availability
5. Check Scapy installation
6. Create required directories

#### Manual Installation

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   ```
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
4. Install required packages:
   ```
   pip install -r requirements.txt
   ```
5. Install MongoDB (required):
   - Download from: https://www.mongodb.com/try/download/community
   - Follow installation instructions for your OS
6. Set up API keys:
   - Copy `.env.template` to `.env`
   - Add your API keys to the new file
   - Run `python verify_api_keys.py` to validate your configuration

### API Key Security

**IMPORTANT**: This system uses API keys for AI services which should be handled securely:

- Never commit API keys to version control
- Always use the `.env` file which is ignored by git
- Regularly rotate your API keys
- Use the built-in `verify_api_keys.py` tool to check your configuration
- For production, consider using environment variables or a secrets manager

### Running the Application

1. Start the web server:
   ```
   python app.py
   ```
2. Open a browser and navigate to `http://localhost:5000`
3. Enter the target URL and select the scan type
4. Review the detailed report when the scan completes

## Scan Types

### Standard Scan
Basic vulnerability detection that checks for:
- Cross-Site Scripting (XSS)
- SQL Injection
- SSL/TLS Security Issues
- Open Ports
- Directory Traversal
- Security Headers

### AI-Enhanced Scan
Comprehensive vulnerability analysis with:
- All standard scan features
- Deep reconnaissance of the target
- AI-powered analysis of vulnerabilities
- Detailed exploitation paths
- AI-generated remediation recommendations
- Comprehensive impact assessment

## Command-Line Usage

You can also run scans from the command line:

### Standard Scanner
```
python app.py <target_url>
```

### AI-Enhanced Scanner
```
python ai_vulnerability_scanner.py <target_url> --output <output_directory>
```

## Troubleshooting

If you encounter issues:

1. Check the log files in the root directory
2. Verify your API keys with `python verify_api_keys.py`
3. Make sure required dependencies are installed:
   - Run `pip install -r requirements.txt` to ensure all packages are installed
   - Verify MongoDB is running with `python -c "import pymongo; pymongo.MongoClient('mongodb://localhost:27017').admin.command('ismaster')"`
   - Check if scapy is working with `python -c "import scapy.all; print('Scapy is working')"`
4. Make sure required directories exist (`templates`, `static`, etc.)
5. If APIs are not working, check your .env file configuration

## Security Notes

- This tool should only be used on websites you own or have explicit permission to scan
- Unauthorized scanning may be illegal and unethical
- The scanner may produce false positives and false negatives
- Always validate findings manually before implementing fixes

## Extending the System

The system is designed to be modular and extensible:
- Add new vulnerability testing modules in separate files
- Implement new AI analysis capabilities in the AI Security Integrator
- Create custom reporting formats for different use cases

## License

This project is for educational purposes only. Use responsibly.

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security testing on any system.

## Security Tools Integration

This system now integrates multiple open-source security tools to provide comprehensive security testing capabilities:

### Vulnerability Scanners

- **OWASP ZAP** - Web application vulnerability scanner with automated scanning, traffic interception, and active/passive scanning
- **Nikto** - Web server scanner for detecting outdated versions, insecure files, and server misconfigurations
- **W3af** - Web application attack and audit framework with a modular architecture
- **W3af AI** - AI-enhanced w3af integration that simulates manual penetration testing methodologies

### Network Analyzers

- **Nmap** - Network mapper for port scanning, service and OS detection, and script-based scanning
- **Wireshark** - Network protocol analyzer for traffic capture and deep protocol analysis
- **TCPDump** - Command-line packet analyzer for network troubleshooting

### Web Application Testing Tools

- **SQLMap** - Automated SQL injection detection and exploitation tool
- **XSSer** - Cross-Site Scripting (XSS) testing framework with advanced payload generation

### Penetration Testing Frameworks

- **Metasploit Framework** - Advanced exploitation platform with a database of exploits and post-exploitation modules
- **BeEF** - Browser Exploitation Framework for testing browser security

### Advanced AI Security Integration

- **AI-powered W3af** - Enhanced web application testing with AI-simulated manual testing techniques
- **IBM Watson for Cybersecurity** - Deep analysis of vulnerabilities and security events with Watson's cognitive capabilities

## New AI-Powered Manual Testing Simulation

The system now includes a powerful AI-driven manual testing simulation capability that:

1. **Simulates human security testing methodologies** - Goes beyond automated scanning by simulating how a human penetration tester would approach the target
2. **Discovers context-aware vulnerabilities** - Identifies issues that require understanding application logic and business rules
3. **Provides exploitation scenarios** - Generates detailed attack paths showing how vulnerabilities could be exploited in real-world scenarios
4. **Delivers detailed remediation guidance** - Offers specific code-level fixes with before/after examples

This capability is implemented through the w3af AI integration module that combines:
- Automated w3af scanning
- AI-simulated manual testing methodology
- Exploitation path analysis
- Defensive measures recommendations

## IBM Watson for Cybersecurity Integration

The system now leverages IBM Watson for Cybersecurity to provide:

1. **Advanced threat intelligence** - Correlates findings with global threat data
2. **Cognitive vulnerability assessment** - Identifies complex vulnerabilities through pattern recognition
3. **Security event analysis** - Detects abnormal patterns in security events
4. **Risk scoring** - Provides quantitative risk assessment based on multiple factors
5. **Detailed remediation recommendations** - Offers prioritized, implementation-ready security fixes

This integration connects with:
- IBM X-Force Exchange for threat intelligence
- IBM QRadar for security event correlation
- IBM Security Advisor for remediation guidance

To use these new capabilities, run:
```
python security_framework.py <target_url> --output <output_directory>
```

To run only specific components:
```
python security_framework.py <target_url> --w3af-only  # Run only w3af AI assessment
python security_framework.py <target_url> --watson-only  # Run only IBM Watson analysis
```

## API Keys and Configuration

To use the AI-enhanced features, you'll need to configure:

1. **OpenAI, Anthropic, or Google Gemini API keys** - For AI-driven analysis and manual testing simulation
2. **IBM Watson API keys** - For IBM Watson for Cybersecurity integration

Configure these in the `.env` file by copying the template:
```
cp .env.template .env
```

Then edit the file to add your API keys.

## Important Security Notice

All security testing tools should only be used on systems you own or have explicit permission to test. Unauthorized scanning or testing is illegal and unethical.

## New Feature: Comprehensive Exploit Documentation

Our system now includes detailed exploitation documentation for all identified vulnerabilities, ensuring that security professionals have complete information about how exploits work and how to reproduce security issues.

### Key Features

- **Detailed Exploitation Steps**: Each vulnerability now includes step-by-step exploitation instructions
- **Command Examples**: Ready-to-use commands to verify and exploit vulnerabilities
- **Code Examples**: Sample code in relevant languages for each exploitation scenario
- **Required Tools**: Lists of tools needed for each exploitation technique
- **Potential Impact**: Comprehensive impact assessment for each vulnerability type
- **Exploitation Guide**: Automatically generates a detailed exploitation guide for all vulnerabilities

### Using the Exploit Documentation Features

The system automatically enhances all vulnerability reports with detailed exploitation information. This information appears in:

1. The HTML vulnerability report in the "Vulnerable Components" section
2. The client vulnerability report with tabbed exploitation details
3. A dedicated exploitation guide (MD format) generated in the report directory

Additionally, you can use the `exploit_documenter.py` utility directly:

```bash
# Generate an exploitation guide from scan results
python exploit_documenter.py --scan-results path/to/scan_results.json

# Validate exploitation documentation in reports
python exploit_documenter.py --validate path/to/report1.json path/to/report2.html

# Generate an exploitation guide with custom output directory
python exploit_documenter.py --scan-results path/to/results.json --output-dir custom_dir
```

## New Feature: Exploit Search System

The system now includes a powerful exploit search capability that automatically detects services running on target systems and finds relevant exploits from multiple databases. This feature generates comprehensive reports with detailed information on how to use the exploits.

### Key Features

- **Automated Service Detection**: Identifies running services and their versions
- **Multi-Source Exploit Search**: Searches for exploits in Exploit-DB, Metasploit, Vulners, NVD, and Rapid7
- **Detailed Usage Documentation**: Provides step-by-step instructions for each exploit
- **Command Examples**: Ready-to-use commands to utilize exploits
- **Code Examples**: Sample code for exploitation where available
- **Comprehensive Reports**: Generates detailed MD and HTML reports
- **Confidence Scoring**: Rates each exploit's relevance to the detected service

### Integrated Exploit Databases

The system connects to multiple exploit databases:

- **Exploit-DB**: Comprehensive collection of public exploits
- **Metasploit Framework**: Extensive database of ready-to-use exploits
- **Vulners**: Vulnerability database with exploit availability information
- **NVD (National Vulnerability Database)**: Standardized vulnerability information
- **Rapid7 Vulnerability Database**: Detailed exploit and vulnerability information

### Using the Exploit Search System

The exploit search system can be run in several ways:

#### Via Unified Security Interface

```bash
# Run exploit search as mode 6 in the unified interface
python unified_security_interface.py --target <ip_or_domain> --mode 6 --scan-type comprehensive
```

#### Using the Dedicated Python Script

```bash
# Run using the specialized script
python run_exploit_search.py <ip_or_domain> --scan-type comprehensive
```

#### Using the Batch File (Windows)

```bash
# Run using the batch file
run_exploit_search.bat <ip_or_domain>
```

#### Using Services File

If you already have a services file (JSON format with services information), you can skip the scanning phase:

```bash
python run_exploit_search.py --services-file path/to/services.json
```

### Output Files

The system generates multiple output files:

- **detected_services.json**: List of services detected on the target
- **exploit_search_results.json**: Raw results of exploit searches
- **documented_exploits.json**: Exploits with detailed usage documentation
- **comprehensive_exploit_report.md**: Markdown report with all findings
- **comprehensive_exploit_report.html**: HTML version of the report
- **exploitation_guide.md**: Detailed guide on using all found exploits

### Example Workflow

1. Run the exploit search system against a target:
   ```bash
   python run_exploit_search.py 192.168.1.1
   ```

2. The system detects services running on the target
3. The system searches for exploits for each detected service
4. The system documents each exploit with usage instructions
5. The system generates comprehensive reports
6. Review the HTML report for a user-friendly overview
7. Use the exploitation guide for detailed instructions

### Integration with Vulnerability Scanning

The exploit search system can be combined with vulnerability scanning for a complete security assessment:

1. Run a comprehensive vulnerability scan:
   ```bash
   python unified_security_interface.py --target <ip_or_domain> --mode 1
   ```

2. Run the exploit search:
   ```bash
   python unified_security_interface.py --target <ip_or_domain> --mode 6
   ```

3. Generate a comprehensive technical report:
   ```bash
   python unified_security_interface.py --target <ip_or_domain> --mode 5
   ```

### Important Security Notice

The exploit search system is provided for educational and authorized security testing purposes only. Always obtain proper authorization before performing security testing on any system. 