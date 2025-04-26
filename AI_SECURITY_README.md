# AI Security Tools Integration

This module integrates seven advanced AI-powered security tools into the existing security framework to enhance vulnerability detection and analysis capabilities.

## Integrated AI Security Tools

1. **OWASP AI Security Scanner**
   - Machine learning for vulnerability detection
   - Automatic code analysis
   - Search for common attack patterns
   - CI/CD integration

2. **Arachni AI**
   - Intelligent scanning
   - Adaptive testing
   - Automatic attack vector detection
   - High accuracy vulnerability detection

3. **AI-BOLIT**
   - Neural network analysis
   - Malicious code detection
   - File system checking
   - Backdoor search capabilities

4. **Deep Exploit**
   - Automatic vulnerability exploitation
   - Self-learning algorithms
   - Exploit generation
   - Security analysis

5. **SecLists AI**
   - AI-generated attack vectors
   - Smart dictionaries for brute force
   - Adaptive payloads
   - Context analysis

6. **AI-Driven Fuzzer**
   - Intelligent fuzzing
   - Test data generation
   - System response analysis
   - Automatic validation

7. **Neural Recon**
   - Infrastructure reconnaissance
   - Attack surface analysis
   - Vulnerability mapping
   - Predictive analysis

## Setup

1. Clone the repository or ensure you have all the required files.
2. Install required dependencies:
   ```
   pip install -r requirements_security_testing.txt
   ```
3. Copy `.env.security_ai.template` to `.env`:
   ```
   cp .env.security_ai.template .env
   ```
4. Edit `.env` and add your API keys for the various AI security services.

## Usage

### Command Line Interface

```bash
python ai_security_integrator.py --target example.com --output results
```

#### Options:

- `--target` or `-t`: Target URL or IP address (required)
- `--output` or `-o`: Output directory for results (default: "ai_security_results")
- `--tools`: Comma-separated list of tools to run (default: all)
- `--html-report`: Generate HTML report
- `--env-file`: Path to custom .env file with API keys

### Running Specific Tools

To run only specific tools, use the `--tools` option:

```bash
python ai_security_integrator.py --target example.com --tools owasp,arachni,neuralrecon
```

Available tool options:
- `owasp`: OWASP AI Security Scanner
- `arachni`: Arachni AI
- `aibolit`: AI-BOLIT
- `deepexploit`: Deep Exploit
- `seclists`: SecLists AI
- `fuzzer`: AI-Driven Fuzzer
- `neuralrecon`: Neural Recon

### Python API

You can also use the tools programmatically:

```python
from ai_security_integrator import AISecurityIntegrator

# Initialize the integrator
integrator = AISecurityIntegrator(target="example.com", output_dir="results")

# Run all tools
results = integrator.run_all_ai_tools()

# Generate HTML report
report_file = integrator.generate_html_report()
```

## Output

The tool will create a structured output directory containing:

- JSON results from each AI security tool
- Combined analysis of all findings
- Comprehensive HTML report (if requested)
- Extracted payloads and attack vectors

## Integration with Existing Framework

This module integrates with the existing security framework, allowing for:

1. Combined analysis of traditional security scans and AI-enhanced results
2. Comprehensive vulnerability assessments
3. Enhanced remediation recommendations
4. Intelligent attack simulation

## Requirements

- Python 3.6+
- Dependencies listed in `requirements_security_testing.txt`
- Valid API keys for each AI service
- For AI-BOLIT: PHP interpreter

## Notes on Usage

- The tools use API keys for authentication, ensure you have valid licenses
- Some tools use machine learning models that may require network access
- For maximum effectiveness, use all tools together to get comprehensive coverage
- If run against production systems, ensure you have proper authorization 