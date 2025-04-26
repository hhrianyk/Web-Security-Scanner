# Advanced Security Testing Framework

This framework provides comprehensive security testing capabilities based on OWASP standards. It includes testing for various vulnerabilities including injection attacks, XSS, authentication issues, and more.

## Features

The framework currently implements testing for:

1. **Injection Attacks**
   - SQL Injection (Boolean-based, Time-based, Error-based, UNION-based, Stacked queries, Out-of-band)
   - NoSQL Injection (MongoDB, Redis, CouchDB)
   - Command Injection (CLI injections, System commands, Parameter injection)

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS (URL parameters, Form inputs, HTTP headers)
   - Stored XSS (Comments, User profiles, File uploads)
   - DOM-based XSS (window.location manipulation, document.referrer exploitation, JavaScript events)

3. **Authentication & Authorization**
   - Brute Force Attacks (Dictionary attacks, Credential stuffing)
   - Session-based Attacks (Session fixation, Session hijacking, Session prediction)
   - OAuth Vulnerabilities (Open redirect, Token theft, Scope manipulation)

4. Additional vulnerability testing modules are planned for future releases.

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd <repository-folder>
```

2. Install dependencies:
```bash
pip install -r requirements_security_testing.txt
```

3. For the modules that use Selenium, ensure you have the appropriate browser and driver:
```bash
# For Firefox (recommended)
pip install webdriver-manager
```

## Usage

### Basic Usage

To run a comprehensive security assessment against a target:

```bash
python advanced_security_tester.py example.com
```

This will run all tests and generate comprehensive HTML and JSON reports.

### Running Specific Tests

To run only specific types of tests:

```bash
# For injection tests only
python advanced_security_tester.py example.com --injection-only

# For XSS tests only
python advanced_security_tester.py example.com --xss-only

# For authentication tests only
python advanced_security_tester.py example.com --auth-only
```

### Output Options

You can specify the output directory and report format:

```bash
# Specify output directory
python advanced_security_tester.py example.com --output my_security_assessment

# Generate only JSON report
python advanced_security_tester.py example.com --format json

# Generate only HTML report
python advanced_security_tester.py example.com --format html
```

## Using Individual Modules

You can also use the individual testing modules directly:

### Injection Attack Testing

```python
from injection_attacks import InjectionAttacker

# Initialize the injection attacker
injector = InjectionAttacker("https://example.com", "output_directory")

# Run all injection tests
results = injector.run_all_tests()

# Or run specific tests
sql_results = injector.run_sql_injection_tests()
nosql_results = injector.run_nosql_injection_tests()
command_results = injector.run_command_injection_tests()

# Save results
injector.save_results()
```

### XSS Attack Testing

```python
from xss_attacks import XSSAttacker

# Initialize the XSS attacker
xss_attacker = XSSAttacker("https://example.com", "output_directory")

# Run all XSS tests
results = xss_attacker.run_all_tests()

# Or run specific tests
reflected_results = xss_attacker.run_reflected_xss_tests()
stored_results = xss_attacker.run_stored_xss_tests()
dom_results = xss_attacker.run_dom_xss_tests()

# Save results
xss_attacker.save_results()
```

### Authentication Attack Testing

```python
from auth_attacks import AuthAttacker

# Initialize the auth attacker
auth_attacker = AuthAttacker("https://example.com", "output_directory")

# Run all auth tests
results = auth_attacker.run_all_tests()

# Or run specific tests
brute_force_results = auth_attacker.run_brute_force_tests()
session_results = auth_attacker.run_session_attack_tests()
oauth_results = auth_attacker.run_oauth_vulnerability_tests()

# Save results
auth_attacker.save_results()
```

## Important Notes

1. **Legal Disclaimer**: Only use this tool with explicit permission on systems you own or are authorized to test. Unauthorized security testing is illegal and unethical.

2. **Rate Limiting**: The tool implements rate limiting to avoid overwhelming the target system, but be aware of potential DoS implications of security testing.

3. **False Positives**: All security findings should be manually verified to eliminate false positives.

4. **Dependencies**: The tool has several dependencies including browsers for XSS testing and MongoDB/Redis libraries for NoSQL testing.

## Reports

The framework generates detailed reports in HTML and JSON formats, including:
- Executive summary with risk level assessment
- Detailed findings with evidence
- Remediation recommendations
- Technical details about each vulnerability

Reports are stored in the output directory specified, or in "security_assessment" by default.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 