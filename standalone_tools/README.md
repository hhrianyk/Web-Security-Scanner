# Standalone Security Tools

This directory contains standalone executable modules for each security tool in the unified framework.
Each tool can be run independently without requiring the entire framework.

## Available Tools

### OwaspZAP

Open-source web application security scanner

**Actions:** web_scan, active_scan, passive_scan, spider, ajax_spider

**Output Formats:** json, xml, html, console

**Usage:**

```bash
python standalone_tools/owaspzap.py --target [TARGET] --action [ACTION]
```

### NiktoScanner

Web server vulnerability scanner

**Actions:** web_scan, server_scan, config_check

**Output Formats:** json, xml, csv, txt

**Usage:**

```bash
python standalone_tools/niktoscanner.py --target [TARGET] --action [ACTION]
```

### W3afScanner

Web application attack and audit framework

**Actions:** web_scan, web_audit, vulnerability_assessment

**Output Formats:** json, xml, html, text

**Usage:**

```bash
python standalone_tools/w3afscanner.py --target [TARGET] --action [ACTION]
```

### NmapScanner

Network exploration and security auditing tool

**Actions:** port_scan, os_detection, service_detection, script_scan, version_detection

**Output Formats:** normal, xml, json, grepable

**Usage:**

```bash
python standalone_tools/nmapscanner.py --target [TARGET] --action [ACTION]
```

### WiresharkAnalyzer

Network protocol analyzer for traffic analysis

**Actions:** capture, analyze, filter, export

**Output Formats:** pcap, pcapng, json, csv, xml

**Usage:**

```bash
python standalone_tools/wiresharkanalyzer.py --target [TARGET] --action [ACTION]
```

### TCPDumpAnalyzer

Command-line packet analyzer for network traffic

**Actions:** capture, analyze, filter

**Output Formats:** pcap, text

**Usage:**

```bash
python standalone_tools/tcpdumpanalyzer.py --target [TARGET] --action [ACTION]
```

### SQLMapTool

Automated SQL injection and database takeover tool

**Actions:** sql_injection, database_enumeration, data_extraction, os_command_execution

**Output Formats:** json, csv, xml, sqlite

**Usage:**

```bash
python standalone_tools/sqlmaptool.py --target [TARGET] --action [ACTION]
```

### XSSerTool

XSS vulnerability testing framework

**Actions:** xss_scan, payload_generation, filter_bypass

**Output Formats:** json, xml, txt

**Usage:**

```bash
python standalone_tools/xssertool.py --target [TARGET] --action [ACTION]
```

### MetasploitFramework

Advanced exploitation framework

**Actions:** exploit, payload_generation, vulnerability_scan, post_exploitation

**Output Formats:** json, xml, txt

**Usage:**

```bash
python standalone_tools/metasploitframework.py --target [TARGET] --action [ACTION]
```

### BeEFFramework

Browser exploitation framework

**Actions:** browser_exploitation, social_engineering, session_hijacking, dom_manipulation

**Output Formats:** json, html

**Usage:**

```bash
python standalone_tools/beefframework.py --target [TARGET] --action [ACTION]
```

