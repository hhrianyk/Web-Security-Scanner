# DNS Spoofing Module

## Overview

This module provides DNS spoofing capabilities integrated with the security assessment framework. The module supports three major DNS spoofing tools:

1. **DNSChef** - A flexible DNS proxy server for spoofing DNS records
2. **Ettercap** - A comprehensive suite for man-in-the-middle attacks with DNS spoofing capabilities
3. **Responder** - A LLMNR, NBT-NS and MDNS poisoner with built-in rogue authentication server

## Features

- Automatic installation of DNS spoofing tools
- Configuration of spoofed domains
- Management of DNS spoofing attacks
- Detailed logging and monitoring

## Technical Features

### DNS Spoofing Techniques

- **DNS Proxy Spoofing** (DNSChef): Acts as a DNS proxy server, intercepting DNS requests and returning spoofed responses
- **ARP Poisoning + DNS Spoofing** (Ettercap): Combines ARP cache poisoning with DNS response spoofing
- **LLMNR/NBT-NS/MDNS Poisoning** (Responder): Targets alternative name resolution protocols

### Protection Mechanisms

The module includes information about protection mechanisms:

- **DNSSEC**: Domain Name System Security Extensions for verification of DNS responses
- **DNS over HTTPS (DoH)**: Encrypts DNS requests to prevent tampering
- **DNS over TLS (DoT)**: Encrypts DNS traffic using TLS
- **Response integrity checking**: Validates the integrity of DNS responses

### Attack Methods

The module supports several attack methods:

- **Cache Poisoning**: Corrupting the DNS resolver's cache
- **DNS Hijacking**: Redirecting DNS queries to malicious servers
- **Zone Transfer Attacks**: Exploiting misconfigured DNS servers
- **DNS Tunneling**: Using DNS protocol for covert data exfiltration

## Installation

The required dependencies are automatically installed when you install the security tools:

```
pip install -r requirements_security_tools.txt
```

## Usage

### Command-line Interface

```
python security_framework.py --dns-spoof --dns-tool dnschef --domain example.com --ip 10.0.0.1
```

#### DNS Spoofing Options

- `--dns-spoof`: Enable DNS spoofing attack
- `--dns-tool`: Select tool (dnschef, ettercap, or responder)
- `--interface`: Network interface to use (default: eth0)
- `--domain`: Domain to spoof (used with --ip)
- `--ip`: IP to redirect to (used with --domain)
- `--domains-file`: JSON file containing domains to spoof {domain: ip, ...}
- `--targets`: Targets for Ettercap (IP addresses/ranges)
- `--stop-dns-spoof`: Stop DNS spoofing attack
- `--list-dns-tools`: List available DNS spoofing tools

### Python API

```python
from security_framework import SecurityFramework

# Initialize the framework
framework = SecurityFramework(target="example.com")

# Start DNS spoofing with DNSChef
domains = {"example.com": "10.0.0.1", "sub.example.com": "10.0.0.2"}
result = framework.run_dns_spoofing_attack(
    tool="dnschef",
    interface="eth0",
    domains=domains
)

# Check status
status = framework.get_dns_spoofing_status("dnschef")
print(status)

# Stop DNS spoofing
framework.stop_dns_spoofing_attack("dnschef")
```

## Examples

### Basic DNS Spoofing with DNSChef

```
python security_framework.py --dns-spoof --dns-tool dnschef --domain victim.com --ip 192.168.1.100
```

### Using Ettercap with Custom Targets

```
python security_framework.py --dns-spoof --dns-tool ettercap --interface eth0 --domain victim.com --ip 192.168.1.100 --targets 192.168.1.5 192.168.1.1
```

### Using Responder for LLMNR/NBT-NS Poisoning

```
python security_framework.py --dns-spoof --dns-tool responder --interface eth0
```

### Spoofing Multiple Domains with a JSON File

Create a file named `domains.json`:

```json
{
  "example.com": "192.168.1.100",
  "mail.example.com": "192.168.1.100",
  "login.example.com": "192.168.1.101"
}
```

Then run:

```
python security_framework.py --dns-spoof --dns-tool dnschef --domains-file domains.json
```

## Security Considerations

This module is intended for educational and security testing purposes only. Unauthorized DNS spoofing is illegal in many jurisdictions and can lead to serious legal consequences.

Always:
- Obtain proper authorization before conducting tests
- Limit testing to controlled environments
- Document all activities
- Understand the potential impact of the testing

## Troubleshooting

- **Tool installation fails**: Check if you have the necessary system prerequisites
- **Permission errors**: Most DNS spoofing tools require root/administrative privileges
- **DNS spoofing doesn't work**: Check firewall settings, network configuration, and ensure the target is using your system as a DNS resolver 