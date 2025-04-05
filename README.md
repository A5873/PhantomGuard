# Rootkit Hunter

Advanced security analysis tool for Linux systems with a focus on rootkit detection and system security.

## Features

- **System Security Checks**: Comprehensive checking of system configurations and security settings
- **Rootkit Detection**: Advanced detection of rootkits and backdoors
- **Memory Forensics**: Analysis of system memory for malicious patterns
- **Network Traffic Analysis**: Detection of suspicious network connections and traffic patterns
- **Container Security**: Analysis of Docker containers and their configurations

## Requirements

- Python 3.7 or higher
- Linux-based operating system
- Root/sudo privileges for comprehensive scanning

Optional:
- Volatility 3 for advanced memory forensics
- Docker for container security analysis
- tcpdump for network capture analysis

## Installation

### From Source

```bash
git clone https://github.com/example/rootkithunter.git
cd rootkithunter
pip install -e .
```

### Using pip

```bash
pip install rootkithunter
```

## Usage

Basic usage:

```bash
sudo rootkithunter
```

Custom scan with output options:

```bash
sudo rootkithunter --scan-type comprehensive --format html --output-dir /path/to/report
```

### Command Line Options

```
usage: rootkithunter [-h] [-o OUTPUT_DIR] [-t {quick,standard,comprehensive}]
                     [-f {txt,html,json}] [-n NETWORK_TIME] [-v] [-k]
                     [--force-no-root]

Rootkit Hunter - Advanced Security Analysis Tool

options:
  -h, --help            Show this help message and exit
  
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to save reports and artifacts
                        
  -t {quick,standard,comprehensive}, --scan-type {quick,standard,comprehensive}
                        Type of scan to perform
                        
  -f {txt,html,json}, --format {txt,html,json}
                        Report format
                        
  -n NETWORK_TIME, --network-time NETWORK_TIME
                        Duration of network capture in seconds
                        
  -v, --verbose         Enable verbose output
  
  -k, --keep-artifacts  Keep temporary artifacts after scanning
  
  --force-no-root       Force scan without root privileges (limited functionality)
```

## Scan Types

- **Quick**: Basic rootkit detection scan
- **Standard**: Rootkit detection and network analysis
- **Comprehensive**: Full analysis including memory forensics and container security

## License

This project is licensed under the MIT License - see the LICENSE file for details.

# Rootkit Hunter Toolkit

A comprehensive set of security tools for Linux systems to detect rootkits, check system security, and scan for vulnerabilities.

## Overview

This repository contains three powerful security tools designed to help system administrators and security professionals identify potential security issues on Linux systems:

1. **Advanced Security Analyzer** - Comprehensive security assessment tool with memory forensics, rootkit detection, and container security features
2. **System Security Checker** - Focused on detecting suspicious system activity, hidden processes, and unexpected configurations
3. **System Vulnerability Scanner** - Identifies vulnerabilities, outdated software, and hardware security issues

All tools use color-coded output for easy interpretation and provide detailed reports of findings.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/rootkithunter.git
cd rootkithunter
```

2. Make the scripts executable:
```bash
chmod +x advanced_security_analyzer.sh system_security_checker.sh system_vulnerability_scanner.sh
```

## Tool 1: Advanced Security Analyzer

### Features

- **Memory Forensics Analysis**: Examines memory for indicators of compromise
- **Rootkit Detection**: Detects sophisticated rootkits and kernel modifications
- **Network Traffic Analysis**: Identifies suspicious network traffic and configurations
- **Container Security**: Analyzes Docker containers for security issues
- **Custom Malware Detection**: Uses YARA rules to identify malicious signatures
- **Comprehensive Reporting**: Generates detailed security assessment reports with risk scoring

### Usage

Basic usage:
```bash
sudo ./advanced_security_analyzer.sh --all
```

Run specific modules:
```bash
sudo ./advanced_security_analyzer.sh --memory --network
sudo ./advanced_security_analyzer.sh --rootkit
sudo ./advanced_security_analyzer.sh --container
```

Advanced options:
```bash
# Run with custom output file
sudo ./advanced_security_analyzer.sh --all --output custom_report.txt

# Run in debug mode (preserves temporary files)
sudo ./advanced_security_analyzer.sh --all --debug

# Set custom network capture duration
sudo ./advanced_security_analyzer.sh --network --time 120
```

View help:
```bash
./advanced_security_analyzer.sh --help
```

### Dependencies

- **Essential**: bash, strings, grep, awk, sed, lsof, ps, netstat, find
- **Memory Analysis**: volatility3 (optional)
- **Network Analysis**: tcpdump
- **Malware Detection**: yara (optional)
- **Container Analysis**: docker (optional)

## Tool 2: System Security Checker

### Features

- **Process Monitoring**: Detects suspicious processes and hidden activities
- **Network Security Analysis**: Identifies unusual connections and potential backdoors
- **System File Integrity**: Checks for modified system files and binaries
- **Rootkit Detection**: Finds known rootkit indicators and suspicious files
- **Cron Job Analysis**: Examines scheduled tasks for malicious commands
- **SUID/SGID Checking**: Discovers unusual setuid binaries that could be used for privilege escalation
- **Log Analysis**: Scans system logs for security events and suspicious activities

### Usage

Basic usage:
```bash
sudo ./system_security_checker.sh
```

### Dependencies

- bash
- core utilities (ls, grep, awk, etc.)
- lsof (for file/process relationship analysis)
- strings (for binary analysis)

## Tool 3: System Vulnerability Scanner

### Features

- **System Information Gathering**: Collects detailed system information
- **Hardware Bug Detection**: Identifies CPU vulnerabilities and hardware issues
- **Software Vulnerability Assessment**: Scans installed packages for known vulnerabilities
- **CVE Checking**: Queries the National Vulnerability Database for security issues
- **Web Application Scanning**: Detects web server vulnerabilities and misconfigurations
- **SSL/TLS Configuration Analysis**: Checks for insecure SSL/TLS configurations
- **Hardware Tampering Detection**: Monitors for unauthorized hardware changes

### Usage

Basic usage:
```bash
sudo ./system_vulnerability_scanner.sh
```

Advanced options:
```bash
# Run a full comprehensive scan
sudo ./system_vulnerability_scanner.sh --full

# Focus on web vulnerabilities and CVE checking
sudo ./system_vulnerability_scanner.sh --web --cve

# Focus on system vulnerabilities
sudo ./system_vulnerability_scanner.sh --system

# Run without cleaning up temporary files
sudo ./system_vulnerability_scanner.sh --no-cleanup
```

View help:
```bash
./system_vulnerability_scanner.sh --help
```

### Dependencies

- **Required**: curl, wget
- **Recommended**: lshw, dmidecode, smartmontools, net-tools, jq

## Security Considerations

- All tools must be run with root privileges to access system information required for thorough checking
- Some features (like memory forensics) might not work on all systems depending on kernel configuration
- The tools are designed for defensive security assessment by authorized personnel

## Troubleshooting

- If you encounter "command not found" errors, install the missing dependencies
- Some features may be limited on certain distributions or containerized environments
- For memory analysis issues, ensure you have the latest version of volatility installed

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues to improve these tools.
