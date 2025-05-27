```
 ╔════════════════════════════════════════════════════════════════╗
 ║ ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗║
 ║ ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║║
 ║ ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║║
 ║ ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║║ 
 ║ ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║║
 ║ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝║
 ╚════════════════════════╦═GUARD═╦═══════════════════════════════╝
                          ╚═══════╝
```

# PhantomGuard

PhantomGuard is a powerful security analysis toolkit that combines advanced rootkit detection, memory forensics, and system monitoring capabilities. Built with Python and Rust, it provides comprehensive protection against sophisticated threats, featuring real-time analysis, container security scanning, and network traffic monitoring.

## Project Status

⚠️ **Notice**: PhantomGuard is currently under active development. APIs may change, and new features are being added regularly.
## Features

- **Advanced Memory Forensics**: Deep analysis of system memory to detect malicious code injection, hidden processes, and runtime anomalies
- **Network Security Monitoring**: Real-time traffic analysis with anomaly detection and suspicious connection identification
- **Rootkit Detection**: Comprehensive scanning for kernel-level and user-mode rootkits with syscall hook detection
- **Container Security**: Analysis of container images and running containers for vulnerabilities and security misconfigurations
- **Vulnerability Management**: System-wide scanning for known vulnerabilities with CVE matching and remediation guidance
- **Real-time System Monitoring**: Continuous monitoring with customizable alerting and automated response capabilities
- **Multi-platform Support**: Compatible with Linux, macOS, and Windows environments
- **Performance Optimization**: Configurable resource usage with Rust-accelerated components for high-performance environments
- **Dual Implementation**: Core functionality in Python with complementary shell scripts for Linux system analysis and standalone operation

## Implementation

The tool is currently implemented in Python with plans for performance-critical components to be implemented in Rust:

- **Python**: High-level orchestration, reporting, and analysis logic
- **Rust**: Performance-critical components (planned)

See [RUST.md](RUST.md) for details on the Rust implementation plans.

## Installation

⚠️ **Note**: PhantomGuard is currently in development and not yet available on PyPI.

```bash
# Clone the repository
git clone https://github.com/A5873/PhantomGuard.git
cd PhantomGuard

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install in development mode
pip install -e '.[dev]'
```

## Usage

```bash
# Basic system scan
phantomguard scan

# Full security analysis
phantomguard analyze --full

# Container security check
phantomguard container-scan

# Memory analysis
phantomguard memory-scan
```

## Shell Scripts

PhantomGuard includes powerful standalone shell scripts for Linux systems that can be used independently or in conjunction with the Python library:

### Advanced Security Analyzer

```bash
# Run a comprehensive security analysis
sudo ./advanced_security_analyzer.sh --all

# Run only specific security checks
sudo ./advanced_security_analyzer.sh --memory --rootkit
```

The Advanced Security Analyzer provides deep security analysis capabilities:
- Memory forensics and runtime process analysis
- Advanced rootkit detection techniques
- Network traffic monitoring and analysis
- Container security scanning
- Custom malware signature detection

### System Security Checker

```bash
# Run a complete system security check
sudo ./system_security_checker.sh
```

The System Security Checker performs these critical security checks:
- Detection of suspicious processes and hidden services
- Network connection analysis and anomaly detection
- System file integrity verification
- Rootkit indicators and backdoor detection
- Suspicious cron job identification
- SUID/SGID binary analysis
- Log file analysis for security events

### System Vulnerability Scanner

```bash
# Run a vulnerability scan with all checks
sudo ./system_vulnerability_scanner.sh --full

# Focus only on specific vulnerability types
sudo ./system_vulnerability_scanner.sh --web --cve
```

The System Vulnerability Scanner includes:
- CVE checking for the OS and installed packages
- Hardware vulnerability and bug detection
- Web application and server configuration analysis
- System information gathering and security assessment

### Integration with Python Library

The shell scripts can be used in different ways alongside the Python library:

1. **Standalone Mode**: Use the scripts directly for quick analysis without installing the full Python package
2. **Complementary Mode**: Run specific shell script capabilities alongside Python analysis
3. **Hybrid Operation**: Call the shell scripts from the Python library for extended functionality:

```python
from phantomguard import ShellIntegration

# Run the advanced security analyzer from Python
shell_integration = ShellIntegration()
results = shell_integration.run_advanced_analysis(memory=True, rootkit=True)

# Process the results in Python
for finding in results.critical_findings:
    print(f"Critical security issue: {finding.description}")
```

## Documentation

PhantomGuard comes with comprehensive documentation to help you get the most out of the toolkit:

- [API Reference](docs/API.md) - Complete reference of all PhantomGuard classes and methods
- [Library Usage Guide](docs/LIBRARY_USAGE.md) - Practical examples and common use cases
- [Performance Optimization](docs/PERFOMANCE.md) - Strategies for optimizing performance across different environments
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Solutions for common issues and debugging techniques

For implementation details of the Rust components, see [RUST.md](RUST.md).

## Development

```bash
# Setup development environment
pip install -e '.[dev]'

# Run tests
pytest

# Run linting
flake8
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security

See [SECURITY.md](SECURITY.md) for security policy and reporting vulnerabilities.
