# PhantomGuard

Advanced security analysis tool for Linux systems with comprehensive security detection, memory forensics, and system security analysis capabilities.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

## 🔍 Overview

PhantomGuard is a powerful security analysis toolkit designed to detect threats, malware, and security vulnerabilities on Linux systems. It combines cutting-edge memory forensics, network traffic analysis, and system monitoring techniques to provide comprehensive security assessment capabilities.

With its unique hybrid architecture, utilizing both Python and Rust, PhantomGuard delivers the perfect balance of development speed and runtime performance.

## ✨ Features

- **Memory Forensics & Analysis**
  - Memory scanning for hidden code
  - Process memory integrity verification
  - Detection of memory-resident malware

- **Rootkit Detection**
  - Hidden process identification
  - Kernel module monitoring
  - System call table integrity checking
  - File hiding detection

- **Network Traffic Analysis**
  - Suspicious connection detection
  - Data exfiltration identification
  - Command & control channel detection
  - DNS analysis

- **Container Security**
  - Docker container security assessment
  - Container image vulnerability scanning
  - Container configuration analysis
  - Container escape detection

- **System Security**
  - System file integrity verification
  - Privilege escalation vulnerability detection
  - Suspicious cron job analysis
  - SUID/SGID binary scanning

## 🚀 Installation

### Installation

PhantomGuard is currently under development and not yet available on PyPI. The recommended way to install is from source:

### Installation from Source

```bash
# Clone the repository
git clone https://github.com/A5873/PhantomGuard.git
cd PhantomGuard

# Install in development mode
pip install -e .

# Or with all development dependencies
pip install -e ".[dev,rust]"
```

## 📊 Quick Start

### Command Line Interface

```bash
# Run a full security scan
phantomguard scan

# Analyze system memory
phantomguard memory

# Inspect running processes
phantomguard processes

# Monitor network traffic
phantomguard network

# Analyze system calls
phantomguard syscalls
```

### Command Options

```bash
# Show help
phantomguard --help
phantomguard scan --help

# Save scan results to a file
phantomguard scan --output security_report.txt

# Save results in JSON format
phantomguard scan --format json --output security_report.json

# Enable verbose output
phantomguard scan --verbose
```

### Sample Output

```
╔══════════════════════════════════════════════════════╗
║                    PHANTOM GUARD                      ║
╚══════════════════════════════════════════════════════╝

[+] Scanning system memory...
    ✓ Memory acquisition complete
    ✓ Analyzing 4.2GB of memory

[+] Inspecting processes...
    ! Found suspicious process: suspicious_process (PID: 1234)
      - Hidden from process list
      - Running from temporary directory
      - Unusual file handles detected

[+] Security Scan Summary
    Memory threats: 0 issues found
    Suspicious processes: 1 issue found
    Network anomalies: 0 issues found
    Syscall anomalies: 0 issues found

Comprehensive report saved to security_report.txt
```

### Python API Usage

You can also use PhantomGuard programmatically in your Python code:

```python
from phantomguard.core import SecurityAnalyzer

# Initialize the analyzer
analyzer = SecurityAnalyzer(debug=True)

# Perform memory analysis
memory_threats = analyzer.scan_memory()
for threat in memory_threats:
    print(f"Memory threat: {threat['type']} in process {threat['process_name']}")

# Inspect running processes
suspicious_processes = analyzer.inspect_processes()
for process in suspicious_processes:
    print(f"Suspicious process: {process['name']} (PID: {process['pid']})")
    print(f"  Anomalies: {', '.join(process['anomalies'])}")

# Perform full analysis
results = analyzer.full_analysis()
print(f"Found {len(results['memory_threats'])} memory threats")
print(f"Found {len(results['suspicious_processes'])} suspicious processes")
print(f"Found {len(results['network_anomalies'])} network anomalies")
print(f"Found {len(results['syscall_anomalies'])} syscall anomalies")
```

## 🛠 Development Setup

### Prerequisites

- Python 3.7+
- Rust (for extension development)
- Linux environment (most functionality requires Linux)
- Required system packages:
  ```bash
  # Debian/Ubuntu
  sudo apt install python3-dev libssl-dev

  # RHEL/Fedora
  sudo dnf install python3-devel openssl-devel
  ```

### Setting Up Development Environment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/A5873/PhantomGuard.git
   cd PhantomGuard
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=phantomguard

# Run specific test file
pytest tests/python/test_security_analyzer.py
```

### Building Rust Components

```bash
# Navigate to the Rust directory
cd rust/phantomguard

# Build the Rust library
cargo build

# Run Rust tests
cargo test

# Build the Python extension module
maturin develop
```

### Packaging

```bash
# Build wheel package
python -m build

# Build source distribution
python -m build --sdist
```

## 🤝 Contributing

Contributions are welcome! Please check out our [contributing guidelines](CONTRIBUTING.md) for details on how to get started.

### Contribution Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and commit them: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Code Style

We use the following tools to enforce code style:
- **Black** for Python code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking
- **rustfmt** for Rust code formatting
- **clippy** for Rust linting

## 🔒 Security Considerations

- **Root Privileges**: Most functionality requires root/sudo privileges to access system memory, inspect processes, etc.
- **System Impact**: Memory analysis and network scanning can be resource-intensive
- **False Positives**: Security scanning may produce false positives; always verify findings
- **Responsible Usage**: Only use this tool on systems you own or have explicit permission to scan

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📚 Documentation

For detailed documentation, see:
- [Full Documentation](https://phantomguard.readthedocs.io/)
- [API Reference](https://phantomguard.readthedocs.io/en/latest/api.html)
- [Development Guide](DEVELOPMENT.md)

## ⚠️ Disclaimer

This tool is intended for legitimate security research and system administration purposes only. Use responsibly and only on systems you own or have permission to scan. The authors are not responsible for any misuse or damage caused by this tool.
