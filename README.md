# Rootkit Hunter

A comprehensive security analysis tool for Linux systems, implementing advanced rootkit detection, memory forensics, and system security analysis.

## Features

- Memory forensics and analysis
- Network traffic monitoring
- Rootkit detection
- Container security analysis
- System vulnerability scanning
- Real-time system monitoring

## Implementation

The tool is currently implemented in Python with plans for performance-critical components to be implemented in Rust:

- **Python**: High-level orchestration, reporting, and analysis logic
- **Rust**: Performance-critical components (planned)

See [RUST.md](RUST.md) for details on the Rust implementation plans.

## Installation

```bash
pip install rootkithunter
```

## Usage

```bash
# Basic system scan
rootkithunter scan

# Full security analysis
rootkithunter analyze --full

# Container security check
rootkithunter container-scan

# Memory analysis
rootkithunter memory-scan
```

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
