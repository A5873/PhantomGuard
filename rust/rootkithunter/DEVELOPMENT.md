# Development Guide for Rootkit Hunter

This document provides comprehensive guidelines for developing the Rootkit Hunter security tool, which consists of both Python and Rust components.

## Project Structure Overview

The Rootkit Hunter project uses a hybrid approach with Python and Rust components:

```
rootkithunter/
├── src/                      # Python source code
│   ├── rootkithunter/        # Main Python package
│   │   ├── __init__.py
│   │   ├── analyzers/        # Security analyzers (Python)
│   │   ├── cli/              # Command-line interface
│   │   ├── core/             # Core functionality
│   │   ├── reporting/        # Report generation
│   │   └── utils/            # Utility functions
├── rust/                     # Rust components
│   └── rootkithunter/        # Rust library package
│       ├── src/
│       │   ├── memory/       # Memory analysis (Rust)
│       │   ├── network/      # Network monitoring (Rust)
│       │   ├── process/      # Process inspection (Rust)
│       │   └── syscall/      # System call monitoring (Rust)
│       └── Cargo.toml
├── tests/                    # Test suite
│   ├── python/               # Python tests
│   └── rust/                 # Rust tests
├── docs/                     # Documentation
├── setup.py                  # Python package configuration
├── pyproject.toml            # Python build settings
├── requirements.txt          # Python dependencies
└── Cargo.toml                # Rust workspace configuration
```

### Component Responsibilities

- **Python Implementation**: Handles high-level orchestration, reporting, CLI, and analysis logic
- **Rust Implementation**: Handles performance-critical components like memory analysis, system call tracing

## Development Setup

### Prerequisites

- Python 3.7+ with pip
- Rust (latest stable via rustup)
- Git
- Linux environment (preferably Debian-based)

### Setting Up the Python Environment

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install the package in development mode:
   ```bash
   pip install -e '.[dev]'
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Setting Up the Rust Environment

1. Ensure Rust is installed and up-to-date:
   ```bash
   rustup update stable
   ```

2. Build the Rust components:
   ```bash
   cd rust/rootkithunter
   cargo build
   ```

3. Generate documentation:
   ```bash
   cargo doc --open
   ```

## Running Tests and Checks

### Python Tests

```bash
# Run all Python tests
pytest

# Run with coverage
pytest --cov=rootkithunter

# Run a specific test file
pytest tests/python/test_analyzer.py
```

### Python Code Quality Checks

```bash
# Run all pre-commit hooks
pre-commit run --all-files

# Run individual tools
black src tests
isort src tests
flake8 src tests
mypy src
```

### Rust Tests

```bash
# Run all Rust tests
cd rust/rootkithunter
cargo test

# Run a specific test
cargo test analyze_memory

# Run with verbose output
cargo test -- --nocapture
```

### Rust Code Quality Checks

```bash
# Check code formatting
cargo fmt -- --check

# Run clippy lints
cargo clippy -- -D warnings

# Check documentation
cargo doc --no-deps
```

## Contributing Guidelines

### General Guidelines

1. Create a feature branch from `main` for each contribution
2. Follow the existing code style and architecture
3. Write tests for new functionality
4. Update documentation as needed
5. Submit a pull request with a clear description

### Python Guidelines

1. Follow PEP 8 style guidelines (enforced by black, isort, and flake8)
2. Add type hints to all functions and methods
3. Document functions with docstrings (Google style)
4. Aim for at least 90% test coverage for new code

### Rust Guidelines

1. Follow Rust API guidelines (https://rust-lang.github.io/api-guidelines/)
2. Document all public API items with doc comments
3. Handle errors properly using anyhow/thiserror
4. Avoid unsafe code where possible; if necessary, thoroughly document why

## Performance Considerations

### When to Use Python

- For high-level orchestration and control flow
- For report generation and data formatting
- For configuration management
- For code where readability and maintenance are more important than speed
- For integrating with external APIs or tools that have Python bindings

### When to Use Rust

- For CPU-intensive operations
- For memory scanning and analysis
- For network packet processing
- For operations requiring direct system access
- For functionality that needs to be thread-safe and performant
- For any component that could become a bottleneck in the analysis pipeline

### FFI Integration

When implementing a new feature, consider these guidelines:

1. Start with a Python prototype to validate the approach
2. Profile the code to identify performance bottlenecks
3. If a component becomes a bottleneck, implement it in Rust
4. Expose the Rust functionality to Python using PyO3 bindings

## Building Packages

### Python Package

```bash
# Build source distribution
python setup.py sdist

# Build wheel
python setup.py bdist_wheel
```

### Rust Binary

```bash
cd rust/rootkithunter
cargo build --release
```

### Creating Combined Distributions

For releases that include both Python and Rust components:

1. Build the Rust binary
2. Include the binary in the Python package data
3. Update the setup.py to include the binary in the package data

## Documentation

- Keep README.md updated with high-level overview
- Document API changes in the code
- Update user documentation in the `docs` directory
- Consider generating API documentation with Sphinx (Python) and cargo-doc (Rust)

## Continuous Integration

The project uses GitHub Actions for CI/CD:

- All pull requests trigger test runs
- Merges to main trigger test runs and documentation builds
- Release tags trigger package builds

See `.github/workflows` for details on the CI/CD configuration.

# Development Guide for Rootkit Hunter

This document provides comprehensive guidelines for developing the Rootkit Hunter security tool, which consists of both Python and Rust components.

## Project Structure Overview

The Rootkit Hunter project uses a hybrid approach with Python and Rust components:

```
rootkithunter/
├── src/                      # Python source code
│   ├── rootkithunter/        # Main Python package
│   │   ├── __init__.py
│   │   ├── analyzers/        # Security analyzers (Python)
│   │   ├── cli/              # Command-line interface
│   │   ├── core/             # Core functionality
│   │   ├── reporting/        # Report generation
│   │   └── utils/            # Utility functions
├── rust/                     # Rust components
│   └── rootkithunter/        # Rust library package
│       ├── src/
│       │   ├── memory/       # Memory analysis (Rust)
│       │   ├── network/      # Network monitoring (Rust)
│       │   ├── process/      # Process inspection (Rust)
│       │   └── syscall/      # System call monitoring (Rust)
│       └── Cargo.toml
├── tests/                    # Test suite
│   ├── python/               # Python tests
│   └── rust/                 # Rust tests
├── docs/                     # Documentation
├── setup.py                  # Python package configuration
├── pyproject.toml            # Python build settings
├── requirements.txt          # Python dependencies
└── Cargo.toml                # Rust workspace configuration
```

### Component Responsibilities

- **Python Implementation**: Handles high-level orchestration, reporting, CLI, and analysis logic
- **Rust Implementation**: Handles performance-critical components like memory analysis, system call tracing

## Development Setup

### Prerequisites

- Python 3.7+ with pip
- Rust (latest stable via rustup)
- Git
- Linux environment (preferably Debian-based)

### Setting Up the Python Environment

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install the package in development mode:
   ```bash
   pip install -e '.[dev]'
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Setting Up the Rust Environment

1. Ensure Rust is installed and up-to-date:
   ```bash
   rustup update stable
   ```

2. Build the Rust components:
   ```bash
   cd rust/rootkithunter
   cargo build
   ```

3. Generate documentation:
   ```bash
   cargo doc --open
   ```

## Running Tests and Checks

### Python Tests

```bash
# Run all Python tests
pytest

# Run with coverage
pytest --cov=rootkithunter

# Run a specific test file
pytest tests/python/test_analyzer.py
```

### Python Code Quality Checks

```bash
# Run all pre-commit hooks
pre-commit run --all-files

# Run individual tools
black src tests
isort src tests
flake8 src tests
mypy src
```

### Rust Tests

```bash
# Run all Rust tests
cd rust/rootkithunter
cargo test

# Run a specific test
cargo test analyze_memory

# Run with verbose output
cargo test -- --nocapture
```

### Rust Code Quality Checks

```bash
# Check code formatting
cargo fmt -- --check

# Run clippy lints
cargo clippy -- -D warnings

# Check documentation
cargo doc --no-deps
```

## Contributing Guidelines

### General Guidelines

1. Create a feature branch from `main` for each contribution
2. Follow the existing code style and architecture
3. Write tests for new functionality
4. Update documentation as needed
5. Submit a pull request with a clear description

### Python Guidelines

1. Follow PEP 8 style guidelines (enforced by black, isort, and flake8)
2. Add type hints to all functions and methods
3. Document functions with docstrings (Google style)
4. Aim for at least 90% test coverage for new code

### Rust Guidelines

1. Follow Rust API guidelines (https://rust-lang.github.io/api-guidelines/)
2. Document all public API items with doc comments
3. Handle errors properly using anyhow/thiserror
4. Avoid unsafe code where possible; if necessary, thoroughly document why

## Performance Considerations

### When to Use Python

- For high-level orchestration and control flow
- For report generation and data formatting
- For configuration management
- For code where readability and maintenance are more important than speed
- For integrating with external APIs or tools that have Python bindings

### When to Use Rust

- For CPU-intensive operations
- For memory scanning and analysis
- For network packet processing
- For operations requiring direct system access
- For functionality that needs to be thread-safe and performant
- For any component that could become a bottleneck in the analysis pipeline

### FFI Integration

When implementing a new feature, consider these guidelines:

1. Start with a Python prototype to validate the approach
2. Profile the code to identify performance bottlenecks
3. If a component becomes a bottleneck, implement it in Rust
4. Expose the Rust functionality to Python using PyO3 bindings

## Building Packages

### Python Package

```bash
# Build source distribution
python setup.py sdist

# Build wheel
python setup.py bdist_wheel
```

### Rust Binary

```bash
cd rust/rootkithunter
cargo build --release
```

### Creating Combined Distributions

For releases that include both Python and Rust components:

1. Build the Rust binary
2. Include the binary in the Python package data
3. Update the setup.py to include the binary in the package data

## Documentation

- Keep README.md updated with high-level overview
- Document API changes in the code
- Update user documentation in the `docs` directory
- Consider generating API documentation with Sphinx (Python) and cargo-doc (Rust)

## Continuous Integration

The project uses GitHub Actions for CI/CD:

- All pull requests trigger test runs
- Merges to main trigger test runs and documentation builds
- Release tags trigger package builds

See `.github/workflows` for details on the CI/CD configuration.
