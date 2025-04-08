# Contributing to PhantomGuard

Thank you for considering contributing to the PhantomGuard project! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please follow these guidelines when contributing:
- Be respectful and considerate of others
- Focus on what is best for the community
- Provide constructive feedback

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with the following information:
- Clear description of the bug
- Steps to reproduce the issue
- Expected behavior
- Screenshots (if applicable)
- Environment information (OS, Python version, etc.)

### Suggesting Enhancements

For enhancement suggestions, please:
- Clearly describe the enhancement
- Explain why it would be useful
- Provide examples of how it would be used

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure they pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

#### Pull Request Guidelines

- Update documentation for any changed functionality
- Add tests for any new features
- Keep the scope of the PR manageable
- Follow the existing code style
- Write clear commit messages

## Development Setup

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run tests:
   ```bash
   pytest
   ```

## Testing

We use pytest for testing. All new code should have appropriate test coverage.

To run tests:
```bash
pytest
```

To run tests with coverage:
```bash
pytest --cov=phantomguard
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for all classes and functions
- Keep lines under 100 characters when possible

Thank you for your contributions!

