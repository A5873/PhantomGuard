"""
Rootkit Hunter - Advanced Security Analysis Tool.

This package provides comprehensive security analysis capabilities for
detecting rootkits, malware, and security vulnerabilities on Linux systems.

Features:
- Memory forensics and analysis
- Rootkit detection
- Network traffic monitoring
- Container security analysis
- System vulnerability scanning

The package uses a hybrid approach with both Python and Rust components:
- High-level functionality and orchestration in Python
- Performance-critical components in Rust (when available)
"""

__version__ = "0.1.0"
__author__ = "Security Tools Team"
__email__ = "security@example.com"
__license__ = "MIT"
__copyright__ = "Copyright 2025 Security Tools Team"

# Package public API
from .core import RustyAnalyzer

# Check for Rust extensions
try:
    import rootkithunter_rs

    _has_rust_extensions = True
except ImportError:
    _has_rust_extensions = False

# Inform user about Rust extensions status
import logging

logger = logging.getLogger(__name__)

if not _has_rust_extensions:
    logger.info(
        "Rust extensions not found. Using Python implementations for all components. "
        "Install Rust extensions for better performance: pip install rootkithunter[rust]"
    )
else:
    logger.debug("Rust extensions loaded successfully.")

__all__ = ["RustyAnalyzer"]
