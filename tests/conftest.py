"""
Common test fixtures and utilities for Rootkit Hunter tests.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def fake_process_output():
    """Sample process output for testing."""
    return """  PID TTY          TIME CMD
    1 ?        00:00:01 systemd
    2 ?        00:00:00 kthreadd
  123 ?        00:00:00 bash
  456 ?        00:00:05 python3
  789 ?        00:00:01 nginx
"""


@pytest.fixture
def fake_network_output():
    """Sample network output for testing."""
    return """Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8080          127.0.0.1:45678         ESTABLISHED
udp        0      0 0.0.0.0:53              0.0.0.0:*
"""


@pytest.fixture
def report_file(temp_dir):
    """Create a temporary file path for test reports."""
    return temp_dir / "test_report.txt"


@pytest.fixture
def mock_system_info():
    """Mock system information for testing."""
    return {
        "Hostname": "test-host",
        "OS": "Linux",
        "Distribution": "Test Linux",
        "Kernel": "5.10.0-test",
        "CPU": "Test CPU @ 2.00GHz",
        "Memory": "8GB",
        "Python": "3.9.0"
    }

