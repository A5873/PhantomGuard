"""
Tests for the main module.
"""

import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from rootkithunter.main import RootkitHunter, parse_args, main


@patch('rootkithunter.main.get_system_info')
@patch('rootkithunter.main.setup_logging')
def test_rootkithunter_init(mock_setup_logging, mock_get_system_info, temp_dir):
    """Test RootkitHunter initialization."""
    # Create a hunter instance
    hunter = RootkitHunter(
        output_dir=str(temp_dir),
        report_format="txt",
        scan_type="quick",
        network_capture_time=30,
        verbose=True,
        keep_artifacts=True
    )
    
    # Check attributes
    assert hunter.output_dir == Path(temp_dir)
    assert hunter.report_format == "txt"
    assert hunter.scan_type == "quick"
    assert hunter.network_capture_time == 30
    assert hunter.verbose is True
    assert hunter.keep_artifacts is True
    
    # Check that the report file was created
    assert hunter.report_file == Path(temp_dir) / "security_report.txt"
    
    # Verify logging was set up
    mock_setup_logging.assert_called_once()


@patch('rootkithunter.main.get_system_info')
def test_initialize_report_txt(mock_get_system_info, temp_dir):
    """Test report initialization with TXT format."""
    # Mock system info
    mock_get_system_info.return_value = {
        "OS": "Linux Test",
        "Kernel": "5.10.0-test"
    }
    
    # Create a hunter instance with txt report
    hunter = RootkitHunter(
        output_dir=str(temp_dir),
        report_format="txt"
    )
    
    # Initialize the report
    hunter._initialize_report()
    
    # Check that the report file exists and has content
    assert hunter.report_file.exists()
    content = hunter.report_file.read_text()
    assert "Rootkit Hunter Security Report" in content
    assert "OS: Linux Test" in content
    assert "Kernel: 5.10.0-test" in content


@patch('rootkithunter.main.get_system_info')
def test_initialize_report_html(mock_get_system_info, temp_dir):
    """Test report initialization with HTML format."""
    # Mock system info
    mock_get_system_info.return_value = {
        "OS": "Linux Test",
        "Kernel": "5.10.0-test"
    }
    
    # Create a hunter instance with html report
    hunter = RootkitHunter(
        output_dir=str(temp_dir),
        report_format="html"
    )
    
    # Initialize the report
    hunter._initialize_report()
    
    # Check that the report file exists and has content
    assert hunter.report_file.exists()
    content = hunter.report_file.read_text()
    assert "<title>Rootkit Hunter Security Report</title>" in content
    assert "Linux Test" in content
    assert "5.10.0-test" in content


@patch('rootkithunter.main.get_system_info')
def test_initialize_report_json(mock_get_system_info, temp_dir):
    """Test report initialization with JSON format."""
    # Mock system info
    mock_get_system_info.return_value = {
        "OS": "Linux Test",
        "Kernel": "5.10.0-test"
    }
    
    # Create a hunter instance with json report
    hunter = RootkitHunter(
        output_dir=str(temp_dir),
        report_format="json"
    )
    
    # Initialize the report
    hunter._initialize_report()
    
    # Check that the report file exists and has content
    assert hunter.report_file.exists()
    
    # Try to parse the json
    import json
    report_data = json.loads(hunter.report_file.read_text())
    assert "system_info" in report_data
    assert report_data["system_info"]["OS"] == "Linux Test"
    assert report_data["system_info"]["Kernel"] == "5.10.0-test"


def test_parse_args():
    """Test argument parsing."""
    with patch('sys.argv', ['rootkithunter', 
                           '--output-dir', '/tmp/test',
                           '--scan-type', 'comprehensive',
                           '--format', 'html',
                           '--network-time', '120',
                           '--verbose',
                           '--keep-artifacts']):
        args = parse_args()
        assert args.output_dir == '/tmp/test'
        assert args.scan_type == 'comprehensive'
        assert args.format == 'html'
        assert args.network_time == 120
        assert args.verbose is True
        assert args.keep_artifacts is True
        assert args.force_no_root is False

