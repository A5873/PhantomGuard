"""
Tests for the common utilities module.
"""

import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the utilities module
from rootkithunter.utils.common import (
    command_exists, run_command, is_root, get_system_info,
    print_banner, print_info, print_error, print_warning, print_success,
    ensure_temp_dir, cleanup_temp_dir
)


def test_command_exists():
    """Test the command_exists function with known commands."""
    # These commands should exist on most systems
    assert command_exists("ls") is True
    assert command_exists("cd") is True
    
    # This command should not exist
    assert command_exists("this_command_definitely_does_not_exist_12345") is False


def test_run_command():
    """Test the run_command function."""
    # Test with a basic command
    returncode, stdout, stderr = run_command("echo 'test'", shell=True)
    assert returncode == 0
    assert "test" in stdout
    assert stderr == ""
    
    # Test with a command that produces an error
    returncode, stdout, stderr = run_command("ls /nonexistent_directory_12345", shell=True)
    assert returncode != 0
    assert stderr != ""


@patch('os.geteuid')
def test_is_root(mock_geteuid):
    """Test the is_root function."""
    # Test when running as root
    mock_geteuid.return_value = 0
    assert is_root() is True
    
    # Test when not running as root
    mock_geteuid.return_value = 1000
    assert is_root() is False


@patch('platform.node')
@patch('platform.system')
@patch('platform.release')
@patch('platform.processor')
@patch('psutil.virtual_memory')
def test_get_system_info(mock_memory, mock_processor, mock_release, 
                        mock_system, mock_node):
    """Test the get_system_info function."""
    # Setup mocks
    mock_node.return_value = "test-host"
    mock_system.return_value = "Linux"
    mock_release.return_value = "5.10.0-test"
    mock_processor.return_value = "x86_64"
    
    # Mock memory object
    memory_mock = MagicMock()
    memory_mock.total = 8 * 1024 * 1024 * 1024  # 8 GB
    mock_memory.return_value = memory_mock
    
    # Get system info
    info = get_system_info()
    
    # Verify results
    assert "Hostname" in info
    assert info["Hostname"] == "test-host"
    assert "OS" in info
    assert info["OS"] == "Linux"
    assert "Kernel" in info
    assert info["Kernel"] == "5.10.0-test"


def test_temp_dir_functions(temp_dir):
    """Test temp directory creation and cleanup functions."""
    with patch('rootkithunter.utils.common.TEMP_DIR', temp_dir):
        # Test ensuring temp directory
        test_dir = ensure_temp_dir()
        assert test_dir.exists()
        assert test_dir.is_dir()
        
        # Create a test file
        test_file = test_dir / "test_file.txt"
        test_file.write_text("Test content")
        assert test_file.exists()
        
        # Test cleanup
        cleanup_temp_dir()
        assert not test_file.exists()


def test_print_functions(capsys):
    """Test the print_* functions."""
    # Test print_banner
    print_banner("TEST BANNER")
    captured = capsys.readouterr()
    assert "TEST BANNER" in captured.out
    
    # Test print_info
    print_info("Test info message")
    captured = capsys.readouterr()
    assert "Test info message" in captured.out
    
    # Test print_success
    print_success("Test success message")
    captured = capsys.readouterr()
    assert "Test success message" in captured.out
    
    # Test print_warning
    print_warning("Test warning message")
    captured = capsys.readouterr()
    assert "Test warning message" in captured.out
    
    # Test print_error
    print_error("Test error message")
    captured = capsys.readouterr()
    assert "Test error message" in captured.out

