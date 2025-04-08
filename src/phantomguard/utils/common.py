#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common utility functions for Rootkit Hunter Tools.

This module provides shared functionality used across all security tools including:
- Color formatting for terminal output
- Logging utilities
- System information gathering
- Command execution wrappers
- Dependency checking
"""

import os
import sys
import subprocess
import platform
import logging
import shutil
import tempfile
import datetime
from typing import Dict, List, Optional, Tuple, Union, Any, Callable
from pathlib import Path

# Set up logging
logger = logging.getLogger(__name__)

# ANSI color codes
class Colors:
    """ANSI color codes for terminal output formatting."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    NC = '\033[0m'  # No Color

# Create temporary directory for tool operations
TEMP_DIR = Path(tempfile.gettempdir()) / f"phantomguard_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"

def ensure_temp_dir() -> Path:
    """
    Ensure the temporary directory exists.
    
    Returns:
        Path: Path to the temporary directory
    """
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    return TEMP_DIR

def cleanup_temp_dir() -> None:
    """
    Clean up the temporary directory if it exists.
    """
    if TEMP_DIR.exists():
        shutil.rmtree(TEMP_DIR)
        logger.debug(f"Removed temporary directory: {TEMP_DIR}")

def colorize(text: str, color: str) -> str:
    """
    Apply color formatting to text.
    
    Args:
        text: The text to colorize
        color: The color code to apply
        
    Returns:
        str: Colorized text string
    """
    return f"{color}{text}{Colors.NC}"

def print_banner(title: str) -> None:
    """
    Print a formatted banner with the given title.
    
    Args:
        title: The title to display in the banner
    """
    border = "═" * (len(title) + 10)
    print(colorize(f"╔{border}╗", Colors.BLUE + Colors.BOLD))
    print(colorize(f"║{' ' * 5}{title}{' ' * 5}║", Colors.BLUE + Colors.BOLD))
    print(colorize(f"╚{border}╝", Colors.BLUE + Colors.BOLD))
    print()

def print_section(name: str) -> None:
    """
    Print a section header.
    
    Args:
        name: The name of the section
    """
    print(f"\n{colorize('[+] ' + name, Colors.CYAN + Colors.BOLD)}")
    print(colorize("=" * 50, Colors.CYAN))

def print_subsection(name: str) -> None:
    """
    Print a subsection header.
    
    Args:
        name: The name of the subsection
    """
    print(f"\n{colorize('[*] ' + name, Colors.BLUE + Colors.BOLD)}")

def print_info(message: str) -> None:
    """
    Print an informational message.
    
    Args:
        message: The message to print
    """
    print(colorize(f"[INFO] {message}", Colors.WHITE))
    logger.info(message)

def print_success(message: str) -> None:
    """
    Print a success message.
    
    Args:
        message: The message to print
    """
    print(colorize(f"[✓] {message}", Colors.GREEN))
    logger.info(f"SUCCESS: {message}")

def print_warning(message: str) -> None:
    """
    Print a warning message.
    
    Args:
        message: The message to print
    """
    print(colorize(f"[!] {message}", Colors.YELLOW))
    logger.warning(message)

def print_error(message: str) -> None:
    """
    Print an error message.
    
    Args:
        message: The message to print
    """
    print(colorize(f"[✗] {message}", Colors.RED))
    logger.error(message)

def run_command(
    command: Union[str, List[str]], 
    shell: bool = False,
    timeout: Optional[int] = None,
    capture_output: bool = True,
    check: bool = False,
    env: Optional[Dict[str, str]] = None
) -> Tuple[int, str, str]:
    """
    Run a system command and return its output.
    
    Args:
        command: Command to run (string or list of arguments)
        shell: Whether to use shell execution
        timeout: Command timeout in seconds
        capture_output: Whether to capture command output
        check: Whether to raise exception on non-zero exit
        env: Environment variables to set
        
    Returns:
        Tuple containing (return_code, stdout, stderr)
    """
    try:
        logger.debug(f"Running command: {command}")
        if isinstance(command, list) and shell:
            command = " ".join(command)
            
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=check,
            env={**os.environ, **(env or {})}
        )
        
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds: {command}")
        return 124, "", f"Command timed out after {timeout} seconds"
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}: {command}")
        return e.returncode, e.stdout or "", e.stderr or ""
    except Exception as e:
        logger.error(f"Failed to run command {command}: {str(e)}")
        return 1, "", str(e)

def command_exists(cmd: str) -> bool:
    """
    Check if a command exists and is executable.
    
    Args:
        cmd: Command name to check
        
    Returns:
        bool: True if command exists, False otherwise
    """
    return shutil.which(cmd) is not None

def check_dependencies(dependencies: List[str]) -> Tuple[List[str], List[str]]:
    """
    Check for required dependencies.
    
    Args:
        dependencies: List of command names to check
        
    Returns:
        Tuple containing (installed_dependencies, missing_dependencies)
    """
    installed = []
    missing = []
    
    for dep in dependencies:
        if command_exists(dep):
            installed.append(dep)
            logger.debug(f"Dependency found: {dep}")
        else:
            missing.append(dep)
            logger.warning(f"Missing dependency: {dep}")
    
    return installed, missing

def get_system_info() -> Dict[str, str]:
    """
    Gather basic system information.
    
    Returns:
        Dict containing system information
    """
    info = {
        'os_name': platform.system(),
        'os_release': platform.release(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'hostname': platform.node(),
        'python_version': platform.python_version(),
    }
    
    # Linux-specific information
    if platform.system() == 'Linux':
        # Get distribution information
        try:
            import distro
            info['distribution'] = distro.name(pretty=True)
            info['distribution_version'] = distro.version()
            info['distribution_id'] = distro.id()
        except ImportError:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    os_release = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_release[key] = value.strip('"\'')
                
                info['distribution'] = os_release.get('NAME', 'Unknown')
                info['distribution_version'] = os_release.get('VERSION_ID', 'Unknown')
                info['distribution_id'] = os_release.get('ID', 'Unknown')
    
    # Get kernel information
    try:
        uname = os.uname()
        info['kernel_version'] = uname.release
        info['kernel_name'] = uname.sysname
    except AttributeError:
        # Not available on Windows
        pass
        
    return info

def is_root() -> bool:
    """
    Check if the script is running with root/administrator privileges.
    
    Returns:
        bool: True if running as root/admin, False otherwise
    """
    if platform.system() == 'Windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0

def require_root() -> None:
    """
    Check if the script is running with root privileges and exit if not.
    """
    if not is_root():
        print_error("This script must be run as root/administrator")
        print("Please run with sudo/as administrator and try again")
        sys.exit(1)

def setup_logging(log_file: Optional[str] = None, level: int = logging.INFO) -> None:
    """
    Set up logging configuration.
    
    Args:
        log_file: Path to log file (if None, log to console only)
        level: Logging level
    """
    # Create logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Create file handler if log file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
    logger.debug("Logging initialized")

if __name__ == "__main__":
    # Example usage when run directly
    setup_logging()
    print_banner("PHANTOMGUARD UTILITIES")
    print_section("System Information")
    
    system_info = get_system_info()
    for key, value in system_info.items():
        print_info(f"{key}: {value}")
    
    print_section("Dependency Check")
    installed, missing = check_dependencies(['python', 'ls', 'nonexistentcommand'])
    
    print_success(f"Found {len(installed)} dependencies: {', '.join(installed)}")
    if missing:
        print_warning(f"Missing {len(missing)} dependencies: {', '.join(missing)}")
    
    print_section("Test Output Formatting")
    print_info("This is an informational message")
    print_success("This is a success message")
    print_warning("This is a warning message")
    print_error("This is an error message")

