#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Security Analyzer Module.

This module provides comprehensive security analysis capabilities including:
- Memory forensics
- Rootkit detection
- Network traffic analysis
- Container security analysis
- Malware detection using signatures

Dependencies:
    - volatility3 (optional, for memory analysis)
    - tcpdump (optional, for network analysis)
    - yara (optional, for malware detection)
    - docker (optional, for container analysis)
"""

import os
import sys
import time
import json
import socket
import re
import glob
import signal
import argparse
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, Set, Callable

# Import common utilities
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from phantomguard.utils.common import (
    Colors, print_banner, print_section, print_subsection,
    print_info, print_success, print_warning, print_error,
    run_command, command_exists, check_dependencies,
    get_system_info, is_root, require_root, setup_logging,
    ensure_temp_dir, cleanup_temp_dir, TEMP_DIR
)


class AnalysisStatus(Enum):
    """Enum for analysis status."""
    SUCCESS = 0
    WARNING = 1
    ERROR = 2
    SKIPPED = 3


class BaseAnalyzer(ABC):
    """Base class for all analyzers."""
    
    def __init__(self, report_file: str = "security_report.txt", debug: bool = False):
        """
        Initialize the analyzer.
        
        Args:
            report_file: Path to the report file
            debug: Enable debug mode
        """
        self.report_file = report_file
        self.debug = debug
        self.temp_dir = ensure_temp_dir() / self.__class__.__name__.lower()
        self.temp_dir.mkdir(exist_ok=True)
        self.findings = []
        self.status = AnalysisStatus.SUCCESS
        
    def add_finding(self, message: str, status: AnalysisStatus = AnalysisStatus.WARNING) -> None:
        """
        Add a finding to the report.
        
        Args:
            message: Finding message
            status: Finding status
        """
        self.findings.append((message, status))
        if status.value > self.status.value:
            self.status = status
            
    def report(self, section_title: str) -> None:
        """
        Write findings to the report file.
        
        Args:
            section_title: Title of the section
        """
        with open(self.report_file, "a") as f:
            f.write(f"\n## {section_title}\n\n")
            
            if not self.findings:
                f.write("No issues found.\n")
                return
            
            for message, status in self.findings:
                prefix = {
                    AnalysisStatus.SUCCESS: "[✓]",
                    AnalysisStatus.WARNING: "[!]",
                    AnalysisStatus.ERROR: "[✗]",
                    AnalysisStatus.SKIPPED: "[*]"
                }.get(status, "[*]")
                
                f.write(f"{prefix} {message}\n")
                
            f.write(f"\n### Summary\n")
            statuses = [status for _, status in self.findings]
            error_count = sum(1 for s in statuses if s == AnalysisStatus.ERROR)
            warning_count = sum(1 for s in statuses if s == AnalysisStatus.WARNING)
            
            f.write(f"Found {error_count} critical issues and {warning_count} warnings.\n")
            
            if error_count > 0:
                f.write("Recommendation: Address critical issues immediately.\n")
            elif warning_count > 0:
                f.write("Recommendation: Review warnings and address potential security concerns.\n")
            else:
                f.write("No significant issues detected.\n")
    
    @abstractmethod
    def check_requirements(self) -> bool:
        """
        Check if all requirements for this analyzer are met.
        
        Returns:
            bool: True if requirements are met, False otherwise
        """
        pass
    
    @abstractmethod
    def analyze(self) -> AnalysisStatus:
        """
        Perform the analysis.
        
        Returns:
            AnalysisStatus: Status of the analysis
        """
        pass


class MemoryAnalyzer(BaseAnalyzer):
    """Memory forensics analyzer."""
    
    def __init__(self, report_file: str = "security_report.txt", debug: bool = False):
        """Initialize the memory analyzer."""
        super().__init__(report_file, debug)
        self.memory_dump = None
        self.volatility_path = self._find_volatility()
    
    def _find_volatility(self) -> Optional[str]:
        """
        Find the volatility executable.
        
        Returns:
            Optional[str]: Path to volatility or None if not found
        """
        # Check loaded libraries for suspicious patterns
        returncode, stdout, _ = run_command(
            "lsof -n | grep -E '\\.so|\\.dll'",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            lib_file = self.temp_dir / "loaded_libraries.txt"
            lib_file.write_text(stdout)
            
            # Look for libraries loaded from suspicious locations
            suspicious_paths = ["/tmp", "/var/tmp", "/dev/shm", "/run/user"]
            for line in stdout.splitlines():
                for path in suspicious_paths:
                    if path in line:
                        self.add_finding(
                            f"Suspicious library loaded from {path}: {line}",
                            AnalysisStatus.ERROR
                        )
    
    def analyze(self) -> AnalysisStatus:
        """
        Perform memory analysis.
        
        Returns:
            AnalysisStatus: Status of the analysis
        """
        print_section("Memory Forensics Analysis")
        
        if not self.check_requirements():
            self.add_finding(
                "Memory analysis requirements not met",
                AnalysisStatus.SKIPPED
            )
            return AnalysisStatus.SKIPPED
        
        # Create memory dump
        self._create_memory_dump()
        
        # Analyze memory strings
        self._analyze_memory_strings()
        
        # Analyze with volatility if available
        if self.volatility_path:
            self._analyze_with_volatility()
        
        # Search for malware patterns
        self._search_malware_patterns()
        
        # Write report
        self.report("Memory Forensics Analysis")
        
        return self.status


class NetworkAnalyzer(BaseAnalyzer):
    """Network traffic and configuration analyzer."""
    
    def __init__(self, report_file: str = "security_report.txt", debug: bool = False, capture_time: int = 60):
        """
        Initialize the network analyzer.
        
        Args:
            report_file: Path to the report file
            debug: Enable debug mode
            capture_time: Network capture duration in seconds
        """
        super().__init__(report_file, debug)
        self.capture_time = capture_time
        self.pcap_file = self.temp_dir / "network_capture.pcap"
        
    def check_requirements(self) -> bool:
        """
        Check if network analysis requirements are met.
        
        Returns:
            bool: True if requirements are met, False otherwise
        """
        has_tcpdump = command_exists("tcpdump")
        if not has_tcpdump:
            print_warning("tcpdump not found. Network packet capture will be skipped.")
            
        return True  # We can still do basic network analysis
    
    def _compare_ps_output(self) -> None:
        """Compare output of different process listing commands to find hidden processes."""
        print_info("Checking for hidden processes...")
        
        # Get processes from different sources
        ps_cmds = [
            ("ps aux", "ps_aux.txt"),
            ("ps -ef", "ps_ef.txt"),
            ("/bin/ps aux", "bin_ps_aux.txt"),
            ("ls -la /proc/", "proc_dir.txt")
        ]
        
        # Store processes from each command
        processes = {}
        
        for cmd, output_file in ps_cmds:
            returncode, stdout, _ = run_command(
                cmd,
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                output_path = self.temp_dir / output_file
                output_path.write_text(stdout)
                
                # Parse process IDs
                pids = set()
                if "ls -la" in cmd:
                    # Parse PIDs from /proc directory listing
                    for line in stdout.splitlines():
                        try:
                            pid = line.split()[8]
                            if pid.isdigit():
                                pids.add(pid)
                        except (IndexError, ValueError):
                            pass
                else:
                    # Parse PIDs from ps output
                    for line in stdout.splitlines()[1:]:  # Skip header
                        try:
                            fields = line.split()
                            if len(fields) > 1:
                                pid = fields[1]
                                if pid.isdigit():
                                    pids.add(pid)
                        except (IndexError, ValueError):
                            pass
                
                processes[cmd] = pids
        
        # Find differences - potential hidden processes
        if len(processes) > 1:
            for cmd1, pids1 in processes.items():
                for cmd2, pids2 in processes.items():
                    if cmd1 != cmd2:
                        # Find PIDs in cmd1 but not in cmd2
                        hidden = pids1 - pids2
                        if hidden:
                            self.add_finding(
                                f"Found {len(hidden)} processes visible to '{cmd1}' but hidden from '{cmd2}': {', '.join(sorted(hidden))}",
                                AnalysisStatus.ERROR
                            )
    
    def _check_for_known_rootkits(self) -> None:
        """Check for known rootkit files and signatures."""
        print_info("Checking for known rootkit files and signatures...")
        
        # Common rootkit files and directories
        suspicious_paths = [
            "/dev/.hidedrootkit",
            "/dev/.hiddenroot",
            "/dev/.udev",
            "/dev/.ps",
            "/dev/.pstree", 
            "/dev/.lsof",
            "/dev/.lsof",
            "/dev/shm/.pulse", 
            "/usr/share/.sshd",
            "/usr/bin/.sshd",
            "/lib/modules/*/extra",
            "/etc/rc.d/init.d/.boot"
        ]
        
        for path in suspicious_paths:
            paths = glob.glob(path)
            for found_path in paths:
                if os.path.exists(found_path):
                    self.add_finding(
                        f"Found suspicious file/directory: {found_path}",
                        AnalysisStatus.ERROR
                    )
        
        # Check for suspicious kernel modules
        returncode, stdout, _ = run_command(
            "lsmod",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            modules_file = self.temp_dir / "kernel_modules.txt"
            modules_file.write_text(stdout)
            
            # Known malicious module names (partial matches)
            suspicious_modules = [
                "hide", "sshrk", "rkit", "adore", "modhide", "ipsecs", "cleaner",
                "synch", "kbeast", "diamorphine", "metasploit", "livesupport"
            ]
            
            for module in suspicious_modules:
                if any(module in line.lower() for line in stdout.splitlines()):
                    self.add_finding(
                        f"Found suspicious kernel module matching '{module}'",
                        AnalysisStatus.ERROR
                    )
    
    def _check_for_lkm_backdoors(self) -> None:
        """Check for loadable kernel module backdoors."""
        print_info("Checking for LKM backdoors...")
        
        # Check for syscall table modifications
        if os.path.exists("/sys/kernel/debug/kprobes/blacklist"):
            with open("/sys/kernel/debug/kprobes/blacklist", "r") as f:
                content = f.read()
                syscall_file = self.temp_dir / "syscall_blacklist.txt"
                syscall_file.write_text(content)
                
                if content.strip():
                    self.add_finding(
                        "Found blacklisted kernel probes - potential syscall hooking",
                        AnalysisStatus.WARNING
                    )
        
        # Check for hidden kernel modules
        returncode, stdout, _ = run_command(
            "cat /proc/modules | wc -l",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            mod_count1 = int(stdout.strip())
            
            returncode, stdout, _ = run_command(
                "lsmod | wc -l",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                # Subtract 1 for the header line in lsmod output
                mod_count2 = int(stdout.strip()) - 1
                
                if mod_count1 != mod_count2:
                    self.add_finding(
                        f"Module count mismatch: /proc/modules ({mod_count1}) vs lsmod ({mod_count2})",
                        AnalysisStatus.ERROR
                    )
    
    def _check_for_file_integrity(self) -> None:
        """Check critical system files for unexpected modifications."""
        print_info("Checking critical file integrity...")
        
        # Critical system files to check
        critical_files = [
            "/bin/ls",
            "/bin/ps",
            "/bin/netstat",
            "/bin/ss",
            "/bin/lsof",
            "/bin/find",
            "/bin/grep",
            "/sbin/ifconfig",
            "/usr/bin/top",
            "/usr/bin/pstree"
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                # Check for unusual file attributes
                returncode, stdout, _ = run_command(
                    f"lsattr {file_path}",
                    shell=True,
                    capture_output=True
                )
                
                if returncode == 0 and stdout.strip():
                    if 'i' in stdout:  # Immutable flag
                        self.add_finding(
                            f"Critical file has immutable flag: {file_path}",
                            AnalysisStatus.WARNING
                        )
                
                # Check file signature or checksum if package manager available
                if command_exists("dpkg") or command_exists("rpm"):
                    verify_cmd = ""
                    if command_exists("dpkg"):
                        verify_cmd = f"dpkg -V $(dpkg -S {file_path} | cut -d':' -f1)"
                    elif command_exists("rpm"):
                        verify_cmd = f"rpm -V $(rpm -qf {file_path})"
                    
                    if verify_cmd:
                        returncode, stdout, _ = run_command(
                            verify_cmd,
                            shell=True,
                            capture_output=True
                        )
                        
                        if returncode != 0 and stdout.strip():
                            self.add_finding(
                                f"File integrity check failed for {file_path}: {stdout.strip()}",
                                AnalysisStatus.ERROR
                            )
    
    def _check_for_preload_backdoors(self) -> None:
        """Check for LD_PRELOAD backdoors."""
        print_info("Checking for LD_PRELOAD backdoors...")
        
        preload_files = [
            "/etc/ld.so.preload",
            "/etc/ld.so.conf.d/"
        ]
        
        for path in preload_files:
            if os.path.exists(path):
                if os.path.isfile(path):
                    with open(path, "r") as f:
                        content = f.read()
                    
                    if content.strip():
                        preload_file = self.temp_dir / os.path.basename(path)
                        preload_file.write_text(content)
                        
                        # Check for suspicious libraries
                        suspicious = False
                        for line in content.splitlines():
                            if line.strip() and not line.strip().startswith("#"):
                                if "/tmp/" in line or "/dev/shm/" in line or "/var/tmp/" in line:
                                    suspicious = True
                        
                        if suspicious:
                            self.add_finding(
                                f"Suspicious LD_PRELOAD configuration in {path}",
                                AnalysisStatus.ERROR
                            )
                        else:
                            self.add_finding(
                                f"LD_PRELOAD configuration found in {path}",
                                AnalysisStatus.WARNING
                            )
                elif os.path.isdir(path):
                    conf_files = glob.glob(f"{path}/*.conf")
                    for conf_file in conf_files:
                        with open(conf_file, "r") as f:
                            content = f.read()
                        
                        if "/tmp/" in content or "/dev/shm/" in content or "/var/tmp/" in content:
                            self.add_finding(
                                f"Suspicious library path in {conf_file}",
                                AnalysisStatus.ERROR
                            )
    
    def _check_for_cron_backdoors(self) -> None:
        """Check for backdoors in cron jobs."""
        print_info("Checking for cron backdoors...")
        
        cron_dirs = [
            "/etc/cron.d/",
            "/etc/cron.hourly/",
            "/etc/cron.daily/",
            "/etc/cron.weekly/",
            "/etc/cron.monthly/"
        ]
        
        cron_files = [
            "/etc/crontab"
        ]
        
        # Also check user crontabs
        returncode, stdout, _ = run_command(
            "cut -d':' -f1 /etc/passwd",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            for user in stdout.splitlines():
                user_crontab = f"/var/spool/cron/crontabs/{user}"
                if os.path.exists(user_crontab):
                    cron_files.append(user_crontab)
        
        # Check all cron directories
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir) and os.path.isdir(cron_dir):
                cron_files.extend(glob.glob(f"{cron_dir}/*"))
        
        # Suspicious patterns in cron jobs
        suspicious_patterns = [
            r"curl\s+.*\s+\|\s+bash",
            r"wget\s+.*\s+\|\s+bash",
            r"base64\s+--decode",
            r"\/dev\/shm",
            r"\/dev\/null\s+2>&1",
            r"nc\s+-[el]",
            r"python\s+-c",
            r"perl\s+-e",
            r"socat",
            r"\.bash_history",
            r"\.ssh\/authorized_keys"
        ]
        
        for cron_file in cron_files:
            if os.path.exists(cron_file) and os.path.isfile(cron_file):
                try:
                    with open(cron_file, "r") as f:
                        content = f.read()
                    
                    if content.strip():
                        cron_output = self.temp_dir / f"cron_{os.path.basename(cron_file)}.txt"
                        cron_output.write_text(content)
                        
                        for pattern in suspicious_patterns:
                            if re.search(pattern, content):
                                self.add_finding(
                                    f"Suspicious pattern '{pattern}' found in {cron_file}",
                                    AnalysisStatus.ERROR
                                )
                except Exception as e:
                    print_warning(f"Could not read cron file {cron_file}: {str(e)}")
    
    def analyze(self) -> AnalysisStatus:
        """
        Perform rootkit detection analysis.
        
        Returns:
            AnalysisStatus: Status of the analysis
        """
        print_section("Rootkit Detection")
        
        if not self.check_requirements():
            self.add_finding(
                "Rootkit detection requirements not met",
                AnalysisStatus.SKIPPED
            )
            return AnalysisStatus.SKIPPED
        
        # Compare process listings
        self._compare_ps_output()
        
        # Check for known rootkits
        self._check_for_known_rootkits()
        
        # Check for LKM backdoors
        self._check_for_lkm_backdoors()
        
        # Check file integrity
        self._check_for_file_integrity()
        
        # Check for preload backdoors
        self._check_for_preload_backdoors()
        
        # Check for cron backdoors
        self._check_for_cron_backdoors()
        
        # Write report
        self.report("Rootkit Detection")
        
        return self.status


class ContainerAnalyzer(BaseAnalyzer):
    """Container security analyzer."""
    
    def __init__(self, report_file: str = "security_report.txt", debug: bool = False):
        """Initialize the container analyzer."""
        super().__init__(report_file, debug)
    
    def check_requirements(self) -> bool:
        """
        Check if container analysis requirements are met.
        
        Returns:
            bool: True if requirements are met, False otherwise
        """
        has_docker = command_exists("docker")
        if not has_docker:
            print_warning("Docker not found. Container analysis will be skipped.")
            return False
            
        return True
    
    def _check_docker_security(self) -> None:
        """Check Docker installation security."""
        print_info("Checking Docker installation security...")
        
        # Check Docker daemon socket permissions
        if os.path.exists("/var/run/docker.sock"):
            socket_perm = os.stat("/var/run/docker.sock").st_mode & 0o777
            if socket_perm & 0o022:  # World readable or writable
                self.add_finding(
                    f"Docker socket has insecure permissions: {socket_perm:o}",
                    AnalysisStatus.ERROR
                )
        
        # Check Docker group membership
        returncode, stdout, _ = run_command(
            "getent group docker",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            docker_group = stdout.strip().split(":")
            if len(docker_group) >= 4:
                members = docker_group[3].split(",")
                if members:
                    self.add_finding(
                        f"Users in docker group (can control Docker without sudo): {', '.join(members)}",
                        AnalysisStatus.WARNING
                    )
        
        # Check Docker daemon configuration
        if os.path.exists("/etc/docker/daemon.json"):
            with open("/etc/docker/daemon.json", "r") as f:
                try:
                    config = json.loads(f.read())
                    daemon_file = self.temp_dir / "docker_daemon.json"
                    daemon_file.write_text(json.dumps(config, indent=2))
                    
                    # Check for insecure configuration
                    if config.get("insecure-registries"):
                        self.add_finding(
                            f"Docker configured with insecure registries: {config['insecure-registries']}",
                            AnalysisStatus.ERROR
                        )
                    
                    if not config.get("live-restore", False):
                        self.add_finding(
                            "Docker not configured with live-restore option",
                            AnalysisStatus.WARNING
                        )
                except json.JSONDecodeError:
                    self.add_finding(
                        "Invalid Docker daemon configuration file",
                        AnalysisStatus.WARNING
                    )
    
    def _list_running_containers(self) -> List[str]:
        """
        List running containers.
        
        Returns:
            List[str]: List of container IDs
        """
        returncode, stdout, _ = run_command(
            "docker ps -q",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            return stdout.strip().splitlines()
        
        return []
    
    def _check_container_security(self) -> None:
        """Check security of running containers."""
        print_info("Checking running container security...")
        
        running_containers = self._list_running_containers()
        
        if not running_containers:
            print_info("No running containers found")
            return
        
        print_info(f"Found {len(running_containers)} running containers")
        
        for container_id in running_containers:
            # Get container details
            returncode, stdout, _ = run_command(
                f"docker inspect {container_id}",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                container_info = json.loads(stdout)[0]
                
                container_file = self.temp_dir / f"container_{container_id}.json"
                container_file.write_text(json.dumps(container_info, indent=2))
                
                name = container_info.get("Name", container_id)
                print_info(f"Analyzing container: {name}")
                
                # Check for privileged mode
                privileged = container_info.get("HostConfig", {}).get("Privileged", False)
                if privileged:
                    self.add_finding(
                        f"Container {name} is running in privileged mode",
                        AnalysisStatus.ERROR
                    )
                
                # Check for host network mode
                network_mode = container_info.get("HostConfig", {}).get("NetworkMode", "")
                if network_mode == "host":
                    self.add_finding(
                        f"Container {name} is using host network mode",
                        AnalysisStatus.WARNING
                    )
                
                # Check for sensitive mounts
                mounts = container_info.get("Mounts", [])
                for mount in mounts:
                    source = mount.get("Source", "")
                    
                    sensitive_paths = [
                        "/etc", "/var/run/docker.sock", "/root", "/home",
                        "/var/log", "/proc", "/sys", "/.ssh"
                    ]
                    
                    for sensitive in sensitive_paths:
                        if source.startswith(sensitive):
                            self.add_finding(
                                f"Container {name} has sensitive path mounted: {source}",
                                AnalysisStatus.WARNING
                            )
                
                # Check for running as root
                user = container_info.get("Config", {}).get("User", "")
                if not user or user == "0" or user == "root":
                    self.add_finding(
                        f"Container {name} is running as root user",
                        AnalysisStatus.WARNING
                    )
                
                # Check for disabled security profiles
                security_opts = container_info.get("HostConfig", {}).get("SecurityOpt", [])
                if any("seccomp=unconfined" in opt for opt in security_opts):
                    self.add_finding(
                        f"Container {name} has seccomp security profile disabled",
                        AnalysisStatus.ERROR
                    )
                
                if any("apparmor=unconfined" in opt for opt in security_opts):
                    self.add_finding(
                        f"Container {name} has AppArmor security profile disabled",
                        AnalysisStatus.ERROR
                    )
                
                # Check for capabilities
                cap_add = container_info.get("HostConfig", {}).get("CapAdd", [])
                dangerous_caps = ["ALL", "SYS_ADMIN", "NET_ADMIN", "DAC_READ_SEARCH"]
                
                for cap in cap_add:
                    if cap in dangerous_caps:
                        self.add_finding(
                            f"Container {name} has dangerous capability: {cap}",
                            AnalysisStatus.ERROR
                        )
    
    def _check_docker_images(self) -> None:
        """Check security of Docker images."""
        print_info("Checking Docker image security...")
        
        # List images
        returncode, stdout, _ = run_command(
            "docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}'",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            image_list = self.temp_dir / "docker_images.txt"
            image_list.write_text(stdout)
            
            images = stdout.strip().splitlines()
            print_info(f"Found {len(images)} Docker images")
            
            # Check for images with known vulnerabilities
            unsupported_images = []
            
            for image in images:
                if ':latest' in image:
                    unsupported_images.append(image)
                
                if 'redis:' in image or 'mongo:' in image or 'mysql:' in image:
                    # Check the tag is not an outdated version
                    if any(old_ver in image for old_ver in ['2.', '3.', '4.', '5.']):
                        unsupported_images.append(image)
            
            if unsupported_images:
                for image in unsupported_images:
                    self.add_finding(
                        f"Potentially outdated or insecure image: {image}",
                        AnalysisStatus.WARNING
                    )
            
            # Check if Trivy is available for advanced scanning
            if command_exists("trivy"):
                print_info("Scanning images with Trivy...")
                
                for image in images[:3]:  # Limit to 3 images for performance
                    image_name = image.split()[0]
                    print_info(f"Scanning {image_name} for vulnerabilities...")
                    
                    returncode, stdout, _ = run_command(
                        f"trivy image --severity HIGH,CRITICAL {image_name}",
                        shell=True,
                        capture_output=True
                    )
                    
                    if returncode == 0 or returncode == 1:  # Trivy returns 1 if vulns found
                        if "CRITICAL" in stdout or "HIGH" in stdout:
                            vuln_file = self.temp_dir / f"vulns_{image_name.replace(':', '_')}.txt"
                            vuln_file.write_text(stdout)
                            
                            # Count vulnerabilities
                            high_count = stdout.count("HIGH")
                            critical_count = stdout.count("CRITICAL")
                            
                            self.add_finding(
                                f"Image {image_name} has {high_count} HIGH and {critical_count} CRITICAL vulnerabilities",
                                AnalysisStatus.ERROR
                            )
    
    def _check_kubernetes_security(self) -> None:
        """Check Kubernetes security if running."""
        print_info("Checking for Kubernetes components...")
        
        # Check if kubectl is available
        if command_exists("kubectl"):
            print_info("Kubernetes CLI detected, checking configuration...")
            
            # Get Kubernetes version
            returncode, stdout, _ = run_command(
                "kubectl version --short",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                k8s_version = self.temp_dir / "kubernetes_version.txt"
                k8s_version.write_text(stdout)
                
                # Check for running pods
                returncode, stdout, _ = run_command(
                    "kubectl get pods --all-namespaces",
                    shell=True,
                    capture_output=True
                )
                
                if returncode == 0 and stdout.strip():
                    pods_file = self.temp_dir / "kubernetes_pods.txt"
                    pods_file.write_text(stdout)
                    
                    # Check privileged pods
                    returncode, stdout, _ = run_command(
                        "kubectl get pods --all-namespaces -o json",
                        shell=True,
                        capture_output=True
                    )
                    
                    if returncode == 0 and stdout.strip():
                        try:
                            pods_json = json.loads(stdout)
                            privileged_pods = []
                            
                            for pod in pods_json.get("items", []):
                                pod_name = pod.get("metadata", {}).get("name", "unknown")
                                namespace = pod.get("metadata", {}).get("namespace", "default")
                                
                                for container in pod.get("spec", {}).get("containers", []):
                                    security_context = container.get("securityContext", {})
                                    
                                    if security_context.get("privileged", False):
                                        privileged_pods.append(f"{namespace}/{pod_name}")
                            
                            if privileged_pods:
                                self.add_finding(
                                    f"Found {len(privileged_pods)} privileged pods: {', '.join(privileged_pods)}",
                                    AnalysisStatus.ERROR
                                )
                        except json.JSONDecodeError:
                            print_warning("Failed to parse Kubernetes pod information")
    
    def analyze(self) -> AnalysisStatus:
        """
        Perform container security analysis.
        
        Returns:
            AnalysisStatus: Status of the analysis
        """
        print_section("Container Security Analysis")
        
        if not self.check_requirements():
            self.add_finding(
                "Container analysis requirements not met",
                AnalysisStatus.SKIPPED
            )
            return AnalysisStatus.SKIPPED
        
        # Check Docker installation security
        self._check_docker_security()
        
        # Check running containers
        self._check_container_security()
        
        # Check Docker images
        self._check_docker_images()
        
        # Check Kubernetes if available
        self._check_kubernetes_security()
        
        # Write report
        self.report("Container Security Analysis")
        
        return self.status


class SecurityAnalyzer:
    """Main security analyzer that coordinates all specialized analyzers."""
    
    def __init__(
        self,
        output_dir: str = None,
        debug: bool = False,
        full_scan: bool = False,
        network_capture_time: int = 60
    ):
        """
        Initialize the security analyzer.
        
        Args:
            output_dir: Directory to save reports and artifacts
            debug: Enable debug mode
            full_scan: Perform a full comprehensive scan
            network_capture_time: Duration of network capture in seconds
        """
        # Create output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%
    
    def _analyze_connections(self) -> None:
        """Analyze current network connections."""
        print_info("Analyzing current network connections...")
        
        # Use netstat to get current connections
        returncode, stdout, _ = run_command(
            "netstat -tunap",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            conn_file = self.temp_dir / "network_connections.txt"
            conn_file.write_text(stdout)
            
            # Analyze for suspicious connections
            suspicious_ports = [
                # Common backdoor ports
                4444, 5555, 6666, 7777, 8888, 9999,
                # Cryptocurrency mining
                3333, 5000, 7777, 14444, 14433,
                # Command and control
                8080, 1080, 1443, 4443
            ]
            
            suspicious_ips = []
            high_port_outbound = []
            
            for line in stdout.splitlines():
                if "ESTABLISHED" in line or "SYN_SENT" in line:
                    fields = line.split()
                    if len(fields) >= 5:
                        # Parse IP:PORT format
                        if ":" in fields[4]:
                            remote = fields[4].split(":")
                            if len(remote) >= 2:
                                remote_ip = remote[0]
                                try:
                                    remote_port = int(remote[1])
                                    
                                    # Check for suspicious ports
                                    if remote_port in suspicious_ports:
                                        suspicious_ips.append((remote_ip, remote_port, line))
                                    
                                    # Check for high outbound ports (potential data exfiltration)
                                    if remote_port > 50000:
                                        high_port_outbound.append((remote_ip, remote_port, line))
                                except ValueError:
                                    pass
            
            if suspicious_ips:
                for ip, port, line in suspicious_ips:
                    self.add_finding(
                        f"Suspicious connection to {ip}:{port}",
                        AnalysisStatus.WARNING
                    )
            
            if high_port_outbound:
                for ip, port, line in high_port_outbound:
                    self.add_finding(
                        f"Potential data exfiltration: High port connection to {ip}:{port}",
                        AnalysisStatus.WARNING
                    )
    
    def _analyze_listening_ports(self) -> None:
        """Analyze listening ports."""
        print_info("Analyzing listening ports...")
        
        returncode, stdout, _ = run_command(
            "netstat -tulnp",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            listening_file = self.temp_dir / "listening_ports.txt"
            listening_file.write_text(stdout)
            
            # Check for unusual listening ports
            unusual_ports = []
            
            for line in stdout.splitlines():
                if "LISTEN" in line:
                    fields = line.split()
                    if len(fields) >= 6:
                        # Parse IP:PORT format
                        if ":" in fields[3]:
                            local = fields[3].split(":")
                            if len(local) >= 2:
                                try:
                                    local_port = int(local[-1])
                                    program = " ".join(fields[6:]) if len(fields) > 6 else "Unknown"
                                    
                                    # Check for non-standard high ports
                                    if local_port > 10000 and local_port not in [27017, 27018, 28017]:  # MongoDB etc
                                        unusual_ports.append((local_port, program))
                                except ValueError:
                                    pass
            
            if unusual_ports:
                for port, program in unusual_ports:
                    self.add_finding(
                        f"Unusual listening port {port} ({program})",
                        AnalysisStatus.WARNING
                    )
    
    def _analyze_dns_configuration(self) -> None:
        """Analyze DNS configuration."""
        print_info("Analyzing DNS configuration...")
        
        dns_files = ["/etc/resolv.conf", "/etc/hosts"]
        
        for file_path in dns_files:
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    content = f.read()
                
                dns_file = self.temp_dir / os.path.basename(file_path)
                dns_file.write_text(content)
                
                # Check for suspicious DNS entries
                if file_path == "/etc/resolv.conf":
                    for line in content.splitlines():
                        if line.strip().startswith("nameserver"):
                            nameserver = line.strip().split()[1]
                            # Check if not using common DNS servers
                            if nameserver not in ["1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "127.0.0.1", "::1"]:
                                self.add_finding(
                                    f"Non-standard DNS server: {nameserver}",
                                    AnalysisStatus.WARNING
                                )
                
                elif file_path == "/etc/hosts":
                    suspicious_domains = [
                        "google", "facebook", "microsoft", "apple", "amazon", 
                        "github", "login", "secure", "bank", "paypal"
                    ]
                    for line in content.splitlines():
                        if line.strip() and not line.strip().startswith("#"):
                            for domain in suspicious_domains:
                                if domain in line.lower():
                                    self.add_finding(
                                        f"Suspicious hosts entry: {line.strip()}",
                                        AnalysisStatus.WARNING
                                    )
    
    def _analyze_captured_traffic(self) -> None:
        """Analyze captured network traffic."""
        if not self.pcap_file.exists() or self.pcap_file.stat().st_size == 0:
            return
        
        print_info("Analyzing captured network traffic...")
        
        # Get a summary of the capture file
        if command_exists("tcpdump"):
            returncode, stdout, _ = run_command(
                f"tcpdump -r {self.pcap_file} -qn",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                summary_file = self.temp_dir / "traffic_summary.txt"
                summary_file.write_text(stdout)
                
                # Analyze for suspicious traffic patterns
                suspicious_patterns = [
                    # DNS tunneling
                    r"\..*\..*\..*\..*\..*\..*\..*\.",
                    # Unusual SSL/TLS traffic
                    r"length [0-9]{4,}",
                    # ICMP tunneling
                    r"ICMP echo request|ICMP echo reply.*length [0-9]{3,}",
                    # Beaconing
                    r"UDP.*length 1"
                ]
                
                for pattern in suspicious_patterns:
                    returncode, stdout, _ = run_command(
                        f"tcpdump -r {self.pcap_file} -qn | grep -E '{pattern}'",
                        shell=True,
                        capture_output=True
                    )
                    
                    if returncode == 0 and stdout.strip():
                        pattern_file = self.temp_dir / f"traffic_pattern_{pattern}.txt"
                        pattern_file.write_text(stdout)
                        self.add_finding(
                            f"Suspicious network traffic pattern detected: {pattern}",
                            AnalysisStatus.WARNING
                        )
        
            # Extract unique connections
            returncode, stdout, _ = run_command(
                f"tcpdump -r {self.pcap_file} -qn | awk '{{print $3, $5}}' | sort | uniq -c | sort -nr",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                connections_file = self.temp_dir / "unique_connections.txt"
                connections_file.write_text(stdout)
    
    def analyze(self) -> AnalysisStatus:
        """
        Perform network analysis.
        
        Returns:
            AnalysisStatus: Status of the analysis
        """
        print_section("Network Traffic Analysis")
        
        if not self.check_requirements():
            self.add_finding(
                "Network analysis requirements not met",
                AnalysisStatus.SKIPPED
            )
            return AnalysisStatus.SKIPPED
        
        # Capture network traffic
        self._capture_network_traffic()
        
        # Analyze current connections
        self._analyze_connections()
        
        # Analyze listening ports
        self._analyze_listening_ports()
        
        # Analyze DNS configuration
        self._analyze_dns_configuration()
        
        # Analyze captured traffic
        self._analyze_captured_traffic()
        
        # Write report
        self.report("Network Traffic Analysis")
        
        return self.status


class RootkitDetector(BaseAnalyzer):
    """Rootkit and backdoor detector."""
    
    def __init__(self, report_file: str = "security_report.txt", debug: bool = False):
        """Initialize the rootkit detector."""
        super().__init__(report_file, debug)
    
    def check_requirements(self) -> bool:
        """
        Check if rootkit detection requirements are met.
        
        Returns:
            bool: True if requirements are met, False otherwise
        """
        # Check for essential tools
        tools = ["ps", "lsof", "find", "grep", "ls", "stat"]
        missing = []
        
        for tool in tools:
            if not command_exists(tool):
                missing.append(tool)
        
        if missing:
            print_warning(f"Missing utilities for rootkit detection: {', '.join(missing)}")
            return False
        
        return True
    
    def _compare_ps_output(self) -> None:
        """Compare output of different process listing commands to find hidden processes."""
        print_info("Checking for hidden processes...")
        
        # Get processes from different sources
        ps_cmds = [
            ("ps aux", "ps_aux.txt"),
            ("ps -ef", "ps_ef.txt"),
            ("/bin/ps aux", "bin_ps_aux.txt"),
            ("ls -la /proc
            bool: True if requirements are met, False otherwise
        """
        if not self.volatility_path:
            print_warning("Volatility not found. Memory analysis will be limited.")
            
        return True  # We can still do basic memory analysis without volatility
    
    def _create_memory_dump(self) -> bool:
        """
        Create a memory dump for analysis.
        
        Returns:
            bool: True if successful, False otherwise
        """
        self.memory_dump = self.temp_dir / "memory.dmp"
        print_info("Attempting to create memory dump...")
        
        # Try /dev/mem
        if Path("/dev/mem").exists() and os.access("/dev/mem", os.R_OK):
            print_info("Using /dev/mem for memory acquisition")
            returncode, _, _ = run_command(
                f"dd if=/dev/mem of={self.memory_dump} bs=1M count=1024",
                shell=True,
                capture_output=True
            )
            if returncode == 0 and self.memory_dump.exists():
                print_success(f"Created memory dump: {self.memory_dump}")
                return True
        
        # Try /proc/kcore
        if Path("/proc/kcore").exists() and os.access("/proc/kcore", os.R_OK):
            print_info("Using /proc/kcore for memory acquisition")
            returncode, _, _ = run_command(
                f"dd if=/proc/kcore of={self.memory_dump} bs=1M count=1024",
                shell=True,
                capture_output=True
            )
            if returncode == 0 and self.memory_dump.exists():
                print_success(f"Created memory dump: {self.memory_dump}")
                return True
        
        print_warning("Could not create memory dump. Limited memory analysis will be performed.")
        return False
    
    def _analyze_memory_strings(self) -> None:
        """Analyze strings in memory for suspicious patterns."""
        print_info("Performing basic memory string analysis...")
        
        # Define memory source
        memory_source = None
        if self.memory_dump and self.memory_dump.exists():
            memory_source = self.memory_dump
        else:
            # Create a combined memory dump from process mappings
            combined_dump = self.temp_dir / "live_memory.dump"
            for proc_map in glob.glob("/proc/*/maps"):
                pid = proc_map.split("/")[2]
                if os.access(f"/proc/{pid}/mem", os.R_OK):
                    with open(combined_dump, "ab") as out_file:
                        try:
                            with open(f"/proc/{pid}/mem", "rb") as in_file:
                                out_file.write(in_file.read())
                        except Exception:
                            pass
            
            if combined_dump.exists() and combined_dump.stat().st_size > 0:
                memory_source = combined_dump
        
        if memory_source:
            # Look for IP addresses
            ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            ip_addresses = set()
            
            returncode, stdout, _ = run_command(
                f"strings {memory_source}",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0:
                for line in stdout.splitlines():
                    match = ip_pattern.search(line)
                    if match:
                        ip_addresses.add(match.group(1))
                
                if ip_addresses:
                    print_info(f"Found {len(ip_addresses)} potential IP addresses in memory")
                    ip_report = "\n".join(sorted(ip_addresses))
                    ip_file = self.temp_dir / "memory_ip_addresses.txt"
                    ip_file.write_text(ip_report)
                    self.add_finding(f"Found {len(ip_addresses)} IP addresses in memory")
            
            # Look for sensitive information
            sensitive_patterns = [
                r'password', r'credentials', r'secret', r'key=', r'token='
            ]
            pattern = '|'.join(sensitive_patterns)
            returncode, stdout, _ = run_command(
                f"strings {memory_source} | grep -E '{pattern}'",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                lines = stdout.splitlines()
                self.add_finding(
                    f"Found {len(lines)} potential sensitive strings in memory",
                    AnalysisStatus.WARNING
                )
    
    def _analyze_with_volatility(self) -> None:
        """Analyze memory using volatility if available."""
        if not self.volatility_path or not self.memory_dump or not self.memory_dump.exists():
            return
        
        print_info("Performing advanced memory analysis with Volatility...")
        
        # Get running processes
        print_info("Analyzing process list from memory dump...")
        returncode, stdout, _ = run_command(
            f"{self.volatility_path} -f {self.memory_dump} windows.pslist.PsList",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            process_file = self.temp_dir / "vol_pslist.txt"
            process_file.write_text(stdout)
            self.add_finding("Process list extracted from memory dump")
        
        # Get network connections
        print_info("Analyzing network connections from memory dump...")
        returncode, stdout, _ = run_command(
            f"{self.volatility_path} -f {self.memory_dump} windows.netscan.NetScan",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            network_file = self.temp_dir / "vol_netscan.txt"
            network_file.write_text(stdout)
            self.add_finding("Network connections extracted from memory dump")
        
        # Find injected code
        print_info("Looking for code injection in memory dump...")
        returncode, stdout, _ = run_command(
            f"{self.volatility_path} -f {self.memory_dump} windows.malfind.Malfind",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            malfind_file = self.temp_dir / "vol_malfind.txt"
            malfind_file.write_text(stdout)
            self.add_finding(
                "Potential code injection detected in memory!",
                AnalysisStatus.ERROR
            )
    
    def _search_malware_patterns(self) -> None:
        """Search for known malware patterns in memory."""
        print_info("Searching for known malware patterns in memory...")
        
        # Define memory source
        memory_source = None
        if self.memory_dump and self.memory_dump.exists():
            memory_source = self.memory_dump
        else:
            combined_dump = self.temp_dir / "live_memory.dump"
            if combined_dump.exists():
                memory_source = combined_dump
        
        if not memory_source:
            print_warning("No memory source available for malware pattern analysis")
            return
        
        # Define malware patterns
        malware_patterns = [
            # Command and control patterns
            r"connect.*:4[4-5][0-9][0-9]",
            r"beacon.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            # Fileless malware indicators
            r"VirtualAlloc.*0x00000040",
            r"CreateRemoteThread",
            r"HeapCreate.*0x40000",
            r"memfd_create",
            # Encryption related
            r"AES_",
            r"RC4",
            r"XOR.*0x[0-9a-f]",
            # Persistence mechanisms
            r"CurrentVersion\\Run",
            r"schtasks /create",
            r"crontab -e",
            # Common payload strings
            r"powershell.*bypass",
            r"cmd.exe /c",
            r"eval.*base64_decode",
            r"bash.*base64.*decode",
            # Rootkit indicators
            r"hide.*process",
            r"syscall.*hook",
            r"kernel.*module.*hide",
            # Cryptocurrency mining indicators
            r"stratum+tcp://",
            r"cryptonight",
            r"minerd",
            r"coinhive",
            r"monero"
        ]
        
        detected_count = 0
        for pattern in malware_patterns:
            print_info(f"Searching for pattern: {pattern}")
            returncode, stdout, _ = run_command(
                f"strings {memory_source} | grep -E '{pattern}'",
                shell=True,
                capture_output=True
            )
            
            if returncode == 0 and stdout.strip():
                detected_count += 1
                pattern_file = self.temp_dir / f"pattern_{detected_count}.txt"
                pattern_file.write_text(stdout)
                self.add_finding(
                    f"Found suspicious pattern in memory: {pattern}",
                    AnalysisStatus.WARNING
                )
        
        # Check loaded libraries for suspicious patterns
        returncode, stdout, _ = run_command(
            "lsof -n | grep -E '\\.so|\\.dll'",
            shell=True,
            capture_output=True
        )
        
        if returncode == 0 and stdout.strip():
            lib_file = self.temp_dir / "loaded_libraries.txt"
            lib_file.write_text(stdout)
            
            # Look for libraries loaded from suspicious locations

