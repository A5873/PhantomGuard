# PhantomGuard API Reference

This document provides a comprehensive reference for the PhantomGuard API, detailing the classes and methods available for security analysis, memory forensics, rootkit detection, container security, and system monitoring.

## Table of Contents

- [Overview](#overview)
- [Core API](#core-api)
- [Memory Forensics API](#memory-forensics-api)
- [Network Monitoring API](#network-monitoring-api)
- [Rootkit Detection API](#rootkit-detection-api)
- [Container Security API](#container-security-api)
- [System Vulnerability API](#system-vulnerability-api)
- [Real-time Monitoring API](#real-time-monitoring-api)
- [Utility Functions](#utility-functions)

## Overview

PhantomGuard's API is organized into modular components that can be used independently or in combination. All modules are accessible through the main `phantomguard` package.

```python
import phantomguard
```

## Core API

### PhantomGuard

The main class providing access to all security analysis features.

```python
from phantomguard import PhantomGuard

# Initialize PhantomGuard with default configuration
guard = PhantomGuard()

# Initialize with custom configuration
guard = PhantomGuard(config_file='/path/to/config.yaml')
```

#### Methods

##### `scan()`

Performs a basic system scan covering essential security checks.

**Parameters:**
- `verbose` (bool, optional): Enable detailed output. Default: `False`
- `output_format` (str, optional): Format for results ('json', 'yaml', 'text'). Default: `'text'`

**Returns:**
- `ScanResult`: Object containing scan findings and recommendations

**Example:**
```python
result = guard.scan(verbose=True, output_format='json')
print(result.summary())
```

##### `analyze(full=False)`

Performs a comprehensive security analysis of the system.

**Parameters:**
- `full` (bool, optional): Enable full deep analysis. Default: `False`
- `include_memory` (bool, optional): Include memory analysis. Default: `True`
- `include_network` (bool, optional): Include network analysis. Default: `True`
- `output_file` (str, optional): Path to save analysis results. Default: `None`

**Returns:**
- `AnalysisResult`: Detailed analysis results

**Example:**
```python
result = guard.analyze(full=True, output_file='security_analysis.json')
critical_issues = result.get_critical_issues()
```

## Memory Forensics API

### MemoryAnalyzer

Class for memory forensics and runtime analysis.

```python
from phantomguard.advanced_analyzer import MemoryAnalyzer

# Initialize the memory analyzer
memory_analyzer = MemoryAnalyzer()
```

#### Methods

##### `scan_process(pid)`

Analyzes a specific process memory space.

**Parameters:**
- `pid` (int): Process ID to analyze

**Returns:**
- `ProcessScanResult`: Process memory analysis results

**Example:**
```python
result = memory_analyzer.scan_process(1234)
if result.has_anomalies():
    print(f"Anomalies detected in process {pid}!")
```

##### `detect_injected_code()`

Scans all processes for signs of code injection.

**Parameters:**
- `scan_depth` (str, optional): Depth of scan ('quick', 'normal', 'deep'). Default: `'normal'`

**Returns:**
- `list`: List of processes with suspected code injection

**Example:**
```python
suspicious_procs = memory_analyzer.detect_injected_code(scan_depth='deep')
for proc in suspicious_procs:
    print(f"Process {proc.pid} ({proc.name}) shows signs of code injection")
```

##### `dump_process_memory(pid, output_file)`

Dumps process memory to a file for offline analysis.

**Parameters:**
- `pid` (int): Process ID to dump
- `output_file` (str): Output file path

**Returns:**
- `bool`: Success status

**Example:**
```python
success = memory_analyzer.dump_process_memory(1234, 'process_dump.bin')
```

## Network Monitoring API

### NetworkMonitor

Class for monitoring and analyzing network traffic.

```python
from phantomguard import NetworkMonitor

# Initialize the network monitor
network_monitor = NetworkMonitor()

# Start monitoring
network_monitor.start()
```

#### Methods

##### `start()`

Starts real-time network monitoring.

**Parameters:**
- `interfaces` (list, optional): Network interfaces to monitor. Default: all interfaces
- `capture_packets` (bool, optional): Store packet data. Default: `False`

**Returns:**
- `None`

**Example:**
```python
network_monitor.start(interfaces=['eth0'], capture_packets=True)
```

##### `stop()`

Stops the network monitoring.

**Parameters:**
- None

**Returns:**
- `MonitoringStatistics`: Statistics from the monitoring session

**Example:**
```python
stats = network_monitor.stop()
print(f"Monitored for {stats.duration} seconds, detected {stats.anomalies} anomalies")
```

##### `get_suspicious_connections()`

Returns connections showing suspicious behavior.

**Parameters:**
- `threshold` (float, optional): Suspicion threshold (0-1). Default: `0.7`

**Returns:**
- `list`: List of suspicious network connections

**Example:**
```python
suspicious = network_monitor.get_suspicious_connections(threshold=0.8)
for conn in suspicious:
    print(f"Suspicious connection: {conn.source_ip}:{conn.source_port} -> {conn.dest_ip}:{conn.dest_port}")
```

## Rootkit Detection API

### RootkitDetector

Class for detecting rootkits and system compromises.

```python
from phantomguard import RootkitDetector

# Initialize the rootkit detector
rootkit_detector = RootkitDetector()
```

#### Methods

##### `scan_system()`

Performs a comprehensive scan for rootkits.

**Parameters:**
- `kernel_check` (bool, optional): Include kernel module analysis. Default: `True`
- `file_check` (bool, optional): Check for hidden files. Default: `True`
- `process_check` (bool, optional): Check for hidden processes. Default: `True`

**Returns:**
- `ScanResult`: Results of the rootkit scan

**Example:**
```python
result = rootkit_detector.scan_system()
if result.rootkits_found:
    print("WARNING: Possible rootkits detected!")
    for rootkit in result.detected_rootkits:
        print(f" - {rootkit.name}: {rootkit.detection_method}")
```

##### `check_syscall_hooks()`

Checks for hooked system calls that might indicate rootkits.

**Parameters:**
- None

**Returns:**
- `list`: List of potentially hooked syscalls

**Example:**
```python
hooked_syscalls = rootkit_detector.check_syscall_hooks()
for syscall in hooked_syscalls:
    print(f"Syscall {syscall.name} appears to be hooked")
```

## Container Security API

### ContainerScanner

Class for analyzing container security.

```python
from phantomguard import ContainerScanner

# Initialize the container scanner
container_scanner = ContainerScanner()
```

#### Methods

##### `scan_container(container_id)`

Scans a specific container for security issues.

**Parameters:**
- `container_id` (str): ID or name of the container
- `scan_type` (str, optional): Type of scan ('quick', 'standard', 'deep'). Default: `'standard'`

**Returns:**
- `ContainerScanResult`: Container scan findings

**Example:**
```python
result = container_scanner.scan_container('web-server-1', scan_type='deep')
for vulnerability in result.vulnerabilities:
    print(f"[{vulnerability.severity}] {vulnerability.title}: {vulnerability.description}")
```

##### `scan_image(image_name)`

Scans a container image for vulnerabilities.

**Parameters:**
- `image_name` (str): Name of the container image
- `include_dependencies` (bool, optional): Scan dependencies. Default: `True`

**Returns:**
- `ImageScanResult`: Image scan findings

**Example:**
```python
result = container_scanner.scan_image('nginx:latest')
print(f"Found {len(result.vulnerabilities)} vulnerabilities")
```

##### `scan_kubernetes_cluster()`

Scans a Kubernetes cluster for security misconfigurations.

**Parameters:**
- `namespace` (str, optional): Kubernetes namespace to scan. Default: all namespaces
- `include_pods` (bool, optional): Include pod security checks. Default: `True`

**Returns:**
- `KubernetesScanResult`: Kubernetes security scan results

**Example:**
```python
result = container_scanner.scan_kubernetes_cluster(namespace='production')
print(f"Cluster security score: {result.security_score}/10")
```

## System Vulnerability API

### VulnerabilityScanner

Class for identifying system vulnerabilities.

```python
from phantomguard.vulnerability_scanner import VulnerabilityScanner

# Initialize the vulnerability scanner
vulnerability_scanner = VulnerabilityScanner()
```

#### Methods

##### `scan_system()`

Scans the system for known vulnerabilities.

**Parameters:**
- `scan_type` (str, optional): Type of scan ('packages', 'configs', 'services', 'all'). Default: `'all'`
- `cve_check` (bool, optional): Check against CVE database. Default: `True`

**Returns:**
- `VulnerabilityScanResult`: Vulnerability scan results

**Example:**
```python
result = vulnerability_scanner.scan_system(scan_type='packages')
for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.title} (CVE: {vuln.cve_id})")
```

##### `check_package_vulnerabilities()`

Checks installed packages against vulnerability databases.

**Parameters:**
- `package_manager` (str, optional): Specific package manager to check. Default: auto-detect

**Returns:**
- `list`: List of vulnerable packages

**Example:**
```python
vulnerable_packages = vulnerability_scanner.check_package_vulnerabilities()
print(f"Found {len(vulnerable_packages)} vulnerable packages")
```

##### `check_service_configurations()`

Analyzes service configurations for security issues.

**Parameters:**
- `services` (list, optional): List of services to check. Default: all running services

**Returns:**
- `dict`: Dictionary of services with configuration issues

**Example:**
```python
insecure_services = vulnerability_scanner.check_service_configurations(['ssh', 'nginx'])
for service, issues in insecure_services.items():
    print(f"Service {service} has {len(issues)} configuration issues")
```

## Real-time Monitoring API

### SystemMonitor

Class for real-time system monitoring.

```python
from phantomguard import SystemMonitor

# Initialize the system monitor
system_monitor = SystemMonitor()

# Start monitoring with custom handlers
system_monitor.on_suspicious_activity = lambda event: print(f"Alert: {event.description}")
system_monitor.start()
```

#### Methods

##### `start()`

Starts real-time system monitoring.

**Parameters:**
- `monitor_processes` (bool, optional): Monitor process creation/termination. Default: `True`
- `monitor_files` (bool, optional): Monitor file changes. Default: `True`
- `monitor_network` (bool, optional): Monitor network connections. Default: `True`

**Returns:**
- `None`

**Example:**
```python
system_monitor.start(monitor_files=False)  # Start without file monitoring
```

##### `stop()`

Stops the system monitoring.

**Parameters:**
- None

**Returns:**
- `MonitoringStatistics`: Statistics from the monitoring session

**Example:**
```python
stats = system_monitor.stop()
print(f"Monitored for {stats.duration} seconds")
```

##### `add_watch(resource_type, resource_id)`

Adds a specific resource to the watch list.

**Parameters:**
- `resource_type` (str): Type of resource ('file', 'process', 'port', etc.)
- `resource_id` (str): Identifier for the resource

**Returns:**
- `bool`: Success status

**Example:**
```python
system_monitor.add_watch('file', '/etc/passwd')
system_monitor.add_watch('port', '22')
```

## Utility Functions

### Common Utilities

```python
from phantomguard.utils.common import hash_file, get_process_info, check_signature

# Get the hash of a file
file_hash = hash_file('/path/to/file', algorithm='sha256')

# Get detailed information about a process
process_info = get_process_info(1234)

# Check if a binary is properly signed
is_signed = check_signature('/usr/bin/example', check_revocation=True)
```

### Analysis Context

```python
from phantomguard import AnalysisContext

# Create a new analysis context to group related operations
context = AnalysisContext(name="Incident Response #1234")

# Associate analysis results with the context
context.add_result(memory_analyzer.scan_process(1234))
context.add_result(rootkit_detector.scan_system())

# Generate a report from all results in the context
report = context.generate_report(format='pdf')
```

---

For more detailed examples and advanced usage, please refer to the [LIBRARY_USAGE.md](LIBRARY_USAGE.md) document.

