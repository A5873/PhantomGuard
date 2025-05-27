# PhantomGuard Troubleshooting Guide

This document provides solutions for common issues, error messages, and debugging techniques when using PhantomGuard. Whether you're encountering installation problems, runtime errors, or performance bottlenecks, this guide will help you resolve issues and get PhantomGuard working optimally.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Runtime Problems](#runtime-problems)
- [Permission and Access Issues](#permission-and-access-issues)
- [Performance Bottlenecks](#performance-bottlenecks)
- [Common Error Messages](#common-error-messages)
- [Debugging Techniques](#debugging-techniques)
- [Platform-Specific Issues](#platform-specific-issues)
- [Advanced Troubleshooting](#advanced-troubleshooting)
- [Getting Help](#getting-help)

## Installation Issues

### Dependency Conflicts

**Problem**: Errors during installation due to conflicting package dependencies.

**Error Message**:
```
ERROR: Cannot install phantomguard due to conflicting dependencies: 
package1 requires dependency==1.2.0, but dependency==2.0.0 is installed
```

**Solution**:
1. Create a clean virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install with isolated dependencies:
   ```bash
   pip install phantomguard --no-deps
   pip install -r requirements.txt
   ```

3. If conflicts persist, try the `--ignore-installed` flag:
   ```bash
   pip install --ignore-installed phantomguard
   ```

### Missing System Libraries

**Problem**: Installation fails due to missing system libraries required by PhantomGuard or its dependencies.

**Error Message**:
```
error: subprocess-exited-with-error ... fatal error: pcap.h: No such file or directory
```

**Solution**:

**On Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev libssl-dev python3-dev
```

**On CentOS/RHEL**:
```bash
sudo yum install gcc gcc-c++ libpcap-devel openssl-devel python3-devel
```

**On macOS**:
```bash
brew install libpcap openssl
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

### Compilation Errors with Rust Components

**Problem**: Installation fails during compilation of Rust-based components.

**Error Message**:
```
error: failed to run custom build command for `phantomguard-rust v0.1.0`
```

**Solution**:
1. Ensure Rust is installed:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. Install with Python-only components:
   ```bash
   pip install phantomguard --no-rust
   ```

3. If compilation issues persist:
   ```bash
   pip install phantomguard --no-build-isolation
   ```

### Installation Verification

If you're unsure whether PhantomGuard was installed correctly:

```python
# In a Python interpreter
import phantomguard
print(phantomguard.__version__)
phantomguard.check_installation()  # Will report any issues with the installation
```

## Runtime Problems

### Module Import Errors

**Problem**: Unable to import PhantomGuard modules after installation.

**Error Message**:
```
ImportError: No module named 'phantomguard.advanced_analyzer'
```

**Solution**:
1. Verify installation:
   ```bash
   pip show phantomguard
   ```

2. Check if you're using the correct Python environment:
   ```bash
   which python  # On Unix-like systems
   where python  # On Windows
   ```

3. Reinstall with:
   ```bash
   pip install --force-reinstall phantomguard
   ```

### Unexpected Termination

**Problem**: PhantomGuard processes unexpectedly terminate during operation.

**Solution**:
1. Check system logs:
   ```bash
   journalctl -xe  # On Linux systems with systemd
   ```

2. Look for out-of-memory (OOM) issues:
   ```bash
   dmesg | grep -i kill
   ```

3. Increase memory limits or use incremental scanning:
   ```python
   from phantomguard import PhantomGuard
   
   guard = PhantomGuard()
   result = guard.analyze(
       incremental=True,
       max_memory_percent=30
   )
   ```

### Hanging or Unresponsive Operations

**Problem**: PhantomGuard operations appear to hang or never complete.

**Solution**:
1. Enable operation timeouts:
   ```python
   from phantomguard import PhantomGuard
   
   guard = PhantomGuard()
   result = guard.analyze(
       operation_timeout=600,  # 10-minute timeout
       enable_progress_tracking=True
   )
   ```

2. Monitor progress:
   ```python
   # When running an operation that supports progress tracking
   operation = guard.start_analysis(full=True)
   
   while not operation.completed:
       print(f"Progress: {operation.progress_percent}%, Stage: {operation.current_stage}")
       time.sleep(5)
   
   result = operation.get_result()
   ```

3. Implement a watchdog timer:
   ```python
   import threading
   import time
   
   def watchdog(operation, timeout=600):
       start_time = time.time()
       while time.time() - start_time < timeout and not operation.completed:
           time.sleep(5)
       
       if not operation.completed:
           print("Operation timed out, attempting to terminate...")
           operation.terminate()
   
   operation = guard.start_analysis(full=True)
   threading.Thread(target=watchdog, args=(operation, 600)).start()
   
   result = operation.get_result()  # Will return partial results if terminated
   ```

## Permission and Access Issues

### Insufficient Privileges

**Problem**: Operations fail due to insufficient system privileges.

**Error Message**:
```
PermissionError: [Errno 13] Permission denied: '/proc/1234/mem'
```

**Solution**:
1. Run PhantomGuard with elevated privileges for operations that require it:
   ```bash
   sudo python -m phantomguard scan --full
   ```

2. Use privilege separation for safer operation:
   ```python
   from phantomguard import PhantomGuard
   
   # Initialize with privilege separation
   guard = PhantomGuard(privilege_separation=True)
   
   # Only elevate privileges for specific operations
   guard.analyze(elevate_for=["memory_analysis", "rootkit_detection"])
   ```

3. Configure PhantomGuard to use capabilities instead of full root (Linux):
   ```bash
   sudo setcap cap_sys_ptrace,cap_net_admin,cap_dac_read_search=eip /path/to/python
   ```

### Access to Special Files

**Problem**: Unable to access special files like `/dev/mem` or `/proc` entries.

**Solution**:
1. Check kernel security settings:
   ```bash
   sysctl kernel.yama.ptrace_scope
   # Should be 0 for unrestricted access
   ```

2. Temporarily modify security settings (not recommended for production):
   ```bash
   sudo sysctl -w kernel.yama.ptrace_scope=0
   ```

3. Use PhantomGuard's built-in fallback mechanisms:
   ```python
   guard = PhantomGuard()
   result = guard.analyze(use_fallback_methods=True)
   ```

### Container and Sandbox Limitations

**Problem**: Limited functionality when running within containers or sandboxed environments.

**Solution**:
1. Mount necessary volumes when using Docker:
   ```bash
   docker run --privileged \
     --pid=host \
     --net=host \
     --cap-add=ALL \
     -v /proc:/proc:ro \
     -v /sys:/sys:ro \
     -v /var/run/docker.sock:/var/run/docker.sock \
     phantomguard-image
   ```

2. Use the container-aware mode:
   ```python
   guard = PhantomGuard(container_aware=True)
   ```

## Performance Bottlenecks

### High Memory Usage

**Problem**: PhantomGuard consumes excessive memory during operation.

**Solution**:
1. Enable incremental scanning:
   ```python
   result = guard.analyze(
       incremental=True,
       segment_size="200MB"
   )
   ```

2. Disable memory-intensive components:
   ```python
   result = guard.analyze(
       exclude_components=["memory_analyzer"],
       memory_limit_mb=1024
   )
   ```

3. See [PERFOMANCE.md](PERFOMANCE.md) for detailed memory optimization strategies.

### High CPU Usage

**Problem**: PhantomGuard consumes too much CPU, affecting system performance.

**Solution**:
1. Throttle CPU usage:
   ```python
   result = guard.analyze(
       cpu_throttle=50,  # Use at most 50% CPU
       nice_level=10     # Increase nice level (lower priority)
   )
   ```

2. Schedule operations during low-usage periods:
   ```python
   from phantomguard import ScheduledScan
   
   scan = ScheduledScan(
       name="Nightly Analysis",
       schedule="0 2 * * *",  # 2 AM daily
       scan_config={"full": True}
   )
   
   guard.add_scheduled_scan(scan)
   guard.start_scheduler()
   ```

### Slow Network Operations

**Problem**: Network monitoring or analysis is slow or causes network degradation.

**Solution**:
1. Use traffic sampling:
   ```python
   from phantomguard import NetworkMonitor
   
   monitor = NetworkMonitor(
       sampling_rate=0.1,  # Analyze 10% of packets
       max_bandwidth_mbps=10
   )
   ```

2. Limit capture size:
   ```python
   monitor.start(
       max_packet_size=128,  # Capture only headers
       max_packets=10000,    # Limit total packets
       timeout=300           # Monitor for 5 minutes max
   )
   ```

## Common Error Messages

### "Failed to initialize memory analyzer"

**Problem**: Memory analyzer component fails to initialize.

**Possible Causes**:
- Missing system permissions
- Kernel security features blocking access
- Insufficient memory

**Solution**:
1. Check system permissions:
   ```bash
   sudo phantomguard check-permissions
   ```

2. Try with fallback mode:
   ```python
   from phantomguard.advanced_analyzer import MemoryAnalyzer
   
   analyzer = MemoryAnalyzer(fallback_mode=True)
   analyzer.initialize()
   ```

3. Increase memory allocation:
   ```python
   analyzer = MemoryAnalyzer(memory_buffer_mb=512)
   ```

### "Unable to capture network traffic"

**Problem**: Network monitoring fails to capture traffic.

**Possible Causes**:
- Missing libpcap
- Insufficient permissions
- Interface in wrong mode

**Solution**:
1. Verify libpcap installation:
   ```bash
   ldconfig -p | grep libpcap  # Linux
   ```

2. Check interface permissions:
   ```bash
   sudo phantomguard check-interfaces
   ```

3. Specify interface explicitly:
   ```python
   from phantomguard import NetworkMonitor
   
   monitor = NetworkMonitor()
   monitor.start(interfaces=["eth0"])
   ```

### "Container security scan failed: API error"

**Problem**: Container scanning operations fail with API errors.

**Possible Causes**:
- Docker daemon not running
- Missing socket permissions
- API version mismatch

**Solution**:
1. Check Docker daemon status:
   ```bash
   systemctl status docker  # For systemd-based systems
   ```

2. Verify socket permissions:
   ```bash
   ls -la /var/run/docker.sock
   ```

3. Use explicit Docker configuration:
   ```python
   from phantomguard import ContainerScanner
   
   scanner = ContainerScanner(
       docker_host="unix:///var/run/docker.sock",
       api_version="auto",
       timeout=30
   )
   ```

### "Vulnerability database update failed"

**Problem**: Unable to update vulnerability databases.

**Possible Causes**:
- Network connectivity issues
- Proxy configuration
- Disk space issues

**Solution**:
1. Check network connectivity:
   ```bash
   curl -v https://vulndb.phantomguard.example.com/status
   ```

2. Configure proxy settings:
   ```python
   from phantomguard.vulnerability_scanner import VulnerabilityScanner
   
   scanner = VulnerabilityScanner(
       proxy={
           "http": "http://proxy.example.com:8080",
           "https": "http://proxy.example.com:8080"
       }
   )
   ```

3. Specify alternative database location:
   ```python
   scanner = VulnerabilityScanner(
       database_path="/path/with/space/vulndb",
       auto_update=True
   )
   ```

## Debugging Techniques

### Enabling Debug Logging

To get detailed diagnostic information:

```python
import logging
from phantomguard import PhantomGuard

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='phantomguard_debug.log'
)

# Enable debug mode
guard = PhantomGuard(debug=True)
```

For command-line usage:
```bash
phantomguard --debug scan --verbose > debug.log 2>&1
```

### Component-Level Debugging

For troubleshooting specific components:

```python
from phantomguard.advanced_analyzer import MemoryAnalyzer
from phantomguard import debug_utils

# Create a component with debugging
analyzer = MemoryAnalyzer(debug=True)

# Start a debugging session
debug_session = debug_utils.start_debug_session("memory_analysis")

try:
    result = analyzer.detect_injected_code()
    # Operations being debugged
finally:
    # Save debug information
    debug_report = debug_session.end()
    debug_report.save("memory_debug_report.json")
```

### Diagnostic Mode

Run PhantomGuard in diagnostic mode to perform self-tests:

```bash
phantomguard diagnostics --full
```

This produces a report of all components and their operational status.

In Python:
```python
from phantomguard import diagnostic

# Run system diagnostics
diag_result = diagnostic.run_full_diagnostics()

# Print results
for component, status in diag_result.component_status.items():
    print(f"{component}: {'OK' if status.operational else 'FAILED'}")
    if not status.operational:
        print(f"  Reason: {status.failure_reason}")
        print(f"  Fix: {status.recommended_fix}")
```

### Inspecting Internal State

For advanced debugging, inspect PhantomGuard's internal state:

```python
from phantomguard import PhantomGuard, debug_utils

guard = PhantomGuard()

# Capture state before operation
state_before = debug_utils.capture_internal_state(guard)

# Perform operation
result = guard.analyze()

# Capture state after operation
state_after = debug_utils.capture_internal_state(guard)

# Compare states to identify changes/issues
diff = debug_utils.compare_states(state_before, state_after)
debug_utils.print_state_diff(diff)
```

## Platform-Specific Issues

### Linux

#### SELinux Blocking Access

**Problem**: SELinux blocks PhantomGuard operations.

**Solution**:
1. Check SELinux status:
   ```bash
   getenforce
   ```

2. Create a custom SELinux policy for PhantomGuard:
   ```bash
   sudo phantomguard generate-selinux-policy
   sudo semodule -i phantomguard.pp
   ```

3. Temporarily set SELinux to permissive mode (not recommended for production):
   ```bash
   sudo setenforce 0
   ```

#### AppArmor Restrictions

**Problem**: AppArmor profiles restrict PhantomGuard operations.

**Solution**:
1. Check if AppArmor is blocking PhantomGuard:
   ```bash
   sudo aa-status
   dmesg | grep DENIED
   ```

2. Use the provided AppArmor profile:
   ```bash
   sudo cp /usr/share/phantomguard/apparmor/phantomguard /etc/apparmor.d/
   sudo apparmor_parser -r /etc/apparmor.d/phantomguard
   ```

### macOS

#### System Integrity Protection (SIP)

**Problem**: SIP prevents certain system analysis operations.

**Solution**:
1. Use the approved APIs mode:
   ```python
   guard = PhantomGuard(macos_sip_compatible=True)
   ```

2. Request user approval for security-sensitive operations:
   ```python
   guard = PhantomGuard(request_permissions=True)
   ```

#### TCC (Transparency, Consent, and Control) Restrictions

**Problem**: macOS privacy controls block access to protected resources.

**Solution**:
1. Grant Full Disk Access to Terminal or your Python environment
2. Use the TCC-aware mode:
   ```python
   guard = PhantomGuard(macos_tcc_aware=True)
   ```

### Windows

#### Windows Defender Interference

**Problem**: Windows Defender or other security software flags PhantomGuard operations.

**Solution**:
1. Add exclusions for PhantomGuard's processes and directories
2. Use the Windows Defender compatible mode:
   ```python
   guard = PhantomGuard(windows_defender_compatible=True)
   ```

#### UAC Prompts

**Problem**: Frequent UAC prompts during operation.

**Solution**:
1. Start your Python environment with administrative privileges
2. Use the UAC-aware mode:
   ```python
   guard = PhantomGuard(windows_uac_aware=True)
   ```

## Advanced Troubleshooting

### Recovery from Failed Operations

If a PhantomGuard operation fails or crashes:

```python
from phantomguard import PhantomGuard, recovery

# Initialize with recovery support
guard = PhantomGuard(enable_recovery=True)

try:
    result = guard.analyze(full=True)
except Exception as e:
    print(f"Operation failed: {str(e)}")
    
    # Attempt to recover
    recovery_manager = recovery.RecoveryManager()
    if recovery_manager.has_recovery_point():
        print("Attempting recovery...")
        partial_result = recovery_manager.recover_last_operation()
        print(f"Recovered partial results with {len(partial_result.findings)} findings")
```

### Data Corruption Issues

If you encounter data corruption or database issues:

```python
from phantomguard import maintenance

# Verify database integrity
db_check = maintenance.check_database_integrity()
if not db_check.is_valid:
    print(f"Database corruption detected: {db_check.errors}")
    
    # Attempt repair
    repair_result = maintenance.repair_database()
    if repair_result.success:
        print("Database successfully repaired")
    else:
        print(f"Repair failed: {repair_result.error}")
        
        # Reset to defaults if repair fails
        maintenance.reset_database()
```

### Resolving Deadlocks

If PhantomGuard operations appear to deadlock:

```python
from phantomguard import PhantomGuard, diagnostics

guard = PhantomGuard()

# Start an operation that might deadlock
operation = guard.start_analysis(full=True)

# In another thread or process, check for deadlocks
deadlock_info = diagnostics.check_for_deadlocks(guard)
if deadlock_info.has_deadlock:
    print(f"Deadlock detected in component: {deadlock_info.component}")
    print(f"Locked resources: {deadlock_info.resources}")
    
    # Attempt to resolve
    diagnostics.resolve_deadlock(guard)
```

### Core Dumps and Crash Analysis

For analyzing crashes:

```python
from phantomguard import crash_analysis

# Parse a core dump
analysis = crash_analysis.analyze_core_dump("/path/to/core.dump")

print(f"Crash occurred in: {analysis.component}")
print(f"Stack trace: {analysis.stack_trace}")
print(f"Likely cause: {analysis.probable_cause}")
print(f"Recommended fix: {analysis.recommendation}")
```

## Getting Help

If you've tried the troubleshooting steps in this guide but still have issues:

1. Check the latest documentation at [https://docs.phantomguard.example.com](https://docs.phantomguard.example.com)

2. Generate a support bundle:
   ```bash
   phantomguard support-bundle --output bundle.zip
   ```

3. File an issue with the support bundle attached at:
   [https://github.com/username/phantomguard/issues](https://github.com/username/phantomguard/issues)

4. For security-related issues, email security@phantomguard.example.com

---

For API reference, see [API.md](API.md).

For usage examples, see [LIBRARY_USAGE.md](LIBRARY_USAGE.md).

For performance optimization, see [PERFOMANCE.md](PERFOMANCE.md).

