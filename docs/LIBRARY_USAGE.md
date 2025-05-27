# PhantomGuard Library Usage Guide

This document provides practical examples and common use cases for the PhantomGuard security analysis toolkit. Whether you're performing basic security checks or implementing complex security monitoring solutions, this guide will help you get the most out of PhantomGuard.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Usage Patterns](#basic-usage-patterns)
- [Common Use Cases](#common-use-cases)
  - [System Security Auditing](#system-security-auditing)
  - [Incident Response](#incident-response)
  - [Continuous Security Monitoring](#continuous-security-monitoring)
  - [Container Security](#container-security)
- [Integration Patterns](#integration-patterns)
  - [Combining Multiple Analyzers](#combining-multiple-analyzers)
  - [Creating Custom Security Workflows](#creating-custom-security-workflows)
- [Advanced Scenarios](#advanced-scenarios)
  - [Automated Threat Hunting](#automated-threat-hunting)
  - [Integration with SIEM Systems](#integration-with-siem-systems)
  - [Custom Detection Rules](#custom-detection-rules)
- [Best Practices](#best-practices)

## Getting Started

### Installation

```bash
# Install from PyPI (when available)
pip install phantomguard

# For development installation
git clone https://github.com/username/phantomguard.git
cd phantomguard
pip install -e '.[dev]'
```

### Basic Initialization

```python
from phantomguard import PhantomGuard

# Initialize with default configuration
guard = PhantomGuard()

# Initialize with custom configuration file
guard = PhantomGuard(config_file='/path/to/config.yaml')

# Initialize with specific options
guard = PhantomGuard(
    log_level='INFO',
    enable_remote_logging=False,
    data_directory='/var/lib/phantomguard'
)
```

## Basic Usage Patterns

### Quick System Scan

Perform a basic security scan of the system:

```python
from phantomguard import PhantomGuard

guard = PhantomGuard()
result = guard.scan()

# Display a summary of the findings
print(result.summary())

# Check if any critical issues were found
if result.has_critical_issues():
    print("Critical security issues detected!")
    for issue in result.get_critical_issues():
        print(f"- {issue.title}: {issue.description}")
```

### Comprehensive Security Analysis

Perform a full security analysis of the system with detailed reporting:

```python
from phantomguard import PhantomGuard

guard = PhantomGuard()
result = guard.analyze(
    full=True,  # Enable full deep analysis
    include_memory=True,
    include_network=True,
    output_file='security_analysis_report.json'
)

# Process the results
print(f"Analysis completed with {len(result.issues)} issues found")
print(f"Security score: {result.security_score}/10")

# Generate a detailed HTML report
report_path = result.generate_report(
    format='html',
    output_file='security_report.html',
    include_recommendations=True
)
print(f"Report generated at: {report_path}")
```

## Common Use Cases

### System Security Auditing

Perform a comprehensive security audit of a system, checking for vulnerabilities, misconfigurations, and compliance issues:

```python
from phantomguard import PhantomGuard, ComplianceFramework
from phantomguard.vulnerability_scanner import VulnerabilityScanner

# Initialize components
guard = PhantomGuard()
vuln_scanner = VulnerabilityScanner()

# Scan for vulnerabilities
vuln_result = vuln_scanner.scan_system(scan_type='all', cve_check=True)

# Check compliance with security frameworks
compliance_result = guard.check_compliance(
    frameworks=[
        ComplianceFramework.CIS_BENCHMARK,
        ComplianceFramework.NIST_800_53
    ]
)

# Generate a consolidated report
audit_context = guard.create_audit_context("System Security Audit")
audit_context.add_result(vuln_result)
audit_context.add_result(compliance_result)

report = audit_context.generate_report(
    format='pdf',
    output_file='security_audit_report.pdf',
    include_executive_summary=True
)
```

### Incident Response

Use PhantomGuard for incident response to investigate potential security breaches:

```python
from phantomguard import PhantomGuard, IncidentResponseWorkflow
from phantomguard.advanced_analyzer import MemoryAnalyzer
from phantomguard import NetworkMonitor, RootkitDetector

# Create an incident response workflow
ir = IncidentResponseWorkflow(
    name="Potential Breach Investigation",
    incident_id="IR-2025-05-27-001"
)

# Add relevant system data to the investigation
ir.collect_system_information()
ir.collect_running_processes()
ir.collect_network_connections()
ir.collect_recent_logins()
ir.collect_file_changes(days=7)

# Perform deep analysis
memory_analyzer = MemoryAnalyzer()
rootkit_detector = RootkitDetector()

# Check for signs of compromise
suspicious_processes = memory_analyzer.detect_injected_code(scan_depth='deep')
for proc in suspicious_processes:
    ir.add_evidence("suspicious_process", proc)
    # Collect process memory dump for further analysis
    dump_path = memory_analyzer.dump_process_memory(
        proc.pid,
        f"evidence/process_{proc.pid}.dump"
    )
    ir.add_evidence_file(dump_path)

# Check for rootkits
rootkit_result = rootkit_detector.scan_system()
if rootkit_result.rootkits_found:
    for rootkit in rootkit_result.detected_rootkits:
        ir.add_evidence("rootkit", rootkit)

# Generate timeline of events
timeline = ir.generate_timeline()

# Create comprehensive incident report
report_path = ir.generate_report(
    format='html',
    include_timeline=True,
    include_evidence=True,
    output_file='incident_report.html'
)
```

### Continuous Security Monitoring

Set up continuous security monitoring to detect threats in real-time:

```python
from phantomguard import SystemMonitor, AlertManager
import time

# Configure alert manager
alert_manager = AlertManager(
    email_alerts=True,
    email_recipients=['security@example.com'],
    slack_webhook='https://hooks.slack.com/services/...',
    alert_threshold='medium'  # Only alert on medium or higher severity
)

# Initialize the system monitor with the alert manager
monitor = SystemMonitor(alert_manager=alert_manager)

# Define custom event handlers
def handle_suspicious_process(event):
    print(f"Suspicious process detected: {event.process_name} (PID: {event.pid})")
    print(f"Command line: {event.command_line}")
    # Perform additional investigation
    # ...

def handle_suspicious_network(event):
    print(f"Suspicious network connection: {event.source_ip}:{event.source_port} -> {event.dest_ip}:{event.dest_port}")
    print(f"Process: {event.process_name} (PID: {event.pid})")
    # Block connection if needed
    # ...

# Register event handlers
monitor.on_suspicious_process = handle_suspicious_process
monitor.on_suspicious_network = handle_suspicious_network

# Add specific resources to watch
monitor.add_watch('file', '/etc/passwd')
monitor.add_watch('file', '/etc/shadow')
monitor.add_watch('directory', '/var/www')
monitor.add_watch('port', '22')
monitor.add_watch('process', 'sshd')

# Start monitoring with all features enabled
monitor.start(
    monitor_processes=True,
    monitor_files=True,
    monitor_network=True
)

try:
    print("Monitoring system... Press Ctrl+C to stop")
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    # Stop monitoring and get statistics
    stats = monitor.stop()
    print(f"Monitoring stopped. Stats: {stats.duration} seconds, {stats.events} events, {stats.alerts} alerts")
```

### Container Security

Scan container images and running containers for security issues:

```python
from phantomguard import ContainerScanner

# Initialize the container scanner
scanner = ContainerScanner()

# Scan a specific container image before deployment
image_result = scanner.scan_image(
    'myapp:latest',
    include_dependencies=True
)

if image_result.has_critical_vulnerabilities():
    print("Critical vulnerabilities found in container image!")
    for vuln in image_result.get_critical_vulnerabilities():
        print(f"- {vuln.cve_id}: {vuln.title}")
    print("Deployment not recommended until vulnerabilities are addressed.")
else:
    print("No critical vulnerabilities found. Image is safe to deploy.")

# Scan all running containers
running_containers = scanner.list_running_containers()
for container in running_containers:
    print(f"Scanning container: {container.name} ({container.id})")
    result = scanner.scan_container(container.id, scan_type='standard')
    if result.vulnerabilities:
        print(f"Found {len(result.vulnerabilities)} vulnerabilities")
        # Group by severity
        by_severity = result.group_by_severity()
        for severity, vulns in by_severity.items():
            print(f"  {severity}: {len(vulns)}")

# Scan Kubernetes cluster for misconfigurations
k8s_result = scanner.scan_kubernetes_cluster(namespace='production')
print(f"Kubernetes security score: {k8s_result.security_score}/10")
for issue in k8s_result.issues:
    print(f"- {issue.severity}: {issue.title}")
    print(f"  Resource: {issue.resource_type}/{issue.resource_name}")
    print(f"  Recommendation: {issue.recommendation}")
```

## Integration Patterns

### Combining Multiple Analyzers

Combine different analyzers to create a comprehensive security assessment:

```python
from phantomguard import PhantomGuard, AnalysisContext
from phantomguard.advanced_analyzer import MemoryAnalyzer
from phantomguard import RootkitDetector, NetworkMonitor
from phantomguard.vulnerability_scanner import VulnerabilityScanner

# Create a unified analysis context
context = AnalysisContext(name="Comprehensive Security Assessment")

# Initialize individual components
memory_analyzer = MemoryAnalyzer()
rootkit_detector = RootkitDetector()
network_monitor = NetworkMonitor()
vuln_scanner = VulnerabilityScanner()

# Perform memory analysis
print("Performing memory analysis...")
memory_result = memory_analyzer.detect_injected_code()
context.add_result(memory_result)

# Check for rootkits
print("Checking for rootkits...")
rootkit_result = rootkit_detector.scan_system()
context.add_result(rootkit_result)

# Monitor network for a short period
print("Monitoring network...")
network_monitor.start(capture_packets=True)
import time
time.sleep(60)  # Monitor for 60 seconds
network_result = network_monitor.stop()
context.add_result(network_result)

# Scan for vulnerabilities
print("Scanning for vulnerabilities...")
vuln_result = vuln_scanner.scan_system()
context.add_result(vuln_result)

# Generate a comprehensive report
print("Generating report...")
report = context.generate_report(
    format='html',
    output_file='comprehensive_security_assessment.html'
)
print(f"Report generated: {report}")

# Get consolidated findings
all_issues = context.get_all_issues()
print(f"Total issues found: {len(all_issues)}")
critical_issues = [i for i in all_issues if i.severity == 'critical']
print(f"Critical issues found: {len(critical_issues)}")
```

### Creating Custom Security Workflows

Create custom security workflows to automate specific security tasks:

```python
from phantomguard import PhantomGuard, SecurityWorkflow
from phantomguard.utils.common import hash_file, check_signature

class SoftwareVerificationWorkflow(SecurityWorkflow):
    """Custom workflow to verify software integrity and authenticity."""
    
    def __init__(self, software_path, expected_hash=None):
        super().__init__(name="Software Verification")
        self.software_path = software_path
        self.expected_hash = expected_hash
        
    def run(self):
        self.add_step("Checking file existence")
        import os
        if not os.path.exists(self.software_path):
            self.add_finding("error", f"File not found: {self.software_path}")
            return False
            
        self.add_step("Calculating file hash")
        actual_hash = hash_file(self.software_path, algorithm='sha256')
        self.add_artifact("file_hash", actual_hash)
        
        if self.expected_hash:
            self.add_step("Verifying hash match")
            if actual_hash.lower() != self.expected_hash.lower():
                self.add_finding(
                    "critical", 
                    "Hash mismatch", 
                    f"Expected: {self.expected_hash}\nActual: {actual_hash}"
                )
                return False
            else:
                self.add_finding("info", "Hash verified successfully")
        
        self.add_step("Checking digital signature")
        is_signed = check_signature(self.software_path)
        if is_signed:
            self.add_finding("info", "Valid digital signature found")
        else:
            self.add_finding("warning", "No valid digital signature found")
        
        self.add_step("Scanning for malware")
        from phantomguard import MalwareScanner
        scanner = MalwareScanner()
        scan_result = scanner.scan_file(self.software_path)
        if scan_result.is_malicious:
            self.add_finding("critical", "Malware detected", scan_result.details)
            return False
            
        return True

# Use the custom workflow
workflow = SoftwareVerificationWorkflow(
    software_path="/path/to/software.exe",
    expected_hash="a1b2c3d4e5f6..."
)

if workflow.run():
    print("Software verified successfully")
else:
    print("Software verification failed")
    for finding in workflow.get_findings():
        if finding.severity in ('warning', 'critical', 'error'):
            print(f"[{finding.severity.upper()}] {finding.title}: {finding.description}")

# Generate a verification report
report = workflow.generate_report(format='pdf', output_file='verification_report.pdf')
```

## Advanced Scenarios

### Automated Threat Hunting

Implement automated threat hunting to proactively search for signs of compromise:

```python
from phantomguard import PhantomGuard, ThreatHunter
from phantomguard.advanced_analyzer import MemoryAnalyzer
from phantomguard import NetworkMonitor
import datetime

# Initialize threat hunter
hunter = ThreatHunter()

# Load hunting rules
hunter.load_rules_from_directory('/path/to/hunting/rules')

# Add custom hunting rule
hunter.add_rule({
    'name': 'SuspiciousPowerShellCommands',
    'description': 'Detects PowerShell commands with encoded scripts or suspicious parameters',
    'severity': 'high',
    'detection': {
        'process_name': 'powershell.exe',
        'command_line_contains': ['-enc', '-encoded', '-command', 'bypass', 'hidden', 'downloadstring']
    }
})

# Create a new hunt
hunt = hunter.create_hunt(
    name="Scheduled Threat Hunt",
    description="Weekly automated threat hunt",
    start_time=datetime.datetime.now()
)

# Add memory analysis to the hunt
memory_analyzer = MemoryAnalyzer()
suspicious_processes = memory_analyzer.detect_injected_code()
for process in suspicious_processes:
    hunt.add_finding(
        rule_name="CodeInjection",
        severity="high",
        process=process
    )

# Add network analysis to the hunt
network_monitor = NetworkMonitor()
network_monitor.start(capture_packets=True)
import time
time.sleep(300)  # Monitor for 5 minutes
network_result = network_monitor.stop()

suspicious_connections = network_result.get_suspicious_connections(threshold=0.8)
for conn in suspicious_connections:
    hunt.add_finding(
        rule_name="SuspiciousNetworkConnection",
        severity="medium",
        connection=conn
    )

# Run automated hunting procedures
hunt.run_procedure("memory_anomalies")
hunt.run_procedure("persistence_mechanisms")
hunt.run_procedure("suspicious_services")

# Complete the hunt
hunt.complete()
if hunt.has_findings():
    print(f"Threat hunt completed with {len(hunt.findings)} findings")
    # Send alert to security team
    hunt.send_alert(
        to="security-team@example.com",
        include_details=True
    )
else:
    print("Threat hunt completed with no findings")

# Generate detailed report
report_path = hunt.generate_report(format='html', output_file='threat_hunt_report.html')
print(f"Report available at: {report_path}")
```

### Integration with SIEM Systems

Integrate PhantomGuard with Security Information and Event Management (SIEM) systems:

```python
from phantomguard import PhantomGuard, SIEMIntegration
from phantomguard.integrations.siem import ElasticSearchSIEM, SplunkSIEM

# Initialize PhantomGuard
guard = PhantomGuard()

# Configure ElasticSearch SIEM integration
elastic_siem = ElasticSearchSIEM(
    hosts=["https://elasticsearch.example.com:9200"],
    index_prefix="security-",
    username="elastic_user",
    password="elastic_password",
    verify_ssl=True
)

# Or configure Splunk integration
splunk_siem = SplunkSIEM(
    host="splunk.example.com",
    port=8089,
    token="splunk_token",
    index="security_events"
)

# Create SIEM integration with the configured backend
siem_integration = SIEMIntegration(backend=elastic_siem)  # or splunk_siem

# Perform security analysis
result = guard.analyze(full=True)

# Send results to SIEM
event_ids = siem_integration.send_results(
    result,
    event_type="security_analysis",
    include_details=True
)
print(f"Sent {len(event_ids)} events to SIEM")

# Configure real-time monitoring with SIEM integration
from phantomguard import SystemMonitor

monitor = SystemMonitor()
monitor.set_siem_integration(siem_integration)

# Start monitoring with SIEM forwarding enabled
monitor.start(
    monitor_processes=True,
    monitor_files=True,
    monitor_network=True,
    siem_forwarding=True,
    siem_batch_size=10,  # Send events in batches of 10
    siem_interval=60     # Send every 60 seconds
)
```

### Custom Detection Rules

Create and implement custom detection rules for specific threats:

```python
from phantomguard import PhantomGuard, DetectionRule, RuleEngine
from phantomguard.utils.common import get_process_info

# Define a custom detection rule
rule = DetectionRule(
    name="SuspiciousCronJob",
    description="Detects suspicious cron jobs that may indicate persistence",
    severity="medium",
    # Define conditions for this rule
    conditions={
        "file_paths": ["/etc/cron.d/*", "/etc/cron.hourly/*", "/var/spool/cron/*"],
        "content_patterns": [
            "curl.*\\|.*sh",
            "wget.*\\|.*bash",
            "\\.\\./\\.\\./\\.\\.",
            "base64.*decode",
            "\\$[0-9]\\(.*\\)"
        ]
    },
    # Define response actions
    actions=[
        {"type": "alert", "recipients": ["security@example.com"]},
        {"type": "log", "level": "warning"},
        {"type": "quarantine_file"}
    ]
)

# Create a custom file system activity rule
fs_rule = DetectionRule(
    name="SensitiveFileModification",
    description="Detects modifications to sensitive system files",
    severity="high",
    conditions={
        "file_paths": [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", 
            "/etc/ssh/sshd_config", "/boot/grub/grub.cfg"
        ],
        "operations": ["write", "delete", "chmod", "rename"]
    },
    actions=[
        {"type": "alert", "recipients": ["admin@example.com"]},
        {"type": "command", "command": "logger -t SECURITY_ALERT 'Sensitive file modification detected: {file_path}'"}
    ]
)

# Create a custom process execution rule
process_rule = DetectionRule(
    name="UnauthorizedPrivilegeEscalation",
    description="Detects attempts to escalate privileges via unauthorized means",
    severity="critical",
    conditions={
        "process_patterns": ["sudo", "su", "pkexec", "doas"],
        "parent_process_exclude": ["bash", "zsh", "ssh", "login"],
        "command_line_patterns": [".*passwd.*", ".*shadow.*", ".*sudoers.*"]
    },
    actions=[
        {"type": "alert", "recipients": ["security@example.com"]},
        {"type": "terminate_process"},
        {"type": "command", "command": "wall 'SECURITY ALERT: Unauthorized privilege escalation attempt detected'"}
    ]
)

# Initialize the rule engine and add the custom rules
rule_engine = RuleEngine()
rule_engine.add_rule(rule)
rule_engine.add_rule(fs_rule)
rule_engine.add_rule(process_rule)

# Load rules from a directory
rule_engine.load_rules_from_directory('/path/to/custom/rules')

# Apply the rules to a file
result = rule_engine.check_file('/etc/cron.d/new_job')
if result.matches:
    print(f"Rule '{result.rule_name}' matched: {result.description}")
    for action in result.actions:
        print(f"Executing action: {action.type}")
        action.execute(file_path=result.file_path)

# Monitor system with custom rules
from phantomguard import SystemMonitor

monitor = SystemMonitor(rule_engine=rule_engine)
monitor.start()
```

## Best Practices

### Performance Optimization

- **Selective Monitoring**: Only monitor the systems and resources that are necessary for your security requirements.
  
  ```python
  # Instead of monitoring everything
  monitor.start()
  
  # Be selective about what to monitor
  monitor.start(
      monitor_processes=True,
      monitor_files=False,  # Disable file monitoring if not needed
      monitor_network=True
  )
  ```

- **Batch Processing**: Process security events in batches rather than individually.
  
  ```python
  # Configure batch processing for alerts
  alert_manager = AlertManager(
      batch_size=50,         # Process 50 events at a time
      batch_interval=300,    # Process every 5 minutes
      deduplicate=True       # Remove duplicate alerts
  )
  ```

- **Resource-Conscious Scanning**: Adjust scan depth based on system resources.
  
  ```python
  # Check system resources before scanning
  import psutil
  
  # Adjust scan depth based on available resources
  if psutil.virtual_memory().available < 4 * 1024 * 1024 * 1024:  # Less than 4GB available
      scan_depth = 'light'
  else:
      scan_depth = 'deep'
      
  # Use the appropriate scan depth
  result = guard.analyze(scan_depth=scan_depth)
  ```

### Security Considerations

- **Secure Storage of Results**: Always encrypt sensitive security findings.
  
  ```python
  from phantomguard.utils.crypto import encrypt_file
  
  # Generate security report
  report_path = result.generate_report(format='json', output_file='security_findings.json')
  
  # Encrypt the report
  encrypt_file(
      report_path,
      'security_findings.json.enc',
      passphrase='strong-encryption-passphrase'
  )
  
  # Remove unencrypted version
  import os
  os.remove(report_path)
  ```

- **Least Privilege**: Run PhantomGuard with minimal required permissions.
  
  ```python
  # Drop privileges after initialization (when running as root)
  import os
  
  # Initialize with root privileges for features that require it
  guard = PhantomGuard()
  
  # Drop to a less privileged user for processing results
  if os.geteuid() == 0:  # If running as root
      # Create a function to drop privileges
      def drop_privileges(uid_name='nobody', gid_name='nogroup'):
          import pwd, grp
          # Get the uid/gid from the name
          running_uid = pwd.getpwnam(uid_name).pw_uid
          running_gid = grp.getgrnam(gid_name).gr_gid
          # Set the new uid/gid
          os.setgroups([])
          os.setgid(running_gid)
          os.setuid(running_uid)
          
      # Drop privileges before processing sensitive data
      drop_privileges()
  ```

- **Data Handling**: Handle security findings responsibly.
  
  ```python
  # Redact sensitive information from reports
  report = result.generate_report(
      format='html',
      redact_sensitive=True,
      redact_patterns=[
          r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
          r'password=\w+',                         # Passwords in URLs
          r'username=\w+',                         # Usernames in URLs
          r'[A-Za-z0-9+/]{88}={0,2}'               # Possible API keys/tokens
      ]
  )
  ```

### Integration Best Practices

- **Error Handling**: Implement robust error handling for security tools.
  
  ```python
  try:
      result = memory_analyzer.scan_process(1234)
  except PermissionError:
      print("Insufficient permissions to analyze process memory")
      # Log the error and continue with other analyses
  except Exception as e:
      print(f"Error during memory analysis: {str(e)}")
      # Log the error and proceed with a fallback approach
      result = memory_analyzer.scan_process_limited(1234)
  ```

- **Automated Remediation**: Implement careful automated remediation for certain issues.
  
  ```python
  # Auto-remediate only certain low-risk issues
  for issue in result.issues:
      if issue.auto_remediable and issue.risk_score < 3:
          try:
              remediation_result = issue.remediate(backup=True)
              print(f"Auto-remediated issue: {issue.title}")
              print(f"Remediation result: {remediation_result.status}")
          except Exception as e:
              print(f"Failed to remediate {issue.title}: {str(e)}")
  ```

- **Scheduled Scans**: Implement regular security scans as part of your security program.
  
  ```python
  from phantomguard import PhantomGuard, ScheduledScan
  
  # Create a scheduled scan configuration
  scheduled_scan = ScheduledScan(
      name="Daily Security Scan",
      description="Daily scan of critical systems",
      schedule="0 3 * * *",  # Run at 3:00 AM daily (cron syntax)
      scan_type="standard",
      notification_email="security@example.com",
      save_history=True
  )
  
  # Register the scheduled scan
  guard = PhantomGuard()
  guard.add_scheduled_scan(scheduled_scan)
  
  # Start the scheduler
  guard.start_scheduler()
  ```

---

For API reference and detailed information about specific classes and methods, please refer to the [API.md](API.md) document.

For performance optimization tips, please see [PERFOMANCE.md](PERFOMANCE.md).

If you encounter any issues, refer to [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for guidance.

