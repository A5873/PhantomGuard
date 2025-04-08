#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhantomGuard - Advanced Security Analysis Tool

This tool provides comprehensive security scanning capabilities including:
- System security checks
- Rootkit detection
- Memory forensics
- Network traffic analysis
- Container security analysis

Usage:
    python -m phantomguard.main [options]
"""

import os
import sys
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Import analyzer modules
from phantomguard.advanced_analyzer.analyzer import (
    MemoryAnalyzer, NetworkAnalyzer, RootkitDetector, ContainerAnalyzer, 
    SecurityAnalyzer, AnalysisStatus
)
from phantomguard.utils.common import (
    Colors, print_banner, print_section, print_subsection,
    print_info, print_success, print_warning, print_error,
    get_system_info, is_root, require_root, setup_logging,
    ensure_temp_dir, cleanup_temp_dir
)


class PhantomGuard:
    """Main class for the PhantomGuard tool."""
    
    def __init__(
        self,
        output_dir: Optional[str] = None,
        report_format: str = "txt",
        scan_type: str = "standard",
        network_capture_time: int = 60,
        verbose: bool = False,
        keep_artifacts: bool = False
    ):
        """
        Initialize the PhantomGuard tool.
        
        Args:
            output_dir: Directory to save reports and artifacts
            report_format: Report format (txt, html, json)
            scan_type: Type of scan to perform (quick, standard, comprehensive)
            network_capture_time: Duration of network capture in seconds
            verbose: Enable verbose output
            keep_artifacts: Keep temporary artifacts after scanning
        """
        self.start_time = datetime.now()
        self.verbose = verbose
        self.keep_artifacts = keep_artifacts
        self.scan_type = scan_type
        self.network_capture_time = network_capture_time
        self.report_format = report_format.lower()
        
        # Set up output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path.home() / f"phantomguard_report_{timestamp}"
            
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_file = self.output_dir / f"security_report.{self.report_format}"
        
        # Set up logging
        log_level = logging.DEBUG if verbose else logging.INFO
        log_file = self.output_dir / "phantomguard.log"
        setup_logging(str(log_file), log_level)
        
        # Initialize results
        self.results = {
            "memory": None,
            "network": None,
            "rootkit": None,
            "container": None,
            "overall": AnalysisStatus.SUCCESS
        }
    
    def _initialize_report(self) -> None:
        """Initialize the security report."""
        system_info = get_system_info()
        
        if self.report_format == "txt":
            with open(self.report_file, "w") as f:
                f.write("# PhantomGuard Security Report\n\n")
                f.write(f"Generated: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## System Information\n\n")
                for key, value in system_info.items():
                    f.write(f"- {key}: {value}\n")
                
                f.write(f"\nScan Type: {self.scan_type.capitalize()}\n")
        
        elif self.report_format == "html":
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>PhantomGuard Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .success {{ color: green; }}
        .warning {{ color: orange; }}
        .error {{ color: red; }}
        .info {{ color: blue; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>PhantomGuard Security Report</h1>
    <p>Generated: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>System Information</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
"""
            
            for key, value in system_info.items():
                html_content += f"        <tr><td>{key}</td><td>{value}</td></tr>\n"
            
            html_content += f"""    </table>
    <p><strong>Scan Type:</strong> {self.scan_type.capitalize()}</p>
</body>
</html>
"""
            with open(self.report_file, "w") as f:
                f.write(html_content)
        
        elif self.report_format == "json":
            import json
            report_data = {
                "timestamp": self.start_time.isoformat(),
                "system_info": system_info,
                "scan_type": self.scan_type,
                "findings": []
            }
            
            with open(self.report_file, "w") as f:
                json.dump(report_data, f, indent=2)
    
    def _update_overall_status(self, status: AnalysisStatus) -> None:
        """
        Update the overall status based on a new status.
        
        Args:
            status: New status to consider
        """
        if status.value > self.results["overall"].value:
            self.results["overall"] = status
    
    def _run_memory_analysis(self) -> AnalysisStatus:
        """
        Run memory forensics analysis.
        
        Returns:
            AnalysisStatus: Analysis status
        """
        print_section("Memory Forensics Analysis")
        
        memory_analyzer = MemoryAnalyzer(
            report_file=str(self.report_file),
            debug=self.verbose
        )
        
        status = memory_analyzer.analyze()
        self.results["memory"] = status
        self._update_overall_status(status)
        
        return status
    
    def _run_network_analysis(self) -> AnalysisStatus:
        """
        Run network traffic analysis.
        
        Returns:
            AnalysisStatus: Analysis status
        """
        print_section("Network Traffic Analysis")
        
        network_analyzer = NetworkAnalyzer(
            report_file=str(self.report_file),
            debug=self.verbose,
            capture_time=self.network_capture_time
        )
        
        status = network_analyzer.analyze()
        self.results["network"] = status
        self._update_overall_status(status)
        
        return status
    
    def _run_rootkit_detection(self) -> AnalysisStatus:
        """
        Run rootkit detection analysis.
        
        Returns:
            AnalysisStatus: Analysis status
        """
        print_section("Rootkit Detection")
        
        rootkit_detector = RootkitDetector(
            report_file=str(self.report_file),
            debug=self.verbose
        )
        
        status = rootkit_detector.analyze()
        self.results["rootkit"] = status
        self._update_overall_status(status)
        
        return status
    
    def _run_container_analysis(self) -> AnalysisStatus:
        """
        Run container security analysis.
        
        Returns:
            AnalysisStatus: Analysis status
        """
        print_section("Container Security Analysis")
        
        container_analyzer = ContainerAnalyzer(
            report_file=str(self.report_file),
            debug=self.verbose
        )
        
        status = container_analyzer.analyze()
        self.results["container"] = status
        self._update_overall_status(status)
        
        return status
    
    def _finalize_report(self) -> None:
        """Finalize the security report."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        if self.report_format == "txt":
            with open(self.report_file, "a") as f:
                f.write("\n\n## Summary\n\n")
                
                statuses = {
                    "Memory Analysis": self.results["memory"],
                    "Network Analysis": self.results["network"],
                    "Rootkit Detection": self.results["rootkit"],
                    "Container Analysis": self.results["container"]
                }
                
                for module, status in statuses.items():
                    status_str = "Success" if status == AnalysisStatus.SUCCESS else \
                                "Warning" if status == AnalysisStatus.WARNING else \
                                "Error" if status == AnalysisStatus.ERROR else "Skipped"
                    
                    f.write(f"- {module}: {status_str}\n")
                
                f.write(f"\nOverall Status: {self.results['overall'].name}\n")
                f.write(f"Scan Duration: {duration:.2f} seconds\n")
                
                if self.results["overall"] == AnalysisStatus.ERROR:
                    f.write("\nCRITICAL SECURITY ISSUES DETECTED! Please review the findings immediately.\n")
                elif self.results["overall"] == AnalysisStatus.WARNING:
                    f.write("\nSecurity warnings detected. Please review the findings and address potential issues.\n")
                else:
                    f.write("\nNo significant security issues detected.\n")
        
        elif self.report_format == "html":
            summary_html = f"""
    <h2>Summary</h2>
    <table>
        <tr><th>Module</th><th>Status</th></tr>
        <tr><td>Memory Analysis</td><td class="{self.results['memory'].name.lower()}">{self.results['memory'].name}</td></tr>
        <tr><td>Network Analysis</td><td class="{self.results['network'].name.lower()}">{self.results['network'].name}</td></tr>
        <tr><td>Rootkit Detection</td><td class="{self.results['rootkit'].name.lower()}">{self.results['rootkit'].name}</td></tr>
        <tr><td>Container Analysis</td><td class="{self.results['container'].name.lower()}">{self.results['container'].name}</td></tr>
    </table>
    
    <p><strong>Overall Status:</strong> <span class="{self.results['overall'].name.lower()}">{self.results['overall'].name}</span></p>
    <p><strong>Scan Duration:</strong> {duration:.2f} seconds</p>
"""
            
            if self.results["overall"] == AnalysisStatus.ERROR:
                summary_html += '    <p class="error"><strong>CRITICAL SECURITY ISSUES DETECTED!</strong> Please review the findings immediately.</p>\n'
            elif self.results["overall"] == AnalysisStatus.WARNING:
                summary_html += '    <p class="warning"><strong>Security warnings detected.</strong> Please review the findings and address potential issues.</p>\n'
            else:
                summary_html += '    <p class="success"><strong>No significant security issues detected.</strong></p>\n'
            
            summary_html += "</body>\n</html>"
            
            with open(self.report_file, "r") as f:
                content = f.read()
            
            content = content.replace("</body>\n</html>", summary_html)
            
            with open(self.report_file, "w") as f:
                f.write(content)
        
        elif self.report_format == "json":
            import json
            
            with open(self.report_file, "r") as f:
                report_data = json.load(f)
            
            report_data["summary"] = {
                "memory_analysis": self.results["memory"].name,
                "network_analysis": self.results["network"].name,
                "rootkit_detection": self.results["rootkit"].name,
                "container_analysis": self.results["container"].name,
                "overall_status": self.results["overall"].name,
                "duration_seconds": duration
            }
            
            with open(self.report_file, "w") as f:
                json.dump(report_data, f, indent=2)
    
    def run(self) -> int:
        """
        Run the security analysis.
        
        Returns:
            int: Exit code (0 for success, non-zero for errors)
        """
        try:
            print_banner("PHANTOM GUARD")
            print_info(f"Starting {self.scan_type} security scan...")
            print_info(f"Output directory: {self.output_dir}")
            
            # Check for root privileges
            if not is_root():
                print_warning("Not running as root. Some checks may be limited.")
                print_info("For comprehensive results, consider running with sudo.")
            
            # Initialize report
            self._initialize_report()
            
            # Run analyses based on scan type
            if self.scan_type in ["quick", "standard", "comprehensive"]:
                self._run_rootkit_detection()
            
            if self.scan_type in ["standard", "comprehensive"]:
                self._run_network_analysis()
            
            if self.scan_type == "comprehensive":
                self._run_memory_analysis()
                self._run_container_analysis()
            
            # Finalize report
            self._finalize_report()
            
            if self.results["overall"] == AnalysisStatus.ERROR:
                print_error("CRITICAL SECURITY ISSUES DETECTED!")
                print_info(f"Please review the report at {self.report_file}")
                return 2
            elif self.results["overall"] == AnalysisStatus.WARNING:
                print_warning("Security warnings detected.")
                print_info(f"Please review the report at {self.report_file}")
                return 1
            else:
                print_success("No significant security issues detected.")
                print_info(f"Report saved to {self.report_file}")
                return 0
                
        except KeyboardInterrupt:
            print_error("\nScan interrupted by user.")
            return 130
        except Exception as e:
            print_error(f"Error during security scan: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            if not self.keep_artifacts:
                cleanup_temp_dir()


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="PhantomGuard - Advanced Security Analysis Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        help="Directory to save reports and artifacts",
        type=str,
        default=None
    )
    
    parser.add_argument(
        "-t", "--scan-type",
        help="Type of scan to perform",
        choices=["quick", "standard", "comprehensive"],
        default="standard"
    )
    
    parser.add_argument(
        "-f", "--format",
        help="Report format",
        choices=["txt", "html", "json"],
        default="txt"
    )
    
    parser.add_argument(
        "-n", "--network-time",
        help="Duration of network capture in seconds",
        type=int,
        default=60
    )
    
    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose output",
        action="store_true"
    )
    
    parser.add_argument(
        "-k", "--keep-artifacts",
        help="Keep temporary artifacts after scanning",
        action="store_true"
    )
    
    parser.add_argument(
        "--force-no-root",
        help="Force scan without root privileges (limited functionality)",
        action="store_true"
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point.
    
    Returns:
        int: Exit code
    """
    args = parse_args()
    
    # Check for root unless explicitly skipped
    if not args.force_no_root:
        require_root()
    
    # Run security scan
    scanner = PhantomGuard(
        output_dir=args.output_dir,
        report_format=args.format,
        scan_type=args.scan_type,
        network_capture_time=args.network_time,
        verbose=args.verbose,
        keep_artifacts=args.keep_artifacts
    )
    
    return scanner.run()


if __name__ == "__main__":
    sys.exit(main())

