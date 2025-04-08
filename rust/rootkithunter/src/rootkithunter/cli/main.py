#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command Line Interface for Rootkit Hunter.

This module provides a command-line interface for running security
analyses and generating reports.
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Union

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from rootkithunter.core import RustyAnalyzer

# Initialize Rich console for pretty output
console = Console()


def print_banner() -> None:
    """Print the Rootkit Hunter banner."""
    console.print(
        "\n[bold blue]╔═══════════════════════════════════════════════════════════╗[/]"
    )
    console.print(
        "[bold blue]║                   [bold white]ROOTKIT HUNTER[/]                     ║[/]"
    )
    console.print(
        "[bold blue]╚═══════════════════════════════════════════════════════════╝[/]\n"
    )


def format_results(results: List[Dict[str, Any]], category: str) -> Table:
    """
    Format analysis results as a Rich table.

    Args:
        results: List of result dictionaries
        category: Category of results (memory, process, etc.)

    Returns:
        Rich Table with formatted results
    """
    if not results:
        return None

    table = Table(title=f"{category.replace('_', ' ').title()} Analysis Results")

    # Common columns for all result types
    table.add_column("Threat Level", style="bold")
    table.add_column("Description")

    # Add columns based on the category
    if category == "memory_threats":
        table.add_column("Process", style="cyan")
        table.add_column("Address", style="magenta")
        table.add_column("Size")

        for result in results:
            table.add_row(
                result.get("threat_level", "unknown"),
                result.get("description", "No description"),
                f"{result.get('process_name', 'unknown')} ({result.get('process_id', 'unknown')})",
                result.get("address", "unknown"),
                str(result.get("size", "unknown")),
            )

    elif category == "suspicious_processes":
        table.add_column("PID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("User")
        table.add_column("Anomalies")

        for result in results:
            anomalies = ", ".join(result.get("anomalies", []))
            table.add_row(
                result.get("threat_level", "unknown"),
                result.get("description", "Suspicious process"),
                str(result.get("pid", "unknown")),
                result.get("name", "unknown"),
                result.get("user", "unknown"),
                anomalies,
            )

    elif category == "network_anomalies":
        table.add_column("Source", style="cyan")
        table.add_column("Destination", style="magenta")
        table.add_column("Protocol")
        table.add_column("Process")

        for result in results:
            source = result.get("source_ip", "unknown")
            dest = f"{result.get('destination_ip', 'unknown')}:{result.get('destination_port', 'unknown')}"
            protocol = result.get("protocol", "unknown")
            process = f"{result.get('process_name', 'unknown')} ({result.get('process_id', 'unknown')})"

            table.add_row(
                result.get("threat_level", "unknown"),
                result.get("description", "Suspicious connection"),
                source,
                dest,
                protocol,
                process,
            )

    elif category == "syscall_anomalies":
        table.add_column("Syscall", style="cyan")
        table.add_column("Process", style="green")
        table.add_column("Frequency")

        for result in results:
            process = f"{result.get('process_name', 'unknown')} ({result.get('process_id', 'unknown')})"

            table.add_row(
                result.get("threat_level", "unknown"),
                result.get("description", "Suspicious system call"),
                result.get("syscall", "unknown"),
                process,
                str(result.get("frequency", "unknown")),
            )

    else:
        # Generic table for other categories
        table.add_column("Details")

        for result in results:
            table.add_row(
                result.get("threat_level", "unknown"),
                result.get("description", "No description"),
                str(result),
            )

    return table


def save_report(
    results: Dict[str, List[Dict[str, Any]]], output_format: str, output_file: Path
) -> None:
    """
    Save analysis results to a file.

    Args:
        results: Analysis results
        output_format: Format to save (json, txt)
        output_file: Path to output file
    """
    # Create directory if it doesn't exist
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        # Save as JSON
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
    else:
        # Save as text
        with open(output_file, "w") as f:
            f.write("ROOTKIT HUNTER SECURITY REPORT\n")
            f.write("===============================\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Hostname: {os.uname().nodename}\n\n")

            for category, category_results in results.items():
                f.write(f"\n{category.replace('_', ' ').upper()}\n")
                f.write("=" * len(category.replace("_", " ").upper()) + "\n\n")

                if not category_results:
                    f.write("No issues found.\n")
                    continue

                for result in category_results:
                    f.write(f"Threat Level: {result.get('threat_level', 'unknown')}\n")
                    f.write(
                        f"Description: {result.get('description', 'No description')}\n"
                    )

                    # Write other details
                    for key, value in result.items():
                        if key not in ("threat_level", "description"):
                            f.write(f"{key.replace('_', ' ').title()}: {value}\n")

                    f.write("\n")

    console.print(f"[green]Report saved to [bold]{output_file}[/][/]")


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """
    Rootkit Hunter - Advanced Security Analysis Tool.

    This tool provides comprehensive security analysis capabilities,
    including rootkit detection, memory forensics, and system security checks.
    """
    print_banner()


@cli.command()
@click.option(
    "-o", "--output", type=click.Path(dir_okay=False), help="Output file for results"
)
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "txt"]),
    default="txt",
    help="Output format",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def syscalls(output, format, verbose):
    """
    Analyze system calls for suspicious patterns.

    This command monitors and analyzes system calls for suspicious patterns
    or behavior that could indicate a compromise.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold blue]Analyzing system calls...", total=100)

        # Simulate progress
        for i in range(100):
            time.sleep(0.02)
            progress.update(task, advance=1)

        # Initialize analyzer
        analyzer = RustyAnalyzer(debug=verbose)

        # Run analysis
        results = analyzer.analyze_syscalls()

    # Display results
    table = format_results(results, "syscall_anomalies")
    if table:
        console.print(table)
    else:
        console.print("[green]No suspicious system calls detected.[/]")

    # Save report if requested
    if output:
        output_path = Path(output)
        save_report({"syscall_anomalies": results}, format, output_path)


@cli.command()
@click.option(
    "-o", "--output", type=click.Path(dir_okay=False), help="Output file for results"
)
@click.option(
    "-f",
    "--format",
    type=click.Choice(["json", "txt"]),
    default="txt",
    help="Output format",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
def scan(output, format, verbose):
    """
    Perform a full security scan.

    This command runs all available security analyses:
    - Memory scanning
    - Process inspection
    - Network monitoring
    - System call analysis

    Results are consolidated into a comprehensive report.
    """
    console.print("[bold]Starting comprehensive security scan...[/]")

    # Initialize analyzer
    analyzer = RustyAnalyzer(debug=verbose)

    # Track results from all scans
    all_results = {}

    # Memory scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold blue]Scanning memory...", total=100)

        # Simulate progress
        for i in range(100):
            time.sleep(0.01)  # Faster for full scan
            progress.update(task, advance=1)

        # Run analysis
        memory_results = analyzer.scan_memory()
        all_results["memory_threats"] = memory_results

    # Process scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold blue]Inspecting processes...", total=100)

        # Simulate progress
        for i in range(100):
            time.sleep(0.01)  # Faster for full scan
            progress.update(task, advance=1)

        # Run analysis
        process_results = analyzer.inspect_processes()
        all_results["suspicious_processes"] = process_results

    # Network scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold blue]Monitoring network...", total=100)

        # Simulate progress
        for i in range(100):
            time.sleep(0.01)  # Faster for full scan
            progress.update(task, advance=1)

        # Run analysis
        network_results = analyzer.monitor_network()
        all_results["network_anomalies"] = network_results

    # Syscall scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[bold blue]Analyzing system calls...", total=100)

        # Simulate progress
        for i in range(100):
            time.sleep(0.01)  # Faster for full scan
            progress.update(task, advance=1)

        # Run analysis
        syscall_results = analyzer.analyze_syscalls()
        all_results["syscall_anomalies"] = syscall_results

    # Display summary results
    console.print("\n[bold]Security Scan Summary[/]")
    console.print("=" * 30)

    # Count issues by severity
    threat_levels = {"high": 0, "medium": 0, "low": 0}
    all_issues = []

    for category, results in all_results.items():
        category_name = category.replace("_", " ").title()

        # Count issues in this category
        if results:
            issue_count = len(results)
            console.print(f"{category_name}: [yellow]{issue_count} issues found[/]")

            # Count by severity
            for result in results:
                level = result.get("threat_level", "unknown").lower()
                if level in threat_levels:
                    threat_levels[level] += 1

                # Add to all issues list for display
                all_issues.append((category, result))
        else:
            console.print(f"{category_name}: [green]No issues found[/]")

    # Print threat summary
    console.print("\n[bold]Threat Level Summary[/]")
    console.print(f"High: [red]{threat_levels['high']}[/]")
    console.print(f"Medium: [yellow]{threat_levels['medium']}[/]")
    console.print(f"Low: [green]{threat_levels['low']}[/]")

    # Display high priority issues
    if threat_levels["high"] > 0:
        console.print("\n[bold red]High Priority Issues[/]")
        for category, issue in all_issues:
            if issue.get("threat_level", "").lower() == "high":
                console.print(f"[red]- {issue.get('description', 'Unknown issue')}[/]")

    # Save report if requested
    if output:
        output_path = Path(output)
        save_report(all_results, format, output_path)
        console.print(
            f"\n[green]Comprehensive report saved to [bold]{output_path}[/][/]"
        )

    # Final message
    if sum(threat_levels.values()) > 0:
        console.print(
            "\n[yellow]Security issues were detected. Please review the report for details.[/]"
        )
    else:
        console.print("\n[green]No security issues were detected.[/]")


def main():
    """Entry point for the CLI."""
    try:
        # Check if running as root
        if os.geteuid() != 0:
            console.print(
                "[bold red]Warning: Some security checks require root privileges.[/]"
            )
            console.print(
                "[yellow]Consider running with sudo for comprehensive results.[/]\n"
            )

        # Run the CLI
        cli()
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/]")
        if "--debug" in sys.argv:
            import traceback

            console.print("[bold red]Traceback:[/]")
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
