#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the RustyAnalyzer class.
"""

import pytest

from rootkithunter.core import RustyAnalyzer


def test_rusty_analyzer_init():
    """Test initialization of RustyAnalyzer."""
    analyzer = RustyAnalyzer()
    assert isinstance(analyzer, RustyAnalyzer)
    assert analyzer.debug is False

    debug_analyzer = RustyAnalyzer(debug=True)
    assert debug_analyzer.debug is True


def test_scan_memory():
    """Test the scan_memory method returns expected structure."""
    analyzer = RustyAnalyzer()
    results = analyzer.scan_memory()

    assert isinstance(results, list)
    assert len(results) > 0

    # Check first result has expected structure
    first_result = results[0]
    assert "type" in first_result
    assert "process_id" in first_result
    assert "threat_level" in first_result
    assert "description" in first_result


def test_inspect_processes():
    """Test the inspect_processes method returns expected structure."""
    analyzer = RustyAnalyzer()
    results = analyzer.inspect_processes()

    assert isinstance(results, list)
    assert len(results) > 0

    # Check first result has expected structure
    first_result = results[0]
    assert "pid" in first_result
    assert "name" in first_result
    assert "threat_level" in first_result
    assert "anomalies" in first_result
    assert isinstance(first_result["anomalies"], list)


def test_monitor_network():
    """Test the monitor_network method returns expected structure."""
    analyzer = RustyAnalyzer()
    results = analyzer.monitor_network()

    assert isinstance(results, list)
    assert len(results) > 0

    # Check first result has expected structure
    first_result = results[0]
    assert "source_ip" in first_result
    assert "destination_ip" in first_result
    assert "destination_port" in first_result
    assert "protocol" in first_result
    assert "threat_level" in first_result


def test_analyze_syscalls():
    """Test the analyze_syscalls method returns expected structure."""
    analyzer = RustyAnalyzer()
    results = analyzer.analyze_syscalls()

    assert isinstance(results, list)
    assert len(results) > 0

    # Check first result has expected structure
    first_result = results[0]
    assert "syscall" in first_result
    assert "process_id" in first_result
    assert "process_name" in first_result
    assert "threat_level" in first_result


def test_full_analysis():
    """Test the full_analysis method returns expected structure."""
    analyzer = RustyAnalyzer()
    results = analyzer.full_analysis()

    assert isinstance(results, dict)
    assert "memory_threats" in results
    assert "suspicious_processes" in results
    assert "network_anomalies" in results
    assert "syscall_anomalies" in results

    assert isinstance(results["memory_threats"], list)
    assert isinstance(results["suspicious_processes"], list)
    assert isinstance(results["network_anomalies"], list)
    assert isinstance(results["syscall_anomalies"], list)
