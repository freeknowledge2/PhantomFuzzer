"""
Scanner module for PhantomFuzzer.

This module provides various scanner implementations for different targets:
    base.py - Base scanner implementation and common utilities
    file_scanner.py - File scanner for detecting malware and vulnerabilities in files
    network.py - Network scanner for port scanning and service detection
    web.py - Web scanner for web application security testing
    api_scanner.py - API scanner for API security testing

Classes:
    BaseScanner - Base class for all scanners
    ScanResult - Class representing scan results
    FileScanner - Scanner for files and directories
    NetworkScanner - Scanner for network targets
    WebScanner - Scanner for web applications
    APIScanner - Scanner for API endpoints

Constants:
    STATUS_* - Scanner status constants
    SEVERITY_* - Vulnerability severity levels
"""

# Import scanner classes for direct import
from phantomfuzzer.scanner.base import (
    BaseScanner, 
    ScanResult,
    # Scanner status constants
    STATUS_IDLE,
    STATUS_RUNNING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_STOPPED,
    # Vulnerability severity levels
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO
)
from phantomfuzzer.scanner.file_scanner import FileScanner
from phantomfuzzer.scanner.network import NetworkScanner
from phantomfuzzer.scanner.web import WebScanner
from phantomfuzzer.scanner.api_scanner import APIScanner
from phantomfuzzer.scanner.ml_enhanced_scanner import MLEnhancedScanner

# Define exported symbols
__all__ = [
    # Scanner classes
    'BaseScanner',
    'ScanResult',
    'FileScanner',
    'NetworkScanner',
    'WebScanner',
    'APIScanner',
    'MLEnhancedScanner',
    # Scanner status constants
    'STATUS_IDLE',
    'STATUS_RUNNING',
    'STATUS_COMPLETED',
    'STATUS_FAILED',
    'STATUS_STOPPED',
    # Vulnerability severity levels
    'SEVERITY_CRITICAL',
    'SEVERITY_HIGH',
    'SEVERITY_MEDIUM',
    'SEVERITY_LOW',
    'SEVERITY_INFO'
]
