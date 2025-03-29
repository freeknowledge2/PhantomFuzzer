#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PhantomFuzzer - Advanced Security Testing Framework

PhantomFuzzer is a comprehensive security testing framework designed for
identifying vulnerabilities in web applications, APIs, networks, and files.
It provides various scanning and fuzzing capabilities with customizable
output control options.

Modules:
    scanner - Various scanner implementations for different targets
    fuzzer - Fuzzing engines for different protocols and inputs
    utils - Utility functions for logging, output formatting, and more
    payloads - Collection of payloads for various attack vectors
    config - Configuration management
    cli - Command-line interface
"""

__version__ = '1.0.0'
__author__ = 'PhantomFuzzer Team'
__email__ = 'info@phantomfuzzer.io'
__license__ = 'MIT'

# Import key modules for easy access
from phantomfuzzer.scanner import (
    BaseScanner, ScanResult,
    FileScanner, NetworkScanner, WebScanner, APIScanner, MLEnhancedScanner,
    # Scanner status constants
    STATUS_IDLE, STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED, STATUS_STOPPED,
    # Vulnerability severity levels
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
)

from phantomfuzzer.utils import (
    # Logging functions
    get_logger, get_module_logger, setup_logger,
    
    # Output control
    VerbosityLevel, Colors, set_verbosity, get_verbosity, set_use_colors,
    
    # Output formatting
    print_error, print_warning, print_success, print_info,
    print_section, print_summary
)

# Define exported symbols
__all__ = [
    # Scanner classes
    'BaseScanner', 'ScanResult',
    'FileScanner', 'NetworkScanner', 'WebScanner', 'APIScanner', 'MLEnhancedScanner',
    
    # Scanner status constants
    'STATUS_IDLE', 'STATUS_RUNNING', 'STATUS_COMPLETED', 'STATUS_FAILED', 'STATUS_STOPPED',
    
    # Vulnerability severity levels
    'SEVERITY_CRITICAL', 'SEVERITY_HIGH', 'SEVERITY_MEDIUM', 'SEVERITY_LOW', 'SEVERITY_INFO',
    
    # Logging functions
    'get_logger', 'get_module_logger', 'setup_logger',
    
    # Output control
    'VerbosityLevel', 'Colors', 'set_verbosity', 'get_verbosity', 'set_use_colors',
    
    # Output formatting
    'print_error', 'print_warning', 'print_success', 'print_info',
    'print_section', 'print_summary'
]