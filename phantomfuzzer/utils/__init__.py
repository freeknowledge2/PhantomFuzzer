#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility modules for PhantomFuzzer.

This package provides various utility functions and classes used throughout
the PhantomFuzzer toolkit, including logging, output formatting, and helper functions.
"""

# Import and expose key functions from the logging module
from phantomfuzzer.utils.logging import (
    get_logger, get_module_logger, setup_logger,
    log_start_operation, log_end_operation, log_scan_result
)

# Import and expose key functions and classes from the helper module
from phantomfuzzer.utils.helper import (
    # Enums and constants
    VerbosityLevel, Colors,
    
    # Configuration functions
    set_verbosity, get_verbosity, set_use_colors,
    
    # Output formatting functions
    format_text, print_quiet, print_normal, print_verbose, print_debug,
    print_error, print_warning, print_success, print_info, print_status,
    print_result, print_json, print_banner, print_section, print_summary,
    print_progress
)