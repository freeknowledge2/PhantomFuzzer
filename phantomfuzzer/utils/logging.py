#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom logging setup for PhantomFuzzer.

This module provides a customized logging setup with colored output,
configurable log levels, and file output capabilities.
"""

import os
import sys
import logging
import datetime
from typing import Optional, Dict, Any, Union
from pathlib import Path

# Try to import colorama for cross-platform colored terminal output
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Define dummy color constants if colorama is not available
    class DummyColor:
        def __getattr__(self, name):
            return ''
    Fore = DummyColor()
    Back = DummyColor()
    Style = DummyColor()

# Log level mapping
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Default log format
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Colored log format
COLORED_LOG_FORMAT = {
    'DEBUG': f'{Fore.CYAN}%(asctime)s - %(name)s - %(levelname)s - %(message)s{Style.RESET_ALL}',
    'INFO': f'{Fore.GREEN}%(asctime)s - %(name)s - %(levelname)s - %(message)s{Style.RESET_ALL}',
    'WARNING': f'{Fore.YELLOW}%(asctime)s - %(name)s - %(levelname)s - %(message)s{Style.RESET_ALL}',
    'ERROR': f'{Fore.RED}%(asctime)s - %(name)s - %(levelname)s - %(message)s{Style.RESET_ALL}',
    'CRITICAL': f'{Back.RED}{Fore.WHITE}%(asctime)s - %(name)s - %(levelname)s - %(message)s{Style.RESET_ALL}'
}

class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored log output."""
    
    def format(self, record):
        log_format = COLORED_LOG_FORMAT.get(record.levelname, DEFAULT_LOG_FORMAT) if COLORS_AVAILABLE else DEFAULT_LOG_FORMAT
        formatter = logging.Formatter(log_format)
        return formatter.format(record)

def get_logger(name: str, log_level: str = 'INFO', log_file: Optional[str] = None, use_colors: bool = True) -> logging.Logger:
    """Get a configured logger instance.
    
    Args:
        name: The name of the logger.
        log_level: The log level to use. Must be one of 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'.
        log_file: Optional path to a log file. If provided, logs will be written to this file.
        use_colors: Whether to use colored output. Only applicable to console output.
    
    Returns:
        A configured logger instance.
    """
    # Convert log level string to logging constant
    level = LOG_LEVELS.get(log_level.upper(), logging.INFO)
    
    # Get or create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:  # Make a copy of the list
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Set formatter based on color preference
    if use_colors and COLORS_AVAILABLE:
        console_formatter = ColoredFormatter()
    else:
        console_formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Add file handler if log_file is provided
    if log_file:
        # Ensure the directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def setup_logging(config: Dict[str, Any] = None) -> logging.Logger:
    """Set up logging based on configuration.
    
    Args:
        config: Configuration dictionary. If None, default values will be used.
    
    Returns:
        The root logger instance.
    """
    if config is None:
        config = {}
    
    # Get configuration values with defaults
    log_level = config.get('log_level', 'INFO')
    log_file = config.get('log_file', None)
    use_colors = config.get('use_colors', True)
    
    # Set up the root logger
    root_logger = get_logger('phantomfuzzer', log_level, log_file, use_colors)
    
    # Configure the logging module's root logger
    logging.root = root_logger
    
    return root_logger

def get_module_logger(module_name: str) -> logging.Logger:
    """Get a logger for a specific module.
    
    This is a convenience function for getting a logger with the module's name.
    The logger will inherit settings from the root logger.
    
    Args:
        module_name: The name of the module.
    
    Returns:
        A logger instance for the module.
    """
    return logging.getLogger(f'phantomfuzzer.{module_name}')

# Helper functions for common log messages

def log_start_operation(logger: logging.Logger, operation: str) -> None:
    """Log the start of an operation.
    
    Args:
        logger: The logger to use.
        operation: The name of the operation.
    """
    logger.info(f"Starting operation: {operation}")

def log_end_operation(logger: logging.Logger, operation: str, success: bool = True) -> None:
    """Log the end of an operation.
    
    Args:
        logger: The logger to use.
        operation: The name of the operation.
        success: Whether the operation was successful.
    """
    if success:
        logger.info(f"Operation completed successfully: {operation}")
    else:
        logger.error(f"Operation failed: {operation}")

def log_scan_result(logger: logging.Logger, target: str, vulnerabilities: int) -> None:
    """Log the result of a scan.
    
    Args:
        logger: The logger to use.
        target: The target of the scan.
        vulnerabilities: The number of vulnerabilities found.
    """
    if vulnerabilities > 0:
        logger.warning(f"Scan of {target} found {vulnerabilities} vulnerabilities")
    else:
        logger.info(f"Scan of {target} completed with no vulnerabilities found")

# Initialize a default logger
default_logger = get_logger('phantomfuzzer')

def setup_logger(name: str, log_level: str = 'INFO', log_file: Optional[str] = None, use_colors: bool = True) -> logging.Logger:
    """
    Set up a logger with a specific name and configuration.
    
    This is a convenience function for setting up a logger with common settings.
    
    Args:
        name: The name of the logger.
        log_level: The log level to use. Must be one of 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'.
        log_file: Optional path to a log file. If provided, logs will be written to this file.
        use_colors: Whether to use colored output. Only applicable to console output.
        
    Returns:
        A configured logger instance.
    """
    return get_logger(name, log_level, log_file, use_colors)