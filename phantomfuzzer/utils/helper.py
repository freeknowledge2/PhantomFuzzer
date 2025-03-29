#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper utilities for PhantomFuzzer.

This module provides utility functions for the PhantomFuzzer toolkit,
including output formatting, progress tracking, and result summarization.
"""

import sys
import os
import json
from typing import Dict, List, Any, Optional, Union
from enum import Enum

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

class VerbosityLevel(Enum):
    """Verbosity levels for output control."""
    QUIET = 0    # Only show critical errors and final results
    NORMAL = 1   # Show standard information and warnings
    VERBOSE = 2  # Show detailed information about operations
    DEBUG = 3    # Show all debug information

# Global verbosity setting (default: NORMAL)
VERBOSITY = VerbosityLevel.NORMAL
USE_COLORS = True

def set_verbosity(level: Union[VerbosityLevel, int, str]) -> None:
    """Set the global verbosity level.
    
    Args:
        level: The verbosity level to set. Can be a VerbosityLevel enum,
            an integer (0-3), or a string ('quiet', 'normal', 'verbose', 'debug').
    """
    global VERBOSITY
    
    if isinstance(level, VerbosityLevel):
        VERBOSITY = level
    elif isinstance(level, int):
        if 0 <= level <= 3:
            VERBOSITY = VerbosityLevel(level)
        else:
            raise ValueError(f"Invalid verbosity level: {level}. Must be between 0 and 3.")
    elif isinstance(level, str):
        level_map = {
            'quiet': VerbosityLevel.QUIET,
            'normal': VerbosityLevel.NORMAL,
            'verbose': VerbosityLevel.VERBOSE,
            'debug': VerbosityLevel.DEBUG
        }
        if level.lower() in level_map:
            VERBOSITY = level_map[level.lower()]
        else:
            raise ValueError(f"Invalid verbosity level: {level}. Must be one of: quiet, normal, verbose, debug.")
    else:
        raise TypeError(f"Invalid type for verbosity level: {type(level)}. Must be VerbosityLevel, int, or str.")

def set_use_colors(use_colors: bool) -> None:
    """Set whether to use colors in terminal output.
    
    Args:
        use_colors: Whether to use colors in terminal output.
    """
    global USE_COLORS
    USE_COLORS = use_colors

def get_verbosity() -> VerbosityLevel:
    """Get the current verbosity level.
    
    Returns:
        The current verbosity level.
    """
    return VERBOSITY

def format_text(text: str, color: Optional[str] = None, bold: bool = False) -> str:
    """Format text with color and style.
    
    Args:
        text: The text to format.
        color: The color to use. Must be a color attribute from the Colors class.
        bold: Whether to make the text bold.
    
    Returns:
        The formatted text.
    """
    if not USE_COLORS:
        return text
    
    formatted = ""
    if bold:
        formatted += Colors.BOLD
    if color:
        formatted += color
    
    formatted += text + Colors.RESET
    return formatted

def print_quiet(message: str, color: Optional[str] = None, bold: bool = False, **kwargs) -> None:
    """Print a message only if verbosity is at least QUIET.
    
    Args:
        message: The message to print.
        color: Optional color to use.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.QUIET.value:
        print(format_text(message, color, bold), **kwargs)

def print_normal(message: str, color: Optional[str] = None, bold: bool = False, **kwargs) -> None:
    """Print a message only if verbosity is at least NORMAL.
    
    Args:
        message: The message to print.
        color: Optional color to use.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        print(format_text(message, color, bold), **kwargs)

def print_verbose(message: str, color: Optional[str] = None, bold: bool = False, **kwargs) -> None:
    """Print a message only if verbosity is at least VERBOSE.
    
    Args:
        message: The message to print.
        color: Optional color to use.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.VERBOSE.value:
        print(format_text(message, color, bold), **kwargs)

def print_debug(message: str, color: Optional[str] = None, bold: bool = False, **kwargs) -> None:
    """Print a message only if verbosity is at least DEBUG.
    
    Args:
        message: The message to print.
        color: Optional color to use.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.DEBUG.value:
        print(format_text(message, color, bold), **kwargs)

def print_error(message: str, bold: bool = True, **kwargs) -> None:
    """Print an error message.
    
    Args:
        message: The error message to print.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    print(format_text(f"ERROR: {message}", Colors.RED, bold), file=sys.stderr, **kwargs)

def print_warning(message: str, bold: bool = False, **kwargs) -> None:
    """Print a warning message.
    
    Args:
        message: The warning message to print.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        print(format_text(f"WARNING: {message}", Colors.YELLOW, bold), file=sys.stderr, **kwargs)

def print_success(message: str, bold: bool = False, **kwargs) -> None:
    """Print a success message.
    
    Args:
        message: The success message to print.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.QUIET.value:
        print(format_text(message, Colors.GREEN, bold), **kwargs)

def print_info(message: str, bold: bool = False, **kwargs) -> None:
    """Print an informational message.
    
    Args:
        message: The informational message to print.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        print(format_text(message, Colors.BLUE, bold), **kwargs)

def print_status(message: str, bold: bool = False, **kwargs) -> None:
    """Print a status message.
    
    Args:
        message: The status message to print.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        print(format_text(message, Colors.CYAN, bold), **kwargs)

def print_result(message: str, bold: bool = True, **kwargs) -> None:
    """Print a result message.
    
    Args:
        message: The result message to print.
        bold: Whether to make the text bold.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.QUIET.value:
        print(format_text(message, Colors.MAGENTA, bold), **kwargs)

def print_json(data: Any, pretty: bool = True, **kwargs) -> None:
    """Print data as JSON.
    
    Args:
        data: The data to print as JSON.
        pretty: Whether to format the JSON with indentation.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        indent = 2 if pretty else None
        print(json.dumps(data, indent=indent), **kwargs)

def print_banner(banner: str, **kwargs) -> None:
    """Print a banner.
    
    Args:
        banner: The banner to print.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.QUIET.value:
        print(format_text(banner, Colors.BRIGHT_CYAN), **kwargs)

def print_section(title: str, **kwargs) -> None:
    """Print a section title.
    
    Args:
        title: The section title to print.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        print(format_text(f"\n=== {title} ===", Colors.BRIGHT_WHITE, True), **kwargs)

def print_summary(title: str, items: List[str], **kwargs) -> None:
    """Print a summary of items.
    
    Args:
        title: The summary title.
        items: The items to include in the summary.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.QUIET.value:
        print(format_text(f"\n{title}:", Colors.BRIGHT_WHITE, True), **kwargs)
        for i, item in enumerate(items, 1):
            print(format_text(f"  {i}. {item}", Colors.WHITE), **kwargs)
        print("", **kwargs)

def print_progress(current: int, total: int, prefix: str = "", suffix: str = "", bar_length: int = 50, **kwargs) -> None:
    """Print a progress bar.
    
    Args:
        current: The current progress value.
        total: The total progress value.
        prefix: Text to display before the progress bar.
        suffix: Text to display after the progress bar.
        bar_length: The length of the progress bar in characters.
        **kwargs: Additional arguments to pass to print().
    """
    if VERBOSITY.value >= VerbosityLevel.NORMAL.value:
        percent = float(current) / total
        filled_length = int(bar_length * percent)
        bar = "█" * filled_length + "-" * (bar_length - filled_length)
        progress_str = f"{prefix} |{bar}| {current}/{total} {suffix}"
        print(format_text(progress_str, Colors.CYAN), end="\r", **kwargs)
        if current >= total:
            print()
