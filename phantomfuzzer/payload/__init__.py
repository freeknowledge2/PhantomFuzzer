#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Payload Module for PhantomFuzzer.

This module provides payload generation capabilities for the PhantomFuzzer project,
including various attack vectors and payload types for security testing.
"""

# Import key components for easy access
from phantomfuzzer.payload.generator import PayloadGenerator

# Define what's available when using "from phantomfuzzer.payload import *"
__all__ = [
    'PayloadGenerator'
]
