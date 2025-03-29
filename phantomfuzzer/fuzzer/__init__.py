#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fuzzer Module for PhantomFuzzer.

This module provides fuzzing capabilities for the PhantomFuzzer project,
including protocol fuzzing, input field fuzzing, and API fuzzing.
"""

# Import key components for easy access
from phantomfuzzer.fuzzer.fuzzer_base import BaseFuzzer
from phantomfuzzer.fuzzer.protocol_fuzzer import ProtocolFuzzer
from phantomfuzzer.fuzzer.input_fuzzer import InputFuzzer
from phantomfuzzer.fuzzer.api_fuzzer import ApiFuzzer
from phantomfuzzer.fuzzer.mutation_engine import MutationEngine

# Define what's available when using "from phantomfuzzer.fuzzer import *"
__all__ = [
    'BaseFuzzer',
    'ProtocolFuzzer',
    'InputFuzzer',
    'MutationEngine',
    'ApiFuzzer'
]
