#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Machine Learning Module for PhantomFuzzer.

This module provides machine learning capabilities for the PhantomFuzzer project,
including anomaly detection, pattern recognition, and model training utilities.
"""

# Import key components for easy access
from phantomfuzzer.ml.integration import MLIntegration
from phantomfuzzer.ml.models.pattern_recognizer import PatternRecognizer
from phantomfuzzer.ml.training.data_loader import DataLoader
from phantomfuzzer.ml.training.trainer import ModelTrainer
from phantomfuzzer.ml.inference import InferenceEngine
from phantomfuzzer.ml.feedback import FeedbackLoop
from phantomfuzzer.ml.storage.pattern_db import PatternDatabase

# Define what's available when using "from phantomfuzzer.ml import *"
__all__ = [
    'MLIntegration',
    'PatternRecognizer',
    'DataLoader',
    'ModelTrainer',
    'InferenceEngine',
    'FeedbackLoop',
    'PatternDatabase'
]
