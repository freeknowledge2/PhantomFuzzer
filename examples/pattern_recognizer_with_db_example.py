#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example script demonstrating the integration of PatternRecognizer with PatternDatabase.

This script shows how to:
1. Initialize a PatternRecognizer with a PatternDatabase
2. Train the model with sample data
3. Use both ML-based predictions and pattern matching
4. Discover and store new patterns automatically
5. Export and import patterns for reuse
"""

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Tuple

# Add project root to path if needed
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import PhantomFuzzer ML components
from phantomfuzzer.ml import PatternRecognizer, PatternDatabase


def setup_argparse():
    """Set up command line argument parsing."""
    parser = argparse.ArgumentParser(
        description='PhantomFuzzer PatternRecognizer with PatternDatabase Example'
    )
    
    parser.add_argument('--train', action='store_true',
                        help='Train a new model')
    parser.add_argument('--train-dir', type=str, default='data/benign',
                        help='Directory with benign files for training')
    parser.add_argument('--analyze', action='store_true',
                        help='Analyze files for anomalies')
    parser.add_argument('--analyze-dir', type=str, default='data/test',
                        help='Directory with files to analyze')
    parser.add_argument('--model-path', type=str, default='models/pattern_recognizer.pkl',
                        help='Path to save/load the model')
    parser.add_argument('--pattern-db-path', type=str, default='data/patterns/patterns.json',
                        help='Path to the pattern database file')
    parser.add_argument('--import-patterns', type=str,
                        help='Import patterns from the specified file')
    parser.add_argument('--export-patterns', type=str,
                        help='Export patterns to the specified file')
    
    return parser.parse_args()


def initialize_components(args):
    """Initialize the PatternRecognizer and PatternDatabase components.
    
    Args:
        args: Command line arguments.
        
    Returns:
        Tuple of (PatternRecognizer, PatternDatabase).
    """
    # Create pattern database
    pattern_db = PatternDatabase(
        db_path=args.pattern_db_path,
        config={
            'auto_save': True,
            'similarity_threshold': 0.7
        }
    )
    
    # Import patterns if specified
    if args.import_patterns:
        print(f"Importing patterns from {args.import_patterns}")
        pattern_db.import_patterns(args.import_patterns)
    
    # Create pattern recognizer with the pattern database
    recognizer = PatternRecognizer(
        config={
            'n_estimators': 100,
            'contamination': 0.1,
            'pattern_match_threshold': 0.7,
            'pattern_weight': 0.3  # Weight for pattern matching vs ML model
        },
        pattern_db=pattern_db
    )
    
    # Load existing model if available and not training
    if not args.train and os.path.exists(args.model_path):
        print(f"Loading model from {args.model_path}")
        recognizer.load_model(args.model_path)
    
    return recognizer, pattern_db


def train_model(recognizer, args):
    """Train the PatternRecognizer model with sample data.
    
    Args:
        recognizer: PatternRecognizer instance.
        args: Command line arguments.
    """
    train_dir = Path(args.train_dir)
    if not train_dir.exists():
        print(f"Training directory {train_dir} does not exist")
        return
    
    # Get list of files for training
    file_paths = []
    for root, _, files in os.walk(train_dir):
        for file in files:
            file_paths.append(os.path.join(root, file))
    
    if not file_paths:
        print(f"No files found in {train_dir}")
        return
    
    print(f"Training model with {len(file_paths)} files from {train_dir}")
    recognizer.train(file_paths)
    
    # Save the trained model
    model_dir = os.path.dirname(args.model_path)
    if model_dir and not os.path.exists(model_dir):
        os.makedirs(model_dir)
    
    recognizer.save_model(args.model_path)
    print(f"Model saved to {args.model_path}")


def analyze_files(recognizer, args):
    """Analyze files for anomalies using both ML and pattern matching.
    
    Args:
        recognizer: PatternRecognizer instance.
        args: Command line arguments.
    """
    analyze_dir = Path(args.analyze_dir)
    if not analyze_dir.exists():
        print(f"Analysis directory {analyze_dir} does not exist")
        return
    
    # Get list of files to analyze
    file_paths = []
    for root, _, files in os.walk(analyze_dir):
        for file in files:
            file_paths.append(os.path.join(root, file))
    
    if not file_paths:
        print(f"No files found in {analyze_dir}")
        return
    
    print(f"Analyzing {len(file_paths)} files from {analyze_dir}")
    
    # Analyze each file
    for file_path in file_paths:
        is_anomaly, score, details = recognizer.predict(file_path)
        
        # Print results
        print(f"\nFile: {file_path}")
        print(f"  Is Anomaly: {is_anomaly}")
        print(f"  Anomaly Score: {score:.4f}")
        
        # Print ML model details if available
        if recognizer.model is not None:
            print(f"  ML Model Prediction: {'Anomaly' if details['ml_is_anomaly'] else 'Normal'}")
            print(f"  ML Score: {details['ml_score']:.4f}")
        
        # Print pattern matching details
        print(f"  Pattern Match: {'Yes' if details['pattern_is_match'] else 'No'}")
        if details['pattern_is_match']:
            print(f"  Pattern Confidence: {details['pattern_confidence']:.4f}")
            print(f"  Matched Pattern: {details['pattern_info']['pattern']}")
        
        # Print if a new pattern was discovered
        if 'discovered_pattern_id' in details:
            print(f"  New Pattern Discovered: {details['discovered_pattern_id']}")


def export_patterns(pattern_db, args):
    """Export patterns to a file.
    
    Args:
        pattern_db: PatternDatabase instance.
        args: Command line arguments.
    """
    if args.export_patterns:
        print(f"Exporting patterns to {args.export_patterns}")
        pattern_db.export_patterns(args.export_patterns)
        print(f"Exported {len(pattern_db.patterns)} patterns")


def main():
    """Main function."""
    args = setup_argparse()
    
    # Initialize components
    recognizer, pattern_db = initialize_components(args)
    
    # Train model if requested
    if args.train:
        train_model(recognizer, args)
    
    # Analyze files if requested
    if args.analyze:
        analyze_files(recognizer, args)
    
    # Export patterns if requested
    if args.export_patterns:
        export_patterns(pattern_db, args)
    
    # Print pattern database statistics
    print(f"\nPattern Database Statistics:")
    print(f"  Total Patterns: {len(pattern_db.patterns)}")
    print(f"  Database Path: {pattern_db.db_path}")


if __name__ == "__main__":
    main()
