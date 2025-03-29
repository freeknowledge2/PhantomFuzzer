#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example script demonstrating the use of ML capabilities in PhantomFuzzer.

This script shows how to:
1. Initialize the ML integration
2. Train a model with sample data
3. Use the model for anomaly detection
4. Collect feedback and improve the model
"""

import os
import sys
import argparse
from pathlib import Path

# Add project root to path if needed
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import PhantomFuzzer ML components
from phantomfuzzer.ml import MLIntegration


def setup_argparse():
    """Set up command line argument parsing."""
    parser = argparse.ArgumentParser(description='PhantomFuzzer ML Example')
    
    parser.add_argument('--train', action='store_true',
                        help='Train a new model')
    parser.add_argument('--benign-dir', type=str, default=None,
                        help='Directory containing benign files for training')
    parser.add_argument('--malicious-dir', type=str, default=None,
                        help='Directory containing malicious files for training')
    parser.add_argument('--model-name', type=str, default=None,
                        help='Name of the model to use or train')
    
    parser.add_argument('--analyze', action='store_true',
                        help='Analyze files for anomalies')
    parser.add_argument('--target-dir', type=str, default=None,
                        help='Directory containing files to analyze')
    parser.add_argument('--target-file', type=str, default=None,
                        help='Single file to analyze')
    
    parser.add_argument('--feedback', action='store_true',
                        help='Provide feedback on a prediction')
    parser.add_argument('--is-correct', action='store_true',
                        help='Whether the prediction was correct')
    parser.add_argument('--notes', type=str, default=None,
                        help='Notes about the feedback')
    
    parser.add_argument('--retrain', action='store_true',
                        help='Retrain model with feedback')
    
    parser.add_argument('--list-models', action='store_true',
                        help='List available models')
    
    return parser


def train_model(ml_integration, args):
    """Train a new model with sample data."""
    print("Training new model...")
    
    if not args.benign_dir:
        print("Error: --benign-dir is required for training")
        return
    
    benign_dir = Path(args.benign_dir)
    if not benign_dir.exists() or not benign_dir.is_dir():
        print(f"Error: Benign directory {benign_dir} does not exist or is not a directory")
        return
    
    malicious_dirs = None
    if args.malicious_dir:
        malicious_dir = Path(args.malicious_dir)
        if not malicious_dir.exists() or not malicious_dir.is_dir():
            print(f"Error: Malicious directory {malicious_dir} does not exist or is not a directory")
            return
        malicious_dirs = [str(malicious_dir)]
    
    model_name = ml_integration.train_model(
        benign_dirs=[str(benign_dir)],
        malicious_dirs=malicious_dirs,
        model_name=args.model_name
    )
    
    print(f"Model trained and saved as: {model_name}")
    
    # Set as default model
    ml_integration.set_default_model(model_name)
    print(f"Set {model_name} as the default model")


def analyze_files(ml_integration, args):
    """Analyze files for anomalies."""
    if args.target_file:
        # Analyze a single file
        file_path = Path(args.target_file)
        if not file_path.exists() or not file_path.is_file():
            print(f"Error: File {file_path} does not exist or is not a file")
            return
        
        print(f"Analyzing file: {file_path}")
        result = ml_integration.detect_file_anomalies(
            file_path=str(file_path),
            model_name=args.model_name
        )
        
        print("Analysis result:")
        print(f"  File: {result.get('file')}")
        print(f"  Is anomaly: {result.get('is_anomaly', False)}")
        print(f"  Anomaly score: {result.get('anomaly_score', 0):.4f}")
        print(f"  Threshold: {result.get('threshold', 0):.4f}")
        
        if 'error' in result:
            print(f"  Error: {result['error']}")
            
        return result
        
    elif args.target_dir:
        # Analyze a directory of files
        dir_path = Path(args.target_dir)
        if not dir_path.exists() or not dir_path.is_dir():
            print(f"Error: Directory {dir_path} does not exist or is not a directory")
            return
        
        print(f"Analyzing directory: {dir_path}")
        results = ml_integration.batch_analyze_directory(
            directory=str(dir_path),
            model_name=args.model_name,
            recursive=True
        )
        
        print("Analysis summary:")
        print(f"  Directory: {results.get('directory')}")
        print(f"  Files analyzed: {results.get('files_analyzed', 0)}")
        print(f"  Anomalies detected: {results.get('anomalies_detected', 0)}")
        print(f"  Errors: {results.get('errors', 0)}")
        print(f"  Average score: {results.get('average_score', 0):.4f}")
        print(f"  Model used: {results.get('model_used')}")
        
        # Print details of anomalies
        anomalies = [r for r in results.get('file_results', []) if r.get('is_anomaly', False)]
        if anomalies:
            print("\nAnomalies detected:")
            for anomaly in anomalies:
                print(f"  {anomaly.get('file')} (score: {anomaly.get('anomaly_score', 0):.4f})")
                
        return results
    else:
        print("Error: Either --target-file or --target-dir is required for analysis")
        return None


def provide_feedback(ml_integration, args, prediction=None):
    """Provide feedback on a prediction."""
    if not args.target_file:
        print("Error: --target-file is required for feedback")
        return
    
    file_path = Path(args.target_file)
    if not file_path.exists() or not file_path.is_file():
        print(f"Error: File {file_path} does not exist or is not a file")
        return
    
    # If no prediction was provided, perform analysis first
    if prediction is None:
        prediction = ml_integration.detect_file_anomalies(
            file_path=str(file_path),
            model_name=args.model_name
        )
    
    # Record feedback
    feedback = ml_integration.record_feedback(
        file_path=str(file_path),
        prediction=prediction,
        is_correct=args.is_correct,
        notes=args.notes
    )
    
    print("Feedback recorded:")
    print(f"  File: {feedback.get('file')}")
    print(f"  Is correct: {feedback.get('is_correct')}")
    print(f"  Feedback ID: {feedback.get('id')}")
    
    if args.notes:
        print(f"  Notes: {feedback.get('notes')}")


def retrain_with_feedback(ml_integration, args):
    """Retrain model with feedback."""
    print("Retraining model with feedback...")
    
    new_model_name = ml_integration.retrain_with_feedback(
        model_name=args.model_name,
        include_original_data=True
    )
    
    if new_model_name:
        print(f"Model retrained and saved as: {new_model_name}")
        
        # Set as default model
        ml_integration.set_default_model(new_model_name)
        print(f"Set {new_model_name} as the default model")
    else:
        print("Retraining failed. Check logs for details.")


def list_models(ml_integration):
    """List available models."""
    models = ml_integration.get_available_models()
    
    print("Available models:")
    for model in models:
        if model == ml_integration.default_model:
            print(f"  {model} (default)")
        else:
            print(f"  {model}")


def main():
    """Main function."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Initialize ML integration
    ml_integration = MLIntegration()
    print("ML integration initialized")
    
    # Process commands
    if args.list_models:
        list_models(ml_integration)
        
    if args.train:
        train_model(ml_integration, args)
        
    if args.analyze:
        prediction = analyze_files(ml_integration, args)
        
        # If feedback flag is set, also provide feedback
        if args.feedback and prediction:
            provide_feedback(ml_integration, args, prediction)
    elif args.feedback:
        provide_feedback(ml_integration, args)
        
    if args.retrain:
        retrain_with_feedback(ml_integration, args)


if __name__ == "__main__":
    main()
