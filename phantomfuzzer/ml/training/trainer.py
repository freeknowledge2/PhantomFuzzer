#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Model Trainer for Machine Learning Models.

This module provides utilities for training and evaluating
machine learning models in PhantomFuzzer.
"""

import os
import time
import json
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any, Callable

# Local imports
from phantomfuzzer.utils.logging import get_logger
from phantomfuzzer.ml.training.data_loader import DataLoader
from phantomfuzzer.ml.models.pattern_recognizer import PatternRecognizer


class ModelTrainer:
    """Trainer for machine learning models.
    
    This class handles the training and evaluation of machine learning models,
    particularly for anomaly detection in PhantomFuzzer.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the model trainer.
        
        Args:
            config: Configuration parameters for training.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.model_dir = self.config.get('model_dir', 'models')
        self.results_dir = self.config.get('results_dir', 'results')
        
        # Create directories if they don't exist
        Path(self.model_dir).mkdir(parents=True, exist_ok=True)
        Path(self.results_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize data loader
        data_loader_config = self.config.get('data_loader', {})
        self.data_loader = DataLoader(data_loader_config)
    
    def train_model(self, model: Any, dataset: List[Dict[str, Any]]) -> None:
        """Train a model with the provided dataset.
        
        Args:
            model: The model to train (must have a train method).
            dataset: The dataset to train on, containing file paths and labels.
        """
        self.logger.info(f"Training model with {len(dataset)} samples")
        
        # Extract file paths from dataset
        file_paths = [item['file_path'] for item in dataset if 'file_path' in item]
        
        if not file_paths:
            self.logger.error("No valid file paths found in dataset")
            raise ValueError("No valid file paths found in dataset")
            
        # Train the model
        model.train(file_paths)
        self.logger.info("Model training completed")
    
    def train_pattern_recognizer(self, 
                                benign_dirs: List[Union[str, Path]],
                                model_name: str = 'pattern_recognizer',
                                model_config: Optional[Dict[str, Any]] = None) -> PatternRecognizer:
        """Train a pattern recognizer model for anomaly detection.
        
        Args:
            benign_dirs: List of directories containing benign files for training.
            model_name: Name to use for the saved model.
            model_config: Configuration for the pattern recognizer model.
            
        Returns:
            The trained PatternRecognizer model.
        """
        self.logger.info(f"Training pattern recognizer model '{model_name}'")
        
        # Load benign files for training
        benign_files, _ = self.data_loader.load_dataset(benign_dirs)
        
        if not benign_files:
            self.logger.error("No benign files found for training")
            raise ValueError("No benign files found for training")
            
        # Split dataset into train and validation sets
        train_files, val_files, _ = self.data_loader.split_dataset(
            benign_files, train_ratio=0.8, val_ratio=0.2, test_ratio=0.0
        )
        
        # Initialize model
        model = PatternRecognizer(model_config)
        
        # Train model
        start_time = time.time()
        model.train(train_files)
        training_time = time.time() - start_time
        
        # Evaluate model on validation set
        val_results = self._evaluate_anomaly_detection(model, val_files, [])
        
        # Save model
        model_path = Path(self.model_dir) / f"{model_name}.pkl"
        model.save_model(model_path)
        
        # Save training results
        results = {
            'model_name': model_name,
            'training_time': training_time,
            'num_train_files': len(train_files),
            'num_val_files': len(val_files),
            'validation_results': val_results
        }
        
        results_path = Path(self.results_dir) / f"{model_name}_results.json"
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        self.logger.info(f"Model trained and saved to {model_path}")
        self.logger.info(f"Training results saved to {results_path}")
        
        return model
    
    def train_with_malicious_samples(self,
                                    benign_dirs: List[Union[str, Path]],
                                    malicious_dirs: List[Union[str, Path]],
                                    model_name: str = 'pattern_recognizer_with_malicious',
                                    model_config: Optional[Dict[str, Any]] = None) -> PatternRecognizer:
        """Train a pattern recognizer with both benign and malicious samples.
        
        Args:
            benign_dirs: List of directories containing benign files.
            malicious_dirs: List of directories containing malicious files.
            model_name: Name to use for the saved model.
            model_config: Configuration for the pattern recognizer model.
            
        Returns:
            The trained PatternRecognizer model.
        """
        self.logger.info(f"Training pattern recognizer with malicious samples '{model_name}'")
        
        # Load dataset
        benign_files, malicious_files = self.data_loader.load_dataset(benign_dirs, malicious_dirs)
        
        if not benign_files or not malicious_files:
            self.logger.error("Insufficient data for training")
            raise ValueError("Insufficient data for training")
            
        # Balance dataset
        balanced_benign, balanced_malicious = self.data_loader.balance_dataset(
            benign_files, malicious_files
        )
        
        # Split datasets
        train_benign, val_benign, _ = self.data_loader.split_dataset(
            balanced_benign, train_ratio=0.8, val_ratio=0.2, test_ratio=0.0
        )
        
        train_malicious, val_malicious, _ = self.data_loader.split_dataset(
            balanced_malicious, train_ratio=0.8, val_ratio=0.2, test_ratio=0.0
        )
        
        # Configure model for semi-supervised learning
        if model_config is None:
            model_config = {}
            
        # Adjust contamination based on dataset balance
        total_train = len(train_benign) + len(train_malicious)
        contamination = len(train_malicious) / total_train if total_train > 0 else 0.1
        model_config['contamination'] = contamination
        
        # Initialize model
        model = PatternRecognizer(model_config)
        
        # Train model on benign samples only
        # (Isolation Forest learns normal patterns from benign files)
        start_time = time.time()
        model.train(train_benign)
        training_time = time.time() - start_time
        
        # Evaluate model
        val_results = self._evaluate_anomaly_detection(model, val_benign, val_malicious)
        
        # Save model
        model_path = Path(self.model_dir) / f"{model_name}.pkl"
        model.save_model(model_path)
        
        # Save training results
        results = {
            'model_name': model_name,
            'training_time': training_time,
            'num_train_benign': len(train_benign),
            'num_train_malicious': len(train_malicious),
            'num_val_benign': len(val_benign),
            'num_val_malicious': len(val_malicious),
            'contamination': contamination,
            'validation_results': val_results
        }
        
        results_path = Path(self.results_dir) / f"{model_name}_results.json"
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        self.logger.info(f"Model trained and saved to {model_path}")
        self.logger.info(f"Training results saved to {results_path}")
        
        return model
    
    def _evaluate_anomaly_detection(self,
                                   model: PatternRecognizer,
                                   benign_files: List[str],
                                   malicious_files: List[str]) -> Dict[str, Any]:
        """Evaluate an anomaly detection model.
        
        Args:
            model: The PatternRecognizer model to evaluate.
            benign_files: List of benign file paths for evaluation.
            malicious_files: List of malicious file paths for evaluation.
            
        Returns:
            Dictionary of evaluation results.
        """
        results = {
            'benign_files': len(benign_files),
            'malicious_files': len(malicious_files),
            'benign_predictions': [],
            'malicious_predictions': [],
            'metrics': {}
        }
        
        # Evaluate on benign files
        true_negatives = 0
        benign_scores = []
        
        for file_path in benign_files:
            is_anomaly, score = model.predict(file_path)
            benign_scores.append(score)
            results['benign_predictions'].append({
                'file': file_path,
                'is_anomaly': is_anomaly,
                'score': score
            })
            
            if not is_anomaly:  # Correctly identified as benign
                true_negatives += 1
        
        # Evaluate on malicious files
        true_positives = 0
        malicious_scores = []
        
        for file_path in malicious_files:
            is_anomaly, score = model.predict(file_path)
            malicious_scores.append(score)
            results['malicious_predictions'].append({
                'file': file_path,
                'is_anomaly': is_anomaly,
                'score': score
            })
            
            if is_anomaly:  # Correctly identified as malicious
                true_positives += 1
        
        # Calculate metrics
        if benign_files:
            specificity = true_negatives / len(benign_files)
            results['metrics']['specificity'] = specificity
            
        if malicious_files:
            sensitivity = true_positives / len(malicious_files)
            results['metrics']['sensitivity'] = sensitivity
            
        if benign_files and malicious_files:
            accuracy = (true_positives + true_negatives) / (len(benign_files) + len(malicious_files))
            results['metrics']['accuracy'] = accuracy
            
        # Calculate average scores
        if benign_scores:
            results['metrics']['avg_benign_score'] = sum(benign_scores) / len(benign_scores)
            
        if malicious_scores:
            results['metrics']['avg_malicious_score'] = sum(malicious_scores) / len(malicious_scores)
            
        return results
    
    def load_model(self, model_name: str) -> PatternRecognizer:
        """Load a trained model from disk.
        
        Args:
            model_name: Name of the model to load.
            
        Returns:
            The loaded PatternRecognizer model.
        """
        model_path = Path(self.model_dir) / f"{model_name}.pkl"
        
        if not model_path.exists():
            self.logger.error(f"Model {model_name} not found at {model_path}")
            raise FileNotFoundError(f"Model {model_name} not found")
            
        model = PatternRecognizer()
        success = model.load_model(model_path)
        
        if not success:
            self.logger.error(f"Failed to load model {model_name}")
            raise RuntimeError(f"Failed to load model {model_name}")
            
        self.logger.info(f"Loaded model {model_name} from {model_path}")
        return model
