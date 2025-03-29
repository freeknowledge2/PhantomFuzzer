#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Inference Engine for Machine Learning Models.

This module provides utilities for making predictions with
trained machine learning models in PhantomFuzzer.
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any

# Local imports
from phantomfuzzer.utils.logging import get_logger
from phantomfuzzer.ml.models.pattern_recognizer import PatternRecognizer


class InferenceEngine:
    """Inference engine for machine learning models.
    
    This class handles loading trained models and making predictions
    on new data for anomaly detection and other ML tasks.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the inference engine.
        
        Args:
            config: Configuration parameters for inference.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.model_dir = self.config.get('model_dir', 'models')
        self.threshold = self.config.get('anomaly_threshold', 0.7)  # Threshold for anomaly detection
        
        # Loaded models cache
        self.models: Dict[str, Any] = {}
    
    def load_pattern_recognizer(self, model_name: str) -> PatternRecognizer:
        """Load a pattern recognizer model.
        
        Args:
            model_name: Name of the model to load.
            
        Returns:
            The loaded PatternRecognizer model.
        """
        # Check if model is already loaded
        if model_name in self.models:
            return self.models[model_name]
            
        # Construct model path
        model_path = Path(self.model_dir) / f"{model_name}.pkl"
        
        if not model_path.exists():
            self.logger.error(f"Model {model_name} not found at {model_path}")
            raise FileNotFoundError(f"Model {model_name} not found at {model_path}")
            
        # Load model
        model = PatternRecognizer()
        success = model.load_model(model_path)
        
        if not success:
            self.logger.error(f"Failed to load model {model_name}")
            raise RuntimeError(f"Failed to load model {model_name}")
            
        # Cache model
        self.models[model_name] = model
        self.logger.info(f"Loaded model {model_name} from {model_path}")
        
        return model
    
    def detect_anomalies(self, 
                         file_paths: List[Union[str, Path]], 
                         model_name: str = 'pattern_recognizer',
                         threshold: Optional[float] = None) -> List[Dict[str, Any]]:
        """Detect anomalies in a list of files.
        
        Args:
            file_paths: List of paths to files to analyze.
            model_name: Name of the model to use for detection.
            threshold: Anomaly score threshold (0-1). Scores above this are considered anomalies.
                If None, use the default threshold from config.
                
        Returns:
            List of dictionaries with detection results for each file.
        """
        if threshold is None:
            threshold = self.threshold
            
        # Load model
        try:
            model = self.load_pattern_recognizer(model_name)
        except (FileNotFoundError, RuntimeError) as e:
            self.logger.error(f"Error loading model: {str(e)}")
            # Return empty results if model can't be loaded
            return [{'file': str(path), 'error': str(e)} for path in file_paths]
            
        # Process files
        results = []
        for file_path in file_paths:
            try:
                # Get prediction
                is_anomaly, score = model.predict(file_path)
                
                # Apply custom threshold if needed
                if threshold != 0.5:  # Default threshold for isolation forest is 0.5
                    is_anomaly = score >= threshold
                    
                # Create result
                result = {
                    'file': str(file_path),
                    'is_anomaly': is_anomaly,
                    'anomaly_score': score,
                    'threshold': threshold
                }
                
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error analyzing {file_path}: {str(e)}")
                results.append({
                    'file': str(file_path),
                    'error': str(e)
                })
                
        return results
    
    def detect_file_anomalies(self, 
                             file_path: Union[str, Path], 
                             model_name: str = 'pattern_recognizer',
                             threshold: Optional[float] = None) -> Dict[str, Any]:
        """Detect anomalies in a single file.
        
        Args:
            file_path: Path to the file to analyze.
            model_name: Name of the model to use for detection.
            threshold: Anomaly score threshold (0-1). Scores above this are considered anomalies.
                If None, use the default threshold from config.
                
        Returns:
            Dictionary with detection results.
        """
        results = self.detect_anomalies([file_path], model_name, threshold)
        return results[0] if results else {'file': str(file_path), 'error': 'Analysis failed'}
    
    def batch_analyze(self, 
                     directory: Union[str, Path], 
                     model_name: str = 'pattern_recognizer',
                     recursive: bool = True,
                     file_extensions: Optional[List[str]] = None,
                     max_files: int = 1000) -> Dict[str, Any]:
        """Analyze all files in a directory for anomalies.
        
        Args:
            directory: Path to the directory to analyze.
            model_name: Name of the model to use for detection.
            recursive: Whether to recursively search subdirectories.
            file_extensions: List of file extensions to include (without leading dot).
                If None, analyze all files.
            max_files: Maximum number of files to analyze.
                
        Returns:
            Dictionary with analysis results and summary statistics.
        """
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            self.logger.error(f"Directory {directory} does not exist or is not a directory")
            return {'error': f"Directory {directory} does not exist or is not a directory"}
            
        # Collect files to analyze
        files = []
        pattern = '**/*' if recursive else '*'
        
        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue
                
            # Check extension if specified
            if file_extensions is not None:
                ext = file_path.suffix.lower()[1:]  # Remove leading dot
                if ext not in file_extensions:
                    continue
                    
            files.append(str(file_path))
            
            if len(files) >= max_files:
                self.logger.info(f"Reached maximum number of files ({max_files})")
                break
                
        # Analyze files
        self.logger.info(f"Analyzing {len(files)} files in {directory}")
        file_results = self.detect_anomalies(files, model_name)
        
        # Compile summary statistics
        anomalies = [r for r in file_results if r.get('is_anomaly', False)]
        errors = [r for r in file_results if 'error' in r]
        
        # Calculate average score
        scores = [r.get('anomaly_score', 0) for r in file_results if 'anomaly_score' in r]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        # Create summary
        summary = {
            'directory': str(directory),
            'files_analyzed': len(files),
            'anomalies_detected': len(anomalies),
            'errors': len(errors),
            'average_score': avg_score,
            'model_used': model_name,
            'file_results': file_results
        }
        
        return summary
    
    def unload_model(self, model_name: str) -> bool:
        """Unload a model from memory.
        
        Args:
            model_name: Name of the model to unload.
            
        Returns:
            True if the model was unloaded, False if it wasn't loaded.
        """
        if model_name in self.models:
            # Clear model's cache if possible
            if hasattr(self.models[model_name], 'clear_cache'):
                self.models[model_name].clear_cache()
                
            # Remove from cache
            del self.models[model_name]
            self.logger.info(f"Unloaded model {model_name}")
            return True
            
        return False
    
    def unload_all_models(self) -> None:
        """Unload all models from memory."""
        model_names = list(self.models.keys())
        for model_name in model_names:
            self.unload_model(model_name)
            
        self.logger.info("Unloaded all models")
