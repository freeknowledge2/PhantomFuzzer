#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pattern Recognizer Model for Anomaly Detection.

This module implements an anomaly detection model using isolation forest
to identify unusual patterns in files that may indicate malicious content.
"""

import os
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any
from datetime import datetime

# For feature extraction
import math
import hashlib
from collections import Counter

# For ML model
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Local imports
from phantomfuzzer.utils.logging import get_logger
from phantomfuzzer.ml.storage.pattern_db import PatternDatabase


class PatternRecognizer:
    """Anomaly detection model for identifying unusual patterns in files.
    
    This class implements an isolation forest-based model that learns normal
    patterns from benign files and detects anomalies in potentially malicious files.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, pattern_db: Optional[PatternDatabase] = None):
        """Initialize the pattern recognizer.
        
        Args:
            config: Configuration parameters for the model.
            pattern_db: Optional PatternDatabase instance for pattern matching.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.n_estimators = self.config.get('n_estimators', 100)
        self.max_samples = self.config.get('max_samples', 'auto')
        self.contamination = self.config.get('contamination', 0.1)
        self.random_state = self.config.get('random_state', 42)
        self.max_features = self.config.get('max_features', 1.0)
        
        # Initialize model
        self.model = None
        self.scaler = StandardScaler()
        
        # Feature extraction settings
        self.n_gram_size = self.config.get('n_gram_size', 2)
        self.top_n_grams = self.config.get('top_n_grams', 100)
        self.feature_cache = {}
        
        # Pattern database integration
        self.pattern_db = pattern_db
        if self.pattern_db is None and self.config.get('use_pattern_db', True):
            self.pattern_db = PatternDatabase(config=self.config.get('pattern_db_config'))
        
        # Pattern matching settings
        self.pattern_match_threshold = self.config.get('pattern_match_threshold', 0.7)
        self.pattern_weight = self.config.get('pattern_weight', 0.3)  # Weight for pattern matching vs ML model
        
    @property
    def is_trained(self) -> bool:
        """Check if the model has been trained.
        
        Returns:
            True if the model has been trained, False otherwise.
        """
        return self.model is not None
        
    def extract_features(self, file_path: Union[str, Path]) -> np.ndarray:
        """Extract features from a file for anomaly detection.
        
        Args:
            file_path: Path to the file to extract features from.
            
        Returns:
            A numpy array of features extracted from the file.
        """
        file_path = Path(file_path)
        
        # Check if features are already cached
        if str(file_path) in self.feature_cache:
            return self.feature_cache[str(file_path)]
        
        try:
            # Read file as binary
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Extract features
            features = []
            
            # 1. Basic file properties
            file_size = len(content)
            features.append(file_size)
            
            # 2. Entropy calculation
            entropy = self._calculate_entropy(content)
            features.append(entropy)
            
            # 3. Byte histogram (frequency of each byte value 0-255)
            byte_hist = self._calculate_byte_histogram(content)
            features.extend(byte_hist)
            
            # 4. N-gram analysis
            n_gram_features = self._extract_n_gram_features(content)
            features.extend(n_gram_features)
            
            # 5. Structural features
            structural_features = self._extract_structural_features(content)
            features.extend(structural_features)
            
            # Convert to numpy array
            feature_array = np.array(features, dtype=np.float32).reshape(1, -1)
            
            # Cache the features
            self.feature_cache[str(file_path)] = feature_array
            
            return feature_array
            
        except Exception as e:
            self.logger.error(f"Error extracting features from {file_path}: {str(e)}")
            # Return a zero vector if feature extraction fails
            return np.zeros((1, 256 + self.top_n_grams + 10), dtype=np.float32)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the data.
        
        Args:
            data: Binary data to calculate entropy for.
            
        Returns:
            Shannon entropy value.
        """
        if not data:
            return 0.0
            
        # Count byte frequencies
        counter = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _calculate_byte_histogram(self, data: bytes) -> List[float]:
        """Calculate normalized histogram of byte values.
        
        Args:
            data: Binary data to analyze.
            
        Returns:
            List of 256 normalized frequency values.
        """
        if not data:
            return [0.0] * 256
            
        # Initialize histogram with zeros
        histogram = [0] * 256
        
        # Count byte frequencies
        for byte in data:
            histogram[byte] += 1
            
        # Normalize
        data_len = len(data)
        normalized_histogram = [count / data_len for count in histogram]
        
        return normalized_histogram
    
    def _extract_n_gram_features(self, data: bytes) -> List[float]:
        """Extract n-gram features from binary data.
        
        Args:
            data: Binary data to analyze.
            
        Returns:
            List of n-gram features.
        """
        if not data or len(data) < self.n_gram_size:
            return [0.0] * self.top_n_grams
            
        # Extract n-grams
        n_grams = []
        for i in range(len(data) - self.n_gram_size + 1):
            n_grams.append(data[i:i+self.n_gram_size])
            
        # Count n-gram frequencies
        n_gram_counter = Counter(n_grams)
        
        # Get top n-grams
        top_n_grams = n_gram_counter.most_common(self.top_n_grams)
        
        # Create feature vector (normalized frequencies of top n-grams)
        n_gram_features = [0.0] * self.top_n_grams
        data_len = len(data) - self.n_gram_size + 1
        
        for i, (n_gram, count) in enumerate(top_n_grams):
            if i < self.top_n_grams:
                n_gram_features[i] = count / data_len
                
        return n_gram_features
    
    def _extract_structural_features(self, data: bytes) -> List[float]:
        """Extract structural features from binary data.
        
        Args:
            data: Binary data to analyze.
            
        Returns:
            List of structural features.
        """
        if not data:
            return [0.0] * 10
            
        features = []
        
        # 1. Ratio of printable ASCII characters
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        features.append(printable_count / len(data) if data else 0)
        
        # 2. Ratio of null bytes
        null_count = data.count(0)
        features.append(null_count / len(data) if data else 0)
        
        # 3. Ratio of high entropy regions
        # Split data into chunks and calculate entropy for each
        chunk_size = 1024
        high_entropy_chunks = 0
        total_chunks = max(1, len(data) // chunk_size)
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            if self._calculate_entropy(chunk) > 7.0:  # High entropy threshold
                high_entropy_chunks += 1
                
        features.append(high_entropy_chunks / total_chunks if total_chunks else 0)
        
        # 4. Compression ratio (as a feature of complexity)
        import zlib
        compressed = zlib.compress(data)
        features.append(len(compressed) / len(data) if data else 0)
        
        # 5. Longest continuous byte sequence
        max_seq_len = 0
        current_seq_len = 1
        
        for i in range(1, len(data)):
            if data[i] == data[i-1]:
                current_seq_len += 1
            else:
                max_seq_len = max(max_seq_len, current_seq_len)
                current_seq_len = 1
                
        max_seq_len = max(max_seq_len, current_seq_len)
        features.append(max_seq_len / len(data) if data else 0)
        
        # Pad to ensure consistent feature vector length
        features.extend([0.0] * (10 - len(features)))
        
        return features
    
    def train(self, file_paths: List[Union[str, Path]]) -> None:
        """Train the anomaly detection model on a set of files.
        
        Args:
            file_paths: List of paths to files to train on.
        """
        self.logger.info(f"Training pattern recognizer on {len(file_paths)} files")
        
        # Extract features from all files
        features = []
        for file_path in file_paths:
            try:
                file_features = self.extract_features(file_path)
                features.append(file_features.flatten())
            except Exception as e:
                self.logger.error(f"Error processing {file_path}: {str(e)}")
                
        if not features:
            self.logger.error("No valid features extracted for training")
            return
            
        # Train with the extracted features
        self.train_with_features(features)
        
    def train_with_features(self, features: List[np.ndarray]) -> None:
        """Train the anomaly detection model with pre-extracted features.
        
        Args:
            features: List of feature vectors extracted from files.
        """
        if not features:
            self.logger.error("No features provided for training")
            return
            
        try:
            # Convert to numpy array
            X = np.vstack(features)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Initialize and train the model
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                max_samples=self.max_samples,
                contamination=self.contamination,
                random_state=self.random_state,
                max_features=self.max_features
            )
            
            self.model.fit(X_scaled)
            self.logger.info("Pattern recognizer training completed")
        except Exception as e:
            self.logger.error(f"Error training model with features: {str(e)}")
    
    def _predict_with_model(self, file_path: Union[str, Path]) -> Tuple[bool, float]:
        """Predict using only the ML model.
        
        Args:
            file_path: Path to the file to analyze.
            
        Returns:
            A tuple of (is_anomaly, anomaly_score).
        """
        if self.model is None:
            self.logger.error("Model not trained. Call train() first.")
            return False, 0.0
            
        try:
            # Extract features
            features = self.extract_features(file_path)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Get anomaly score (-1 for anomalies, 1 for normal)
            # Convert to a 0-1 scale where higher values indicate more anomalous
            raw_score = self.model.decision_function(features_scaled)[0]
            anomaly_score = 1.0 - (raw_score + 1) / 2
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            is_anomaly = bool(prediction == -1)  # Convert numpy bool to Python bool
            
            return is_anomaly, float(anomaly_score)  # Ensure we return Python float
            
        except Exception as e:
            self.logger.error(f"Error predicting for {file_path}: {str(e)}")
            return False, 0.0
            
    def check_pattern_match(self, file_path: Union[str, Path]) -> Tuple[bool, float, Optional[Dict[str, Any]]]:
        """Check if a file matches any patterns in the database.
        
        Args:
            file_path: Path to the file to check.
            
        Returns:
            Tuple of (is_match, confidence, pattern_info).
        """
        if self.pattern_db is None:
            return False, 0.0, None
            
        file_path = Path(file_path)
        file_name = file_path.name
        
        # Check for exact matches by filename
        pattern_entry = self.pattern_db.get_pattern_by_value(file_name)
        if pattern_entry:
            self.pattern_db.increment_usage_count(hashlib.md5(file_name.encode()).hexdigest())
            return True, pattern_entry['confidence'], pattern_entry
        
        # Check for similar patterns by filename
        similar_patterns = self.pattern_db.find_similar_patterns(
            file_name, threshold=self.pattern_match_threshold
        )
        if similar_patterns:
            top_match = similar_patterns[0]
            self.pattern_db.increment_usage_count(top_match['id'])
            return True, top_match['similarity'] * top_match['entry']['confidence'], top_match['entry']
        
        # If no match by filename, could add content-based matching here
        
        return False, 0.0, None
            
    def predict(self, file_path: Union[str, Path]) -> Tuple[bool, float, Dict[str, Any]]:
        """Predict if a file contains anomalous patterns.
        
        Args:
            file_path: Path to the file to analyze.
            
        Returns:
            A tuple of (is_anomaly, anomaly_score, details).
        """
        # Get ML model prediction
        ml_is_anomaly, ml_score = False, 0.0
        if self.model is not None:
            ml_is_anomaly, ml_score = self._predict_with_model(file_path)
        
        # Get pattern match prediction
        pattern_is_match, pattern_confidence, pattern_info = self.check_pattern_match(file_path)
        
        # Combine predictions
        details = {
            'ml_is_anomaly': ml_is_anomaly,
            'ml_score': ml_score,
            'pattern_is_match': pattern_is_match,
            'pattern_confidence': pattern_confidence,
            'pattern_info': pattern_info
        }
        
        # If we have a high-confidence pattern match, it takes precedence
        if pattern_is_match and pattern_confidence > 0.8:
            return pattern_is_match, pattern_confidence, details
        
        # Otherwise blend the two scores
        if self.model is not None:
            combined_score = (ml_score * (1 - self.pattern_weight) + 
                             pattern_confidence * self.pattern_weight)
            is_anomaly = ml_is_anomaly or pattern_is_match
        else:
            # If no ML model is trained, rely solely on pattern matching
            combined_score = pattern_confidence
            is_anomaly = pattern_is_match
        
        details['combined_score'] = combined_score
        
        # If this is an anomaly, consider adding it to the pattern database
        if is_anomaly and combined_score > 0.7:
            pattern_id = self.discover_patterns(file_path, is_anomaly, combined_score)
            if pattern_id:
                details['discovered_pattern_id'] = pattern_id
        
        return is_anomaly, combined_score, details
    
    def batch_predict(self, file_paths: List[Union[str, Path]]) -> List[Tuple[str, bool, float, Dict[str, Any]]]:
        """Predict anomalies for multiple files.
        
        Args:
            file_paths: List of paths to files to analyze.
            
        Returns:
            List of tuples (file_path, is_anomaly, anomaly_score, details).
        """
        results = []
        
        for file_path in file_paths:
            is_anomaly, score, details = self.predict(file_path)
            results.append((str(file_path), is_anomaly, score, details))
            
        return results
        
    def discover_patterns(self, file_path: Union[str, Path], 
                         is_anomaly: bool, confidence: float) -> Optional[str]:
        """Discover potential new patterns from analyzed files.
        
        Args:
            file_path: Path to the file that was analyzed.
            is_anomaly: Whether the file was classified as anomalous.
            confidence: Confidence score of the classification.
            
        Returns:
            Pattern ID if a new pattern was discovered, None otherwise.
        """
        if self.pattern_db is None or not is_anomaly or confidence < 0.7:
            return None
            
        file_path = Path(file_path)
        file_name = file_path.name
        
        # Check if this pattern already exists
        existing_pattern = self.pattern_db.get_pattern_by_value(file_name)
        if existing_pattern:
            # Update existing pattern confidence
            pattern_id = hashlib.md5(file_name.encode()).hexdigest()
            self.pattern_db.update_pattern(
                pattern_id=pattern_id,
                confidence=max(existing_pattern['confidence'], confidence),
                metadata={'last_seen': datetime.now().isoformat()}
            )
            return pattern_id
        
        # Add as a new pattern if it's anomalous with high confidence
        pattern_id = self.pattern_db.add_pattern(
            pattern=file_name,
            source='ml_discovery',
            confidence=confidence,
            metadata={
                'discovered_at': datetime.now().isoformat(),
                'discovery_method': 'anomaly_detection'
            }
        )
        
        self.logger.info(f"Discovered new pattern: {file_name} with ID: {pattern_id}")
        return pattern_id
    
    def save_model(self, model_path: Union[str, Path]) -> bool:
        """Save the trained model to disk.
        
        Args:
            model_path: Path to save the model to.
            
        Returns:
            True if successful, False otherwise.
        """
        if self.model is None:
            self.logger.error("No trained model to save")
            return False
            
        try:
            model_path = Path(model_path)
            model_path.parent.mkdir(parents=True, exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'config': self.config
            }
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
                
            self.logger.info(f"Model saved to {model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            return False
    
    def load_model(self, model_path: Union[str, Path]) -> bool:
        """Load a trained model from disk.
        
        Args:
            model_path: Path to load the model from.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.config = model_data['config']
            
            # Update configuration parameters
            self.n_estimators = self.config.get('n_estimators', 100)
            self.max_samples = self.config.get('max_samples', 'auto')
            self.contamination = self.config.get('contamination', 0.1)
            self.random_state = self.config.get('random_state', 42)
            self.max_features = self.config.get('max_features', 1.0)
            self.n_gram_size = self.config.get('n_gram_size', 2)
            self.top_n_grams = self.config.get('top_n_grams', 100)
            
            self.logger.info(f"Model loaded from {model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False
    
    def clear_cache(self) -> None:
        """Clear the feature cache to free memory."""
        self.feature_cache.clear()
