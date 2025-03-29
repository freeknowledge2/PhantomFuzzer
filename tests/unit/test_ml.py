#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the ML module in PhantomFuzzer.

This module contains tests for the ML components, including:
- Pattern recognizer model
- Data loading and preprocessing
- Model training
- Anomaly detection
- Feedback collection and processing
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import ML components
from phantomfuzzer.ml import MLIntegration
from phantomfuzzer.ml.models import PatternRecognizer
from phantomfuzzer.ml.training import DataLoader, ModelTrainer
from phantomfuzzer.ml.feedback import FeedbackLoop


class TestPatternRecognizer(unittest.TestCase):
    """Test cases for the PatternRecognizer model."""
    
    def setUp(self):
        """Set up test environment."""
        self.model = PatternRecognizer()
    
    def test_initialization(self):
        """Test model initialization."""
        self.assertIsNotNone(self.model)
        # The model is initialized but not trained yet, so model attribute might be None
        self.assertEqual(self.model.threshold, 0.5)
    
    def test_feature_extraction(self):
        """Test feature extraction from text."""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("This is a test file with some content for feature extraction.")
        
        try:
            # Extract features
            features = self.model.extract_features(temp_file.name)
            
            # Check that features were extracted
            self.assertIsNotNone(features)
            self.assertIsInstance(features, dict)
            self.assertGreater(len(features), 0)
            
            # Check specific feature categories
            self.assertIn('text_features', features)
            self.assertIn('statistical_features', features)
        finally:
            # Clean up
            os.unlink(temp_file.name)
    
    def test_predict(self):
        """Test prediction functionality."""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("This is a test file for prediction.")
        
        try:
            # Create a simple dataset and train the model
            features = self.model.extract_features(temp_file.name)
            self.model.train_with_features([features])
            
            # Make a prediction
            is_anomaly, score = self.model.predict(temp_file.name)
            
            # Check prediction result
            self.assertIsNotNone(is_anomaly)
            self.assertIsNotNone(score)
            self.assertIsInstance(is_anomaly, bool)
            self.assertIsInstance(score, float)
        finally:
            # Clean up
            os.unlink(temp_file.name)


class TestDataLoader(unittest.TestCase):
    """Test cases for the DataLoader class."""
    
    def setUp(self):
        """Set up test environment."""
        self.data_loader = DataLoader()
    
    def test_load_dataset(self):
        """Test loading dataset from directories."""
        # Create a temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create some test files
            for i in range(5):
                with open(os.path.join(temp_dir, f"test_file_{i}.txt"), 'w') as f:
                    f.write(f"This is test file {i}")
            
            # Load dataset
            benign_files, _ = self.data_loader.load_dataset([temp_dir])
            
            # Check that files were loaded
            self.assertEqual(len(benign_files), 5)
            self.assertTrue(all(os.path.exists(f) for f in benign_files))
    
    def test_preprocess_files(self):
        """Test data preprocessing."""
        # Create a temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create some test files
            for i in range(3):
                with open(os.path.join(temp_dir, f"benign_{i}.txt"), 'w') as f:
                    f.write(f"This is a benign file {i}")
            
            for i in range(2):
                with open(os.path.join(temp_dir, f"malicious_{i}.txt"), 'w') as f:
                    f.write(f"This is a malicious file {i} with suspicious content")
            
            # Preprocess data
            benign_files = [os.path.join(temp_dir, f"benign_{i}.txt") for i in range(3)]
            malicious_files = [os.path.join(temp_dir, f"malicious_{i}.txt") for i in range(2)]
            
            dataset = self.data_loader.preprocess_files(benign_files, malicious_files)
            
            # Check dataset
            self.assertIsNotNone(dataset)
            self.assertTrue(len(dataset) > 0)  # Should have at least some data points
            
            # Check structure of dataset items
            for item in dataset:
                self.assertTrue(isinstance(item, dict))
                self.assertIn('file_path', item)


class TestModelTrainer(unittest.TestCase):
    """Test cases for the ModelTrainer class."""
    
    def setUp(self):
        """Set up test environment."""
        self.trainer = ModelTrainer()
        self.model = PatternRecognizer()
    
    def test_train_model(self):
        """Test model training."""
        # Create a simple dataset
        dataset = [
            {'features': {'text_features': {'word_count': 10}, 'statistical_features': {'entropy': 0.5}}, 'label': 0, 'file_path': 'file1.txt'},
            {'features': {'text_features': {'word_count': 15}, 'statistical_features': {'entropy': 0.6}}, 'label': 0, 'file_path': 'file2.txt'},
            {'features': {'text_features': {'word_count': 20}, 'statistical_features': {'entropy': 0.8}}, 'label': 1, 'file_path': 'file3.txt'}
        ]
        
        # Train the model
        self.trainer.train_model(self.model, dataset)
        
        # Check that the model was trained
        self.assertTrue(self.model.is_trained)
    
    def test_evaluate_model(self):
        """Test model evaluation."""
        # Create a simple dataset
        train_dataset = [
            {'features': {'text_features': {'word_count': 10}, 'statistical_features': {'entropy': 0.5}}, 'label': 0, 'file_path': 'file1.txt'},
            {'features': {'text_features': {'word_count': 15}, 'statistical_features': {'entropy': 0.6}}, 'label': 0, 'file_path': 'file2.txt'},
            {'features': {'text_features': {'word_count': 20}, 'statistical_features': {'entropy': 0.8}}, 'label': 1, 'file_path': 'file3.txt'}
        ]
        
        test_dataset = [
            {'features': {'text_features': {'word_count': 12}, 'statistical_features': {'entropy': 0.55}}, 'label': 0, 'file_path': 'file4.txt'},
            {'features': {'text_features': {'word_count': 22}, 'statistical_features': {'entropy': 0.85}}, 'label': 1, 'file_path': 'file5.txt'}
        ]
        
        # Train the model
        self.trainer.train_model(self.model, train_dataset)
        
        # Evaluate the model
        metrics = self.trainer.evaluate_model(self.model, test_dataset)
        
        # Check metrics
        self.assertIsNotNone(metrics)
        self.assertIn('accuracy', metrics)
        self.assertIn('precision', metrics)
        self.assertIn('recall', metrics)
        self.assertIn('f1_score', metrics)


class TestMLIntegration(unittest.TestCase):
    """Test cases for the MLIntegration class."""
    
    def setUp(self):
        """Set up test environment."""
        self.ml_integration = MLIntegration()
    
    def test_initialization(self):
        """Test initialization of the ML integration."""
        self.assertIsNotNone(self.ml_integration)
    
    @patch('phantomfuzzer.ml.models.PatternRecognizer')
    def test_detect_file_anomalies(self, mock_recognizer):
        """Test file anomaly detection."""
        # Mock the model's predict method
        mock_instance = mock_recognizer.return_value
        mock_instance.predict.return_value = {
            'is_anomaly': True,
            'anomaly_score': 0.75,
            'threshold': 0.5
        }
        
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("This is a test file for anomaly detection.")
        
        try:
            # Detect anomalies
            result = self.ml_integration.detect_file_anomalies(temp_file.name)
            
            # Check result
            self.assertIsNotNone(result)
            self.assertIn('is_anomaly', result)
            self.assertIn('anomaly_score', result)
            self.assertTrue(result['is_anomaly'])
            self.assertEqual(result['anomaly_score'], 0.75)
        finally:
            # Clean up
            os.unlink(temp_file.name)
    
    def test_batch_analyze_directory(self):
        """Test batch analysis of a directory."""
        # Create a temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create some test files
            for i in range(5):
                with open(os.path.join(temp_dir, f"test_file_{i}.txt"), 'w') as f:
                    f.write(f"This is test file {i}")
            
            # Mock the detect_file_anomalies method
            self.ml_integration.detect_file_anomalies = MagicMock(return_value={
                'is_anomaly': False,
                'anomaly_score': 0.3,
                'threshold': 0.5,
                'file': 'test_file.txt'
            })
            
            # Analyze directory
            results = self.ml_integration.batch_analyze_directory(temp_dir)
            
            # Check results
            self.assertIsNotNone(results)
            self.assertEqual(results['files_analyzed'], 5)
            self.assertIn('file_results', results)
            self.assertEqual(len(results['file_results']), 5)


class TestFeedbackLoop(unittest.TestCase):
    """Test cases for the FeedbackLoop class."""
    
    def setUp(self):
        """Set up test environment."""
        self.feedback_loop = FeedbackLoop()
    
    def test_record_feedback(self):
        """Test recording feedback."""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("This is a test file for feedback.")
        
        try:
            # Create a prediction
            prediction = {
                'is_anomaly': True,
                'anomaly_score': 0.75,
                'threshold': 0.5,
                'file': temp_file.name
            }
            
            # Record feedback
            feedback = self.feedback_loop.record_feedback(
                file_path=temp_file.name,
                prediction=prediction,
                is_correct=False,
                notes="This is not actually an anomaly."
            )
            
            # Check feedback
            self.assertIsNotNone(feedback)
            self.assertIn('id', feedback)
            self.assertIn('file', feedback)
            self.assertIn('is_correct', feedback)
            self.assertIn('notes', feedback)
            self.assertEqual(feedback['file'], temp_file.name)
            self.assertFalse(feedback['is_correct'])
            self.assertEqual(feedback['notes'], "This is not actually an anomaly.")
        finally:
            # Clean up
            os.unlink(temp_file.name)


if __name__ == '__main__':
    unittest.main()
