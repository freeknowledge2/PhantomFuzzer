#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Feedback Loop for Machine Learning Models.

This module provides utilities for collecting feedback on model predictions
and using that feedback to improve the models over time.
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any

# Local imports
from phantomfuzzer.utils.logging import get_logger
from phantomfuzzer.ml.models.pattern_recognizer import PatternRecognizer
from phantomfuzzer.ml.training.trainer import ModelTrainer


class FeedbackLoop:
    """Feedback loop for machine learning models.
    
    This class handles collecting feedback on model predictions and using
    that feedback to improve the models over time.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the feedback loop.
        
        Args:
            config: Configuration parameters for the feedback loop.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.feedback_dir = self.config.get('feedback_dir', 'feedback')
        self.model_dir = self.config.get('model_dir', 'models')
        
        # Create directories if they don't exist
        Path(self.feedback_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize model trainer
        trainer_config = self.config.get('trainer', {})
        trainer_config['model_dir'] = self.model_dir
        self.trainer = ModelTrainer(trainer_config)
    
    def record_feedback(self, 
                       file_path: Union[str, Path], 
                       prediction: Dict[str, Any], 
                       is_correct: bool, 
                       feedback_type: str = 'anomaly_detection',
                       notes: Optional[str] = None) -> Dict[str, Any]:
        """Record feedback on a model prediction.
        
        Args:
            file_path: Path to the file that was analyzed.
            prediction: The model's prediction for the file.
            is_correct: Whether the prediction was correct.
            feedback_type: Type of feedback (e.g., 'anomaly_detection').
            notes: Optional notes about the feedback.
            
        Returns:
            Dictionary with the recorded feedback information.
        """
        file_path = Path(file_path)
        
        # Create feedback entry
        feedback = {
            'file': str(file_path),
            'prediction': prediction,
            'is_correct': is_correct,
            'feedback_type': feedback_type,
            'notes': notes,
            'timestamp': time.time()
        }
        
        # Generate feedback ID
        feedback_id = f"{int(time.time())}_{file_path.name}"
        
        # Save feedback to file
        feedback_path = Path(self.feedback_dir) / f"{feedback_id}.json"
        with open(feedback_path, 'w') as f:
            json.dump(feedback, f, indent=2)
            
        self.logger.info(f"Recorded feedback for {file_path} (ID: {feedback_id})")
        
        # Add feedback ID to the returned dictionary
        feedback['id'] = feedback_id
        
        return feedback
    
    def get_feedback(self, feedback_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific feedback entry.
        
        Args:
            feedback_id: ID of the feedback entry to retrieve.
            
        Returns:
            The feedback entry, or None if not found.
        """
        feedback_path = Path(self.feedback_dir) / f"{feedback_id}.json"
        
        if not feedback_path.exists():
            self.logger.warning(f"Feedback {feedback_id} not found")
            return None
            
        try:
            with open(feedback_path, 'r') as f:
                feedback = json.load(f)
                
            return feedback
            
        except Exception as e:
            self.logger.error(f"Error loading feedback {feedback_id}: {str(e)}")
            return None
    
    def get_all_feedback(self, feedback_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all feedback entries, optionally filtered by type.
        
        Args:
            feedback_type: Optional type to filter by.
            
        Returns:
            List of feedback entries.
        """
        feedback_entries = []
        
        for feedback_path in Path(self.feedback_dir).glob('*.json'):
            try:
                with open(feedback_path, 'r') as f:
                    feedback = json.load(f)
                    
                # Filter by type if specified
                if feedback_type is None or feedback.get('feedback_type') == feedback_type:
                    # Add ID if not present
                    if 'id' not in feedback:
                        feedback['id'] = feedback_path.stem
                        
                    feedback_entries.append(feedback)
                    
            except Exception as e:
                self.logger.error(f"Error loading feedback {feedback_path}: {str(e)}")
                
        return feedback_entries
    
    def get_false_positives(self, feedback_type: str = 'anomaly_detection') -> List[Dict[str, Any]]:
        """Get all false positive feedback entries.
        
        Args:
            feedback_type: Type of feedback to filter by.
            
        Returns:
            List of false positive feedback entries.
        """
        all_feedback = self.get_all_feedback(feedback_type)
        
        # Filter for false positives (predicted anomaly but actually benign)
        false_positives = []
        for feedback in all_feedback:
            prediction = feedback.get('prediction', {})
            is_correct = feedback.get('is_correct', True)
            
            if not is_correct and prediction.get('is_anomaly', False):
                false_positives.append(feedback)
                
        return false_positives
    
    def get_false_negatives(self, feedback_type: str = 'anomaly_detection') -> List[Dict[str, Any]]:
        """Get all false negative feedback entries.
        
        Args:
            feedback_type: Type of feedback to filter by.
            
        Returns:
            List of false negative feedback entries.
        """
        all_feedback = self.get_all_feedback(feedback_type)
        
        # Filter for false negatives (predicted benign but actually anomalous)
        false_negatives = []
        for feedback in all_feedback:
            prediction = feedback.get('prediction', {})
            is_correct = feedback.get('is_correct', True)
            
            if not is_correct and not prediction.get('is_anomaly', True):
                false_negatives.append(feedback)
                
        return false_negatives
    
    def retrain_model_with_feedback(self, 
                                   model_name: str = 'pattern_recognizer',
                                   feedback_type: str = 'anomaly_detection',
                                   include_original_data: bool = True) -> bool:
        """Retrain a model using feedback data.
        
        Args:
            model_name: Name of the model to retrain.
            feedback_type: Type of feedback to use for retraining.
            include_original_data: Whether to include the original training data.
            
        Returns:
            True if retraining was successful, False otherwise.
        """
        self.logger.info(f"Retraining model {model_name} with feedback")
        
        # Get feedback data
        false_positives = self.get_false_positives(feedback_type)
        false_negatives = self.get_false_negatives(feedback_type)
        
        if not false_positives and not false_negatives:
            self.logger.warning("No feedback data available for retraining")
            return False
            
        # Extract file paths from feedback
        fp_files = [feedback.get('file') for feedback in false_positives if 'file' in feedback]
        fn_files = [feedback.get('file') for feedback in false_negatives if 'file' in feedback]
        
        # Check if files exist
        fp_files = [f for f in fp_files if Path(f).exists()]
        fn_files = [f for f in fn_files if Path(f).exists()]
        
        if not fp_files and not fn_files:
            self.logger.warning("No valid files found in feedback data")
            return False
            
        try:
            # Load original model to get its configuration
            original_model = None
            try:
                original_model = self.trainer.load_model(model_name)
                model_config = original_model.config
            except Exception as e:
                self.logger.warning(f"Could not load original model: {str(e)}")
                model_config = {}
                
            # Create new model name with timestamp
            new_model_name = f"{model_name}_retrained_{int(time.time())}"
            
            # Prepare training data
            if include_original_data and original_model is not None:
                # TODO: Implement a way to get original training data
                # For now, we'll just use the feedback data
                benign_dirs = []
                malicious_dirs = []
            else:
                benign_dirs = []
                malicious_dirs = []
                
            # Create temporary directories for feedback files
            temp_benign_dir = Path(self.feedback_dir) / "temp_benign"
            temp_malicious_dir = Path(self.feedback_dir) / "temp_malicious"
            
            temp_benign_dir.mkdir(exist_ok=True)
            temp_malicious_dir.mkdir(exist_ok=True)
            
            # Create symlinks to feedback files
            for file_path in fp_files:  # False positives are actually benign
                target = temp_benign_dir / Path(file_path).name
                if not target.exists():
                    os.symlink(file_path, target)
                    
            for file_path in fn_files:  # False negatives are actually malicious
                target = temp_malicious_dir / Path(file_path).name
                if not target.exists():
                    os.symlink(file_path, target)
                    
            # Add temporary directories to training data
            benign_dirs.append(str(temp_benign_dir))
            malicious_dirs.append(str(temp_malicious_dir))
            
            # Train new model
            if malicious_dirs:
                self.trainer.train_with_malicious_samples(
                    benign_dirs=benign_dirs,
                    malicious_dirs=malicious_dirs,
                    model_name=new_model_name,
                    model_config=model_config
                )
            else:
                self.trainer.train_pattern_recognizer(
                    benign_dirs=benign_dirs,
                    model_name=new_model_name,
                    model_config=model_config
                )
                
            # Clean up temporary directories
            for file_path in temp_benign_dir.glob('*'):
                os.unlink(file_path)
                
            for file_path in temp_malicious_dir.glob('*'):
                os.unlink(file_path)
                
            temp_benign_dir.rmdir()
            temp_malicious_dir.rmdir()
            
            self.logger.info(f"Model retrained and saved as {new_model_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error retraining model: {str(e)}")
            return False
    
    def adjust_threshold(self, 
                        model_name: str = 'pattern_recognizer',
                        feedback_type: str = 'anomaly_detection') -> Optional[float]:
        """Adjust the anomaly detection threshold based on feedback.
        
        Args:
            model_name: Name of the model to adjust threshold for.
            feedback_type: Type of feedback to use for adjustment.
            
        Returns:
            The new threshold, or None if adjustment failed.
        """
        self.logger.info(f"Adjusting threshold for model {model_name} based on feedback")
        
        # Get feedback data
        all_feedback = self.get_all_feedback(feedback_type)
        
        if not all_feedback:
            self.logger.warning("No feedback data available for threshold adjustment")
            return None
            
        # Extract scores from feedback
        scores = []
        for feedback in all_feedback:
            prediction = feedback.get('prediction', {})
            is_correct = feedback.get('is_correct', True)
            score = prediction.get('anomaly_score')
            
            if score is not None:
                scores.append((score, prediction.get('is_anomaly', False), is_correct))
                
        if not scores:
            self.logger.warning("No valid scores found in feedback data")
            return None
            
        # Find optimal threshold
        best_threshold = 0.5
        best_accuracy = 0.0
        
        for threshold in [i/100 for i in range(1, 100)]:
            correct = 0
            for score, predicted_anomaly, is_correct in scores:
                # Determine if the prediction would be correct with this threshold
                would_predict_anomaly = score >= threshold
                would_be_correct = (would_predict_anomaly == predicted_anomaly and is_correct) or \
                                  (would_predict_anomaly != predicted_anomaly and not is_correct)
                                  
                if would_be_correct:
                    correct += 1
                    
            accuracy = correct / len(scores)
            
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_threshold = threshold
                
        self.logger.info(f"Adjusted threshold for model {model_name} to {best_threshold} (accuracy: {best_accuracy:.2f})")
        
        # Save the new threshold
        threshold_path = Path(self.model_dir) / f"{model_name}_threshold.json"
        with open(threshold_path, 'w') as f:
            json.dump({'threshold': best_threshold, 'accuracy': best_accuracy}, f, indent=2)
            
        return best_threshold
