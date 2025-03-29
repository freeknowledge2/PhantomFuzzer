#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ML Integration Module for PhantomFuzzer.

This module provides a unified interface for integrating machine learning
capabilities into the PhantomFuzzer scanner.
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any

# Local imports
from phantomfuzzer.utils.logging import get_logger
from phantomfuzzer.ml.models.pattern_recognizer import PatternRecognizer
from phantomfuzzer.ml.training.trainer import ModelTrainer
from phantomfuzzer.ml.training.data_loader import DataLoader
from phantomfuzzer.ml.inference import InferenceEngine
from phantomfuzzer.ml.feedback import FeedbackLoop


class MLIntegration:
    """Integration class for machine learning capabilities in PhantomFuzzer.
    
    This class provides a unified interface for using machine learning
    models within the PhantomFuzzer scanner, including anomaly detection,
    training, and feedback collection.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the ML integration.
        
        Args:
            config: Configuration parameters for ML integration.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.base_dir = self.config.get('base_dir', os.path.join(os.getcwd(), 'ml_data'))
        self.model_dir = self.config.get('model_dir', os.path.join(self.base_dir, 'models'))
        self.data_dir = self.config.get('data_dir', os.path.join(self.base_dir, 'data'))
        self.results_dir = self.config.get('results_dir', os.path.join(self.base_dir, 'results'))
        self.feedback_dir = self.config.get('feedback_dir', os.path.join(self.base_dir, 'feedback'))
        
        # Create directories if they don't exist
        for directory in [self.base_dir, self.model_dir, self.data_dir, 
                          self.results_dir, self.feedback_dir]:
            Path(directory).mkdir(parents=True, exist_ok=True)
            
        # Initialize components with shared configuration
        component_config = {
            'model_dir': self.model_dir,
            'data_dir': self.data_dir,
            'results_dir': self.results_dir,
            'feedback_dir': self.feedback_dir
        }
        
        # Initialize components
        self.inference_engine = InferenceEngine(component_config)
        self.trainer = ModelTrainer(component_config)
        self.data_loader = DataLoader(component_config)
        self.feedback_loop = FeedbackLoop(component_config)
        
        # Default model name
        self.default_model = self.config.get('default_model', 'pattern_recognizer')
        
        # Load default model if available
        self._load_default_model()
    
    def _load_default_model(self) -> None:
        """Load the default model if available."""
        model_path = Path(self.model_dir) / f"{self.default_model}.pkl"
        
        if model_path.exists():
            try:
                self.inference_engine.load_pattern_recognizer(self.default_model)
                self.logger.info(f"Loaded default model: {self.default_model}")
            except Exception as e:
                self.logger.warning(f"Failed to load default model: {str(e)}")
    
    def detect_anomalies(self, 
                        file_paths: List[Union[str, Path]], 
                        model_name: Optional[str] = None,
                        threshold: Optional[float] = None) -> List[Dict[str, Any]]:
        """Detect anomalies in a list of files.
        
        Args:
            file_paths: List of paths to files to analyze.
            model_name: Name of the model to use for detection.
                If None, use the default model.
            threshold: Anomaly score threshold (0-1).
                If None, use the default threshold from config.
                
        Returns:
            List of dictionaries with detection results for each file.
        """
        if model_name is None:
            model_name = self.default_model
            
        return self.inference_engine.detect_anomalies(file_paths, model_name, threshold)
    
    def detect_file_anomalies(self, 
                             file_path: Union[str, Path], 
                             model_name: Optional[str] = None,
                             threshold: Optional[float] = None) -> Dict[str, Any]:
        """Detect anomalies in a single file.
        
        Args:
            file_path: Path to the file to analyze.
            model_name: Name of the model to use for detection.
                If None, use the default model.
            threshold: Anomaly score threshold (0-1).
                If None, use the default threshold from config.
                
        Returns:
            Dictionary with detection results.
        """
        if model_name is None:
            model_name = self.default_model
            
        return self.inference_engine.detect_file_anomalies(file_path, model_name, threshold)
    
    def batch_analyze_directory(self, 
                               directory: Union[str, Path], 
                               model_name: Optional[str] = None,
                               recursive: bool = True,
                               file_extensions: Optional[List[str]] = None,
                               max_files: int = 1000) -> Dict[str, Any]:
        """Analyze all files in a directory for anomalies.
        
        Args:
            directory: Path to the directory to analyze.
            model_name: Name of the model to use for detection.
                If None, use the default model.
            recursive: Whether to recursively search subdirectories.
            file_extensions: List of file extensions to include (without leading dot).
                If None, analyze all files.
            max_files: Maximum number of files to analyze.
                
        Returns:
            Dictionary with analysis results and summary statistics.
        """
        if model_name is None:
            model_name = self.default_model
            
        return self.inference_engine.batch_analyze(
            directory, model_name, recursive, file_extensions, max_files
        )
    
    def train_model(self, 
                   benign_dirs: List[Union[str, Path]],
                   malicious_dirs: Optional[List[Union[str, Path]]] = None,
                   model_name: Optional[str] = None,
                   model_config: Optional[Dict[str, Any]] = None) -> str:
        """Train a new model for anomaly detection.
        
        Args:
            benign_dirs: List of directories containing benign files for training.
            malicious_dirs: Optional list of directories containing malicious files.
                If provided, train with both benign and malicious samples.
            model_name: Name to use for the saved model.
                If None, use the default model name with a timestamp.
            model_config: Configuration for the pattern recognizer model.
                
        Returns:
            Name of the trained model.
        """
        if model_name is None:
            import time
            model_name = f"{self.default_model}_{int(time.time())}"
            
        if malicious_dirs:
            self.trainer.train_with_malicious_samples(
                benign_dirs=benign_dirs,
                malicious_dirs=malicious_dirs,
                model_name=model_name,
                model_config=model_config
            )
        else:
            self.trainer.train_pattern_recognizer(
                benign_dirs=benign_dirs,
                model_name=model_name,
                model_config=model_config
            )
            
        return model_name
    
    def record_feedback(self, 
                       file_path: Union[str, Path], 
                       prediction: Dict[str, Any], 
                       is_correct: bool, 
                       notes: Optional[str] = None) -> Dict[str, Any]:
        """Record feedback on a model prediction.
        
        Args:
            file_path: Path to the file that was analyzed.
            prediction: The model's prediction for the file.
            is_correct: Whether the prediction was correct.
            notes: Optional notes about the feedback.
            
        Returns:
            Dictionary with the recorded feedback information.
        """
        return self.feedback_loop.record_feedback(
            file_path=file_path,
            prediction=prediction,
            is_correct=is_correct,
            notes=notes
        )
    
    def retrain_with_feedback(self, 
                             model_name: Optional[str] = None,
                             include_original_data: bool = True) -> Optional[str]:
        """Retrain a model using feedback data.
        
        Args:
            model_name: Name of the model to retrain.
                If None, use the default model.
            include_original_data: Whether to include the original training data.
            
        Returns:
            Name of the retrained model, or None if retraining failed.
        """
        if model_name is None:
            model_name = self.default_model
            
        success = self.feedback_loop.retrain_model_with_feedback(
            model_name=model_name,
            include_original_data=include_original_data
        )
        
        if success:
            import time
            new_model_name = f"{model_name}_retrained_{int(time.time())}"
            return new_model_name
        else:
            return None
    
    def adjust_threshold(self, model_name: Optional[str] = None) -> Optional[float]:
        """Adjust the anomaly detection threshold based on feedback.
        
        Args:
            model_name: Name of the model to adjust threshold for.
                If None, use the default model.
            
        Returns:
            The new threshold, or None if adjustment failed.
        """
        if model_name is None:
            model_name = self.default_model
            
        return self.feedback_loop.adjust_threshold(model_name=model_name)
    
    def set_default_model(self, model_name: str) -> bool:
        """Set the default model for anomaly detection.
        
        Args:
            model_name: Name of the model to set as default.
            
        Returns:
            True if the model was set as default, False otherwise.
        """
        model_path = Path(self.model_dir) / f"{model_name}.pkl"
        
        if not model_path.exists():
            self.logger.error(f"Model {model_name} not found at {model_path}")
            return False
            
        self.default_model = model_name
        self._load_default_model()
        
        # Save default model configuration
        config_path = Path(self.base_dir) / "config.json"
        import json
        with open(config_path, 'w') as f:
            json.dump({'default_model': model_name}, f, indent=2)
            
        self.logger.info(f"Set default model to {model_name}")
        return True
    
    def get_available_models(self) -> List[str]:
        """Get a list of available trained models.
        
        Returns:
            List of model names.
        """
        models = []
        for model_path in Path(self.model_dir).glob('*.pkl'):
            models.append(model_path.stem)
            
        return models
    
    def analyze_vulnerability(self,
                             content: str,
                             vulnerability_type: str,
                             payload: Optional[str] = None,
                             threshold: Optional[float] = None) -> Dict[str, Any]:
        """Analyze if content indicates a vulnerability.
        
        Args:
            content: The content to analyze (usually HTTP response).
            vulnerability_type: Type of vulnerability to check for (e.g., 'xss', 'sqli').
            payload: The payload that was used to generate the response.
            threshold: Confidence threshold (0-1).
                If None, use the default threshold from config.
                
        Returns:
            Dictionary with analysis results.
        """
        if threshold is None:
            threshold = self.config.get('detection_threshold', 0.6)
        
        try:
            # Create a temporary file with the content
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name
            
            # Use pattern recognizer to analyze the content
            result = self.inference_engine.detect_file_anomalies(
                file_path=temp_path,
                model_name=self.default_model,
                threshold=threshold
            )
            
            # Add vulnerability-specific analysis
            is_vulnerable = False
            confidence = result.get('anomaly_score', 0.0)
            evidence = ""
            
            # Check for vulnerability patterns based on type
            if vulnerability_type.lower() == 'xss':
                # Look for XSS indicators
                if payload and payload in content:
                    # Check if payload appears in a potentially executable context
                    import re
                    script_pattern = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL)
                    event_pattern = re.compile(r'on\w+=["\'].*?["\']')
                    
                    if script_pattern.search(content) or event_pattern.search(content):
                        is_vulnerable = True
                        evidence = f"Payload found in potentially executable context: {payload}"
                        confidence = max(confidence, 0.7)  # Boost confidence
            
            elif vulnerability_type.lower() == 'sqli':
                # Look for SQL error messages
                sql_errors = [
                    'SQL syntax', 'mysql_fetch_array', 'ORA-', 'Oracle error',
                    'SQL statement', 'sqlite_error', 'not a valid MySQL', 'SQL command',
                    'syntax error', 'mysql_num_rows', 'mysql_query', 'pg_query',
                    'division by zero', 'supplied argument is not a valid MySQL',
                    'unclosed quotation mark', 'ODBC SQL Server Driver'
                ]
                
                for error in sql_errors:
                    if error.lower() in content.lower():
                        is_vulnerable = True
                        evidence = f"SQL error message found: {error}"
                        confidence = max(confidence, 0.8)  # Strong indicator
                        break
            
            # Clean up temporary file
            import os
            os.unlink(temp_path)
            
            # Combine ML analysis with pattern-based analysis
            if confidence >= threshold:
                is_vulnerable = True
            
            return {
                'is_vulnerable': is_vulnerable,
                'confidence': confidence,
                'vulnerability_type': vulnerability_type,
                'evidence': evidence,
                'payload': payload,
                'ml_analysis': result
            }
        
        except Exception as e:
            self.logger.error(f"Error analyzing vulnerability: {str(e)}")
            return {
                'is_vulnerable': False,
                'confidence': 0.0,
                'vulnerability_type': vulnerability_type,
                'evidence': f"Error during analysis: {str(e)}",
                'payload': payload,
                'ml_analysis': {}
            }
    
    def analyze_web_responses(self,
                            response_data: List[Dict[str, Any]],
                            threshold: Optional[float] = None) -> List[Dict[str, Any]]:
        """Analyze web responses for potential vulnerabilities.
        
        Args:
            response_data: List of response data to analyze.
                Each item should be a dictionary with 'url', 'content', 'status_code', etc.
            threshold: Confidence threshold (0-1).
                If None, use the default threshold from config.
                
        Returns:
            List of analysis results.
        """
        if threshold is None:
            threshold = self.config.get('detection_threshold', 0.6)
        
        results = []
        
        try:
            for response in response_data:
                url = response.get('url', '')
                content = response.get('content', '')
                status_code = response.get('status_code', 0)
                headers = response.get('headers', {})
                
                # Skip empty responses or non-text responses
                if not content or not isinstance(content, str):
                    continue
                
                # Analyze for common vulnerabilities
                vulnerability_types = ['xss', 'sqli', 'open_redirect', 'info_disclosure']
                
                for vuln_type in vulnerability_types:
                    analysis = self.analyze_vulnerability(
                        content=content,
                        vulnerability_type=vuln_type,
                        threshold=threshold
                    )
                    
                    if analysis.get('is_vulnerable', False):
                        results.append({
                            'url': url,
                            'vulnerability_type': vuln_type,
                            'is_vulnerable': True,
                            'confidence': analysis.get('confidence', 0.0),
                            'evidence': analysis.get('evidence', ''),
                            'remediation': self._get_remediation_for_vulnerability(vuln_type)
                        })
                
                # Check for sensitive information disclosure
                sensitive_patterns = [
                    r'\b(?:[0-9]{4}[- ]?){3}[0-9]{4}\b',  # Credit card numbers
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
                    r'\bpassword\s*[=:]\s*[^\s;]+',  # Passwords in URL or config
                    r'\bapi[_-]?key\s*[=:]\s*[^\s;]+',  # API keys
                    r'\baccess[_-]?token\s*[=:]\s*[^\s;]+'  # Access tokens
                ]
                
                import re
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        results.append({
                            'url': url,
                            'vulnerability_type': 'info_disclosure',
                            'is_vulnerable': True,
                            'confidence': 0.9,  # High confidence for pattern matches
                            'evidence': f"Sensitive information found: {matches[0]}",
                            'remediation': "Remove sensitive information from responses or encrypt it."
                        })
                        break
        
        except Exception as e:
            self.logger.error(f"Error analyzing web responses: {str(e)}")
        
        return results
    
    def record_web_vulnerability_feedback(self,
                                        url: str,
                                        vulnerability_type: str,
                                        is_vulnerable: bool,
                                        notes: Optional[str] = None) -> Dict[str, Any]:
        """Record feedback for web vulnerability detection.
        
        Args:
            url: The URL where the vulnerability was detected.
            vulnerability_type: Type of vulnerability (e.g., 'xss', 'sqli').
            is_vulnerable: Whether the URL is actually vulnerable.
            notes: Optional notes about the feedback.
            
        Returns:
            Dictionary with the recorded feedback information.
        """
        feedback_data = {
            'url': url,
            'vulnerability_type': vulnerability_type,
            'is_vulnerable': is_vulnerable,
            'timestamp': time.time(),
            'notes': notes or ''
        }
        
        # Save feedback to file
        import json
        import time
        import uuid
        
        feedback_id = str(uuid.uuid4())
        feedback_path = Path(self.feedback_dir) / f"web_{feedback_id}.json"
        
        with open(feedback_path, 'w') as f:
            json.dump(feedback_data, f, indent=2)
        
        self.logger.info(f"Recorded web vulnerability feedback for {url}")
        return feedback_data
    
    def get_payload_generator(self):
        """Get a payload generator for ML-enhanced payloads.
        
        Returns:
            PayloadGenerator instance or None if not available.
        """
        try:
            from phantomfuzzer.payload import PayloadGenerator
            from phantomfuzzer.ml.payload_enhancement import MLPayloadEnhancer
            
            # Create a standard payload generator
            payload_generator = PayloadGenerator()
            
            # Enhance it with ML capabilities
            ml_enhancer = MLPayloadEnhancer(self.default_model)
            payload_generator.set_enhancer(ml_enhancer)
            
            return payload_generator
        except ImportError as e:
            self.logger.error(f"Error creating payload generator: {str(e)}")
            return None
    
    def _get_remediation_for_vulnerability(self, vulnerability_type: str) -> str:
        """Get remediation advice for a specific vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability.
            
        Returns:
            Remediation advice string.
        """
        remediation_map = {
            'xss': "Implement proper input validation and output encoding. Consider using Content-Security-Policy headers.",
            'sqli': "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
            'open_redirect': "Validate all redirect URLs against a whitelist or use indirect reference maps.",
            'csrf': "Implement anti-CSRF tokens in all forms and require them for all state-changing operations.",
            'info_disclosure': "Remove sensitive information from responses. Review error handling to prevent leaking implementation details.",
            'insecure_headers': "Implement security headers such as Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, etc."
        }
        
        return remediation_map.get(vulnerability_type.lower(), "Review the vulnerability and implement appropriate security controls.")
