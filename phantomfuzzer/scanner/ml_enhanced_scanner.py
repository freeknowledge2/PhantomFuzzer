#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ML-enhanced scanner implementation for PhantomFuzzer.

This module extends the FileScanner with machine learning capabilities
to improve detection accuracy and identify anomalies that traditional
signature-based scanning might miss.
"""

import os
import sys
import json
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from pathlib import Path

# Import from phantomfuzzer package
from phantomfuzzer.scanner.file_scanner import FileScanner
from phantomfuzzer.scanner.base import ScanResult
from phantomfuzzer.scanner.base import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from phantomfuzzer.utils.logging import get_module_logger
from phantomfuzzer.utils.helper import print_section, print_info, print_success, print_warning, print_error, print_debug

# Import ML components
from phantomfuzzer.ml import MLIntegration
from phantomfuzzer.ml.models import PatternRecognizer

# ML-specific vulnerability types
VULN_ML_ANOMALY = 'ML-Detected Anomaly'
VULN_PATTERN_MATCH = 'Suspicious Pattern Match'


class MLEnhancedScanner(FileScanner):
    """ML-enhanced file scanner implementation.
    
    This class extends the FileScanner with machine learning capabilities
    to improve detection accuracy and identify anomalies that traditional
    signature-based scanning might miss.
    """
    
    def _init_scanner(self):
        """Initialize scanner-specific settings.
        
        This method is called by the BaseScanner constructor.
        """
        # Initialize the base file scanner
        super()._init_scanner()
        
        # Initialize ML-specific settings
        self.logger = get_module_logger('ml_enhanced_scanner')
        
        # ML configuration
        self.ml_threshold = self.config.get('ml_threshold', 0.6)
        self.ml_model_name = self.config.get('ml_model_name', None)
        self.ml_auto_feedback = self.config.get('ml_auto_feedback', False)
        
        # Initialize ML integration if enabled
        self.ml_integration = None
        if self.ml_enabled:
            try:
                self.ml_integration = MLIntegration()
                self.logger.info("ML integration initialized")
                print_info("ML integration initialized")
                
                # Check if we have a default model
                if self.ml_integration.default_model:
                    self.logger.info(f"Using default ML model: {self.ml_integration.default_model}")
                    print_info(f"Using default ML model: {self.ml_integration.default_model}")
                else:
                    self.logger.warning("No default ML model found. ML-based scanning may be limited.")
                    print_warning("No default ML model found. ML-based scanning may be limited.")
            except Exception as e:
                error_msg = f"Error initializing ML integration: {str(e)}"
                self.logger.error(error_msg)
                print_error(error_msg)
                self.ml_enabled = False
    
    def _apply_ml_enhancements(self):
        """Apply ML enhancements.
        
        This method applies ML enhancements to the scanner to improve
        its effectiveness and accuracy.
        """
        super()._apply_ml_enhancements()
        
        if self.ml_enabled and self.ml_integration:
            print_section("Applying ML Enhancements")
            print_info(f"ML threshold: {self.ml_threshold}")
            if self.ml_model_name:
                print_info(f"Using custom ML model: {self.ml_model_name}")
            
            # Load any specific models if needed
            if self.ml_model_name and self.ml_model_name != self.ml_integration.default_model:
                try:
                    self.ml_integration.load_model(self.ml_model_name)
                    print_success(f"Successfully loaded model: {self.ml_model_name}")
                except Exception as e:
                    print_error(f"Failed to load model {self.ml_model_name}: {str(e)}")
        else:
            print_debug("ML enhancements not applied (disabled or initialization failed)")
        
        if not self.ml_enabled or not self.ml_integration:
            self.logger.warning("ML enhancements are disabled or ML integration failed to initialize")
            return
        
        # Get ML configuration
        ml_config = self.config_manager.get_ml_config()
        
        # Update ML settings from config
        self.ml_threshold = ml_config.get('threshold', self.ml_threshold)
        self.ml_model_name = ml_config.get('model_name', self.ml_model_name)
        self.ml_auto_feedback = ml_config.get('auto_feedback', self.ml_auto_feedback)
        
        self.logger.info(f"ML enhancements applied with threshold: {self.ml_threshold}")
    
    def _scan_file(self, file_path: Path, scan_result: ScanResult) -> None:
        """Scan a single file with ML enhancements.
        
        Args:
            file_path: The file to scan.
            scan_result: The scan result to update.
        """
        # Perform standard file scanning
        super()._scan_file(file_path, scan_result)
        
        # Apply ML-based scanning if enabled
        if self.ml_enabled and self.ml_integration:
            self._scan_file_with_ml(file_path, scan_result)
    
    def _scan_file_with_ml(self, file_path: Path, scan_result: ScanResult) -> None:
        """Scan a file using machine learning.
        
        Args:
            file_path: The file to scan.
            scan_result: The scan result to update.
        """
        try:
            self.logger.debug(f"Performing ML-based analysis on: {file_path}")
            
            # Detect anomalies using ML
            ml_result = self.ml_integration.detect_file_anomalies(
                file_path=str(file_path),
                model_name=self.ml_model_name
            )
            
            # Add ML result to file info
            if 'files' in scan_result.scan_info and len(scan_result.scan_info['files']) > 0:
                for file_info in scan_result.scan_info['files']:
                    if file_info.get('path') == str(file_path):
                        file_info['ml_analysis'] = ml_result
                        break
            
            # Check if the file is an anomaly
            if ml_result.get('is_anomaly', False):
                anomaly_score = ml_result.get('anomaly_score', 0)
                threshold = ml_result.get('threshold', self.ml_threshold)
                
                # Determine severity based on anomaly score
                severity = SEVERITY_LOW
                if anomaly_score > threshold + 0.3:
                    severity = SEVERITY_HIGH
                elif anomaly_score > threshold + 0.15:
                    severity = SEVERITY_MEDIUM
                
                # Add vulnerability to scan result
                scan_result.add_vulnerability(
                    name=VULN_ML_ANOMALY,
                    description=f"Machine learning model detected an anomaly with score {anomaly_score:.4f} (threshold: {threshold:.4f})",
                    severity=severity,
                    location=str(file_path),
                    evidence=f"Anomaly score: {anomaly_score:.4f}, Threshold: {threshold:.4f}",
                    remediation="Review the file for potential security issues or malicious content."
                )
                
                self.logger.info(f"ML detected anomaly in {file_path} with score {anomaly_score:.4f}")
                
                # Add detailed ML insights if available
                if 'insights' in ml_result:
                    for insight in ml_result['insights']:
                        scan_result.add_vulnerability(
                            name=VULN_PATTERN_MATCH,
                            description=f"Suspicious pattern detected: {insight.get('pattern', 'Unknown')}",
                            severity=SEVERITY_MEDIUM,
                            location=f"{file_path}:{insight.get('line', 'unknown')}",
                            evidence=insight.get('evidence', 'N/A'),
                            remediation=insight.get('recommendation', 'Review the suspicious pattern.')
                        )
            
            # Provide automatic feedback if enabled
            if self.ml_auto_feedback and 'vulnerabilities' in scan_result.__dict__:
                # Check if traditional scanning found vulnerabilities
                traditional_vulnerabilities = [v for v in scan_result.vulnerabilities 
                                              if v.get('name') not in [VULN_ML_ANOMALY, VULN_PATTERN_MATCH]]
                
                # If ML detected an anomaly but traditional scanning didn't find vulnerabilities,
                # or vice versa, provide feedback
                ml_detected_anomaly = ml_result.get('is_anomaly', False)
                traditional_detected_vulnerability = len(traditional_vulnerabilities) > 0
                
                if ml_detected_anomaly != traditional_detected_vulnerability:
                    is_correct = ml_detected_anomaly == traditional_detected_vulnerability
                    notes = None
                    
                    if ml_detected_anomaly and not traditional_detected_vulnerability:
                        notes = "ML detected an anomaly, but traditional scanning found no vulnerabilities. Possible false positive."
                    elif not ml_detected_anomaly and traditional_detected_vulnerability:
                        notes = "Traditional scanning found vulnerabilities, but ML did not detect an anomaly. Possible false negative."
                    
                    # Record feedback
                    self.ml_integration.record_feedback(
                        file_path=str(file_path),
                        prediction=ml_result,
                        is_correct=is_correct,
                        notes=notes
                    )
                    
                    self.logger.debug(f"Automatic feedback recorded for {file_path}")
        
        except Exception as e:
            self.logger.error(f"Error in ML-based scanning of {file_path}: {str(e)}")
            
            # Add error information to scan result
            if 'ml_errors' not in scan_result.scan_info:
                scan_result.scan_info['ml_errors'] = []
            
            scan_result.scan_info['ml_errors'].append({
                'file': str(file_path),
                'error': str(e)
            })
    
    def train_model_from_scan_results(self, scan_results: List[ScanResult], model_name: Optional[str] = None) -> Optional[str]:
        """Train a new ML model using past scan results.
        
        Args:
            scan_results: List of scan results to use for training.
            model_name: Optional name for the new model.
            
        Returns:
            The name of the trained model, or None if training failed.
        """
        if not self.ml_enabled or not self.ml_integration:
            error_msg = "ML is not enabled or ML integration failed to initialize"
            self.logger.error(error_msg)
            print_error(error_msg)
            return None
        
        try:
            self.logger.info("Training new ML model from scan results")
            print_section("Training New ML Model")
            print_info("Collecting training data from scan results...")
            
            # Collect benign and malicious files from scan results
            benign_files = []
            malicious_files = []
            
            for result in scan_results:
                if 'files' not in result.scan_info:
                    continue
                
                for file_info in result.scan_info['files']:
                    file_path = file_info.get('path')
                    if not file_path or not os.path.exists(file_path):
                        continue
                    
                    # Check if the file has vulnerabilities
                    has_vulnerabilities = False
                    for vuln in result.vulnerabilities:
                        if vuln.get('location') == file_path:
                            has_vulnerabilities = True
                            break
                    
                    if has_vulnerabilities:
                        malicious_files.append(file_path)
                    else:
                        benign_files.append(file_path)
            
            collection_msg = f"Collected {len(benign_files)} benign files and {len(malicious_files)} malicious files for training"
            self.logger.info(collection_msg)
            print_info(collection_msg)
            
            if len(benign_files) == 0:
                error_msg = "No benign files found for training"
                self.logger.error(error_msg)
                print_error(error_msg)
                return None
            
            # Train the model
            new_model_name = self.ml_integration.train_model(
                benign_dirs=None,  # We're providing file lists directly
                malicious_dirs=None,
                benign_files=benign_files,
                malicious_files=malicious_files,
                model_name=model_name
            )
            
            if new_model_name:
                self.logger.info(f"Successfully trained new model: {new_model_name}")
                
                # Set as default model if requested
                self.ml_model_name = new_model_name
                
                return new_model_name
            else:
                self.logger.error("Failed to train new model")
                return None
                
        except Exception as e:
            self.logger.error(f"Error training model from scan results: {str(e)}")
            return None
