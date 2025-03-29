#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ML-enhanced web scanner implementation for PhantomFuzzer.

This module extends the WebScanner with machine learning capabilities
to improve detection accuracy and identify vulnerabilities that traditional
signature-based scanning might miss.
"""

import os
import sys
import time
import json
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from pathlib import Path

# Import from phantomfuzzer package
from phantomfuzzer.scanner.web import WebScanner
from phantomfuzzer.scanner.base import ScanResult
from phantomfuzzer.scanner.base import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from phantomfuzzer.utils.logging import get_module_logger
from phantomfuzzer.utils.helper import (
    print_section, print_info, print_success, print_warning, print_error, 
    print_debug, print_verbose, print_progress
)

# Import ML components
try:
    from phantomfuzzer.ml.integration import MLIntegration
except ImportError as e:
    print(f"Error importing ML integration: {e}")

# ML-specific vulnerability types
VULN_ML_ANOMALY = 'ML-Detected Anomaly'
VULN_PATTERN_MATCH = 'Suspicious Pattern Match'
VULN_ML_ENHANCED_XSS = 'ML-Enhanced XSS Detection'
VULN_ML_ENHANCED_SQLI = 'ML-Enhanced SQL Injection Detection'


class MLEnhancedWebScanner(WebScanner):
    """ML-enhanced web scanner implementation.
    
    This class extends the WebScanner with machine learning capabilities
    to improve detection accuracy and identify vulnerabilities that traditional
    signature-based scanning might miss.
    """
    
    def _init_scanner(self) -> None:
        """Initialize scanner-specific settings.
        
        This method is called by the BaseScanner constructor.
        """
        # Initialize the base web scanner
        super()._init_scanner()
        
        # Initialize ML-specific settings
        self.logger = get_module_logger('ml_enhanced_web_scanner')
        
        # ML configuration
        self.ml_threshold = self.config.get('ml_threshold', 0.6)
        self.ml_model_name = self.config.get('ml_model_name', None)
        self.ml_auto_feedback = self.config.get('ml_auto_feedback', False)
        
        # Enhanced payloads
        self.ml_enhanced_payloads = {
            'xss': [],
            'sqli': [],
            'open_redirect': [],
            'csrf': []
        }
        
        # Initialize ML integration if enabled
        self.ml_integration = None
        if self.ml_enabled:
            try:
                # Get ML configuration from config
                ml_config = self.config_manager.get_ml_config() if hasattr(self, 'config_manager') else {}
                
                # Initialize ML integration
                self.ml_integration = MLIntegration(config=ml_config)
                self.logger.info("ML integration initialized")
                print_info("ML integration initialized")
                
                # Check if we have a default model
                if hasattr(self.ml_integration, 'default_model') and self.ml_integration.default_model:
                    self.logger.info(f"Using default ML model: {self.ml_integration.default_model}")
                    print_info(f"Using default ML model: {self.ml_integration.default_model}")
                else:
                    self.logger.warning("No default ML model found. ML-based scanning may be limited.")
                    print_warning("No default ML model found. ML-based scanning may be limited.")
                
                # Generate ML-enhanced payloads
                self._generate_ml_enhanced_payloads()
            except Exception as e:
                error_msg = f"Error initializing ML integration: {str(e)}"
                self.logger.error(error_msg)
                print_error(error_msg)
                self.ml_enabled = False
                # Continue with standard scanning without ML enhancements
    
    def _apply_ml_enhancements(self) -> None:
        """Apply ML enhancements for web scanning.
        
        This method overrides the base implementation to apply web-specific
        ML enhancements.
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
        
        # Apply web-specific ML settings
        self.use_ml_for_payload_generation = ml_config.get('use_for_payload_generation', True)
        self.use_ml_for_vulnerability_detection = ml_config.get('use_for_vulnerability_detection', True)
        
        self.logger.info(f"ML enhancements applied with threshold: {self.ml_threshold}")
    
    def _generate_ml_enhanced_payloads(self) -> None:
        """Generate ML-enhanced payloads for vulnerability testing."""
        if not self.ml_enabled or not self.ml_integration:
            return
        
        try:
            # Check if the get_payload_generator method exists
            if not hasattr(self.ml_integration, 'get_payload_generator'):
                self.logger.warning("ML integration does not support payload generation")
                # Fall back to default payloads
                self._set_default_payloads()
                return
            
            # Get payload generator from ML integration
            payload_generator = self.ml_integration.get_payload_generator()
            if not payload_generator:
                self.logger.warning("ML payload generator not available")
                # Fall back to default payloads
                self._set_default_payloads()
                return
            
            # Generate enhanced XSS payloads
            try:
                self.ml_enhanced_payloads['xss'] = payload_generator.generate_payloads(
                    category='xss',
                    count=10,
                    context={'advanced': True}
                )
            except Exception as e:
                self.logger.warning(f"Error generating XSS payloads: {str(e)}")
                self.ml_enhanced_payloads['xss'] = self._get_default_payloads('xss')
            
            # Generate enhanced SQLi payloads
            try:
                self.ml_enhanced_payloads['sqli'] = payload_generator.generate_payloads(
                    category='sql_injection',
                    count=10,
                    context={'advanced': True}
                )
            except Exception as e:
                self.logger.warning(f"Error generating SQLi payloads: {str(e)}")
                self.ml_enhanced_payloads['sqli'] = self._get_default_payloads('sqli')
            
            # Generate enhanced open redirect payloads
            try:
                self.ml_enhanced_payloads['open_redirect'] = payload_generator.generate_payloads(
                    category='open_redirect',
                    count=5,
                    context={'advanced': True}
                )
            except Exception as e:
                self.logger.warning(f"Error generating open redirect payloads: {str(e)}")
                self.ml_enhanced_payloads['open_redirect'] = self._get_default_payloads('open_redirect')
            
            # Generate enhanced CSRF payloads
            try:
                self.ml_enhanced_payloads['csrf'] = payload_generator.generate_payloads(
                    category='csrf',
                    count=5,
                    context={'advanced': True}
                )
            except Exception as e:
                self.logger.warning(f"Error generating CSRF payloads: {str(e)}")
                self.ml_enhanced_payloads['csrf'] = self._get_default_payloads('csrf')
            
            self.logger.info("Generated ML-enhanced payloads for vulnerability testing")
        except Exception as e:
            self.logger.error(f"Error generating ML-enhanced payloads: {str(e)}")
            # Fall back to default payloads
            self._set_default_payloads()
    
    def _set_default_payloads(self) -> None:
        """Set default payloads when ML-enhanced payloads cannot be generated."""
        self.ml_enhanced_payloads['xss'] = self._get_default_payloads('xss')
        self.ml_enhanced_payloads['sqli'] = self._get_default_payloads('sqli')
        self.ml_enhanced_payloads['open_redirect'] = self._get_default_payloads('open_redirect')
        self.ml_enhanced_payloads['csrf'] = self._get_default_payloads('csrf')
        self.logger.info("Using default payloads for vulnerability testing")
    
    def _get_default_payloads(self, category: str) -> List[str]:
        """Get default payloads for a specific category.
        
        Args:
            category: The vulnerability category.
            
        Returns:
            List of default payloads.
        """
        default_payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '"<script>alert(1)</script>',
                '\'\';alert(1);//'
            ],
            'sqli': [
                "' OR 1=1 --",
                "\" OR 1=1 --",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --"
            ],
            'open_redirect': [
                'https://evil.com',
                '//evil.com',
                '/\\evil.com',
                'javascript:document.location="https://evil.com"',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
            ],
            'csrf': [
                '<form action="https://victim.com/change_password" method="POST">',
                '<img src="https://victim.com/api/delete?id=123">',
                '<script>fetch("https://victim.com/api/update", {method: "POST", body: JSON.stringify({data: "malicious"})})</script>'
            ]
        }
        
        return default_payloads.get(category, [])
    
    def _scan_for_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Scan for vulnerabilities in the discovered URLs and forms.
        
        This method overrides the base implementation to add ML-enhanced
        vulnerability detection.
        
        Args:
            scan_result: The scan result to update.
        """
        # First, perform standard vulnerability scanning
        super()._scan_for_vulnerabilities(scan_result)
        
        # Then, perform ML-enhanced vulnerability scanning if enabled
        if self.ml_enabled and self.ml_integration and self.use_ml_for_vulnerability_detection:
            self.logger.info("Performing ML-enhanced vulnerability scanning")
            print_section("ML-Enhanced Vulnerability Scanning")
            
            # Scan forms with ML-enhanced payloads
            self._scan_forms_with_ml_enhanced_payloads(scan_result)
            
            # Analyze response patterns for potential vulnerabilities
            self._analyze_response_patterns(scan_result)
    
    def _scan_forms_with_ml_enhanced_payloads(self, scan_result: ScanResult) -> None:
        """Scan forms using ML-enhanced payloads.
        
        Args:
            scan_result: The scan result to update.
        """
        if not self.forms_found:
            return
        
        print_info(f"Scanning {len(self.forms_found)} forms with ML-enhanced payloads...")
        
        for form in self.forms_found:
            # Skip forms that have already been tested
            if form.get('tested', False):
                continue
            
            form_url = form.get('action', '')
            form_method = form.get('method', 'GET')
            form_inputs = form.get('inputs', [])
            
            # Skip forms with no inputs
            if not form_inputs:
                continue
            
            # Prepare form data
            form_data = {}
            for input_field in form_inputs:
                input_name = input_field.get('name', '')
                input_type = input_field.get('type', '')
                
                # Skip submit buttons and hidden fields
                if input_type in ['submit', 'button', 'image']:
                    continue
                
                # Use appropriate test values based on input type
                if input_type == 'email':
                    form_data[input_name] = 'test@example.com'
                elif input_type == 'password':
                    form_data[input_name] = 'Password123!'
                elif input_type == 'number':
                    form_data[input_name] = '123'
                else:
                    form_data[input_name] = 'test'
            
            # Test for XSS with ML-enhanced payloads
            if self.enable_xss and self.ml_enhanced_payloads['xss']:
                self._test_form_for_ml_enhanced_xss(form, form_data, scan_result)
            
            # Test for SQLi with ML-enhanced payloads
            if self.enable_sqli and self.ml_enhanced_payloads['sqli']:
                self._test_form_for_ml_enhanced_sqli(form, form_data, scan_result)
            
            # Mark form as tested
            form['tested'] = True
    
    def _test_form_for_ml_enhanced_xss(self, form: Dict[str, Any], form_data: Dict[str, str], scan_result: ScanResult) -> None:
        """Test a form for XSS vulnerabilities using ML-enhanced payloads.
        
        Args:
            form: The form information.
            form_data: The form data to submit.
            scan_result: The scan result to update.
        """
        form_url = form.get('action', '')
        form_method = form.get('method', 'GET')
        
        # Test each input field with ML-enhanced XSS payloads
        for input_name in form_data.keys():
            for payload in self.ml_enhanced_payloads['xss']:
                # Skip empty payloads
                if not payload:
                    continue
                
                # Create a copy of the form data with the payload
                test_data = form_data.copy()
                test_data[input_name] = payload
                
                try:
                    # Submit the form
                    if form_method.upper() == 'GET':
                        response = self._make_request(form_url, method='GET', params=test_data)
                    else:
                        response = self._make_request(form_url, method='POST', data=test_data)
                    
                    # Check if the payload is reflected in the response
                    if response and payload in response.text:
                        # Use ML to analyze if the payload execution is likely
                        if self.ml_integration:
                            is_vulnerable = self._analyze_xss_response(response.text, payload)
                            if is_vulnerable:
                                scan_result.add_vulnerability(
                                    name=VULN_ML_ENHANCED_XSS,
                                    description=f"ML-enhanced XSS vulnerability detected in form input: {input_name}",
                                    severity=SEVERITY_HIGH,
                                    location=f"{form_url} (input: {input_name})",
                                    evidence=f"Payload: {payload}",
                                    remediation="Implement proper input validation and output encoding."
                                )
                                self.logger.info(f"ML-enhanced XSS vulnerability found in {form_url}, input: {input_name}")
                                print_warning(f"ML-enhanced XSS vulnerability found in {form_url}, input: {input_name}")
                                
                                # Record feedback for ML model
                                if self.ml_auto_feedback:
                                    self._record_vulnerability_feedback(form_url, 'xss', True)
                                
                                # Only report one vulnerability per input field
                                break
                
                except Exception as e:
                    self.logger.debug(f"Error testing form for ML-enhanced XSS: {str(e)}")
    
    def _test_form_for_ml_enhanced_sqli(self, form: Dict[str, Any], form_data: Dict[str, str], scan_result: ScanResult) -> None:
        """Test a form for SQL injection vulnerabilities using ML-enhanced payloads.
        
        Args:
            form: The form information.
            form_data: The form data to submit.
            scan_result: The scan result to update.
        """
        form_url = form.get('action', '')
        form_method = form.get('method', 'GET')
        
        # Test each input field with ML-enhanced SQLi payloads
        for input_name in form_data.keys():
            for payload in self.ml_enhanced_payloads['sqli']:
                # Skip empty payloads
                if not payload:
                    continue
                
                # Create a copy of the form data with the payload
                test_data = form_data.copy()
                test_data[input_name] = payload
                
                try:
                    # Submit the form
                    if form_method.upper() == 'GET':
                        response = self._make_request(form_url, method='GET', params=test_data)
                    else:
                        response = self._make_request(form_url, method='POST', data=test_data)
                    
                    # Check for SQL error patterns in the response
                    if response:
                        # Use ML to analyze if the response indicates SQL injection
                        if self.ml_integration:
                            is_vulnerable = self._analyze_sqli_response(response.text, payload)
                            if is_vulnerable:
                                scan_result.add_vulnerability(
                                    name=VULN_ML_ENHANCED_SQLI,
                                    description=f"ML-enhanced SQL injection vulnerability detected in form input: {input_name}",
                                    severity=SEVERITY_HIGH,
                                    location=f"{form_url} (input: {input_name})",
                                    evidence=f"Payload: {payload}",
                                    remediation="Use parameterized queries or prepared statements."
                                )
                                self.logger.info(f"ML-enhanced SQL injection vulnerability found in {form_url}, input: {input_name}")
                                print_warning(f"ML-enhanced SQL injection vulnerability found in {form_url}, input: {input_name}")
                                
                                # Record feedback for ML model
                                if self.ml_auto_feedback:
                                    self._record_vulnerability_feedback(form_url, 'sqli', True)
                                
                                # Only report one vulnerability per input field
                                break
                
                except Exception as e:
                    self.logger.debug(f"Error testing form for ML-enhanced SQLi: {str(e)}")
    
    def _analyze_response_patterns(self, scan_result: ScanResult) -> None:
        """Analyze response patterns for potential vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        if not hasattr(self, 'responses_collected') or not self.responses_collected:
            return
        
        print_info("Analyzing response patterns with ML...")
        
        try:
            # Extract response data for analysis
            response_data = []
            for url, response_info in self.responses_collected.items():
                if 'content' in response_info and response_info['content']:
                    response_data.append({
                        'url': url,
                        'status_code': response_info.get('status_code', 0),
                        'content': response_info['content'],
                        'headers': response_info.get('headers', {})
                    })
            
            # Skip if no response data available
            if not response_data:
                return
            
            # Use ML to analyze response patterns
            if self.ml_integration:
                analysis_results = self._analyze_response_data(response_data)
                
                # Process analysis results
                for result in analysis_results:
                    if result.get('is_vulnerable', False):
                        vuln_type = result.get('vulnerability_type', 'Unknown')
                        url = result.get('url', '')
                        confidence = result.get('confidence', 0)
                        evidence = result.get('evidence', '')
                        
                        # Determine severity based on confidence
                        severity = SEVERITY_MEDIUM
                        if confidence > 0.8:
                            severity = SEVERITY_HIGH
                        elif confidence < 0.6:
                            severity = SEVERITY_LOW
                        
                        # Add vulnerability to scan result
                        scan_result.add_vulnerability(
                            name=f"ML-Detected {vuln_type}",
                            description=f"Machine learning detected potential {vuln_type} vulnerability",
                            severity=severity,
                            location=url,
                            evidence=evidence,
                            remediation=result.get('remediation', 'Review the vulnerability and implement appropriate security controls.')
                        )
                        
                        self.logger.info(f"ML detected {vuln_type} vulnerability in {url} with confidence {confidence:.2f}")
                        print_warning(f"ML detected {vuln_type} vulnerability in {url} with confidence {confidence:.2f}")
        
        except Exception as e:
            self.logger.error(f"Error analyzing response patterns: {str(e)}")
    
    def _analyze_xss_response(self, response_text: str, payload: str) -> bool:
        """Analyze response for XSS vulnerability using ML.
        
        Args:
            response_text: The response text to analyze.
            payload: The XSS payload used.
            
        Returns:
            True if the response indicates XSS vulnerability, False otherwise.
        """
        try:
            # Use ML integration to analyze XSS vulnerability
            analysis_result = self.ml_integration.analyze_vulnerability(
                content=response_text,
                vulnerability_type='xss',
                payload=payload,
                threshold=self.ml_threshold
            )
            
            return analysis_result.get('is_vulnerable', False)
        except Exception as e:
            self.logger.error(f"Error analyzing XSS response: {str(e)}")
            return False
    
    def _analyze_sqli_response(self, response_text: str, payload: str) -> bool:
        """Analyze response for SQL injection vulnerability using ML.
        
        Args:
            response_text: The response text to analyze.
            payload: The SQL injection payload used.
            
        Returns:
            True if the response indicates SQL injection vulnerability, False otherwise.
        """
        try:
            # Use ML integration to analyze SQL injection vulnerability
            analysis_result = self.ml_integration.analyze_vulnerability(
                content=response_text,
                vulnerability_type='sqli',
                payload=payload,
                threshold=self.ml_threshold
            )
            
            return analysis_result.get('is_vulnerable', False)
        except Exception as e:
            self.logger.error(f"Error analyzing SQLi response: {str(e)}")
            return False
    
    def _analyze_response_data(self, response_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze response data for potential vulnerabilities using ML.
        
        Args:
            response_data: List of response data to analyze.
            
        Returns:
            List of analysis results.
        """
        try:
            # Use ML integration to analyze response data
            analysis_results = self.ml_integration.analyze_web_responses(
                response_data=response_data,
                threshold=self.ml_threshold
            )
            
            return analysis_results
        except Exception as e:
            self.logger.error(f"Error analyzing response data: {str(e)}")
            return []
    
    def _record_vulnerability_feedback(self, url: str, vulnerability_type: str, is_vulnerable: bool) -> None:
        """Record feedback for ML model.
        
        Args:
            url: The URL where the vulnerability was found.
            vulnerability_type: The type of vulnerability.
            is_vulnerable: Whether the URL is vulnerable.
        """
        try:
            if self.ml_integration:
                self.ml_integration.record_web_vulnerability_feedback(
                    url=url,
                    vulnerability_type=vulnerability_type,
                    is_vulnerable=is_vulnerable
                )
        except Exception as e:
            self.logger.error(f"Error recording vulnerability feedback: {str(e)}")
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Perform a web scan on the target with ML enhancements.
        
        Args:
            target: The target URL to scan.
            options: Optional scan options.
        
        Returns:
            The scan result.
        """
        # Initialize responses collection for ML analysis
        self.responses_collected = {}
        
        # Perform the scan with ML enhancements
        print_section("ML-Enhanced Web Scanning")
        print_info(f"Target: {target}")
        print_info("ML enhancements active - using machine learning for improved vulnerability detection")
        
        # Call the parent scan method
        scan_result = super().scan(target, options)
        
        # Add ML-specific information to scan result
        if self.ml_enabled and self.ml_integration:
            scan_result.scan_info['ml_enhanced'] = True
            scan_result.scan_info['ml_model'] = self.ml_integration.default_model
            
            # Add ML statistics if available
            if hasattr(self, 'ml_stats'):
                scan_result.scan_info['ml_stats'] = self.ml_stats
        
        return scan_result
