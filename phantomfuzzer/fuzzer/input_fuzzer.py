#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Input Fuzzer for PhantomFuzzer.

This module provides input field fuzzing capabilities for the PhantomFuzzer project,
focusing on web forms, API parameters, and other input fields.
"""

import random
import string
import json
import urllib.parse
from typing import Dict, List, Tuple, Union, Optional, Any

# Local imports
from phantomfuzzer.fuzzer.fuzzer_base import BaseFuzzer


class InputFuzzer(BaseFuzzer):
    """Input field fuzzer for web forms, API parameters, etc.
    
    This class extends the BaseFuzzer to provide input field-specific fuzzing
    capabilities for various input types including text fields, numbers, dates, etc.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the input fuzzer.
        
        Args:
            config: Configuration parameters for the fuzzer.
        """
        super().__init__(config)
        
        # Input-specific configuration
        self.input_fields = self.config.get('input_fields', [])
        self.input_types = self.config.get('input_types', {})
        self.default_input_type = self.config.get('default_input_type', 'text')
        self.max_field_length = self.config.get('max_field_length', 1000)
        self.include_special_chars = self.config.get('include_special_chars', True)
        self.include_sql_injection = self.config.get('include_sql_injection', True)
        self.include_xss = self.config.get('include_xss', True)
        self.include_format_strings = self.config.get('include_format_strings', True)
        self.include_overflow = self.config.get('include_overflow', True)
        
        # Payload templates
        self.payload_templates = self._load_payload_templates()
        
        self.logger.info(f"Initialized InputFuzzer with {len(self.input_fields)} fields")
    
    def _load_payload_templates(self) -> Dict[str, List[str]]:
        """Load payload templates for different attack types.
        
        Returns:
            Dictionary of payload templates by attack type.
        """
        # Default templates
        templates = {
            'sql_injection': [
                "' OR '1'='1",
                "' OR 1=1 --",
                "\" OR 1=1 --",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            'format_strings': [
                "%s%s%s%s%s%s%s",
                "%x%x%x%x",
                "%n%n%n%n",
                "%d%d%d%d"
            ],
            'overflow': [
                "A" * 100,
                "A" * 1000,
                "A" * 5000
            ],
            'special_chars': [
                "!@#$%^&*()",
                "\\\"'\\\";",
                "\\n\\r\\t",
                "\u0000\u0001\u0002"
            ]
        }
        
        # Add custom templates from config if available
        custom_templates = self.config.get('payload_templates', {})
        for attack_type, payloads in custom_templates.items():
            if attack_type in templates:
                templates[attack_type].extend(payloads)
            else:
                templates[attack_type] = payloads
        
        return templates
    
    def generate_fuzz_data(self) -> Dict[str, Any]:
        """Generate data for input field fuzzing.
        
        Returns:
            Dictionary of field names and fuzzed values.
        """
        fuzz_data = {}
        
        # If no input fields are specified, generate random ones
        if not self.input_fields:
            num_fields = random.randint(1, 5)
            field_names = [f"field_{i}" for i in range(num_fields)]
            for field_name in field_names:
                field_type = self.default_input_type
                fuzz_data[field_name] = self._generate_field_value(field_type)
        else:
            # Generate values for specified fields
            for field in self.input_fields:
                if isinstance(field, dict):
                    field_name = field.get('name')
                    field_type = field.get('type', self.default_input_type)
                else:
                    field_name = field
                    field_type = self.input_types.get(field_name, self.default_input_type)
                
                fuzz_data[field_name] = self._generate_field_value(field_type)
        
        return fuzz_data
    
    def _generate_field_value(self, field_type: str) -> Any:
        """Generate a fuzzed value for a specific field type.
        
        Args:
            field_type: Type of the field (text, number, date, etc.)
            
        Returns:
            Fuzzed value for the field.
        """
        # Decide whether to use a normal value or an attack payload
        use_attack_payload = random.random() < 0.7  # 70% chance to use attack payload
        
        if use_attack_payload:
            return self._generate_attack_payload()
        
        # Generate normal value based on field type
        if field_type == 'text':
            return self._generate_text()
        elif field_type == 'number':
            return self._generate_number()
        elif field_type == 'date':
            return self._generate_date()
        elif field_type == 'email':
            return self._generate_email()
        elif field_type == 'url':
            return self._generate_url()
        elif field_type == 'boolean':
            return random.choice([True, False])
        elif field_type == 'json':
            return self._generate_json()
        else:
            # Default to text for unknown types
            return self._generate_text()
    
    def _generate_attack_payload(self) -> str:
        """Generate an attack payload.
        
        Returns:
            Attack payload as string.
        """
        attack_types = []
        
        if self.include_sql_injection:
            attack_types.append('sql_injection')
        if self.include_xss:
            attack_types.append('xss')
        if self.include_format_strings:
            attack_types.append('format_strings')
        if self.include_overflow:
            attack_types.append('overflow')
        if self.include_special_chars:
            attack_types.append('special_chars')
        
        if not attack_types:
            # If no attack types are enabled, return random text
            return self._generate_text()
        
        # Select a random attack type
        attack_type = random.choice(attack_types)
        
        # Select a random payload from the templates
        payloads = self.payload_templates.get(attack_type, [])
        if not payloads:
            return self._generate_text()
        
        return random.choice(payloads)
    
    def _generate_text(self, min_length: int = 1, max_length: int = 50) -> str:
        """Generate random text.
        
        Args:
            min_length: Minimum length of the text.
            max_length: Maximum length of the text.
            
        Returns:
            Random text string.
        """
        length = random.randint(min_length, max_length)
        chars = string.ascii_letters + string.digits
        if self.include_special_chars:
            chars += string.punctuation
        
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_number(self) -> Union[int, float]:
        """Generate a random number.
        
        Returns:
            Random number (int or float).
        """
        # Decide whether to generate an integer or float
        if random.random() < 0.5:
            # Generate integer
            return random.randint(-1000000, 1000000)
        else:
            # Generate float
            return random.uniform(-1000000.0, 1000000.0)
    
    def _generate_date(self) -> str:
        """Generate a random date string.
        
        Returns:
            Random date string in ISO format.
        """
        year = random.randint(1970, 2030)
        month = random.randint(1, 12)
        day = random.randint(1, 28)  # Simplified to avoid month-specific logic
        
        return f"{year:04d}-{month:02d}-{day:02d}"
    
    def _generate_email(self) -> str:
        """Generate a random email address.
        
        Returns:
            Random email address.
        """
        username = self._generate_text(3, 10)
        domain = self._generate_text(3, 10)
        tld = random.choice(['com', 'org', 'net', 'edu', 'io'])
        
        return f"{username}@{domain}.{tld}"
    
    def _generate_url(self) -> str:
        """Generate a random URL.
        
        Returns:
            Random URL.
        """
        protocol = random.choice(['http', 'https'])
        domain = self._generate_text(3, 10)
        tld = random.choice(['com', 'org', 'net', 'io'])
        path = self._generate_text(0, 10)
        
        url = f"{protocol}://{domain}.{tld}"
        if path:
            url += f"/{path}"
        
        return url
    
    def _generate_json(self, max_depth: int = 2, current_depth: int = 0) -> Dict[str, Any]:
        """Generate a random JSON object.
        
        Args:
            max_depth: Maximum depth of the JSON object.
            current_depth: Current depth in the recursion.
            
        Returns:
            Random JSON-serializable object.
        """
        # Limit recursion depth
        if current_depth >= max_depth:
            return self._generate_text()
        
        # Decide what type of value to generate
        value_type = random.choice(['string', 'number', 'boolean', 'array', 'object'])
        
        if value_type == 'string':
            return self._generate_text()
        elif value_type == 'number':
            return self._generate_number()
        elif value_type == 'boolean':
            return random.choice([True, False])
        elif value_type == 'array':
            # Generate a random array
            array_length = random.randint(0, 5)
            return [self._generate_json(max_depth, current_depth + 1) for _ in range(array_length)]
        elif value_type == 'object':
            # Generate a random object
            obj = {}
            num_keys = random.randint(1, 5)
            for _ in range(num_keys):
                key = self._generate_text(1, 10)
                obj[key] = self._generate_json(max_depth, current_depth + 1)
            return obj
    
    def execute_fuzz(self, fuzz_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute input field fuzzing with the provided data.
        
        Args:
            fuzz_data: Dictionary of field names and fuzzed values.
            
        Returns:
            Dictionary with results of the fuzzing operation.
        """
        if not self.target:
            self.logger.error("No target specified")
            return {'status': 'error', 'message': 'No target specified'}
        
        result = {
            'target': self.target,
            'timestamp': self._get_timestamp(),
            'status': 'unknown',
            'input_data': fuzz_data,
            'response': None,
            'error': None
        }
        
        try:
            # Determine how to send the data based on the target
            if self.target.startswith(('http://', 'https://')):
                # Web form or API endpoint
                self._execute_web_fuzz(fuzz_data, result)
            else:
                # Unsupported target type
                result['status'] = 'error'
                result['error'] = f"Unsupported target type: {self.target}"
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _execute_web_fuzz(self, fuzz_data: Dict[str, Any], result: Dict[str, Any]):
        """Execute web form or API endpoint fuzzing.
        
        Args:
            fuzz_data: Dictionary of field names and fuzzed values.
            result: Result dictionary to update.
        """
        import requests
        
        # Determine HTTP method
        method = self.config.get('http_method', 'POST').upper()
        
        # Determine content type
        content_type = self.config.get('content_type', 'application/x-www-form-urlencoded')
        
        # Prepare headers
        headers = self.config.get('headers', {})
        headers['Content-Type'] = content_type
        
        # Prepare data based on content type
        if content_type == 'application/json':
            data = json.dumps(fuzz_data)
        elif content_type == 'application/x-www-form-urlencoded':
            data = urllib.parse.urlencode(fuzz_data)
        else:
            # Default to raw data
            data = fuzz_data
        
        # Send request
        try:
            response = requests.request(
                method=method,
                url=self.target,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            
            # Update result
            result['status'] = 'success'
            result['response'] = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:1000]  # Limit content size
            }
            
            # Check for potential vulnerabilities
            if response.status_code >= 500:
                result['potential_vulnerability'] = 'Server error - possible vulnerability'
            elif 'error' in response.text.lower() or 'exception' in response.text.lower():
                result['potential_vulnerability'] = 'Error message in response - possible information disclosure'
            
        except requests.exceptions.Timeout:
            result['status'] = 'timeout'
            result['error'] = 'Request timeout'
        except requests.exceptions.RequestException as e:
            result['status'] = 'error'
            result['error'] = str(e)
    
    def _get_timestamp(self):
        """Get current timestamp.
        
        Returns:
            Current timestamp as float.
        """
        import time
        return time.time()