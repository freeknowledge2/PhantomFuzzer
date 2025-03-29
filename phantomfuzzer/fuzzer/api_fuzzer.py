#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Fuzzer for PhantomFuzzer.

This module provides API-specific fuzzing capabilities for the PhantomFuzzer project,
focusing on REST, GraphQL, and other API types.
"""

import json
import random
import urllib.parse
from typing import Dict, List, Tuple, Union, Optional, Any

# Local imports
from phantomfuzzer.fuzzer.fuzzer_base import BaseFuzzer
from phantomfuzzer.fuzzer.input_fuzzer import InputFuzzer


class ApiFuzzer(BaseFuzzer):
    """API fuzzer for REST, GraphQL, and other API types.
    
    This class extends the BaseFuzzer to provide API-specific fuzzing
    capabilities for various API types including REST, GraphQL, etc.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the API fuzzer.
        
        Args:
            config: Configuration parameters for the fuzzer.
        """
        super().__init__(config)
        
        # API-specific configuration
        self.api_type = self.config.get('api_type', 'rest').lower()
        self.endpoints = self.config.get('endpoints', [])
        self.auth_type = self.config.get('auth_type', None)
        self.auth_credentials = self.config.get('auth_credentials', {})
        self.headers = self.config.get('headers', {})
        self.base_url = self.config.get('base_url', None)
        
        # Initialize input fuzzer for parameter fuzzing
        input_fuzzer_config = self.config.get('input_fuzzer_config', {})
        self.input_fuzzer = InputFuzzer(input_fuzzer_config)
        
        # API schema if available
        self.api_schema = self.config.get('api_schema', {})
        
        self.logger.info(f"Initialized ApiFuzzer for {self.api_type} API")
    
    def set_target(self, target: str) -> None:
        """Set the target API base URL for fuzzing.
        
        Args:
            target: Target API base URL.
        """
        self.target = target
        self.base_url = target
        self.logger.info(f"Target API set to: {target}")
    
    def generate_fuzz_data(self) -> Dict[str, Any]:
        """Generate data for API fuzzing.
        
        Returns:
            Dictionary with endpoint, method, headers, and parameters.
        """
        # Select a random endpoint or generate one
        if self.endpoints and random.random() < 0.8:  # 80% chance to use a known endpoint
            endpoint_info = random.choice(self.endpoints)
            if isinstance(endpoint_info, dict):
                endpoint = endpoint_info.get('path', '/')
                method = endpoint_info.get('method', 'GET')
                params_info = endpoint_info.get('params', [])
            else:
                endpoint = endpoint_info
                method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
                params_info = []
        else:
            # Generate a random endpoint
            endpoint = self._generate_random_endpoint()
            method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            params_info = []
        
        # Generate parameters
        if params_info:
            # Use known parameters
            self.input_fuzzer.input_fields = params_info
            parameters = self.input_fuzzer.generate_fuzz_data()
        else:
            # Generate random parameters
            num_params = random.randint(0, 5)
            parameters = {f"param_{i}": self._generate_param_value() for i in range(num_params)}
        
        # Generate headers
        headers = self.headers.copy()
        if random.random() < 0.3:  # 30% chance to fuzz headers
            headers = self._fuzz_headers(headers)
        
        # Add authentication if configured
        auth_headers = self._generate_auth_headers()
        headers.update(auth_headers)
        
        return {
            'endpoint': endpoint,
            'method': method,
            'headers': headers,
            'parameters': parameters
        }
    
    def _generate_random_endpoint(self) -> str:
        """Generate a random API endpoint.
        
        Returns:
            Random endpoint path.
        """
        # Generate path segments
        num_segments = random.randint(1, 4)
        segments = []
        
        for _ in range(num_segments):
            segment_type = random.choice(['resource', 'id', 'action'])
            
            if segment_type == 'resource':
                # Resource names like 'users', 'products', etc.
                resources = ['users', 'products', 'orders', 'items', 'categories', 'posts', 'comments', 'profiles']
                segments.append(random.choice(resources))
            elif segment_type == 'id':
                # IDs like '123', 'abc-def', etc.
                id_type = random.choice(['numeric', 'uuid', 'slug'])
                if id_type == 'numeric':
                    segments.append(str(random.randint(1, 9999)))
                elif id_type == 'uuid':
                    import uuid
                    segments.append(str(uuid.uuid4()))
                else:  # slug
                    import string
                    slug_length = random.randint(5, 15)
                    slug = ''.join(random.choice(string.ascii_lowercase + '-') for _ in range(slug_length))
                    segments.append(slug)
            else:  # action
                # Actions like 'create', 'update', etc.
                actions = ['create', 'update', 'delete', 'activate', 'deactivate', 'search', 'filter', 'sort']
                segments.append(random.choice(actions))
        
        # Combine segments into a path
        path = '/' + '/'.join(segments)
        
        # Add query parameters for GET requests
        if random.random() < 0.5:  # 50% chance to add query parameters
            num_params = random.randint(1, 3)
            query_params = {}
            for _ in range(num_params):
                param_name = random.choice(['limit', 'offset', 'page', 'sort', 'filter', 'include', 'fields'])
                param_value = self._generate_param_value()
                query_params[param_name] = param_value
            
            # Convert to query string
            query_string = urllib.parse.urlencode(query_params)
            path += '?' + query_string
        
        return path
    
    def _generate_param_value(self) -> Any:
        """Generate a random parameter value.
        
        Returns:
            Random parameter value.
        """
        param_type = random.choice(['string', 'number', 'boolean', 'array', 'object'])
        
        if param_type == 'string':
            return self.input_fuzzer._generate_text()
        elif param_type == 'number':
            return self.input_fuzzer._generate_number()
        elif param_type == 'boolean':
            return random.choice([True, False])
        elif param_type == 'array':
            # Generate a random array
            array_length = random.randint(0, 3)
            return [self._generate_param_value() for _ in range(array_length)]
        elif param_type == 'object':
            # Generate a random object
            obj = {}
            num_keys = random.randint(1, 3)
            for _ in range(num_keys):
                key = self.input_fuzzer._generate_text(1, 10)
                obj[key] = self._generate_param_value()
            return obj
    
    def _fuzz_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Fuzz HTTP headers.
        
        Args:
            headers: Original headers.
            
        Returns:
            Fuzzed headers.
        """
        fuzzed_headers = headers.copy()
        
        # Randomly modify, add, or remove headers
        actions = ['modify', 'add', 'remove']
        action = random.choice(actions)
        
        if action == 'modify' and fuzzed_headers:
            # Modify an existing header
            header_to_modify = random.choice(list(fuzzed_headers.keys()))
            fuzzed_headers[header_to_modify] = self.input_fuzzer._generate_text()
        elif action == 'add':
            # Add a new header
            common_headers = [
                'X-Forwarded-For', 'X-Requested-With', 'X-Custom-Header',
                'User-Agent', 'Referer', 'Origin', 'Cache-Control'
            ]
            new_header = random.choice(common_headers)
            fuzzed_headers[new_header] = self.input_fuzzer._generate_text()
        elif action == 'remove' and fuzzed_headers:
            # Remove a header
            header_to_remove = random.choice(list(fuzzed_headers.keys()))
            del fuzzed_headers[header_to_remove]
        
        return fuzzed_headers
    
    def _generate_auth_headers(self) -> Dict[str, str]:
        """Generate authentication headers based on configured auth type.
        
        Returns:
            Dictionary of authentication headers.
        """
        auth_headers = {}
        
        if not self.auth_type:
            return auth_headers
        
        if self.auth_type.lower() == 'basic':
            # Basic authentication
            import base64
            username = self.auth_credentials.get('username', '')
            password = self.auth_credentials.get('password', '')
            auth_string = f"{username}:{password}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            auth_headers['Authorization'] = f"Basic {encoded_auth}"
        
        elif self.auth_type.lower() == 'bearer':
            # Bearer token authentication
            token = self.auth_credentials.get('token', '')
            auth_headers['Authorization'] = f"Bearer {token}"
        
        elif self.auth_type.lower() == 'api_key':
            # API key authentication
            api_key = self.auth_credentials.get('api_key', '')
            key_name = self.auth_credentials.get('key_name', 'X-API-Key')
            auth_headers[key_name] = api_key
        
        return auth_headers
    
    def execute_fuzz(self, fuzz_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute API fuzzing with the provided data.
        
        Args:
            fuzz_data: Dictionary with endpoint, method, headers, and parameters.
            
        Returns:
            Dictionary with results of the fuzzing operation.
        """
        if not self.base_url:
            self.logger.error("No base URL specified")
            return {'status': 'error', 'message': 'No base URL specified'}
        
        endpoint = fuzz_data.get('endpoint', '/')
        method = fuzz_data.get('method', 'GET')
        headers = fuzz_data.get('headers', {})
        parameters = fuzz_data.get('parameters', {})
        
        # Construct full URL
        url = self.base_url.rstrip('/') + '/' + endpoint.lstrip('/')
        
        result = {
            'url': url,
            'method': method,
            'headers': headers,
            'parameters': parameters,
            'timestamp': self._get_timestamp(),
            'status': 'unknown',
            'response': None,
            'error': None
        }
        
        try:
            # Execute the API request based on the API type
            if self.api_type == 'rest':
                self._execute_rest_api_fuzz(url, method, headers, parameters, result)
            elif self.api_type == 'graphql':
                self._execute_graphql_api_fuzz(url, headers, parameters, result)
            else:
                result['status'] = 'error'
                result['error'] = f"Unsupported API type: {self.api_type}"
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _execute_rest_api_fuzz(self, url: str, method: str, headers: Dict[str, str], 
                              parameters: Dict[str, Any], result: Dict[str, Any]):
        """Execute REST API fuzzing.
        
        Args:
            url: Full URL to fuzz.
            method: HTTP method to use.
            headers: HTTP headers to send.
            parameters: Request parameters.
            result: Result dictionary to update.
        """
        import requests
        
        # Determine how to send parameters based on method
        kwargs = {
            'headers': headers,
            'timeout': self.timeout
        }
        
        if method in ['GET', 'DELETE']:
            kwargs['params'] = parameters
        else:  # POST, PUT, PATCH
            # Determine content type
            content_type = headers.get('Content-Type', 'application/json')
            
            if content_type == 'application/json':
                kwargs['json'] = parameters
            elif content_type == 'application/x-www-form-urlencoded':
                kwargs['data'] = parameters
            else:
                kwargs['data'] = parameters
        
        # Send request
        try:
            response = requests.request(method=method, url=url, **kwargs)
            
            # Update result
            result['status'] = 'success'
            result['response'] = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type', ''),
                'content': response.text[:1000]  # Limit content size
            }
            
            # Try to parse JSON response
            try:
                if 'application/json' in response.headers.get('Content-Type', ''):
                    result['response']['json'] = response.json()
            except:
                pass
            
            # Check for potential vulnerabilities
            self._check_api_vulnerabilities(response, result)
            
        except requests.exceptions.Timeout:
            result['status'] = 'timeout'
            result['error'] = 'Request timeout'
        except requests.exceptions.RequestException as e:
            result['status'] = 'error'
            result['error'] = str(e)
    
    def _execute_graphql_api_fuzz(self, url: str, headers: Dict[str, str], 
                                parameters: Dict[str, Any], result: Dict[str, Any]):
        """Execute GraphQL API fuzzing.
        
        Args:
            url: Full URL to fuzz.
            headers: HTTP headers to send.
            parameters: Request parameters.
            result: Result dictionary to update.
        """
        import requests
        
        # Generate a GraphQL query if not provided
        if 'query' not in parameters:
            parameters['query'] = self._generate_graphql_query()
        
        # Add variables if not provided
        if 'variables' not in parameters and random.random() < 0.5:
            parameters['variables'] = self._generate_graphql_variables()
        
        # Send request
        try:
            response = requests.post(
                url=url,
                headers=headers,
                json=parameters,
                timeout=self.timeout
            )
            
            # Update result
            result['status'] = 'success'
            result['response'] = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:1000]  # Limit content size
            }
            
            # Try to parse JSON response
            try:
                result['response']['json'] = response.json()
            except:
                pass
            
            # Check for potential vulnerabilities
            self._check_api_vulnerabilities(response, result)
            
        except requests.exceptions.Timeout:
            result['status'] = 'timeout'
            result['error'] = 'Request timeout'
        except requests.exceptions.RequestException as e:
            result['status'] = 'error'
            result['error'] = str(e)
    
    def _generate_graphql_query(self) -> str:
        """Generate a random GraphQL query.
        
        Returns:
            Random GraphQL query string.
        """
        # Simple GraphQL query templates
        query_templates = [
            # Basic query
            "query { user { id name email } }",
            # Query with argument
            "query { user(id: %s) { id name email } }",
            # Nested query
            "query { user { id name posts { id title content } } }",
            # Mutation
            "mutation { createUser(name: \"%s\", email: \"%s\") { id name email } }",
            # Introspection query
            "{ __schema { types { name kind description } } }",
            # Field aliases
            "query { user { userId: id userName: name userEmail: email } }"
        ]
        
        # Select a random template
        template = random.choice(query_templates)
        
        # Fill in placeholders if needed
        if '%s' in template:
            if 'mutation' in template:
                # Fill in name and email for mutation
                name = self.input_fuzzer._generate_text(3, 10)
                email = self.input_fuzzer._generate_email()
                query = template % (name, email)
            else:
                # Fill in ID for query
                id_value = random.randint(1, 1000)
                query = template % id_value
        else:
            query = template
        
        return query
    
    def _generate_graphql_variables(self) -> Dict[str, Any]:
        """Generate random GraphQL variables.
        
        Returns:
            Dictionary of GraphQL variables.
        """
        # Generate a random number of variables
        num_variables = random.randint(1, 3)
        variables = {}
        
        for _ in range(num_variables):
            var_name = random.choice(['id', 'name', 'email', 'limit', 'offset', 'filter'])
            variables[var_name] = self._generate_param_value()
        
        return variables
    
    def _check_api_vulnerabilities(self, response, result: Dict[str, Any]):
        """Check for potential API vulnerabilities in the response.
        
        Args:
            response: Response object from the request.
            result: Result dictionary to update.
        """
        vulnerabilities = []
        
        # Check for server errors
        if response.status_code >= 500:
            vulnerabilities.append("Server error - possible vulnerability")
        
        # Check for error messages in the response
        error_indicators = ['error', 'exception', 'stack trace', 'traceback', 'syntax error']
        for indicator in error_indicators:
            if indicator in response.text.lower():
                vulnerabilities.append(f"Error message in response - possible information disclosure: {indicator}")
                break
        
        # Check for sensitive information in the response
        sensitive_indicators = ['password', 'token', 'secret', 'key', 'credential', 'auth']
        for indicator in sensitive_indicators:
            if indicator in response.text.lower():
                vulnerabilities.append(f"Sensitive information in response: {indicator}")
                break
        
        # Check for GraphQL-specific vulnerabilities
        if self.api_type == 'graphql' and 'errors' in response.text.lower():
            try:
                response_json = response.json()
                if 'errors' in response_json:
                    vulnerabilities.append("GraphQL errors in response - possible vulnerability")
            except:
                pass
        
        # Update result with vulnerabilities
        if vulnerabilities:
            result['potential_vulnerabilities'] = vulnerabilities
    
    def _get_timestamp(self):
        """Get current timestamp.
        
        Returns:
            Current timestamp as float.
        """
        import time
        return time.time()