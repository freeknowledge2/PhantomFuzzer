#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API scanner implementation for PhantomFuzzer.

This module provides a scanner implementation for APIs,
including REST, GraphQL, and SOAP API discovery and testing.
"""

import os
import sys
import time
import json
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Try to import required libraries
try:
    import requests
    from requests.exceptions import RequestException, Timeout, TooManyRedirects
    import jwt
    REQUESTS_AVAILABLE = True
    JWT_AVAILABLE = True
except ImportError as e:
    REQUESTS_AVAILABLE = 'requests' not in str(e)
    JWT_AVAILABLE = 'jwt' not in str(e)

# Import from phantomfuzzer package
from phantomfuzzer.scanner.base import BaseScanner, ScanResult
from phantomfuzzer.scanner.base import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from phantomfuzzer.scanner.base import STATUS_COMPLETED, STATUS_FAILED
from phantomfuzzer.utils.logging import get_module_logger

# Default request timeout
DEFAULT_TIMEOUT = 10

# Default user agent
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# API vulnerability types
VULN_INJECTION = 'API Injection'
VULN_BROKEN_AUTH = 'Broken Authentication'
VULN_BROKEN_OBJECT_AUTH = 'Broken Object Level Authorization'
VULN_EXCESSIVE_DATA = 'Excessive Data Exposure'
VULN_RATE_LIMIT = 'Lack of Rate Limiting'
VULN_MASS_ASSIGNMENT = 'Mass Assignment'
VULN_SECURITY_MISCONFIG = 'Security Misconfiguration'
VULN_IMPROPER_ASSETS = 'Improper Assets Management'

# API types
API_TYPE_REST = 'REST'
API_TYPE_GRAPHQL = 'GraphQL'
API_TYPE_SOAP = 'SOAP'
API_TYPE_UNKNOWN = 'Unknown'

class APIScanner(BaseScanner):
    """API scanner implementation.
    
    This class implements a scanner for various API types, including
    REST, GraphQL, and SOAP APIs. It provides functionality for endpoint
    discovery, authentication testing, and vulnerability assessment.
    """
    
    def _init_scanner(self) -> None:
        """Initialize scanner-specific settings.
        
        This method is called by the BaseScanner constructor.
        """
        if not REQUESTS_AVAILABLE:
            self.logger.error("Required library not available: requests")
            raise ImportError("Required library not available: requests")
        
        # Get API scanner configuration
        api_config = self.config.get('api_scan', {})
        
        # Initialize settings
        self.timeout = api_config.get('timeout', DEFAULT_TIMEOUT)
        self.user_agent = api_config.get('user_agent', DEFAULT_USER_AGENT)
        self.follow_redirects = api_config.get('follow_redirects', True)
        self.verify_ssl = api_config.get('verify_ssl', True)
        self.max_endpoints = api_config.get('max_endpoints', 100)
        
        # API discovery settings
        self.discover_rest = api_config.get('discover_rest', True)
        self.discover_graphql = api_config.get('discover_graphql', True)
        self.discover_soap = api_config.get('discover_soap', True)
        self.parse_swagger = api_config.get('parse_swagger', True)
        self.parse_raml = api_config.get('parse_raml', True)
        
        # Authentication settings
        self.test_auth = api_config.get('test_auth', True)
        self.test_jwt = api_config.get('test_jwt', True) and JWT_AVAILABLE
        self.test_oauth = api_config.get('test_oauth', True)
        self.test_api_keys = api_config.get('test_api_keys', True)
        
        # Vulnerability testing settings
        self.test_injection = api_config.get('test_injection', True)
        self.test_bola = api_config.get('test_bola', True)
        self.test_mass_assignment = api_config.get('test_mass_assignment', True)
        self.test_rate_limit = api_config.get('test_rate_limit', True)
        
        # Initialize scan state
        self.discovered_endpoints = []
        self.api_type = API_TYPE_UNKNOWN
        self.auth_methods = []
        
        # Load payloads
        self._load_payloads()
    
    def _load_payloads(self) -> None:
        """Load payloads for API vulnerability testing."""
        payload_config = self.config_manager.get_payload_config()
        
        # Default payloads in case config doesn't have them
        self.injection_payloads = payload_config.get('api_injection', [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "<script>alert(1)</script>",
            "${7*7}",
            "$(cat /etc/passwd)",
            "{{7*7}}"
        ])
        
        self.auth_bypass_payloads = payload_config.get('auth_bypass', [
            "",  # Empty token
            "null",  # Null token
            "undefined",  # Undefined token
            "admin",  # Common value
            "guest",  # Common value
            "Bearer ",  # Empty bearer token
            "Basic YWRtaW46YWRtaW4="  # Basic auth with admin:admin
        ])
        
        self.common_api_paths = payload_config.get('api_paths', [
            "/api",
            "/api/v1",
            "/api/v2",
            "/rest",
            "/graphql",
            "/query",
            "/soap",
            "/swagger",
            "/swagger.json",
            "/api-docs",
            "/openapi.json",
            "/spec"
        ])
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Perform an API scan on the target.
        
        Args:
            target: The target URL to scan.
            options: Optional scan options.
        
        Returns:
            The scan result.
        """
        # Initialize scan options
        if options is None:
            options = {}
        
        # Override default settings with options
        max_endpoints = options.get('max_endpoints', self.max_endpoints)
        
        # Start the scan
        scan_result = self.start_scan(target, options)
        
        try:
            # Initialize scan state
            self.discovered_endpoints = []
            self.api_type = API_TYPE_UNKNOWN
            self.auth_methods = []
            
            # Add scan info
            scan_result.scan_info = {
                'max_endpoints': max_endpoints,
                'user_agent': self.user_agent,
                'follow_redirects': self.follow_redirects,
                'verify_ssl': self.verify_ssl,
                'api_type': self.api_type,
                'auth_methods': self.auth_methods
            }
            
            # Discover API endpoints
            self._discover_api_endpoints(target, scan_result)
            
            # Determine API type
            self._determine_api_type(scan_result)
            
            # Discover authentication methods
            if self.test_auth:
                self._discover_auth_methods(scan_result)
            
            # Test for vulnerabilities
            self._test_api_vulnerabilities(scan_result)
            
            # Generate API documentation
            self._generate_api_documentation(scan_result)
            
            # Generate final report
            self._generate_final_report(scan_result)
            
            # Update scan info with final results
            scan_result.scan_info['api_type'] = self.api_type
            scan_result.scan_info['auth_methods'] = self.auth_methods
            scan_result.scan_info['endpoints_discovered'] = len(self.discovered_endpoints)
            
            # Complete the scan
            return self.finish_scan(STATUS_COMPLETED)
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {str(e)}")
            scan_result.scan_info['error'] = str(e)
            return self.finish_scan(STATUS_FAILED)
    
    def _discover_api_endpoints(self, base_url: str, scan_result: ScanResult) -> None:
        """Discover API endpoints.
        
        Args:
            base_url: The base URL to start discovery from.
            scan_result: The scan result to update.
        """
        self.logger.info(f"Starting API endpoint discovery for {base_url}")
        
        # Normalize base URL
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        
        # Try common API paths
        for path in self.common_api_paths:
            api_url = urljoin(base_url, path)
            self._check_endpoint(api_url, scan_result)
        
        # Look for API documentation
        if self.parse_swagger:
            self._parse_swagger_docs(base_url, scan_result)
        
        if self.parse_raml:
            self._parse_raml_docs(base_url, scan_result)
        
        # Specific discovery methods based on API type
        if self.discover_graphql:
            self._discover_graphql_endpoints(base_url, scan_result)
        
        if self.discover_soap:
            self._discover_soap_endpoints(base_url, scan_result)
        
        self.logger.info(f"Discovered {len(self.discovered_endpoints)} API endpoints")
    
    def _check_endpoint(self, url: str, scan_result: ScanResult) -> bool:
        """Check if a URL is a valid API endpoint.
        
        Args:
            url: The URL to check.
            scan_result: The scan result to update.
        
        Returns:
            True if the URL is a valid API endpoint, False otherwise.
        """
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=self.follow_redirects
            )
            
            # Check if the response looks like an API
            content_type = response.headers.get('Content-Type', '')
            is_api = (
                'application/json' in content_type or
                'application/xml' in content_type or
                'application/soap+xml' in content_type or
                'application/graphql' in content_type
            )
            
            # Check response body for API indicators
            if not is_api and response.text:
                try:
                    # Try to parse as JSON
                    json_data = response.json()
                    is_api = True
                except json.JSONDecodeError as e:
                    # Check for XML/SOAP structure
                    is_api = (
                        '<soap:Envelope' in response.text or
                        '<?xml' in response.text or
                        '<wsdl:definitions' in response.text
                    )
            
            if is_api:
                self.logger.debug(f"Found API endpoint: {url}")
                self.discovered_endpoints.append({
                    'url': url,
                    'method': 'GET',
                    'content_type': content_type,
                    'status_code': response.status_code
                })
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error checking endpoint {url}: {str(e)}")
            return False
    
    def _parse_swagger_docs(self, base_url: str, scan_result: ScanResult) -> None:
        """Parse Swagger/OpenAPI documentation to discover endpoints.
        
        Args:
            base_url: The base URL to start discovery from.
            scan_result: The scan result to update.
        """
        swagger_paths = [
            '/swagger.json',
            '/api-docs',
            '/openapi.json',
            '/swagger/v1/swagger.json',
            '/api/swagger',
            '/spec'
        ]
        
        for path in swagger_paths:
            swagger_url = urljoin(base_url, path)
            try:
                headers = {'User-Agent': self.user_agent}
                response = requests.get(
                    swagger_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
                    try:
                        swagger_data = response.json()
                        if 'swagger' in swagger_data or 'openapi' in swagger_data:
                            self.logger.info(f"Found Swagger/OpenAPI documentation at {swagger_url}")
                            
                            # Extract API information
                            api_info = swagger_data.get('info', {})
                            scan_result.scan_info['api_title'] = api_info.get('title')
                            scan_result.scan_info['api_version'] = api_info.get('version')
                            scan_result.scan_info['api_description'] = api_info.get('description')
                            
                            # Extract paths/endpoints
                            paths = swagger_data.get('paths', {})
                            for path, methods in paths.items():
                                for method, details in methods.items():
                                    if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                                        continue
                                    
                                    endpoint_url = urljoin(base_url, path)
                                    self.discovered_endpoints.append({
                                        'url': endpoint_url,
                                        'method': method.upper(),
                                        'description': details.get('summary', ''),
                                        'parameters': details.get('parameters', []),
                                        'responses': details.get('responses', {}),
                                        'source': 'swagger'
                                    })
                            
                            # Set API type to REST since most Swagger docs are for REST APIs
                            self.api_type = API_TYPE_REST
                            
                            # Extract security schemes
                            security_schemes = swagger_data.get('securityDefinitions', {})
                            security_schemes.update(swagger_data.get('components', {}).get('securitySchemes', {}))
                            
                            for scheme_name, scheme in security_schemes.items():
                                scheme_type = scheme.get('type', '').lower()
                                if scheme_type == 'apikey':
                                    self.auth_methods.append('API Key')
                                elif scheme_type == 'oauth2':
                                    self.auth_methods.append('OAuth2')
                                elif scheme_type == 'http' and scheme.get('scheme', '').lower() == 'bearer':
                                    self.auth_methods.append('JWT')
                                elif scheme_type == 'http' and scheme.get('scheme', '').lower() == 'basic':
                                    self.auth_methods.append('Basic Auth')
                    except Exception as e:
                        self.logger.debug(f"Failed to parse Swagger JSON at {swagger_url}: {str(e)}")
            except Exception as e:
                continue
    
    def _parse_raml_docs(self, base_url: str, scan_result: ScanResult) -> None:
        """Parse RAML documentation to discover endpoints.
        
        Args:
            base_url: The base URL to start discovery from.
            scan_result: The scan result to update.
        """
        raml_paths = [
            '/api.raml',
            '/raml/api.raml',
            '/docs/api.raml'
        ]
        
        for path in raml_paths:
            raml_url = urljoin(base_url, path)
            try:
                headers = {'User-Agent': self.user_agent}
                response = requests.get(
                    raml_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200 and response.text.startswith('#%RAML'):
                    self.logger.info(f"Found RAML documentation at {raml_url}")
                    # Basic RAML parsing - in a real implementation, this would use a proper RAML parser
                    lines = response.text.split('\n')
                    
                    # Extract API title and version
                    for line in lines:
                        if line.startswith('title:'):
                            scan_result.scan_info['api_title'] = line.split('title:')[1].strip()
                        elif line.startswith('version:'):
                            scan_result.scan_info['api_version'] = line.split('version:')[1].strip()
                    
                    # Set API type to REST since most RAML docs are for REST APIs
                    self.api_type = API_TYPE_REST
                    
                    # Simple endpoint extraction - this is a basic implementation
                    current_path = None
                    for line in lines:
                        line = line.strip()
                        if line.startswith('/'):
                            current_path = line.split(':')[0].strip()
                        elif current_path and line in ['get:', 'post:', 'put:', 'delete:', 'patch:']:
                            method = line.replace(':', '')
                            endpoint_url = urljoin(base_url, current_path)
                            self.discovered_endpoints.append({
                                'url': endpoint_url,
                                'method': method.upper(),
                                'source': 'raml'
                            })
            except Exception as e:
                self.logger.debug(f"Failed to parse RAML at {raml_url}: {str(e)}")
                continue
    
    def _discover_graphql_endpoints(self, base_url: str, scan_result: ScanResult) -> None:
        """Discover GraphQL endpoints.
        
        Args:
            base_url: The base URL to start discovery from.
            scan_result: The scan result to update.
        """
        graphql_paths = [
            '/graphql',
            '/api/graphql',
            '/query',
            '/gql'
        ]
        
        for path in graphql_paths:
            graphql_url = urljoin(base_url, path)
            try:
                # Try introspection query to detect GraphQL
                introspection_query = {
                    'query': '''
                    {
                        __schema {
                            queryType {
                                name
                            }
                        }
                    }
                    '''
                }
                
                headers = {
                    'User-Agent': self.user_agent,
                    'Content-Type': 'application/json'
                }
                
                response = requests.post(
                    graphql_url,
                    headers=headers,
                    json=introspection_query,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in data['data']:
                            self.logger.info(f"Found GraphQL endpoint at {graphql_url}")
                            self.discovered_endpoints.append({
                                'url': graphql_url,
                                'method': 'POST',
                                'content_type': 'application/json',
                                'api_type': API_TYPE_GRAPHQL,
                                'source': 'introspection'
                            })
                            
                            # Set API type to GraphQL
                            self.api_type = API_TYPE_GRAPHQL
                            
                            # Perform full introspection to get schema details
                            self._perform_graphql_introspection(graphql_url, scan_result)
                    except Exception as e:
                        self.logger.debug(f"Error parsing GraphQL response from {graphql_url}: {str(e)}")
                        pass
            except Exception as e:
                self.logger.debug(f"Error checking GraphQL endpoint at {graphql_url}: {str(e)}")
                continue
    
    def _perform_graphql_introspection(self, graphql_url: str, scan_result: ScanResult) -> None:
        """Perform GraphQL introspection to get schema details.
        
        Args:
            graphql_url: The GraphQL endpoint URL.
            scan_result: The scan result to update.
        """
        try:
            # Full introspection query
            introspection_query = {
                'query': '''
                {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            kind
                            name
                            description
                            fields {
                                name
                                description
                                args {
                                    name
                                    description
                                    type { kind name ofType { kind name } }
                                    defaultValue
                                }
                                type {
                                    kind
                                    name
                                    ofType { kind name }
                                }
                            }
                        }
                    }
                }
                '''
            }
            
            headers = {
                'User-Agent': self.user_agent,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                graphql_url,
                headers=headers,
                json=introspection_query,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    schema = data['data']['__schema']
                    
                    # Extract queries
                    query_type = schema.get('queryType', {}).get('name')
                    if query_type:
                        for type_info in schema.get('types', []):
                            if type_info.get('name') == query_type:
                                for field in type_info.get('fields', []):
                                    self.discovered_endpoints.append({
                                        'url': graphql_url,
                                        'method': 'POST',
                                        'operation': 'query',
                                        'name': field.get('name'),
                                        'description': field.get('description'),
                                        'arguments': field.get('args', []),
                                        'api_type': API_TYPE_GRAPHQL
                                    })
                    
                    # Extract mutations
                    mutation_type = schema.get('mutationType', {}).get('name')
                    if mutation_type:
                        for type_info in schema.get('types', []):
                            if type_info.get('name') == mutation_type:
                                for field in type_info.get('fields', []):
                                    self.discovered_endpoints.append({
                                        'url': graphql_url,
                                        'method': 'POST',
                                        'operation': 'mutation',
                                        'name': field.get('name'),
                                        'description': field.get('description'),
                                        'arguments': field.get('args', []),
                                        'api_type': API_TYPE_GRAPHQL
                                    })
                    
                    # Store schema in scan info
                    scan_result.scan_info['graphql_schema'] = schema
        except Exception as e:
            self.logger.debug(f"Error performing GraphQL introspection: {str(e)}")
    
    def _discover_soap_endpoints(self, base_url: str, scan_result: ScanResult) -> None:
        """Discover SOAP endpoints.
        
        Args:
            base_url: The base URL to start discovery from.
            scan_result: The scan result to update.
        """
        soap_paths = [
            '/soap',
            '/ws',
            '/services',
            '/wsdl'
        ]
        
        for path in soap_paths:
            soap_url = urljoin(base_url, path)
            try:
                # Try to get WSDL
                params = {'wsdl': ''}
                headers = {'User-Agent': self.user_agent}
                
                response = requests.get(
                    soap_url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200 and (
                    'text/xml' in response.headers.get('Content-Type', '') or
                    'application/xml' in response.headers.get('Content-Type', '')
                ):
                    if '<wsdl:definitions' in response.text or '<definitions' in response.text:
                        self.logger.info(f"Found SOAP WSDL at {soap_url}?wsdl")
                        
                        # Set API type to SOAP
                        self.api_type = API_TYPE_SOAP
                        
                        # Basic WSDL parsing - in a real implementation, this would use a proper WSDL parser
                        # Extract operations
                        operations = re.findall(r'<wsdl:operation name="([^"]+)"', response.text)
                        if not operations:
                            operations = re.findall(r'<operation name="([^"]+)"', response.text)
                        
                        for operation in operations:
                            self.discovered_endpoints.append({
                                'url': soap_url,
                                'method': 'POST',
                                'operation': operation,
                                'api_type': API_TYPE_SOAP,
                                'source': 'wsdl'
                            })
                        
                        # Store WSDL URL in scan info
                        scan_result.scan_info['soap_wsdl_url'] = f"{soap_url}?wsdl"
            except Exception as e:
                self.logger.debug(f"Error checking SOAP endpoint at {soap_url}: {str(e)}")
                continue
    
    def _determine_api_type(self, scan_result: ScanResult) -> None:
        """Determine the API type based on discovered endpoints.
        
        Args:
            scan_result: The scan result to update.
        """
        # Count endpoints by type
        rest_count = 0
        graphql_count = 0
        soap_count = 0
        
        for endpoint in self.discovered_endpoints:
            api_type = endpoint.get('api_type')
            if api_type == API_TYPE_GRAPHQL:
                graphql_count += 1
            elif api_type == API_TYPE_SOAP:
                soap_count += 1
            else:
                rest_count += 1
        
        # Determine predominant API type
        if graphql_count > 0 and graphql_count >= rest_count and graphql_count >= soap_count:
            self.api_type = API_TYPE_GRAPHQL
        elif soap_count > 0 and soap_count >= rest_count and soap_count >= graphql_count:
            self.api_type = API_TYPE_SOAP
        elif rest_count > 0:
            self.api_type = API_TYPE_REST
        
        self.logger.info(f"Determined API type: {self.api_type}")
    
    def _discover_auth_methods(self, scan_result: ScanResult) -> None:
        """Discover authentication methods used by the API.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.info("Discovering authentication methods")
        
        # Check for authentication headers in responses
        auth_headers = {
            'WWW-Authenticate': ['Basic', 'Bearer', 'Digest'],
            'X-API-Key': ['API Key'],
            'Authorization': ['Bearer', 'Basic']
        }
        
        # Sample a few endpoints
        sample_endpoints = self.discovered_endpoints[:min(5, len(self.discovered_endpoints))]
        
        for endpoint in sample_endpoints:
            url = endpoint.get('url')
            method = endpoint.get('method', 'GET')
            
            try:
                headers = {'User-Agent': self.user_agent}
                
                if method == 'GET':
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False
                    )
                else:
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False,
                        data={}
                    )
                
                # Check for auth-related status codes
                if response.status_code in [401, 403]:
                    # Check response headers for auth hints
                    for header, auth_types in auth_headers.items():
                        if header in response.headers:
                            header_value = response.headers[header]
                            for auth_type in auth_types:
                                if auth_type.lower() in header_value.lower():
                                    if auth_type not in self.auth_methods:
                                        self.auth_methods.append(auth_type)
                    
                    # Check response body for auth hints
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        try:
                            data = response.json()
                            error_msg = str(data).lower()
                            
                            auth_keywords = {
                                'token': 'JWT/Token',
                                'jwt': 'JWT',
                                'api key': 'API Key',
                                'apikey': 'API Key',
                                'oauth': 'OAuth',
                                'unauthorized': 'Authentication Required',
                                'authentication': 'Authentication Required'
                            }
                            
                            for keyword, auth_type in auth_keywords.items():
                                if keyword in error_msg and auth_type not in self.auth_methods:
                                    self.auth_methods.append(auth_type)
                        except Exception as e:
                            self.logger.debug(f"Error parsing authentication error message: {str(e)}")
                            pass
            except Exception as e:
                self.logger.debug(f"Error checking authentication for endpoint {endpoint.get('url')}: {str(e)}")
                continue
        
        # If no auth methods detected but we got 401/403 responses, add generic auth
        if not self.auth_methods and any(e.get('status_code') in [401, 403] for e in sample_endpoints if 'status_code' in e):
            self.auth_methods.append('Authentication Required')
        
        self.logger.info(f"Discovered authentication methods: {', '.join(self.auth_methods) if self.auth_methods else 'None'}")
    
    def _test_api_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Test the API for common vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.info("Testing API for vulnerabilities")
        
        # Test for injection vulnerabilities
        if self.test_injection:
            self._test_injection_vulnerabilities(scan_result)
        
        # Test for broken authentication
        if self.test_auth:
            self._test_authentication_vulnerabilities(scan_result)
        
        # Test for broken object level authorization
        if self.test_bola:
            self._test_bola_vulnerabilities(scan_result)
        
        # Test for mass assignment
        if self.test_mass_assignment:
            self._test_mass_assignment_vulnerabilities(scan_result)
        
        # Test for rate limiting
        if self.test_rate_limit:
            self._test_rate_limiting(scan_result)
    
    def _test_injection_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Test the API for injection vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.debug("Testing for injection vulnerabilities")
        
        # For each endpoint, try injection payloads
        for endpoint in self.discovered_endpoints:
            url = endpoint.get('url')
            method = endpoint.get('method', 'GET')
            api_type = endpoint.get('api_type', API_TYPE_REST)
            
            # Skip if not a valid endpoint
            if not url:
                continue
            
            # Get parameters to test based on API type
            parameters = []
            
            if api_type == API_TYPE_GRAPHQL:
                # For GraphQL, test arguments of operations
                operation = endpoint.get('operation')
                name = endpoint.get('name')
                args = endpoint.get('arguments', [])
                
                if operation and name and args:
                    for arg in args:
                        arg_name = arg.get('name')
                        if arg_name:
                            parameters.append(arg_name)
            elif api_type == API_TYPE_SOAP:
                # For SOAP, we would need to parse the WSDL more thoroughly
                # This is a simplified implementation
                operation = endpoint.get('operation')
                if operation:
                    parameters.append('searchString')
                    parameters.append('id')
                    parameters.append('name')
            else:  # REST API
                # For REST, use common parameter names
                parameters = [
                    'q', 'query', 'search', 'id', 'name', 'username',
                    'user', 'password', 'pass', 'key', 'token', 'auth',
                    'filter', 'order', 'sort', 'limit', 'offset'
                ]
                
                # Add parameters from Swagger if available
                endpoint_params = endpoint.get('parameters', [])
                for param in endpoint_params:
                    param_name = param.get('name')
                    if param_name and param_name not in parameters:
                        parameters.append(param_name)
            
            # Test each parameter with each payload
            for param in parameters:
                for payload in self.injection_payloads:
                    # Skip testing if we've reached the maximum endpoints
                    if len(self.discovered_endpoints) >= self.max_endpoints:
                        break
                    
                    try:
                        # Prepare the request based on API type
                        if api_type == API_TYPE_GRAPHQL:
                            # For GraphQL, inject into query variables
                            operation_type = endpoint.get('operation', 'query')
                            operation_name = endpoint.get('name', 'test')
                            
                            query = f"{operation_type} {{ {operation_name}({param}: \"{payload}\") {{ id name }} }}"
                            data = {'query': query}
                            headers = {
                                'User-Agent': self.user_agent,
                                'Content-Type': 'application/json'
                            }
                            
                            response = requests.post(
                                url,
                                headers=headers,
                                json=data,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                        elif api_type == API_TYPE_SOAP:
                            # For SOAP, inject into SOAP envelope
                            soap_envelope = f'''
                            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
                                <soap:Body>
                                    <{endpoint.get('operation')}>
                                        <{param}>{payload}</{param}>
                                    </{endpoint.get('operation')}>
                                </soap:Body>
                            </soap:Envelope>
                            '''
                            
                            headers = {
                                'User-Agent': self.user_agent,
                                'Content-Type': 'application/soap+xml',
                                'SOAPAction': f'"{endpoint.get("operation")}"'
                            }
                            
                            response = requests.post(
                                url,
                                headers=headers,
                                data=soap_envelope,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                        else:  # REST API
                            # For REST, inject into query parameters or body based on method
                            if method in ['GET', 'DELETE']:
                                # Inject into query parameters
                                params = {param: payload}
                                headers = {'User-Agent': self.user_agent}
                                
                                response = requests.request(
                                    method,
                                    url,
                                    headers=headers,
                                    params=params,
                                    timeout=self.timeout,
                                    verify=self.verify_ssl
                                )
                            else:  # POST, PUT, PATCH
                                # Inject into body
                                data = {param: payload}
                                headers = {
                                    'User-Agent': self.user_agent,
                                    'Content-Type': 'application/json'
                                }
                                
                                response = requests.request(
                                    method,
                                    url,
                                    headers=headers,
                                    json=data,
                                    timeout=self.timeout,
                                    verify=self.verify_ssl
                                )
                        
                        # Check for injection vulnerabilities in the response
                        self._check_injection_response(url, param, payload, response, scan_result)
                        
                    except Exception as e:
                        self.logger.debug(f"Error testing injection on {url}, param {param}: {str(e)}")
    
    def _check_injection_response(self, url: str, param: str, payload: str, response, scan_result: ScanResult) -> None:
        """Check the response for signs of successful injection.
        
        Args:
            url: The URL that was tested.
            param: The parameter that was tested.
            payload: The payload that was used.
            response: The response object.
            scan_result: The scan result to update.
        """
        # Check for SQL injection indicators
        sql_error_patterns = [
            'SQL syntax',
            'mysql_fetch_array',
            'ORA-[0-9]+',
            'PostgreSQL.*ERROR',
            'SQLite3::',
            'Microsoft SQL Server',
            'ODBC Driver',
            'Warning: mysql_',
            'unclosed quotation mark after the character string',
            'quoted string not properly terminated'
        ]
        
        # Check for XSS indicators
        xss_indicators = [
            payload in response.text and '<script>' in payload,
            'alert(1)' in payload and payload in response.text,
            '<svg onload=' in payload and payload in response.text
        ]
        
        # Check for template injection indicators
        template_indicators = [
            '${7*7}' in payload and '49' in response.text,
            '{{7*7}}' in payload and '49' in response.text
        ]
        
        # Check for command injection indicators
        command_indicators = [
            'root:x:' in response.text and 'cat /etc/passwd' in payload,
            'uid=' in response.text and 'id' in payload
        ]
        
        # Check for SQL injection
        for pattern in sql_error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                scan_result.add_vulnerability(
                    name=VULN_INJECTION,
                    description=f"SQL Injection vulnerability detected in parameter '{param}'",
                    severity=SEVERITY_HIGH,
                    location=f"{url} - Parameter: {param}",
                    evidence=f"Payload: {payload}\nResponse contains SQL error: {pattern}",
                    remediation="Implement proper input validation and parameterized queries. Never trust user input."
                )
                return
        
        # Check for XSS
        for indicator in xss_indicators:
            if indicator:
                scan_result.add_vulnerability(
                    name=VULN_INJECTION,
                    description=f"Cross-Site Scripting (XSS) vulnerability detected in parameter '{param}'",
                    severity=SEVERITY_MEDIUM,
                    location=f"{url} - Parameter: {param}",
                    evidence=f"Payload: {payload}\nResponse reflects the XSS payload",
                    remediation="Implement proper input validation and output encoding. Consider using a Content Security Policy."
                )
                return
        
        # Check for template injection
        for indicator in template_indicators:
            if indicator:
                scan_result.add_vulnerability(
                    name=VULN_INJECTION,
                    description=f"Template Injection vulnerability detected in parameter '{param}'",
                    severity=SEVERITY_HIGH,
                    location=f"{url} - Parameter: {param}",
                    evidence=f"Payload: {payload}\nResponse indicates template evaluation",
                    remediation="Avoid passing user input to template engines. If necessary, implement strict validation."
                )
                return
        
        # Check for command injection
        for indicator in command_indicators:
            if indicator:
                scan_result.add_vulnerability(
                    name=VULN_INJECTION,
                    description=f"Command Injection vulnerability detected in parameter '{param}'",
                    severity=SEVERITY_CRITICAL,
                    location=f"{url} - Parameter: {param}",
                    evidence=f"Payload: {payload}\nResponse contains command output",
                    remediation="Never pass user input to system commands. If necessary, implement a whitelist of allowed values."
                )
                return
    
    def _test_authentication_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Test the API for authentication vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.debug("Testing for authentication vulnerabilities")
        
        # Skip if no auth methods detected
        if not self.auth_methods:
            return
        
        # Sample a few endpoints that might require authentication
        auth_endpoints = []
        for endpoint in self.discovered_endpoints:
            # Look for endpoints that might require authentication
            url = endpoint.get('url')
            method = endpoint.get('method', 'GET')
            status_code = endpoint.get('status_code')
            
            if url and (status_code in [401, 403] or any(auth in url.lower() for auth in ['login', 'auth', 'token', 'jwt', 'oauth'])):
                auth_endpoints.append(endpoint)
        
        # If no auth endpoints found, use a sample of discovered endpoints
        if not auth_endpoints:
            auth_endpoints = self.discovered_endpoints[:min(5, len(self.discovered_endpoints))]
        
        # Test auth bypass on each endpoint
        for endpoint in auth_endpoints:
            url = endpoint.get('url')
            method = endpoint.get('method', 'GET')
            
            if not url:
                continue
            
            # Test each auth bypass payload
            for payload in self.auth_bypass_payloads:
                try:
                    # Prepare headers with auth bypass payload
                    headers = {
                        'User-Agent': self.user_agent,
                        'Authorization': payload
                    }
                    
                    # Add common API key headers
                    if 'API Key' in self.auth_methods:
                        headers['X-API-Key'] = payload
                        headers['api-key'] = payload
                        headers['apikey'] = payload
                    
                    # Make the request
                    if method == 'GET':
                        response = requests.get(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                    else:
                        response = requests.request(
                            method,
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl,
                            json={}
                        )
                    
                    # Check if auth bypass was successful
                    if response.status_code == 200:
                        # Verify it's not a false positive by checking content
                        if not ('error' in response.text.lower() or 'unauthorized' in response.text.lower()):
                            scan_result.add_vulnerability(
                                name=VULN_BROKEN_AUTH,
                                description="Authentication bypass vulnerability detected",
                                severity=SEVERITY_CRITICAL,
                                location=url,
                                evidence=f"Payload: {payload}\nResponse: {response.status_code} {response.reason}",
                                remediation="Implement proper authentication checks. Ensure all endpoints validate authentication tokens correctly."
                            )
                            break
                except Exception as e:
                    self.logger.debug(f"Error testing auth bypass on {url}: {str(e)}")
        
        # Test for JWT vulnerabilities if JWT is used
        if 'JWT' in self.auth_methods or 'Bearer' in self.auth_methods:
            self._test_jwt_vulnerabilities(auth_endpoints, scan_result)
    
    def _test_jwt_vulnerabilities(self, endpoints, scan_result: ScanResult) -> None:
        """Test for JWT-specific vulnerabilities.
        
        Args:
            endpoints: The endpoints to test.
            scan_result: The scan result to update.
        """
        if not JWT_AVAILABLE:
            self.logger.debug("JWT library not available, skipping JWT vulnerability tests")
            return
        
        self.logger.debug("Testing for JWT vulnerabilities")
        
        # JWT payloads for testing
        none_alg_token = jwt.encode({"sub": "1234567890", "name": "Admin User", "admin": True}, "", algorithm="none")
        
        for endpoint in endpoints:
            url = endpoint.get('url')
            method = endpoint.get('method', 'GET')
            
            if not url:
                continue
            
            try:
                # Test 'none' algorithm
                headers = {
                    'User-Agent': self.user_agent,
                    'Authorization': f'Bearer {none_alg_token}'
                }
                
                # Make the request
                if method == 'GET':
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                else:
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        json={}
                    )
                
                # Check if 'none' algorithm bypass was successful
                if response.status_code == 200:
                    # Verify it's not a false positive
                    if not ('error' in response.text.lower() or 'unauthorized' in response.text.lower()):
                        scan_result.add_vulnerability(
                            name=VULN_BROKEN_AUTH,
                            description="JWT 'none' algorithm vulnerability detected",
                            severity=SEVERITY_CRITICAL,
                            location=url,
                            evidence=f"JWT with 'none' algorithm accepted\nResponse: {response.status_code} {response.reason}",
                            remediation="Ensure your JWT library rejects tokens with 'none' algorithm. Always validate the algorithm used."
                        )
            except Exception as e:
                self.logger.debug(f"Error testing JWT vulnerabilities on {url}: {str(e)}")
    
    def _test_bola_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Test for Broken Object Level Authorization vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.debug("Testing for Broken Object Level Authorization vulnerabilities")
        
        # Look for endpoints that might contain object IDs
        resource_endpoints = []
        for endpoint in self.discovered_endpoints:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')
            
            # Look for URLs with ID patterns
            id_patterns = [
                r'/[a-zA-Z]+/\d+$',  # /users/123
                r'/[a-zA-Z]+/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',  # /users/uuid
                r'/[a-zA-Z]+/[0-9a-f]{24}$',  # /users/objectid
                r'/[a-zA-Z]+/[a-zA-Z0-9_-]+$'  # /users/username
            ]
            
            for pattern in id_patterns:
                if re.search(pattern, url):
                    resource_endpoints.append(endpoint)
                    break
        
        # Test a sample of resource endpoints
        for endpoint in resource_endpoints[:min(5, len(resource_endpoints))]:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')
            
            # Extract the resource ID from the URL
            resource_id = url.split('/')[-1]
            resource_type = url.split('/')[-2]
            
            try:
                # Try to access the resource without authentication
                headers = {'User-Agent': self.user_agent}
                
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # If we can access the resource without auth, it might be a BOLA vulnerability
                if response.status_code == 200:
                    # Try to access a different resource ID to confirm BOLA
                    new_id = self._modify_resource_id(resource_id)
                    new_url = url.replace(resource_id, new_id)
                    
                    new_response = requests.request(
                        method,
                        new_url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    # If we can access a different resource without auth, it's likely a BOLA vulnerability
                    if new_response.status_code == 200:
                        scan_result.add_vulnerability(
                            name=VULN_BROKEN_OBJECT_AUTH,
                            description=f"Broken Object Level Authorization vulnerability detected on {resource_type} resource",
                            severity=SEVERITY_HIGH,
                            location=url,
                            evidence=f"Resource {resource_id} and {new_id} accessible without proper authorization",
                            remediation="Implement proper authorization checks for each resource access. Verify the user has permission to access the specific resource."
                        )
            except Exception as e:
                self.logger.debug(f"Error testing BOLA on {url}: {str(e)}")
    
    def _modify_resource_id(self, resource_id: str) -> str:
        """Modify a resource ID to test for BOLA vulnerabilities.
        
        Args:
            resource_id: The original resource ID.
        
        Returns:
            A modified resource ID.
        """
        # If the ID is numeric, increment or decrement it
        if resource_id.isdigit():
            id_int = int(resource_id)
            if id_int > 1:
                return str(id_int - 1)
            else:
                return str(id_int + 1)
        
        # If the ID is a UUID, modify one character
        elif re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', resource_id):
            parts = resource_id.split('-')
            parts[0] = parts[0][:-1] + ('0' if parts[0][-1] != '0' else '1')
            return '-'.join(parts)
        
        # If the ID is alphanumeric, modify one character
        else:
            if len(resource_id) > 1:
                return resource_id[:-1] + ('0' if resource_id[-1] != '0' else '1')
            else:
                return resource_id + '1'
    
    def _test_mass_assignment_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Test for Mass Assignment vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.debug("Testing for Mass Assignment vulnerabilities")
        
        # Look for endpoints that might be vulnerable to mass assignment
        vulnerable_methods = ['POST', 'PUT', 'PATCH']
        potential_endpoints = []
        
        for endpoint in self.discovered_endpoints:
            method = endpoint.get('method', '')
            url = endpoint.get('url', '')
            
            if method in vulnerable_methods:
                potential_endpoints.append(endpoint)
        
        # Test a sample of potential endpoints
        for endpoint in potential_endpoints[:min(5, len(potential_endpoints))]:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'POST')
            
            # Skip if not a valid endpoint
            if not url:
                continue
            
            try:
                # Prepare payload with sensitive fields
                sensitive_fields = {
                    'admin': True,
                    'isAdmin': True,
                    'role': 'admin',
                    'permissions': ['admin', 'superuser'],
                    'accessLevel': 100,
                    'verified': True
                }
                
                headers = {
                    'User-Agent': self.user_agent,
                    'Content-Type': 'application/json'
                }
                
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    json=sensitive_fields,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # Check if the request was successful (might indicate mass assignment)
                if response.status_code in [200, 201, 202, 204]:
                    # Check if the response contains any of our sensitive fields
                    response_text = response.text.lower()
                    if any(field.lower() in response_text for field in sensitive_fields.keys()):
                        scan_result.add_vulnerability(
                            name=VULN_MASS_ASSIGNMENT,
                            description="Mass Assignment vulnerability detected",
                            severity=SEVERITY_HIGH,
                            location=url,
                            evidence=f"Sensitive fields accepted in {method} request",
                            remediation="Implement a whitelist of allowed fields for each endpoint. Never trust client-provided data for sensitive fields."
                        )
            except Exception as e:
                self.logger.debug(f"Error testing Mass Assignment on {url}: {str(e)}")
    
    def _test_rate_limiting(self, scan_result: ScanResult) -> None:
        """Test for lack of rate limiting.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.debug("Testing for lack of rate limiting")
        
        # Sample a few endpoints to test
        sample_endpoints = self.discovered_endpoints[:min(3, len(self.discovered_endpoints))]
        
        for endpoint in sample_endpoints:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')
            
            if not url:
                continue
            
            try:
                # Make multiple rapid requests
                headers = {'User-Agent': self.user_agent}
                responses = []
                
                for _ in range(10):
                    if method == 'GET':
                        response = requests.get(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                    else:
                        response = requests.request(
                            method,
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl,
                            json={}
                        )
                    
                    responses.append(response)
                
                # Check if all requests were successful (might indicate lack of rate limiting)
                if all(r.status_code not in [429, 403, 503] for r in responses):
                    # Check if there are any rate limiting headers
                    rate_limit_headers = [
                        'X-Rate-Limit',
                        'X-RateLimit-Limit',
                        'X-RateLimit-Remaining',
                        'X-RateLimit-Reset',
                        'Retry-After'
                    ]
                    
                    if not any(header in responses[-1].headers for header in rate_limit_headers):
                        scan_result.add_vulnerability(
                            name=VULN_RATE_LIMIT,
                            description="Lack of rate limiting detected",
                            severity=SEVERITY_MEDIUM,
                            location=url,
                            evidence="Multiple rapid requests were successful without rate limiting",
                            remediation="Implement rate limiting to protect against abuse, brute force attacks, and denial of service."
                        )
            except Exception as e:
                self.logger.debug(f"Error testing rate limiting on {url}: {str(e)}")
    
    def _generate_api_documentation(self, scan_result: ScanResult) -> None:
        """Generate documentation for the discovered API.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.info("Generating API documentation")
        
        # Initialize documentation structure
        api_docs = {
            'title': scan_result.scan_info.get('api_title', 'Discovered API'),
            'version': scan_result.scan_info.get('api_version', '1.0'),
            'description': scan_result.scan_info.get('api_description', 'API discovered by PhantomFuzzer'),
            'type': self.api_type,
            'auth_methods': self.auth_methods,
            'endpoints': []
        }
        
        # Process endpoints based on API type
        if self.api_type == API_TYPE_GRAPHQL:
            # Group GraphQL operations
            queries = []
            mutations = []
            
            for endpoint in self.discovered_endpoints:
                operation = endpoint.get('operation')
                name = endpoint.get('name')
                args = endpoint.get('arguments', [])
                
                if operation == 'query' and name:
                    queries.append({
                        'name': name,
                        'description': endpoint.get('description', ''),
                        'arguments': args
                    })
                elif operation == 'mutation' and name:
                    mutations.append({
                        'name': name,
                        'description': endpoint.get('description', ''),
                        'arguments': args
                    })
            
            api_docs['graphql'] = {
                'queries': queries,
                'mutations': mutations,
                'schema': scan_result.scan_info.get('graphql_schema')
            }
        elif self.api_type == API_TYPE_SOAP:
            # Group SOAP operations
            operations = []
            
            for endpoint in self.discovered_endpoints:
                operation = endpoint.get('operation')
                if operation:
                    operations.append({
                        'name': operation,
                        'url': endpoint.get('url')
                    })
            
            api_docs['soap'] = {
                'wsdl_url': scan_result.scan_info.get('soap_wsdl_url'),
                'operations': operations
            }
        else:  # REST API
            # Group REST endpoints by path
            endpoints_by_path = {}
            
            for endpoint in self.discovered_endpoints:
                url = endpoint.get('url', '')
                method = endpoint.get('method', 'GET')
                
                if url and method:
                    if url not in endpoints_by_path:
                        endpoints_by_path[url] = []
                    
                    endpoints_by_path[url].append({
                        'method': method,
                        'description': endpoint.get('description', ''),
                        'parameters': endpoint.get('parameters', []),
                        'responses': endpoint.get('responses', {})
                    })
            
            # Format endpoints for documentation
            for url, methods in endpoints_by_path.items():
                api_docs['endpoints'].append({
                    'path': url,
                    'methods': methods
                })
        
        # Store documentation in scan info
        scan_result.scan_info['api_documentation'] = api_docs
        
        self.logger.info(f"Generated documentation for {len(api_docs['endpoints'])} endpoints")
    
    def _generate_final_report(self, scan_result: ScanResult) -> None:
        """Generate a final report summarizing the API scan results.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.info("Generating final API scan report")
        
        # Calculate scan duration
        start_time = datetime.fromisoformat(scan_result.scan_info['start_time'])
        end_time = datetime.fromisoformat(scan_result.scan_info.get('end_time', datetime.now().isoformat()))
        duration = (end_time - start_time).total_seconds()
        
        # Count vulnerabilities by severity
        vuln_counts = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 0,
            SEVERITY_MEDIUM: 0,
            SEVERITY_LOW: 0,
            SEVERITY_INFO: 0
        }
        
        for vuln in scan_result.vulnerabilities:
            severity = vuln.get('severity', SEVERITY_INFO)
            vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        # Generate summary report
        report = {
            'summary': {
                'target': scan_result.target,
                'scan_duration': duration,
                'endpoints_discovered': len(self.discovered_endpoints),
                'api_type': self.api_type,
                'auth_methods': self.auth_methods,
                'vulnerability_counts': vuln_counts,
                'total_vulnerabilities': len(scan_result.vulnerabilities)
            },
            'security_score': self._calculate_security_score(vuln_counts),
            'recommendations': self._generate_recommendations(scan_result)
        }
        
        # Add report to scan info
        scan_result.scan_info['report'] = report
        
        self.logger.info(f"Final report generated. Security score: {report['security_score']}/100")
    
    def _calculate_security_score(self, vuln_counts: Dict[str, int]) -> int:
        """Calculate a security score based on vulnerability counts.
        
        Args:
            vuln_counts: Dictionary of vulnerability counts by severity.
            
        Returns:
            Security score from 0-100.
        """
        # Base score starts at 100
        score = 100
        
        # Deduct points based on vulnerability severity
        score -= vuln_counts.get(SEVERITY_CRITICAL, 0) * 20  # -20 points per critical vulnerability
        score -= vuln_counts.get(SEVERITY_HIGH, 0) * 10      # -10 points per high vulnerability
        score -= vuln_counts.get(SEVERITY_MEDIUM, 0) * 5     # -5 points per medium vulnerability
        score -= vuln_counts.get(SEVERITY_LOW, 0) * 2        # -2 points per low vulnerability
        score -= vuln_counts.get(SEVERITY_INFO, 0) * 0.5     # -0.5 points per info vulnerability
        
        # Ensure score is between 0 and 100
        return max(0, min(100, int(score)))
    
    def _generate_recommendations(self, scan_result: ScanResult) -> List[Dict[str, str]]:
        """Generate security recommendations based on scan results.
        
        Args:
            scan_result: The scan result.
            
        Returns:
            List of recommendations.
        """
        recommendations = []
        
        # Add general API security recommendations
        recommendations.append({
            'title': 'Implement API Security Best Practices',
            'description': 'Follow OWASP API Security Top 10 guidelines to secure your API.',
            'link': 'https://owasp.org/API-Security/editions/2023/en/0x00-introduction/'
        })
        
        # Add authentication recommendations if needed
        if not self.auth_methods:
            recommendations.append({
                'title': 'Implement API Authentication',
                'description': 'Your API appears to lack authentication. Implement a secure authentication mechanism such as OAuth 2.0 or API keys.',
                'severity': SEVERITY_HIGH
            })
        elif 'Basic' in self.auth_methods:
            recommendations.append({
                'title': 'Upgrade Authentication Method',
                'description': 'Basic authentication is not recommended for production APIs. Consider upgrading to OAuth 2.0 or JWT.',
                'severity': SEVERITY_MEDIUM
            })
        
        # Add recommendations based on vulnerability types found
        vuln_types = set(vuln.get('name') for vuln in scan_result.vulnerabilities)
        
        if VULN_INJECTION in vuln_types:
            recommendations.append({
                'title': 'Fix Injection Vulnerabilities',
                'description': 'Implement input validation, parameterized queries, and output encoding to prevent injection attacks.',
                'severity': SEVERITY_HIGH
            })
        
        if VULN_BROKEN_AUTH in vuln_types:
            recommendations.append({
                'title': 'Fix Authentication Vulnerabilities',
                'description': 'Implement proper authentication checks and token validation. Consider using a well-tested authentication framework.',
                'severity': SEVERITY_CRITICAL
            })
        
        if VULN_BROKEN_OBJECT_AUTH in vuln_types:
            recommendations.append({
                'title': 'Fix Broken Object Level Authorization',
                'description': 'Implement proper authorization checks for each resource access. Verify the user has permission to access the specific resource.',
                'severity': SEVERITY_HIGH
            })
        
        if VULN_MASS_ASSIGNMENT in vuln_types:
            recommendations.append({
                'title': 'Fix Mass Assignment Vulnerabilities',
                'description': 'Implement a whitelist of allowed fields for each endpoint. Never trust client-provided data for sensitive fields.',
                'severity': SEVERITY_HIGH
            })
        
        if VULN_RATE_LIMIT in vuln_types:
            recommendations.append({
                'title': 'Implement Rate Limiting',
                'description': 'Add rate limiting to your API to protect against abuse, brute force attacks, and denial of service.',
                'severity': SEVERITY_MEDIUM
            })
        
        return recommendations