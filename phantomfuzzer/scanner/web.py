#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web application scanner implementation for PhantomFuzzer.

This module provides a scanner implementation for web applications,
including crawling, endpoint discovery, and vulnerability detection.
"""

import os
import sys
import time
import json
import re
import urllib.parse
import socket
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from urllib.parse import urlparse, urljoin

# Try to import required libraries
try:
    import requests
    from requests.exceptions import RequestException, Timeout, TooManyRedirects
    from bs4 import BeautifulSoup
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Import from phantomfuzzer package
from phantomfuzzer.scanner.base import BaseScanner, ScanResult
from phantomfuzzer.scanner.base import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from phantomfuzzer.scanner.base import STATUS_COMPLETED, STATUS_FAILED
from phantomfuzzer.utils.logging import get_module_logger
from phantomfuzzer.utils.helper import (
    VerbosityLevel, print_status, print_info, print_warning,
    print_error, print_success, print_debug, print_verbose,
    print_section, print_summary, print_progress
)

# Default request timeout
DEFAULT_TIMEOUT = 10

# Default user agent
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# Common web vulnerabilities
VULN_XSS = 'Cross-Site Scripting (XSS)'
VULN_SQLI = 'SQL Injection'
VULN_CSRF = 'Cross-Site Request Forgery (CSRF)'
VULN_OPEN_REDIRECT = 'Open Redirect'
VULN_INFO_DISCLOSURE = 'Information Disclosure'
VULN_INSECURE_HEADERS = 'Insecure Headers'

class WebScanner(BaseScanner):
    """Web application scanner implementation.
    
    This class implements a scanner for web applications, including
    crawling, endpoint discovery, and vulnerability detection.
    """
    
    def _init_scanner(self) -> None:
        """Initialize scanner-specific settings.
        
        This method is called by the BaseScanner constructor.
        """
        if not REQUESTS_AVAILABLE:
            self.logger.error("Required libraries not available: requests, beautifulsoup4")
            raise ImportError("Required libraries not available: requests, beautifulsoup4")
        
        # Get web scanner configuration
        web_config = self.config.get('web_scan', {})
        
        # Initialize settings
        self.max_depth = web_config.get('max_depth', 3)
        self.max_urls = web_config.get('max_urls', 100)
        self.timeout = web_config.get('timeout', DEFAULT_TIMEOUT)
        self.user_agent = web_config.get('user_agent', DEFAULT_USER_AGENT)
        self.follow_redirects = web_config.get('follow_redirects', True)
        self.verify_ssl = web_config.get('verify_ssl', True)
        
        # Initialize scan state
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.forms_found = []
        
        # Initialize vulnerability checks
        self.enable_xss = web_config.get('enable_xss', True)
        self.enable_sqli = web_config.get('enable_sqli', True)
        self.enable_csrf = web_config.get('enable_csrf', True)
        self.enable_open_redirect = web_config.get('enable_open_redirect', True)
        self.enable_info_disclosure = web_config.get('enable_info_disclosure', True)
        self.enable_header_checks = web_config.get('enable_header_checks', True)
        
        # Load payloads
        self._load_payloads()
    
    def _load_payloads(self) -> None:
        """Load payloads for vulnerability testing."""
        payload_config = self.config_manager.get_payload_config()
        
        # Default payloads in case config doesn't have them
        self.xss_payloads = payload_config.get('xss', [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>'
        ])
        
        self.sqli_payloads = payload_config.get('sqli', [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1' --",
            "1\" OR \"1\"=\"1\" --",
            "' UNION SELECT 1,2,3 --"
        ])
        
        self.open_redirect_payloads = payload_config.get('open_redirect', [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'javascript:alert(1)'
        ])
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Perform a web scan on the target.
        
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
        max_depth = options.get('max_depth', self.max_depth)
        max_urls = options.get('max_urls', self.max_urls)
        
        # Start the scan
        scan_result = self.start_scan(target, options)
        
        try:
            # Initialize scan state
            self.visited_urls = set()
            self.urls_to_scan = {target}
            self.forms_found = []
            
            # Get IP information for the target
            ip_info = self._get_ip_information(target)
            
            # Add scan info
            scan_result.scan_info = {
                'max_depth': max_depth,
                'max_urls': max_urls,
                'user_agent': self.user_agent,
                'follow_redirects': self.follow_redirects,
                'verify_ssl': self.verify_ssl,
                'ip_information': ip_info
            }
            
            # Crawl the website
            self._crawl(target, max_depth, max_urls, scan_result)
            
            # Scan for vulnerabilities
            self._scan_for_vulnerabilities(scan_result)
            
            # Complete the scan
            return self.finish_scan(STATUS_COMPLETED)
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {str(e)}")
            scan_result.scan_info['error'] = str(e)
            return self.finish_scan(STATUS_FAILED)
    
    def _crawl(self, base_url: str, max_depth: int, max_urls: int, scan_result: ScanResult) -> None:
        """Crawl the website to discover URLs and forms.
        
        Args:
            base_url: The base URL to start crawling from.
            max_depth: The maximum crawl depth.
            max_urls: The maximum number of URLs to crawl.
            scan_result: The scan result to update.
        """
        self.logger.info(f"Starting crawl of {base_url} (max depth: {max_depth}, max URLs: {max_urls})")
        print_section(f"Web Crawling: {base_url}")
        print_info(f"Max depth: {max_depth}, Max URLs: {max_urls}")
        
        current_depth = 0
        urls_by_depth = {0: [base_url]}
        
        while current_depth <= max_depth and len(self.visited_urls) < max_urls:
            if current_depth not in urls_by_depth or not urls_by_depth[current_depth]:
                current_depth += 1
                continue
            
            current_urls = urls_by_depth[current_depth]
            if current_depth + 1 not in urls_by_depth:
                urls_by_depth[current_depth + 1] = []
            
            for url in current_urls:
                if url in self.visited_urls or len(self.visited_urls) >= max_urls:
                    continue
                
                try:
                    self.logger.debug(f"Crawling URL: {url}")
                    print_debug(f"Crawling URL: {url}")
                    self.visited_urls.add(url)
                    
                    # Make the request
                    headers = {'User-Agent': self.user_agent}
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                        verify=self.verify_ssl
                    )
                    
                    # Check for forms
                    self._extract_forms(url, response.text, scan_result)
                    
                    # Extract links
                    new_urls = self._extract_urls(base_url, url, response.text)
                    for new_url in new_urls:
                        if new_url not in self.visited_urls and len(urls_by_depth[current_depth + 1]) < max_urls:
                            urls_by_depth[current_depth + 1].append(new_url)
                    
                except RequestException as e:
                    self.logger.warning(f"Error crawling {url}: {str(e)}")
                    print_warning(f"Error crawling {url}: {str(e)}")
            
            current_depth += 1
            # Show progress
            print_progress(len(self.visited_urls), max_urls, prefix="Crawling progress:", suffix=f"Depth: {current_depth}/{max_depth}")
        
        self.logger.info(f"Crawl completed. Visited {len(self.visited_urls)} URLs.")
        print_success(f"Crawl completed. Visited {len(self.visited_urls)} URLs.")
        print_info(f"Forms found: {len(self.forms_found)}")
        scan_result.scan_info['urls_crawled'] = len(self.visited_urls)
        scan_result.scan_info['forms_found'] = len(self.forms_found)
    
    def _extract_urls(self, base_url: str, current_url: str, html_content: str) -> Set[str]:
        """Extract URLs from HTML content.
        
        Args:
            base_url: The base URL of the website.
            current_url: The current URL being processed.
            html_content: The HTML content to extract URLs from.
        
        Returns:
            A set of extracted URLs.
        """
        urls = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract links from <a> tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                absolute_url = urljoin(current_url, href)
                
                # Only include URLs from the same domain
                if self._is_same_domain(base_url, absolute_url):
                    urls.add(absolute_url)
        except Exception as e:
            self.logger.warning(f"Error extracting URLs from {current_url}: {str(e)}")
            print_debug(f"Error extracting URLs from {current_url}: {str(e)}")
        
        return urls
    
    def _extract_forms(self, url: str, html_content: str, scan_result: ScanResult) -> None:
        """Extract forms from HTML content.
        
        Args:
            url: The URL being processed.
            html_content: The HTML content to extract forms from.
            scan_result: The scan result to update.
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_info = {
                    'url': url,
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                
                self.forms_found.append(form_info)
        except Exception as e:
            self.logger.warning(f"Error extracting forms from {url}: {str(e)}")
            print_debug(f"Error extracting forms from {url}: {str(e)}")
    
    def _is_same_domain(self, base_url: str, url: str) -> bool:
        """Check if a URL is from the same domain as the base URL.
        
        Args:
            base_url: The base URL to compare against.
            url: The URL to check.
        
        Returns:
            True if the URL is from the same domain, False otherwise.
        """
        base_domain = urlparse(base_url).netloc
        url_domain = urlparse(url).netloc
        
        return url_domain == base_domain or url_domain.endswith('.' + base_domain)
    
    def _get_ip_information(self, url: str) -> Dict[str, Any]:
        """Get IP information for a given URL.
        
        Args:
            url: The URL to get IP information for.
            
        Returns:
            A dictionary containing IP information.
        """
        try:
            # Parse the URL to get the hostname
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            # Get IP address
            ip_address = socket.gethostbyname(hostname)
            
            # Try to get additional information about the IP
            try:
                host_info = socket.gethostbyaddr(ip_address)
                hostname_from_ip = host_info[0]
                aliases = host_info[1]
            except socket.herror:
                hostname_from_ip = "Unknown"
                aliases = []
            
            # Return IP information
            return {
                'hostname': hostname,
                'ip_address': ip_address,
                'hostname_from_ip': hostname_from_ip,
                'aliases': aliases
            }
        except Exception as e:
            self.logger.warning(f"Error getting IP information for {url}: {str(e)}")
            return {
                'hostname': urlparse(url).netloc,
                'ip_address': "Unknown",
                'error': str(e)
            }
    
    def _scan_for_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Scan for vulnerabilities in the discovered URLs and forms.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.info("Starting vulnerability scan")
        print_section("Vulnerability Scanning")
        
        # Check for vulnerabilities in forms
        if self.enable_xss or self.enable_sqli:
            self._scan_forms_for_vulnerabilities(scan_result)
        
        # Check for open redirects
        if self.enable_open_redirect:
            self._scan_for_open_redirects(scan_result)
        
        # Check for CSRF vulnerabilities
        if self.enable_csrf:
            self._scan_for_csrf(scan_result)
        
        # Check for information disclosure
        if self.enable_info_disclosure:
            self._scan_for_info_disclosure(scan_result)
        
        # Check for insecure headers
        if self.enable_header_checks:
            self._scan_for_insecure_headers(scan_result)
        
        self.logger.info("Vulnerability scan completed")
        print_success("Vulnerability scan completed")
        
        # Print summary of vulnerabilities found
        vulnerabilities = scan_result.vulnerabilities
        if vulnerabilities:
            vuln_summary = [f"{v['name']} ({v['severity'].upper()}) at {v['location']}" for v in vulnerabilities]
            print_summary(f"Found {len(vulnerabilities)} vulnerabilities", vuln_summary)
        else:
            print_info("No vulnerabilities found")
    
    def _scan_forms_for_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Scan forms for XSS and SQL injection vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        for form in self.forms_found:
            self.logger.debug(f"Scanning form at {form['url']} with action {form['action']}")
            print_verbose(f"Scanning form at {form['url']} with action {form['action']}")
            
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name']:
                    form_data[input_field['name']] = input_field['value'] or 'test'
            
            # Test for XSS
            if self.enable_xss:
                self._test_form_for_xss(form, form_data, scan_result)
            
            # Test for SQL injection
            if self.enable_sqli:
                self._test_form_for_sqli(form, form_data, scan_result)
    
    def _test_form_for_xss(self, form: Dict[str, Any], form_data: Dict[str, str], scan_result: ScanResult) -> None:
        """Test a form for XSS vulnerabilities.
        
        Args:
            form: The form information.
            form_data: The form data to submit.
            scan_result: The scan result to update.
        """
        for input_name in form_data.keys():
            for payload in self.xss_payloads:
                test_data = form_data.copy()
                test_data[input_name] = payload
                
                try:
                    headers = {'User-Agent': self.user_agent}
                    
                    if form['method'] == 'post':
                        response = requests.post(
                            form['action'],
                            data=test_data,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=self.follow_redirects,
                            verify=self.verify_ssl
                        )
                    else:  # GET
                        response = requests.get(
                            form['action'],
                            params=test_data,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=self.follow_redirects,
                            verify=self.verify_ssl
                        )
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        scan_result.add_vulnerability(
                            name=VULN_XSS,
                            description=f"Possible XSS vulnerability found in {form['method'].upper()} form at {form['url']} (parameter: {input_name})",
                            severity=SEVERITY_HIGH,
                            location=f"{form['url']} (form action: {form['action']})",
                            evidence=f"Payload: {payload}",
                            remediation="Implement proper input validation and output encoding."
                        )
                        break  # Found a vulnerability, no need to test more payloads for this input
                
                except RequestException as e:
                    self.logger.warning(f"Error testing form at {form['url']} for XSS: {str(e)}")
                    print_warning(f"Error testing form at {form['url']} for XSS: {str(e)}")
    
    def _test_form_for_sqli(self, form: Dict[str, Any], form_data: Dict[str, str], scan_result: ScanResult) -> None:
        """Test a form for SQL injection vulnerabilities.
        
        Args:
            form: The form information.
            form_data: The form data to submit.
            scan_result: The scan result to update.
        """
        for input_name in form_data.keys():
            for payload in self.sqli_payloads:
                test_data = form_data.copy()
                test_data[input_name] = payload
                
                try:
                    headers = {'User-Agent': self.user_agent}
                    
                    if form['method'] == 'post':
                        response = requests.post(
                            form['action'],
                            data=test_data,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=self.follow_redirects,
                            verify=self.verify_ssl
                        )
                    else:  # GET
                        response = requests.get(
                            form['action'],
                            params=test_data,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=self.follow_redirects,
                            verify=self.verify_ssl
                        )
                    
                    # Check for SQL error patterns
                    sql_error_patterns = [
                        'SQL syntax',
                        'mysql_fetch_array',
                        'ORA-',
                        'PostgreSQL',
                        'SQLite3::',
                        'Microsoft SQL Server',
                        'ODBC Driver',
                        'syntax error',
                        'unclosed quotation mark'
                    ]
                    
                    for pattern in sql_error_patterns:
                        if pattern.lower() in response.text.lower():
                            scan_result.add_vulnerability(
                                name=VULN_SQLI,
                                description=f"Possible SQL injection vulnerability found in {form['method'].upper()} form at {form['url']} (parameter: {input_name})",
                                severity=SEVERITY_CRITICAL,
                                location=f"{form['url']} (form action: {form['action']})",
                                evidence=f"Payload: {payload}, Error pattern: {pattern}",
                                remediation="Use parameterized queries or prepared statements."
                            )
                            break  # Found a vulnerability, no need to check more patterns
                
                except RequestException as e:
                    self.logger.warning(f"Error testing form at {form['url']} for SQL injection: {str(e)}")
                    print_warning(f"Error testing form at {form['url']} for SQL injection: {str(e)}")
    
    def _scan_for_open_redirects(self, scan_result: ScanResult) -> None:
        """Scan for open redirect vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        redirect_params = ['url', 'redirect', 'redirect_to', 'return', 'return_to', 'goto', 'next', 'target', 'destination', 'redir']
        
        for url in self.visited_urls:
            parsed_url = urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in redirect_params:
                if param in query_params:
                    for payload in self.open_redirect_payloads:
                        test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={payload}")
                        
                        try:
                            headers = {'User-Agent': self.user_agent}
                            response = requests.get(
                                test_url,
                                headers=headers,
                                timeout=self.timeout,
                                allow_redirects=False,  # Don't follow redirects
                                verify=self.verify_ssl
                            )
                            
                            # Check for redirect response
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if payload in location or payload.replace('https://', '') in location:
                                    scan_result.add_vulnerability(
                                        name=VULN_OPEN_REDIRECT,
                                        description=f"Open redirect vulnerability found at {url} (parameter: {param})",
                                        severity=SEVERITY_MEDIUM,
                                        location=url,
                                        evidence=f"Redirect to: {location}",
                                        remediation="Implement a whitelist of allowed redirect destinations."
                                    )
                                    print_warning(f"Open redirect vulnerability found at {url} (parameter: {param})")
                        
                        except RequestException as e:
                            self.logger.warning(f"Error testing {url} for open redirect: {str(e)}")
                            print_debug(f"Error testing {url} for open redirect: {str(e)}")
    
    def _scan_for_csrf(self, scan_result: ScanResult) -> None:
        """Scan for CSRF vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        for form in self.forms_found:
            if form['method'] == 'post':
                # Check for CSRF token
                has_csrf_token = False
                for input_field in form['inputs']:
                    name = input_field['name'].lower()
                    if 'csrf' in name or 'token' in name or '_token' in name:
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    scan_result.add_vulnerability(
                        name=VULN_CSRF,
                        description=f"Possible CSRF vulnerability found in POST form at {form['url']}",
                        severity=SEVERITY_MEDIUM,
                        location=f"{form['url']} (form action: {form['action']})",
                        evidence="No CSRF token found in the form",
                        remediation="Implement CSRF tokens for all state-changing operations."
                    )
                    print_warning(f"Possible CSRF vulnerability found in POST form at {form['url']}")
    
    def _scan_for_info_disclosure(self, scan_result: ScanResult) -> None:
        """Scan for information disclosure vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        info_disclosure_patterns = [
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP address'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'Email address'),
            (r'(?i)password\s*[=:]\s*[^\s]+', 'Password in HTML/JS'),
            (r'(?i)api[_-]?key\s*[=:]\s*[^\s]+', 'API key'),
            (r'(?i)secret\s*[=:]\s*[^\s]+', 'Secret key'),
            (r'(?i)BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY', 'Private key')
        ]
        
        for url in self.visited_urls:
            try:
                headers = {'User-Agent': self.user_agent}
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    verify=self.verify_ssl
                )
                
                for pattern, description in info_disclosure_patterns:
                    matches = re.findall(pattern, response.text)
                    if matches:
                        # Limit the number of matches to report
                        evidence = ', '.join(matches[:3])
                        if len(matches) > 3:
                            evidence += f" and {len(matches) - 3} more"
                        
                        scan_result.add_vulnerability(
                            name=VULN_INFO_DISCLOSURE,
                            description=f"Information disclosure: {description} found at {url}",
                            severity=SEVERITY_MEDIUM,
                            location=url,
                            evidence=evidence,
                            remediation="Remove sensitive information from client-side code and responses."
                        )
            
            except RequestException as e:
                self.logger.warning(f"Error scanning {url} for information disclosure: {str(e)}")
                print_debug(f"Error scanning {url} for information disclosure: {str(e)}")
    
    def _scan_for_insecure_headers(self, scan_result: ScanResult) -> None:
        """Scan for insecure headers.
        
        Args:
            scan_result: The scan result to update.
        """
        # Sample URL from the visited URLs
        if not self.visited_urls:
            return
        
        url = next(iter(self.visited_urls))
        
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=self.verify_ssl
            )
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS not implemented',
                'Content-Security-Policy': 'CSP not implemented',
                'X-Content-Type-Options': 'X-Content-Type-Options header missing',
                'X-Frame-Options': 'X-Frame-Options header missing',
                'X-XSS-Protection': 'X-XSS-Protection header missing'
            }
            
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header, description in security_headers.items():
                if header.lower() not in response_headers:
                    scan_result.add_vulnerability(
                        name=VULN_INSECURE_HEADERS,
                        description=f"Insecure headers: {description}",
                        severity=SEVERITY_LOW,
                        location=url,
                        evidence=f"Header {header} is missing",
                        remediation=f"Implement the {header} header."
                    )
                    print_verbose(f"Insecure header: {header} is missing")
        
        except RequestException as e:
            self.logger.warning(f"Error checking security headers for {url}: {str(e)}")
            print_debug(f"Error checking security headers for {url}: {str(e)}")
    
    def _apply_stealth_mode(self) -> None:
        """Apply stealth mode settings for web scanning.
        
        This method overrides the base implementation to apply web-specific
        stealth settings.
        """
        super()._apply_stealth_mode()
        
        stealth_config = self.config_manager.get_stealth_config()
        
        # Apply web-specific stealth settings
        self.user_agent = stealth_config.get('user_agent', self.user_agent)
        self.timeout = stealth_config.get('request_timeout', self.timeout)
        
        # Add random delays between requests
        self.request_delay_min = stealth_config.get('request_delay_min', 1)
        self.request_delay_max = stealth_config.get('request_delay_max', 3)
        
        # Limit request rate
        self.max_requests_per_second = stealth_config.get('max_requests_per_second', 2)
        
        self.logger.debug("Applied web-specific stealth settings")
    
    def _apply_ml_enhancements(self) -> None:
        """Apply ML enhancements for web scanning.
        
        This method overrides the base implementation to apply web-specific
        ML enhancements.
        """
        super()._apply_ml_enhancements()
        
        ml_config = self.config_manager.get_ml_config()
        
        # Apply web-specific ML settings
        self.use_ml_for_payload_generation = ml_config.get('use_for_payload_generation', False)
        self.use_ml_for_vulnerability_detection = ml_config.get('use_for_vulnerability_detection', False)
        
        self.logger.debug("Applied web-specific ML enhancements")
