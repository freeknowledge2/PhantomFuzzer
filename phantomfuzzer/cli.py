#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PhantomFuzzer CLI - Command-line interface for the PhantomFuzzer toolkit

This module provides a command-line interface for interacting with various
components of the PhantomFuzzer toolkit, including the PayloadGenerator,
fuzzers, and scanners.
"""

# Suppress warnings before importing other modules
import os
import sys
import warnings
import tempfile
import logging
import subprocess

# Completely silence specific loggers
logging.getLogger('matplotlib').setLevel(logging.ERROR)
logging.getLogger('PIL').setLevel(logging.ERROR)
logging.getLogger('scapy').setLevel(logging.ERROR)

# Set environment variables to suppress warnings
os.environ['PYTHONWARNINGS'] = 'ignore::DeprecationWarning,ignore::PendingDeprecationWarning'
os.environ['MPLCONFIGDIR'] = tempfile.mkdtemp()

# Suppress all deprecation warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=PendingDeprecationWarning)
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', message='.*moved to cryptography.hazmat.decrepit.*')
warnings.filterwarnings('ignore', message='.*Matplotlib created a temporary config.*')

import json
import click
import logging
from typing import Dict, List, Optional, Any, Union

from phantomfuzzer.payload import PayloadGenerator
from phantomfuzzer.utils.logging import setup_logger
from phantomfuzzer.utils.helper import VerbosityLevel, set_verbosity, set_use_colors, print_banner

# Import fuzzer modules
from phantomfuzzer.fuzzer.api_fuzzer import ApiFuzzer as APIFuzzer
from phantomfuzzer.fuzzer.protocol_fuzzer import ProtocolFuzzer
from phantomfuzzer.fuzzer.input_fuzzer import InputFuzzer

# Import scanner modules
from phantomfuzzer.scanner.web import WebScanner
from phantomfuzzer.scanner.api_scanner import APIScanner
from phantomfuzzer.scanner.file_scanner import FileScanner

# Setup logger
logger = setup_logger('cli')

# Load ASCII art banner from file
try:
    # Try multiple possible locations for the ASCII banner
    banner_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ascii.txt'),  # Project root
        '/app/ascii.txt',  # Docker container path
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ascii.txt'),  # Module directory
    ]
    
    for path in banner_paths:
        if os.path.exists(path):
            with open(path, 'r') as f:
                BANNER = f.read()
            break
    else:
        raise FileNotFoundError("ASCII banner file not found in any of the expected locations")
        
except Exception as e:
    # Don't log the warning to avoid cluttering the output
    # Fallback banner
    BANNER = r'''
██████╗░██╗░░██╗░█████╗░███╗░░██╗████████╗░█████╗░███╗░░░███╗
██╔══██╗██║░░██║██╔══██╗████╗░██║╚══██╔══╝██╔══██╗████╗░████║
██████╔╝███████║██║░░██║██╔██╗██║░░░██║░░░██║░░██║██╔████╔██║
██╔═══╝░██╔══██║██║░░██║██║╚████║░░░██║░░░██║░░██║██║╚██╔╝██║
██║░░░░░██║░░██║╚█████╔╝██║░╚███║░░░██║░░░╚█████╔╝██║░╚═╝░██║
╚═╝░░░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚══╝░░░╚═╝░░░░╚════╝░╚═╝░░░░░╚═╝

███████╗██╗░░░██╗███████╗███████╗███████╗██████╗░
██╔════╝██║░░░██║╚════██║╚════██║██╔════╝██╔══██╗
█████╗░░██║░░░██║░░███╔═╝░░███╔═╝█████╗░░██████╔╝
██╔══╝░░██║░░░██║██╔══╝░░██╔══╝░░██╔══╝░░██╔══██╗
██║░░░░░╚██████╔╝███████╗███████╗███████╗██║░░██║
╚═╝░░░░░░╚═════╝░╚══════╝╚══════╝╚══════╝╚═╝░░╚═╝
[*]Enhanced ML Web Scanner, Fuzzer, and Payload Generator  
                by Ghost Security
    '''

# Custom help class to ensure banner is always displayed
class CustomHelp(click.Command):
    def format_help(self, ctx, formatter):
        # Display banner first
        formatter.write(BANNER + "\n\n")
        # Then display the standard help text
        super().format_help(ctx, formatter)

class CustomGroup(click.Group):
    def format_help(self, ctx, formatter):
        # Display banner first
        formatter.write(BANNER + "\n\n")
        # Then display the standard help text
        super().format_help(ctx, formatter)

# Click group for all PhantomFuzzer commands
@click.group(cls=CustomGroup)
@click.version_option(version='0.1.0')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--quiet', '-q', is_flag=True, help='Minimize output (only show critical messages and results)')
@click.option('--verbose', '-v', is_flag=True, help='Show more detailed output')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.pass_context
def cli(ctx, debug, quiet, verbose, no_color):
    """
    PhantomFuzzer: Advanced Security Testing Toolkit
    
    A comprehensive toolkit for security testing, fuzzing, and vulnerability discovery.
    
    This tool provides multiple modules for security professionals:
    
    \b
    * SCANNER: Identify security issues in web applications, APIs, and files
      - Web Scanner: Test websites for XSS, CSRF, SQLi, and more
      - API Scanner: Find vulnerabilities in API endpoints
      - File Scanner: Detect malicious code and security issues in files
    
    \b
    * FUZZER: Test applications for vulnerabilities by sending unexpected inputs
      - API Fuzzer: Test API endpoints for error handling and injection flaws
      - Protocol Fuzzer: Test network protocols for implementation vulnerabilities
      - Input Fuzzer: Test file parsers and application inputs
    
    \b
    * PAYLOAD: Generate attack payloads for various security testing scenarios
      - Generate specialized payloads for XSS, SQLi, command injection
      - Create multiple payloads for comprehensive testing
      - Produce random payloads from any category
    
    For detailed usage examples, run: phantomfuzzer COMMAND --help
    """
    # Set verbosity level based on command-line options
    if debug:
        verbosity = VerbosityLevel.DEBUG
    elif verbose:
        verbosity = VerbosityLevel.VERBOSE
    elif quiet:
        verbosity = VerbosityLevel.QUIET
    else:
        verbosity = VerbosityLevel.NORMAL
    
    # Configure helper module
    set_verbosity(verbosity)
    set_use_colors(not no_color)
    
    # Also print banner when running the base command without --help
    if ctx.invoked_subcommand is None:
        print_banner(BANNER)
    
    # Configure logging based on verbosity
    log_levels = {
        VerbosityLevel.QUIET: logging.WARNING,
        VerbosityLevel.NORMAL: logging.INFO,
        VerbosityLevel.VERBOSE: logging.INFO,  # Still INFO but with more helper output
        VerbosityLevel.DEBUG: logging.DEBUG
    }
    log_level = log_levels[verbosity]
    
    # Configure logging
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Silence some noisy loggers regardless of verbosity
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('bs4').setLevel(logging.WARNING)
    
    # Initialize context object
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['VERBOSITY'] = verbosity
    ctx.obj['USE_COLORS'] = not no_color

# Reorganized for better command ordering - Scanner first as it's likely the most used
# Scanner command group
@cli.group(cls=CustomGroup)
@click.pass_context
def scanner(ctx):
    """
    Run various types of scanners against targets.
    
    The scanner module provides tools to identify security vulnerabilities
    in web applications, APIs, and files using advanced detection techniques.
    
    Commands:
      web    Scan web applications for vulnerabilities like XSS, SQLi, CSRF
      api    Scan API endpoints for security issues and misconfigurations
      file   Scan files and directories for malicious code and vulnerabilities
    
    Examples:
      phantomfuzzer scanner web --url https://example.com
      phantomfuzzer scanner api --url https://api.example.com --spec openapi.json
      phantomfuzzer scanner file --path ./target --recursive
    """
    # Initialize common scanner options
    ctx.obj['scanner_options'] = {}

@scanner.command('web', cls=CustomHelp)
@click.option('--url', '-u', required=True, help='Target URL to scan')
@click.option('--depth', '-d', type=int, default=2, help='Crawl depth (1-5)')
@click.option('--threads', '-t', type=int, default=5, help='Number of concurrent threads')
@click.option('--user-agent', help='Custom user agent string')
@click.option('--cookies', help='JSON string with cookies')
@click.option('--headers', '-h', help='JSON string with request headers')
@click.option('--auth', '-a', help='JSON string with authentication details')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html']), default='text', help='Output format')
@click.option('--stealth', is_flag=True, help='Enable stealth mode to avoid detection')
@click.option('--ml-enhanced', is_flag=True, help='Use machine learning to enhance scanning')
@click.pass_context
def web_scanner(ctx, url, depth, threads, user_agent, cookies, headers, auth, output, format, stealth, ml_enhanced):
    """
    Scan web applications for vulnerabilities.
    
    This command runs a comprehensive web scanner against the specified URL,
    testing for various web vulnerabilities such as XSS, CSRF, SQLi, and more.
    
    Examples:
      Basic scan:
        phantomfuzzer scanner web --url https://example.com
      
      Scan with authentication:
        phantomfuzzer scanner web --url https://example.com --auth '{"username":"user","password":"pass"}'
      
      Deep scan with increased thread count:
        phantomfuzzer scanner web --url https://example.com --depth 4 --threads 10
      
      Save results to file:
        phantomfuzzer scanner web --url https://example.com --output results.json --format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Parse JSON options
    cookies_dict = {}
    headers_dict = {}
    auth_dict = {}
    
    if cookies:
        try:
            cookies_dict = json.loads(cookies)
        except json.JSONDecodeError:
            click.echo("Error: Cookies must be a valid JSON string", err=True)
            sys.exit(1)
    
    if headers:
        try:
            headers_dict = json.loads(headers)
        except json.JSONDecodeError:
            click.echo("Error: Headers must be a valid JSON string", err=True)
            sys.exit(1)
    
    if auth:
        try:
            auth_dict = json.loads(auth)
        except json.JSONDecodeError:
            click.echo("Error: Auth must be a valid JSON string", err=True)
            sys.exit(1)
    
    # Configure scanner
    config = {
        'target': url,
        'depth': depth,
        'threads': threads,
        'user_agent': user_agent,
        'cookies': cookies_dict,
        'headers': headers_dict,
        'auth': auth_dict,
        'stealth_enabled': stealth,
        'ml_enabled': ml_enhanced
    }
    
    try:
        # Initialize and run scanner
        click.echo(f"Starting web scanning against {url}...")
        
        # Use ML-enhanced scanner if the flag is provided
        if ml_enhanced:
            from phantomfuzzer.scanner.ml_enhanced_web_scanner import MLEnhancedWebScanner
            click.echo("Using ML-enhanced scanning capabilities")
            web_scanner = MLEnhancedWebScanner(config)
        else:
            web_scanner = WebScanner(config)
            
        results = web_scanner.scan(url)
        
        # Process and output results
        try:
            if results and len(results) > 0:
                # Ensure results is iterable
                if not hasattr(results, '__iter__'):
                    results = [results]
                
                click.echo(f"\nFound {len(results)} vulnerabilities")
                
                # Format output
                if format == 'json':
                    # Convert results to dict list for JSON serialization
                    results_list = []
                    for vuln in results:
                        vuln_dict = {
                            'name': getattr(vuln, 'name', 'Unknown'),
                            'severity': getattr(vuln, 'severity', 'Unknown'),
                            'description': getattr(vuln, 'description', 'N/A'),
                            'location': getattr(vuln, 'location', 'N/A'),
                            'evidence': getattr(vuln, 'evidence', None),
                            'remediation': getattr(vuln, 'remediation', None)
                        }
                        results_list.append(vuln_dict)
                    
                    # Get IP information from scan_info if available
                    scan_info = getattr(results, 'scan_info', {}) if hasattr(results, 'scan_info') else {}
                    ip_info = scan_info.get('ip_information', {})
                    
                    output_data = json.dumps({
                        'target': url,
                        'ip_information': ip_info,
                        'vulnerabilities_count': len(results),
                        'vulnerabilities': results_list
                    }, indent=2)
                elif format == 'html':
                    # Simple HTML report
                    # Get IP information from scan_info if available
                    scan_info = getattr(results, 'scan_info', {}) if hasattr(results, 'scan_info') else {}
                    ip_info = scan_info.get('ip_information', {})
                    ip_address = ip_info.get('ip_address', 'Unknown')
                    hostname = ip_info.get('hostname', 'Unknown')
                    hostname_from_ip = ip_info.get('hostname_from_ip', 'Unknown')
                    
                    output_data = f"""<html>
<head><title>PhantomFuzzer Web Scanning Results</title></head>
<body>
<h1>PhantomFuzzer Web Scanning Results</h1>
<p>Target: {url}</p>
<p>IP Information:</p>
<ul>
    <li>IP Address: {ip_address}</li>
    <li>Hostname: {hostname}</li>
    <li>Reverse DNS: {hostname_from_ip}</li>
</ul>
<p>Found {len(results)} vulnerabilities</p>
<ul>
"""
                    for vuln in results:
                        vuln_name = getattr(vuln, 'name', 'Unknown')
                        vuln_desc = getattr(vuln, 'description', 'N/A')
                        vuln_severity = getattr(vuln, 'severity', 'Unknown')
                        vuln_location = getattr(vuln, 'location', 'N/A')
                        vuln_evidence = getattr(vuln, 'evidence', None)
                        vuln_remediation = getattr(vuln, 'remediation', None)
                        
                        output_data += f"<li><strong>{vuln_name}</strong>: {vuln_desc}</li>\n"
                        output_data += f"<ul><li>Severity: {vuln_severity}</li>"
                        output_data += f"<li>Location: {vuln_location}</li>"
                        if vuln_evidence:
                            output_data += f"<li>Evidence: {vuln_evidence}</li>"
                        if vuln_remediation:
                            output_data += f"<li>Remediation: {vuln_remediation}</li>"
                        output_data += "</ul>"
                    output_data += "</ul>\n</body>\n</html>"
                else:  # text format
                    # Get IP information from scan_info if available
                    scan_info = getattr(results, 'scan_info', {}) if hasattr(results, 'scan_info') else {}
                    ip_info = scan_info.get('ip_information', {})
                    ip_address = ip_info.get('ip_address', 'Unknown')
                    hostname = ip_info.get('hostname', 'Unknown')
                    hostname_from_ip = ip_info.get('hostname_from_ip', 'Unknown')
                    
                    output_data = f"PhantomFuzzer Web Scanning Results\n\nTarget: {url}\nIP Address: {ip_address}\nHostname: {hostname}\nReverse DNS: {hostname_from_ip}\nFound {len(results)} vulnerabilities\n\n"
                    for i, vuln in enumerate(results, 1):
                        vuln_name = getattr(vuln, 'name', 'Unknown')
                        vuln_desc = getattr(vuln, 'description', 'N/A')
                        vuln_severity = getattr(vuln, 'severity', 'Unknown')
                        vuln_location = getattr(vuln, 'location', 'N/A')
                        vuln_evidence = getattr(vuln, 'evidence', None)
                        vuln_remediation = getattr(vuln, 'remediation', None)
                        
                        output_data += f"{i}. {vuln_name} ({vuln_severity})\n"
                        output_data += f"   Description: {vuln_desc}\n"
                        output_data += f"   Location: {vuln_location}\n"
                        if vuln_evidence:
                            output_data += f"   Evidence: {vuln_evidence}\n"
                        if vuln_remediation:
                            output_data += f"   Remediation: {vuln_remediation}\n"
                        output_data += "\n"
                
                # Write to file or stdout
                if output:
                    # Ensure directories exist before writing
                    output_dir = os.path.dirname(output)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    with open(output, 'w') as f:
                        f.write(output_data)
                    click.echo(f"Results saved to {output}")
                else:
                    click.echo(output_data)
            else:
                click.echo("No vulnerabilities found")
        except Exception as e:
            click.echo(f"Error processing results: {str(e)}", err=True)
            if ctx.obj.get('DEBUG'):
                import traceback
                click.echo(traceback.format_exc(), err=True)
        else:
            click.echo("No vulnerabilities found")
    
    except Exception as e:
        click.echo(f"Error during web scanning: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@scanner.command('api', cls=CustomHelp)
@click.option('--url', '-u', required=True, help='Target API base URL')
@click.option('--spec', '-s', type=click.Path(exists=True), help='API specification file (OpenAPI/Swagger)')
@click.option('--headers', '-h', help='JSON string with request headers')
@click.option('--auth', '-a', help='JSON string with authentication details')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html']), default='text', help='Output format')
@click.option('--stealth', is_flag=True, help='Enable stealth mode to avoid detection')
@click.option('--ml-enhanced', is_flag=True, help='Use machine learning to enhance scanning')
@click.pass_context
def api_scanner(ctx, url, spec, headers, auth, output, format, stealth, ml_enhanced):
    """
    Scan API endpoints for vulnerabilities.
    
    This command runs an API scanner against the specified API,
    testing for various API vulnerabilities such as improper access control,
    information disclosure, and more.
    
    Examples:
      Basic API scan:
        phantomfuzzer scanner api --url https://api.example.com
      
      Scan with OpenAPI specification:
        phantomfuzzer scanner api --url https://api.example.com --spec openapi.json
      
      Scan with authentication:
        phantomfuzzer scanner api --url https://api.example.com --auth '{"token":"your-api-token"}'
      
      Save results to file:
        phantomfuzzer scanner api --url https://api.example.com --output api_results.json --format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Parse JSON options
    headers_dict = {}
    auth_dict = {}
    
    if headers:
        try:
            headers_dict = json.loads(headers)
        except json.JSONDecodeError:
            click.echo("Error: Headers must be a valid JSON string", err=True)
            sys.exit(1)
    
    if auth:
        try:
            auth_dict = json.loads(auth)
        except json.JSONDecodeError:
            click.echo("Error: Auth must be a valid JSON string", err=True)
            sys.exit(1)
    
    # Configure scanner
    config = {
        'target': url,
        'spec_file': spec,
        'headers': headers_dict,
        'auth': auth_dict,
        'stealth_enabled': stealth,
        'ml_enabled': ml_enhanced
    }
    
    try:
        # Initialize and run scanner
        click.echo(f"Starting API scanning against {url}...")
        api_scanner = APIScanner(config)
        results = api_scanner.scan(url)
        
        # Process and output results
        try:
            if results and len(results) > 0:
                # Ensure results is iterable
                if not hasattr(results, '__iter__'):
                    results = [results]
                
                click.echo(f"\nFound {len(results)} vulnerabilities")
                
                # Format output
                if format == 'json':
                    # Convert results to proper dict format for JSON serialization
                    results_list = []
                    for result in results:
                        if hasattr(result, '__dict__'):
                            result_dict = result.__dict__
                        elif isinstance(result, dict):
                            result_dict = result
                        else:
                            result_dict = {
                                'name': getattr(result, 'name', 'Unknown'),
                                'type': getattr(result, 'type', 'Unknown'),
                                'description': getattr(result, 'description', 'N/A'),
                                'severity': getattr(result, 'severity', 'Unknown')
                            }
                        results_list.append(result_dict)
                    
                    output_data = json.dumps({
                        'target': url,
                        'vulnerabilities_count': len(results),
                        'results': results_list
                    }, indent=2)
                elif format == 'html':
                    # Simple HTML report
                    output_data = f"""<html>
<head><title>PhantomFuzzer API Scanning Results</title></head>
<body>
<h1>PhantomFuzzer API Scanning Results</h1>
<p>Target: {url}</p>
<p>Found {len(results)} vulnerabilities</p>
<ul>
"""
                    for result in results:
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"<li><strong>{result_type}</strong>: {result_desc}</li>\n"
                    output_data += "</ul>\n</body>\n</html>"
                else:  # text format
                    output_data = f"PhantomFuzzer API Scanning Results\n\nTarget: {url}\nFound {len(results)} vulnerabilities\n\n"
                    for i, result in enumerate(results, 1):
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"{i}. {result_type}: {result_desc}\n"
                
                # Write to file or stdout
                if output:
                    # Ensure directories exist before writing
                    output_dir = os.path.dirname(output)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    with open(output, 'w') as f:
                        f.write(output_data)
                    click.echo(f"Results saved to {output}")
                else:
                    click.echo(output_data)
            else:
                click.echo("No vulnerabilities found")
        except Exception as e:
            click.echo(f"Error processing results: {str(e)}", err=True)
            if ctx.obj.get('DEBUG'):
                import traceback
                click.echo(traceback.format_exc(), err=True)
    
    except Exception as e:
        click.echo(f"Error during API scanning: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@scanner.command('file', cls=CustomHelp)
@click.option('--path', '-p', required=True, type=click.Path(exists=True), help='File or directory to scan')
@click.option('--recursive', '-r', is_flag=True, help='Scan directories recursively')
@click.option('--pattern', help='File pattern to match (e.g., "*.php")')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html']), default='text', help='Output format')
@click.option('--ml-enhanced', is_flag=True, help='Use machine learning to enhance scanning')
@click.pass_context
def file_scanner(ctx, path, recursive, pattern, output, format, ml_enhanced):
    """
    Scan files for vulnerabilities and malicious content.
    
    This command runs a file scanner against the specified file or directory,
    testing for various vulnerabilities and malicious content in files.
    
    Examples:
      Scan a single file:
        phantomfuzzer scanner file --path ./target/file.php
      
      Scan directory recursively:
        phantomfuzzer scanner file --path ./target --recursive
      
      Scan with file pattern matching:
        phantomfuzzer scanner file --path ./target --recursive --pattern "*.php"
      
      Save results to file:
        phantomfuzzer scanner file --path ./target --output file_results.json --format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Configure scanner
    config = {
        'target': path,
        'recursive': recursive,
        'pattern': pattern,
        'ml_enabled': ml_enhanced
    }
    
    # Create a callback function to display vulnerabilities in real-time
    def vuln_callback(vulnerability):
        # Print the vulnerability information as soon as it's found
        file_path = vulnerability.get('details', {}).get('file_path', 'Unknown')
        vuln_type = vulnerability.get('type', 'Unknown')
        description = vulnerability.get('description', '')
        severity = vulnerability.get('severity', 'Unknown').upper()
        click.echo(f"[{severity}] {file_path}: {vuln_type} - {description}")
    
    try:
        # Initialize and run scanner
        click.echo(f"Starting file scanning on {path}...")
        file_scanner = FileScanner(config)
        # Set the real-time callback
        file_scanner.set_vulnerability_callback(vuln_callback)
        results = file_scanner.scan(path)
        
        # Process and output final results summary
        try:
            if results and len(results) > 0:
                # Ensure results is iterable
                if not hasattr(results, '__iter__'):
                    results = [results]
                
                click.echo(f"\nScan complete. Found {len(results)} vulnerabilities or issues")
                
                # Format detailed output if requested
                if format == 'json':
                    # Convert results to proper dict format for JSON serialization
                    results_list = []
                    for result in results:
                        if hasattr(result, '__dict__'):
                            result_dict = result.__dict__
                        elif isinstance(result, dict):
                            result_dict = result
                        else:
                            result_dict = {
                                'file': getattr(result, 'file', 'Unknown'),
                                'type': getattr(result, 'type', 'Unknown'),
                                'description': getattr(result, 'description', 'N/A'),
                                'severity': getattr(result, 'severity', 'Unknown')
                            }
                        results_list.append(result_dict)
                    
                    output_data = json.dumps({
                        'target': path,
                        'vulnerabilities_count': len(results),
                        'results': results_list
                    }, indent=2)
                elif format == 'html':
                    # Simple HTML report
                    output_data = f"""<html>
<head><title>PhantomFuzzer File Scanning Results</title></head>
<body>
<h1>PhantomFuzzer File Scanning Results</h1>
<p>Target: {path}</p>
<p>Found {len(results)} vulnerabilities or issues</p>
<ul>
"""
                    for result in results:
                        result_file = result.get('file', 'Unknown') if isinstance(result, dict) else getattr(result, 'file', 'Unknown')
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"<li><strong>{result_file}</strong>: {result_type} - {result_desc}</li>\n"
                    output_data += "</ul>\n</body>\n</html>"
                else:  # text format
                    output_data = f"PhantomFuzzer File Scanning Results\n\nTarget: {path}\nFound {len(results)} vulnerabilities or issues\n\n"
                    for i, result in enumerate(results, 1):
                        result_file = result.get('file', 'Unknown') if isinstance(result, dict) else getattr(result, 'file', 'Unknown')
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"{i}. {result_file}: {result_type} - {result_desc}\n"
                
                # Write to file if output is specified
                if output:
                    # Ensure directories exist before writing
                    output_dir = os.path.dirname(output)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    with open(output, 'w') as f:
                        f.write(output_data)
                    click.echo(f"\nDetailed results saved to {output}")
            else:
                click.echo("No vulnerabilities or issues found")
        except Exception as e:
            click.echo(f"Error processing results: {str(e)}", err=True)
            if ctx.obj.get('DEBUG'):
                import traceback
                click.echo(traceback.format_exc(), err=True)
    
    except Exception as e:
        click.echo(f"Error during file scanning: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

# Fuzzer command group
@cli.group(cls=CustomGroup)
@click.pass_context
def fuzzer(ctx):
    """
    Run various types of fuzzers against targets.
    
    The fuzzer module provides tools to test applications by sending unexpected inputs,
    helping identify potential security vulnerabilities and bugs.
    
    Commands:
      api        Fuzz API endpoints for vulnerabilities
      protocol   Fuzz network protocols for implementation flaws
      input      Fuzz file inputs or application inputs
    
    Examples:
      phantomfuzzer fuzzer api --target https://api.example.com/users --method GET
      phantomfuzzer fuzzer protocol --target example.com --port 80 --protocol http
      phantomfuzzer fuzzer input --target ./application --input-type file
    """
    # Initialize common fuzzer options
    ctx.obj['fuzzer_options'] = {}

@fuzzer.command('api', cls=CustomHelp)
@click.option('--target', '-t', required=True, help='Target API endpoint URL')
@click.option('--method', '-m', type=click.Choice(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']), default='GET', help='HTTP method to use')
@click.option('--headers', '-h', help='JSON string with request headers')
@click.option('--data', '-d', help='JSON string with request data for POST/PUT')
@click.option('--auth', '-a', help='JSON string with authentication details')
@click.option('--iterations', '-i', type=int, default=100, help='Number of fuzzing iterations')
@click.option('--delay', type=float, default=0.5, help='Delay between requests in seconds')
@click.option('--timeout', type=int, default=30, help='Request timeout in seconds')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html']), default='text', help='Output format')
@click.option('--stealth', is_flag=True, help='Enable stealth mode to avoid detection')
@click.pass_context
def api_fuzzer(ctx, target, method, headers, data, auth, iterations, delay, timeout, output, format, stealth):
    """
    Fuzz API endpoints for vulnerabilities.
    
    This command runs API fuzzing against the specified target endpoint,
    testing for various vulnerabilities such as injection, authentication bypass,
    and improper error handling.
    
    Examples:
      Basic API fuzzing:
        phantomfuzzer fuzzer api --target https://api.example.com/v1/users --method GET
      
      POST request fuzzing:
        phantomfuzzer fuzzer api --target https://api.example.com/v1/users --method POST --data '{"username":"test"}'
      
      Fuzz with authentication:
        phantomfuzzer fuzzer api --target https://api.example.com/v1/users --auth '{"token":"your-api-token"}'
      
      Control fuzzing intensity:
        phantomfuzzer fuzzer api --target https://api.example.com/v1/users --iterations 200 --delay 0.2
      
      Save results to file:
        phantomfuzzer fuzzer api --target https://api.example.com/v1/users --output results.json --format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Parse JSON options
    headers_dict = {}
    data_dict = {}
    auth_dict = {}
    
    if headers:
        try:
            headers_dict = json.loads(headers)
        except json.JSONDecodeError:
            click.echo("Error: Headers must be a valid JSON string", err=True)
            sys.exit(1)
    
    if data:
        try:
            data_dict = json.loads(data)
        except json.JSONDecodeError:
            click.echo("Error: Data must be a valid JSON string", err=True)
            sys.exit(1)
    
    if auth:
        try:
            auth_dict = json.loads(auth)
        except json.JSONDecodeError:
            click.echo("Error: Auth must be a valid JSON string", err=True)
            sys.exit(1)
    
    # Configure fuzzer
    config = {
        'target': target,
        'method': method,
        'headers': headers_dict,
        'data': data_dict,
        'auth': auth_dict,
        'iterations': iterations,
        'delay': delay,
        'timeout': timeout,
        'stealth_enabled': stealth
    }
    
    try:
        # Initialize and run fuzzer
        click.echo(f"Starting API fuzzing against {target}...")
        api_fuzzer = APIFuzzer(config)
        results = api_fuzzer.run()
        
        # Process and output results
        try:
            if results and len(results) > 0:
                # Ensure results is iterable
                if not hasattr(results, '__iter__'):
                    results = [results]
                
                click.echo(f"\nFound {len(results)} potential vulnerabilities")
                
                # Format output
                if format == 'json':
                    # Convert results to proper dict format for JSON serialization
                    results_list = []
                    for result in results:
                        if hasattr(result, '__dict__'):
                            result_dict = result.__dict__
                        elif isinstance(result, dict):
                            result_dict = result
                        else:
                            result_dict = {
                                'type': getattr(result, 'type', 'Unknown'),
                                'description': getattr(result, 'description', 'N/A'),
                                'severity': getattr(result, 'severity', 'Unknown')
                            }
                        results_list.append(result_dict)
                    
                    output_data = json.dumps({
                        'target': target,
                        'vulnerabilities_count': len(results),
                        'results': results_list
                    }, indent=2)
                elif format == 'html':
                    # Simple HTML report
                    output_data = f"""<html>
<head><title>PhantomFuzzer API Fuzzing Results</title></head>
<body>
<h1>PhantomFuzzer API Fuzzing Results</h1>
<p>Target: {target}</p>
<p>Found {len(results)} potential vulnerabilities</p>
<ul>
"""
                    for result in results:
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"<li><strong>{result_type}</strong>: {result_desc}</li>\n"
                    output_data += "</ul>\n</body>\n</html>"
                else:  # text format
                    output_data = f"PhantomFuzzer API Fuzzing Results\n\nTarget: {target}\nFound {len(results)} potential vulnerabilities\n\n"
                    for i, result in enumerate(results, 1):
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"{i}. {result_type}: {result_desc}\n"
                
                # Write to file or stdout
                if output:
                    # Ensure directories exist before writing
                    output_dir = os.path.dirname(output)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    with open(output, 'w') as f:
                        f.write(output_data)
                    click.echo(f"Results saved to {output}")
                else:
                    click.echo(output_data)
            else:
                click.echo("No vulnerabilities found")
        except Exception as e:
            click.echo(f"Error processing results: {str(e)}", err=True)
            if ctx.obj.get('DEBUG'):
                import traceback
                click.echo(traceback.format_exc(), err=True)
    
    except Exception as e:
        click.echo(f"Error during API fuzzing: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@fuzzer.command('protocol', cls=CustomHelp)
@click.option('--target', '-t', required=True, help='Target host or IP address')
@click.option('--port', '-p', type=int, required=True, help='Target port number')
@click.option('--protocol', type=click.Choice(['tcp', 'udp', 'http', 'https', 'ftp', 'smtp', 'ssh']), required=True, help='Protocol to fuzz')
@click.option('--iterations', '-i', type=int, default=100, help='Number of fuzzing iterations')
@click.option('--delay', type=float, default=0.5, help='Delay between requests in seconds')
@click.option('--timeout', type=int, default=30, help='Connection timeout in seconds')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html']), default='text', help='Output format')
@click.option('--stealth', is_flag=True, help='Enable stealth mode to avoid detection')
@click.pass_context
def protocol_fuzzer(ctx, target, port, protocol, iterations, delay, timeout, output, format, stealth):
    """
    Fuzz network protocols for vulnerabilities.
    
    This command runs protocol fuzzing against the specified target,
    testing for vulnerabilities in the implementation of various network protocols.
    
    Examples:
      TCP protocol fuzzing:
        phantomfuzzer fuzzer protocol --target example.com --port 80 --protocol tcp
      
      SSH protocol fuzzing:
        phantomfuzzer fuzzer protocol --target example.com --port 22 --protocol ssh
      
      HTTP protocol fuzzing with custom settings:
        phantomfuzzer fuzzer protocol --target example.com --port 80 --protocol http --iterations 100 --delay 0.5
      
      Save results to file:
        phantomfuzzer fuzzer protocol --target example.com --port 80 --protocol http --output protocol_results.json --format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Configure fuzzer
    config = {
        'target': target,
        'port': port,
        'protocol': protocol,
        'iterations': iterations,
        'delay': delay,
        'timeout': timeout,
        'stealth_enabled': stealth
    }
    
    try:
        # Initialize and run fuzzer
        click.echo(f"Starting protocol fuzzing against {target}:{port} ({protocol})...")
        protocol_fuzzer = ProtocolFuzzer(config)
        results = protocol_fuzzer.run()
        
        # Process and output results
        try:
            if results and len(results) > 0:
                # Ensure results is iterable
                if not hasattr(results, '__iter__'):
                    results = [results]
                
                click.echo(f"\nFound {len(results)} potential vulnerabilities")
                
                # Format output
                if format == 'json':
                    # Convert results to proper dict format for JSON serialization
                    results_list = []
                    for result in results:
                        if hasattr(result, '__dict__'):
                            result_dict = result.__dict__
                        elif isinstance(result, dict):
                            result_dict = result
                        else:
                            result_dict = {
                                'type': getattr(result, 'type', 'Unknown'),
                                'description': getattr(result, 'description', 'N/A'),
                                'severity': getattr(result, 'severity', 'Unknown')
                            }
                        results_list.append(result_dict)
                    
                    output_data = json.dumps({
                        'target': f"{target}:{port}",
                        'protocol': protocol,
                        'vulnerabilities_count': len(results),
                        'results': results_list
                    }, indent=2)
                elif format == 'html':
                    # Simple HTML report
                    output_data = f"""<html>
<head><title>PhantomFuzzer Protocol Fuzzing Results</title></head>
<body>
<h1>PhantomFuzzer Protocol Fuzzing Results</h1>
<p>Target: {target}:{port} ({protocol})</p>
<p>Found {len(results)} potential vulnerabilities</p>
<ul>
"""
                    for result in results:
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"<li><strong>{result_type}</strong>: {result_desc}</li>\n"
                    output_data += "</ul>\n</body>\n</html>"
                else:  # text format
                    output_data = f"PhantomFuzzer Protocol Fuzzing Results\n\nTarget: {target}:{port} ({protocol})\nFound {len(results)} potential vulnerabilities\n\n"
                    for i, result in enumerate(results, 1):
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"{i}. {result_type}: {result_desc}\n"
                
                # Write to file or stdout
                if output:
                    # Ensure directories exist before writing
                    output_dir = os.path.dirname(output)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    with open(output, 'w') as f:
                        f.write(output_data)
                    click.echo(f"Results saved to {output}")
                else:
                    click.echo(output_data)
            else:
                click.echo("No vulnerabilities found")
        except Exception as e:
            click.echo(f"Error processing results: {str(e)}", err=True)
            if ctx.obj.get('DEBUG'):
                import traceback
                click.echo(traceback.format_exc(), err=True)
    
    except Exception as e:
        click.echo(f"Error during protocol fuzzing: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@fuzzer.command('input', cls=CustomHelp)
@click.option('--target', '-t', required=True, help='Target file or application')
@click.option('--input-type', type=click.Choice(['file', 'stdin', 'argument']), default='file', help='Input method')
@click.option('--format', type=click.Choice(['binary', 'text', 'json', 'xml', 'auto']), default='auto', help='Input format')
@click.option('--iterations', '-i', type=int, default=100, help='Number of fuzzing iterations')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--output-format', '-f', type=click.Choice(['text', 'json', 'html']), default='text', help='Output format')
@click.pass_context
def input_fuzzer(ctx, target, input_type, format, iterations, output, output_format):
    """
    Fuzz file inputs or application inputs for vulnerabilities.
    
    This command runs input fuzzing against the specified target,
    testing for vulnerabilities related to input handling such as buffer overflows,
    format string vulnerabilities, and more.
    
    Examples:
      File input fuzzing:
        phantomfuzzer fuzzer input --target ./target/application --input-type file
      
      Command-line argument fuzzing:
        phantomfuzzer fuzzer input --target ./target/application --input-type argument
      
      Text format fuzzing:
        phantomfuzzer fuzzer input --target ./target/application --input-type file --format text
      
      Save results to file:
        phantomfuzzer fuzzer input --target ./target/application --output input_results.json --output-format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Configure fuzzer
    config = {
        'target': target,
        'input_type': input_type,
        'format': format,
        'iterations': iterations
    }
    
    try:
        # Initialize and run fuzzer
        click.echo(f"Starting input fuzzing against {target}...")
        input_fuzzer = InputFuzzer(config)
        results = input_fuzzer.run()
        
        # Process and output results
        try:
            if results and len(results) > 0:
                # Ensure results is iterable
                if not hasattr(results, '__iter__'):
                    results = [results]
                
                click.echo(f"\nFound {len(results)} potential vulnerabilities")
                
                # Format output
                if output_format == 'json':
                    # Convert results to proper dict format for JSON serialization
                    results_list = []
                    for result in results:
                        if hasattr(result, '__dict__'):
                            result_dict = result.__dict__
                        elif isinstance(result, dict):
                            result_dict = result
                        else:
                            result_dict = {
                                'type': getattr(result, 'type', 'Unknown'),
                                'description': getattr(result, 'description', 'N/A'),
                                'severity': getattr(result, 'severity', 'Unknown')
                            }
                        results_list.append(result_dict)
                    
                    output_data = json.dumps({
                        'target': target,
                        'vulnerabilities_count': len(results),
                        'results': results_list
                    }, indent=2)
                elif output_format == 'html':
                    # Simple HTML report
                    output_data = f"""<html>
<head><title>PhantomFuzzer Input Fuzzing Results</title></head>
<body>
<h1>PhantomFuzzer Input Fuzzing Results</h1>
<p>Target: {target}</p>
<p>Found {len(results)} potential vulnerabilities</p>
<ul>
"""
                    for result in results:
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"<li><strong>{result_type}</strong>: {result_desc}</li>\n"
                    output_data += "</ul>\n</body>\n</html>"
                else:  # text format
                    output_data = f"PhantomFuzzer Input Fuzzing Results\n\nTarget: {target}\nFound {len(results)} potential vulnerabilities\n\n"
                    for i, result in enumerate(results, 1):
                        result_type = result.get('type', 'Unknown') if isinstance(result, dict) else getattr(result, 'type', 'Unknown')
                        result_desc = result.get('description', 'N/A') if isinstance(result, dict) else getattr(result, 'description', 'N/A')
                        output_data += f"{i}. {result_type}: {result_desc}\n"
                
                # Write to file or stdout
                if output:
                    # Ensure directories exist before writing
                    output_dir = os.path.dirname(output)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    with open(output, 'w') as f:
                        f.write(output_data)
                    click.echo(f"Results saved to {output}")
                else:
                    click.echo(output_data)
            else:
                click.echo("No vulnerabilities found")
        except Exception as e:
            click.echo(f"Error processing results: {str(e)}", err=True)
            if ctx.obj.get('DEBUG'):
                import traceback
                click.echo(traceback.format_exc(), err=True)
    
    except Exception as e:
        click.echo(f"Error during input fuzzing: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

# Payload generator command group
@cli.group(cls=CustomGroup)
@click.pass_context
def payload(ctx):
    """
    Generate attack payloads for security testing.
    
    The payload module provides functionality to generate various types of attack payloads
    for security testing purposes, including SQL injection, XSS, and more.
    
    Commands:
      list       List available payload categories and subcategories
      generate   Generate payloads for a specific category
      random     Generate random payloads from any category
    
    Examples:
      List payload categories:
        phantomfuzzer payload list
      
      Generate SQL injection payloads:
        phantomfuzzer payload generate --category sql_injection --count 5
      
      Generate random payloads:
        phantomfuzzer payload random --count 3 --output payloads.txt
    """
    # Initialize payload generator
    ctx.obj['payload_generator'] = PayloadGenerator()

@payload.command('list', cls=CustomHelp)
@click.option('--category', '-c', help='Filter payloads by category')
@click.pass_context
def list_payloads(ctx, category):
    """
    List available payload categories and subcategories.
    
    This command displays all available payload categories and their subcategories,
    helping you identify the types of payloads you can generate.
    
    Examples:
      List all categories:
        phantomfuzzer payload list
      
      List subcategories for a specific category:
        phantomfuzzer payload list --category sql_injection
    """
    # Print banner before execution
    click.echo(BANNER)
    
    payload_gen = ctx.obj['payload_generator']
    
    # Get all available categories
    categories = {
        'sql_injection': list(payload_gen.sql_injection_payloads.keys()),
        'xss': list(payload_gen.xss_payloads.keys()),
        'command_injection': list(payload_gen.command_injection_payloads.keys()),
        'path_traversal': list(payload_gen.path_traversal_payloads.keys()),
        'format_string': list(payload_gen.format_string_payloads.keys()),
        'buffer_overflow': list(payload_gen.buffer_overflow_payloads.keys()),
        'xxe': list(payload_gen.xxe_payloads.keys()),
        'ssrf': list(payload_gen.ssrf_payloads.keys()),
        'nosql_injection': list(payload_gen.nosql_injection_payloads.keys()),
        'template_injection': list(payload_gen.template_injection_payloads.keys())
    }
    
    if category and category in categories:
        # Display subcategories for the specified category
        click.echo(f"\nSubcategories for {category}:")
        for subcategory in categories[category]:
            click.echo(f"  - {subcategory}")
    else:
        # Display all categories and their subcategories
        click.echo("\nAvailable payload categories:")
        for cat, subcats in categories.items():
            click.echo(f"\n{cat}:")
            for subcat in subcats:
                click.echo(f"  - {subcat}")

@payload.command('generate', cls=CustomHelp)
@click.option('--category', '-c', required=True, help='Payload category')
@click.option('--subcategory', '-s', help='Payload subcategory')
@click.option('--count', '-n', type=int, default=1, help='Number of payloads to generate')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--context', help='JSON string with context for payload customization')
@click.pass_context
def generate_payload(ctx, category, subcategory, count, output, format, context):
    """
    Generate attack payloads for security testing.
    
    This command generates payloads for the specified category and subcategory,
    allowing you to create customized attack vectors for security testing.
    
    Examples:
      Generate a single SQL injection payload:
        phantomfuzzer payload generate --category sql_injection
      
      Generate multiple XSS payloads:
        phantomfuzzer payload generate --category xss --subcategory dom --count 5
      
      Generate payloads with context:
        phantomfuzzer payload generate --category command_injection --context '{"os":"linux"}'
      
      Save payloads to file:
        phantomfuzzer payload generate --category sql_injection --count 10 --output sql_payloads.txt
    """
    # Print banner before execution
    click.echo(BANNER)
    
    payload_gen = ctx.obj['payload_generator']
    
    # Parse context if provided
    ctx_dict = None
    if context:
        try:
            ctx_dict = json.loads(context)
        except json.JSONDecodeError:
            click.echo("Error: Context must be a valid JSON string", err=True)
            sys.exit(1)
    
    try:
        # Generate payloads
        if count == 1:
            payloads = [payload_gen.get_payload(category, subcategory, ctx_dict)]
        else:
            # Modify context to include subcategory if provided
            if subcategory:
                if ctx_dict is None:
                    ctx_dict = {'subcategory': subcategory}
                else:
                    ctx_dict['subcategory'] = subcategory
            payloads = payload_gen.get_multiple_payloads(category, count, ctx_dict)
        
        # Format output
        if format == 'json':
            output_data = json.dumps({"payloads": payloads}, indent=2)
        else:  # text format
            output_data = '\n'.join(payloads)
        
        # Write to file or stdout
        if output:
            with open(output, 'w') as f:
                f.write(output_data)
            click.echo(f"Generated {count} payload(s) and saved to {output}")
            # Also log to console for visibility
            if format == 'json':
                click.echo(f"\nPayload preview: {payloads[0] if payloads else 'No payloads generated'}")
        else:
            click.echo(output_data)
    
    except Exception as e:
        click.echo(f"Error generating payloads: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@payload.command('random', cls=CustomHelp)
@click.option('--count', '-n', type=int, default=1, help='Number of random payloads to generate')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.pass_context
def random_payload(ctx, count, output, format):
    """
    Generate random payloads from any category.
    
    This command generates random payloads from various categories,
    providing a diverse set of attack vectors for comprehensive testing.
    
    Examples:
      Generate a single random payload:
        phantomfuzzer payload random
      
      Generate multiple random payloads:
        phantomfuzzer payload random --count 5
      
      Save random payloads to file:
        phantomfuzzer payload random --count 10 --output random_payloads.json --format json
    """
    # Print banner before execution
    click.echo(BANNER)
    
    payload_gen = ctx.obj['payload_generator']
    
    try:
        # Generate random payloads
        payloads = [payload_gen.get_random_payload() for _ in range(count)]
        
        # Format output
        if format == 'json':
            output_data = json.dumps({"payloads": payloads}, indent=2)
        else:  # text format
            output_data = '\n'.join(payloads)
        
        # Write to file or stdout
        if output:
            with open(output, 'w') as f:
                f.write(output_data)
            click.echo(f"Generated {count} random payload(s) and saved to {output}")
            # Also log to console for visibility
            if format == 'json':
                click.echo(f"\nPayload preview: {payloads[0] if payloads else 'No payloads generated'}")
        else:
            click.echo(output_data)
    
    except Exception as e:
        click.echo(f"Error generating random payloads: {str(e)}", err=True)
        if ctx.obj.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

# Add man command to display manual
@cli.command('man', cls=CustomHelp)
def show_manual():
    """
    Display the PhantomFuzzer manual page.
    
    This command displays the PhantomFuzzer manual page, providing comprehensive
    documentation about all available commands and options.
    
    Examples:
      View the manual:
        phantomfuzzer man
    """
    # Print banner before execution
    click.echo(BANNER)
    
    # Path to the man page file
    man_page_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'phantomfuzzer.1')
    
    try:
        # Check if the man command is available
        try:
            subprocess.run(['man', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            # If man is available, use it to display the man page
            subprocess.run(['man', man_page_path], check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            # If man is not available, display the content directly
            if os.path.exists(man_page_path):
                with open(man_page_path, 'r') as f:
                    man_content = f.read()
                click.echo("\nPhantomFuzzer Manual Page\n")
                click.echo("=========================\n")
                # Simple formatting for man page content
                lines = man_content.split('\n')
                for line in lines:
                    # Skip man formatting commands
                    if line.startswith('.') or line.startswith('\''):
                        continue
                    click.echo(line)
            else:
                click.echo(f"Error: Man page not found at {man_page_path}", err=True)
    except Exception as e:
        click.echo(f"Error displaying manual: {str(e)}", err=True)
        if os.environ.get('DEBUG'):
            import traceback
            click.echo(traceback.format_exc(), err=True)

# Entry point for the CLI
if __name__ == '__main__':
    cli()