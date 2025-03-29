#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abstract base class for scanners in PhantomFuzzer.

This module defines the interface that all scanner implementations must follow,
as well as common functionality for configuration, logging, and result handling.
"""

import os
import sys
import time
import json
import abc
import uuid
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime

# Import from phantomfuzzer package
from phantomfuzzer.config import get_config
from phantomfuzzer.utils.logging import get_module_logger, log_start_operation, log_end_operation, log_scan_result
from phantomfuzzer.utils.helper import print_section, print_info, print_success, print_warning, print_error, print_summary

# Scanner status constants
STATUS_IDLE = 'idle'
STATUS_RUNNING = 'running'
STATUS_COMPLETED = 'completed'
STATUS_FAILED = 'failed'
STATUS_STOPPED = 'stopped'

# Vulnerability severity levels
SEVERITY_CRITICAL = 'critical'
SEVERITY_HIGH = 'high'
SEVERITY_MEDIUM = 'medium'
SEVERITY_LOW = 'low'
SEVERITY_INFO = 'info'

class ScanResult:
    """Class representing the result of a scan."""
    
    def __init__(self, scanner_id: str, target: str):
        """Initialize a scan result.
        
        Args:
            scanner_id: The ID of the scanner that produced this result.
            target: The target that was scanned.
        """
        self.id = str(uuid.uuid4())
        self.scanner_id = scanner_id
        self.target = target
        self.start_time = datetime.now()
        self.end_time = None
        self.status = STATUS_RUNNING
        self.vulnerabilities = []
        self.scan_info = {}
    
    def add_vulnerability(self, name: str, description: str, severity: str, location: str,
                         evidence: Optional[str] = None, remediation: Optional[str] = None) -> None:
        """Add a vulnerability to the scan result.
        
        Args:
            name: The name of the vulnerability.
            description: A description of the vulnerability.
            severity: The severity of the vulnerability (one of the SEVERITY_* constants).
            location: The location of the vulnerability (e.g., URL, file path).
            evidence: Optional evidence of the vulnerability.
            remediation: Optional remediation advice.
        """
        vulnerability = {
            'id': str(uuid.uuid4()),
            'name': name,
            'description': description,
            'severity': severity,
            'location': location,
            'evidence': evidence,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vulnerability)
    
    def complete(self, status: str = STATUS_COMPLETED) -> None:
        """Mark the scan as complete.
        
        Args:
            status: The final status of the scan.
        """
        self.end_time = datetime.now()
        self.status = status
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the scan result to a dictionary.
        
        Returns:
            A dictionary representation of the scan result.
        """
        return {
            'id': self.id,
            'scanner_id': self.scanner_id,
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'vulnerabilities': self.vulnerabilities,
            'scan_info': self.scan_info,
            'vulnerability_count': len(self.vulnerabilities),
            'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.end_time else None
        }
    
    def to_json(self, pretty: bool = False) -> str:
        """Convert the scan result to a JSON string.
        
        Args:
            pretty: Whether to format the JSON with indentation.
        
        Returns:
            A JSON string representation of the scan result.
        """
        indent = 4 if pretty else None
        return json.dumps(self.to_dict(), indent=indent)
    
    def save_to_file(self, file_path: str) -> None:
        """Save the scan result to a file.
        
        Args:
            file_path: The path to save the file to.
        """
        with open(file_path, 'w') as f:
            f.write(self.to_json(pretty=True))
    
    def __len__(self) -> int:
        """Return the number of vulnerabilities in the scan result.
        
        This allows using len(scan_result) to get the vulnerability count.
        
        Returns:
            The number of vulnerabilities found in the scan.
        """
        return len(self.vulnerabilities)
    
    def __iter__(self):
        """Allow iterating through the vulnerabilities in the scan result.
        
        This enables using the scan result in a for loop directly.
        
        Yields:
            Each vulnerability in the scan result.
        """
        for vulnerability in self.vulnerabilities:
            yield vulnerability

class BaseScanner(abc.ABC):
    """Abstract base class for scanners.
    
    This class defines the interface that all scanner implementations must follow,
    as well as common functionality for configuration, logging, and result handling.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the scanner.
        
        Args:
            config: Optional configuration dictionary. If None, the global
                configuration will be used.
        """
        self.id = str(uuid.uuid4())
        self.logger = get_module_logger('scanner')
        
        # Get configuration
        self.config_manager = get_config()
        self.config = config or self.config_manager.get_scanner_config()
        
        # Initialize state
        self.status = STATUS_IDLE
        self.current_scan = None
        self.scan_history = []
        
        # ML and stealth settings
        self.ml_enabled = self.config.get('ml_enabled', False)
        self.stealth_enabled = self.config.get('stealth_enabled', False)
        
        # Initialize scanner-specific settings
        self._init_scanner()
    
    @abc.abstractmethod
    def _init_scanner(self) -> None:
        """Initialize scanner-specific settings.
        
        This method should be implemented by subclasses to initialize
        any scanner-specific settings or resources.
        """
        pass
    
    @abc.abstractmethod
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Perform a scan on the target.
        
        Args:
            target: The target to scan.
            options: Optional scan options.
        
        Returns:
            The scan result.
        """
        pass
    
    def start_scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Start a scan on the target.
        
        This method handles common pre-scan tasks such as logging and
        initializing the scan result.
        
        Args:
            target: The target to scan.
            options: Optional scan options.
        
        Returns:
            The scan result.
        """
        # Log scan start
        log_start_operation(self.logger, f"Scanning {target}")
        print_section(f"Starting Scan: {target}")
        
        # Print scan options if provided
        if options:
            print_info("Scan options:")
            for key, value in options.items():
                print_info(f"  {key}: {value}")
        
        # Initialize scan result
        self.current_scan = ScanResult(self.id, target)
        self.status = STATUS_RUNNING
        
        # Apply stealth mode if enabled
        if self.stealth_enabled:
            self._apply_stealth_mode()
        
        # Apply ML enhancements if enabled
        if self.ml_enabled:
            self._apply_ml_enhancements()
        
        return self.current_scan
    
    def finish_scan(self, status: str = STATUS_COMPLETED) -> ScanResult:
        """Finish the current scan.
        
        This method handles common post-scan tasks such as logging and
        updating the scan result.
        
        Args:
            status: The final status of the scan.
        
        Returns:
            The completed scan result.
        """
        if self.current_scan is None:
            raise ValueError("No scan is currently running")
        
        # Complete the scan result
        self.current_scan.complete(status)
        
        # Update scanner status
        self.status = STATUS_IDLE
        
        # Log scan completion
        log_end_operation(
            self.logger,
            f"Scanning {self.current_scan.target}",
            success=(status == STATUS_COMPLETED)
        )
        
        # Log vulnerabilities found
        log_scan_result(
            self.logger,
            self.current_scan.target,
            len(self.current_scan.vulnerabilities)
        )
        
        # Print scan summary
        print_section("Scan Summary")
        print_info(f"Target: {self.current_scan.target}")
        if self.current_scan.end_time and self.current_scan.start_time:
            duration = (self.current_scan.end_time - self.current_scan.start_time).total_seconds()
            print_info(f"Duration: {duration:.2f} seconds")
        
        # Print vulnerability summary
        vulnerabilities = self.current_scan.vulnerabilities
        if vulnerabilities:
            # Group vulnerabilities by severity
            severity_counts = {}
            for v in vulnerabilities:
                severity = v['severity']
                if severity not in severity_counts:
                    severity_counts[severity] = 0
                severity_counts[severity] += 1
            
            # Print severity counts
            print_warning(f"Found {len(vulnerabilities)} vulnerabilities:")
            for severity in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
                if severity in severity_counts:
                    print_warning(f"  {severity.upper()}: {severity_counts[severity]}")
            
            # Print top vulnerabilities
            top_vulns = sorted(vulnerabilities, key=lambda v: [
                v['severity'] == SEVERITY_CRITICAL,
                v['severity'] == SEVERITY_HIGH,
                v['severity'] == SEVERITY_MEDIUM,
                v['severity'] == SEVERITY_LOW,
                v['severity'] == SEVERITY_INFO
            ], reverse=True)[:5]  # Show top 5 most severe
            
            vuln_summary = [f"{v['name']} ({v['severity'].upper()}) at {v['location']}" for v in top_vulns]
            print_summary("Top vulnerabilities", vuln_summary)
        else:
            print_success("No vulnerabilities found")
        
        # Add to scan history
        self.scan_history.append(self.current_scan)
        
        # Return the completed scan
        completed_scan = self.current_scan
        self.current_scan = None
        return completed_scan
    
    def stop_scan(self) -> Optional[ScanResult]:
        """Stop the current scan.
        
        Returns:
            The stopped scan result, or None if no scan is running.
        """
        if self.current_scan is None:
            return None
        
        return self.finish_scan(STATUS_STOPPED)
    
    def get_scan_history(self) -> List[ScanResult]:
        """Get the scan history.
        
        Returns:
            A list of past scan results.
        """
        return self.scan_history
    
    def _apply_stealth_mode(self) -> None:
        """Apply stealth mode settings.
        
        This method applies stealth mode settings to the scanner to make
        it less detectable by security systems.
        """
        stealth_config = self.config_manager.get_stealth_config()
        
        # Log stealth mode activation
        self.logger.debug("Activating stealth mode")
        
        # Subclasses should override this method to implement stealth mode
    
    def _apply_ml_enhancements(self) -> None:
        """Apply ML enhancements.
        
        This method applies ML enhancements to the scanner to improve
        its effectiveness and accuracy.
        """
        ml_config = self.config_manager.get_ml_config()
        
        # Log ML enhancements activation
        self.logger.debug("Activating ML enhancements")
        
        # Subclasses should override this method to implement ML enhancements