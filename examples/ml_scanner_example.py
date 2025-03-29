#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example script demonstrating the use of the ML-enhanced scanner in PhantomFuzzer.

This script shows how to:
1. Initialize the ML-enhanced scanner
2. Scan files and directories with ML capabilities
3. Interpret the scan results
4. Train a model based on scan results
"""

import os
import sys
import argparse
import json
from pathlib import Path

# Add project root to path if needed
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import PhantomFuzzer components
from phantomfuzzer.scanner import MLEnhancedScanner
from phantomfuzzer.scanner import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO


def setup_argparse():
    """Set up command line argument parsing."""
    parser = argparse.ArgumentParser(description='PhantomFuzzer ML-Enhanced Scanner Example')
    
    parser.add_argument('--target-dir', type=str, default=None,
                        help='Directory containing files to scan')
    parser.add_argument('--target-file', type=str, default=None,
                        help='Single file to scan')
    
    parser.add_argument('--ml-enabled', action='store_true', default=True,
                        help='Enable ML-based scanning (default: True)')
    parser.add_argument('--ml-model', type=str, default=None,
                        help='Specific ML model to use')
    parser.add_argument('--ml-threshold', type=float, default=0.6,
                        help='Threshold for ML anomaly detection (default: 0.6)')
    
    parser.add_argument('--output', type=str, default=None,
                        help='Output file for scan results (JSON format)')
    
    parser.add_argument('--train-from-results', action='store_true',
                        help='Train a new model from scan results')
    parser.add_argument('--new-model-name', type=str, default=None,
                        help='Name for the newly trained model')
    
    return parser


def initialize_scanner(args):
    """Initialize the ML-enhanced scanner with the specified configuration."""
    # Create scanner configuration
    config = {
        'ml_enabled': args.ml_enabled,
        'ml_model_name': args.ml_model,
        'ml_threshold': args.ml_threshold,
        'max_file_size': 10 * 1024 * 1024,  # 10 MB
        'scan_archives': True,
        'extract_metadata': True
    }
    
    # Initialize scanner
    scanner = MLEnhancedScanner(config)
    print("ML-Enhanced Scanner initialized")
    
    if args.ml_enabled:
        print(f"ML scanning enabled with threshold: {args.ml_threshold}")
        if args.ml_model:
            print(f"Using ML model: {args.ml_model}")
        else:
            print(f"Using default ML model: {scanner.ml_integration.default_model if scanner.ml_integration else 'None'}")
    
    return scanner


def scan_target(scanner, args):
    """Scan the specified target (file or directory)."""
    target = args.target_file or args.target_dir
    if not target:
        print("Error: No target specified. Use --target-file or --target-dir")
        return None
    
    print(f"Scanning target: {target}")
    
    # Set up scan options
    options = {
        'recursive': True,
        'file_pattern': '*'
    }
    
    # Perform scan
    scan_result = scanner.scan(target, options)
    
    return scan_result


def print_scan_summary(scan_result):
    """Print a summary of the scan results."""
    if not scan_result:
        print("No scan results available")
        return
    
    print("\nScan Summary:")
    print(f"Target: {scan_result.target}")
    print(f"Status: {scan_result.status}")
    print(f"Start Time: {scan_result.start_time}")
    print(f"End Time: {scan_result.end_time}")
    print(f"Duration: {(scan_result.end_time - scan_result.start_time).total_seconds():.2f} seconds")
    
    # Print scan info
    if hasattr(scan_result, 'scan_info'):
        print("\nScan Information:")
        print(f"Files Scanned: {scan_result.scan_info.get('files_scanned', 0)}")
        print(f"Files Skipped: {scan_result.scan_info.get('files_skipped', 0)}")
        print(f"Total Size: {scan_result.scan_info.get('total_size', 0) / 1024 / 1024:.2f} MB")
    
    # Print vulnerabilities
    if hasattr(scan_result, 'vulnerabilities'):
        vuln_count = len(scan_result.vulnerabilities)
        print(f"\nVulnerabilities Found: {vuln_count}")
        
        if vuln_count > 0:
            # Count vulnerabilities by severity
            severity_counts = {
                SEVERITY_CRITICAL: 0,
                SEVERITY_HIGH: 0,
                SEVERITY_MEDIUM: 0,
                SEVERITY_LOW: 0,
                SEVERITY_INFO: 0
            }
            
            # Count vulnerabilities by type
            type_counts = {}
            
            for vuln in scan_result.vulnerabilities:
                severity = vuln.get('severity', SEVERITY_INFO)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                vuln_type = vuln.get('name', 'Unknown')
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            # Print severity breakdown
            print("\nSeverity Breakdown:")
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"  {severity.capitalize()}: {count}")
            
            # Print type breakdown
            print("\nVulnerability Types:")
            for vuln_type, count in type_counts.items():
                print(f"  {vuln_type}: {count}")
            
            # Print ML-specific vulnerabilities
            ml_vulns = [v for v in scan_result.vulnerabilities if v.get('name') == 'ML-Detected Anomaly']
            if ml_vulns:
                print(f"\nML-Detected Anomalies: {len(ml_vulns)}")
                for vuln in ml_vulns[:5]:  # Show first 5
                    print(f"  {vuln.get('location')} - Score: {vuln.get('evidence')}")
                
                if len(ml_vulns) > 5:
                    print(f"  ... and {len(ml_vulns) - 5} more")


def save_results(scan_result, output_file):
    """Save scan results to a file."""
    if not scan_result:
        print("No scan results to save")
        return
    
    try:
        scan_result.save_to_file(output_file)
        print(f"Scan results saved to {output_file}")
    except Exception as e:
        print(f"Error saving scan results: {str(e)}")


def train_model_from_results(scanner, scan_result, model_name):
    """Train a new model from scan results."""
    if not scanner.ml_enabled or not scanner.ml_integration:
        print("ML is not enabled or ML integration failed to initialize")
        return
    
    print("Training new model from scan results...")
    
    # Train model
    new_model_name = scanner.train_model_from_scan_results([scan_result], model_name)
    
    if new_model_name:
        print(f"Successfully trained new model: {new_model_name}")
        print(f"Set {new_model_name} as the default model")
    else:
        print("Failed to train new model")


def main():
    """Main function."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = initialize_scanner(args)
    
    # Scan target
    scan_result = scan_target(scanner, args)
    
    # Print scan summary
    print_scan_summary(scan_result)
    
    # Save results if output file specified
    if args.output and scan_result:
        save_results(scan_result, args.output)
    
    # Train model from results if requested
    if args.train_from_results and scan_result:
        train_model_from_results(scanner, scan_result, args.new_model_name)


if __name__ == "__main__":
    main()
