#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network scanner implementation for PhantomFuzzer.

This module provides a scanner implementation for network infrastructure,
including port scanning, service detection, and basic vulnerability assessment.
"""

import os
import sys
import time
import json
import socket
import ipaddress
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from concurrent.futures import ThreadPoolExecutor

# Try to import required libraries
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import from phantomfuzzer package
from phantomfuzzer.scanner.base import BaseScanner, ScanResult
from phantomfuzzer.scanner.base import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from phantomfuzzer.scanner.base import STATUS_COMPLETED, STATUS_FAILED
from phantomfuzzer.utils.logging import get_module_logger

# Default timeout for socket connections
DEFAULT_TIMEOUT = 3

# Default number of threads for port scanning
DEFAULT_THREADS = 10

# Common network vulnerabilities
VULN_OPEN_PORT = 'Open Port'
VULN_INSECURE_SERVICE = 'Insecure Service'
VULN_DEFAULT_CREDS = 'Default Credentials'
VULN_OUTDATED_SERVICE = 'Outdated Service Version'
VULN_WEAK_ENCRYPTION = 'Weak Encryption'

# Common ports and their services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

# Known vulnerable service versions
VULNERABLE_SERVICES = {
    'OpenSSH': {
        'versions': ['7.5', '7.4', '7.3', '7.2', '7.1', '7.0', '6.9', '6.8', '6.7', '6.6', '6.5', '6.4'],
        'severity': SEVERITY_MEDIUM,
        'description': 'Older OpenSSH versions with known vulnerabilities',
        'remediation': 'Upgrade to the latest version of OpenSSH'
    },
    'Apache': {
        'versions': ['2.4.48', '2.4.47', '2.4.46', '2.4.45', '2.4.44', '2.4.43', '2.4.42', '2.4.41'],
        'severity': SEVERITY_MEDIUM,
        'description': 'Older Apache versions with known vulnerabilities',
        'remediation': 'Upgrade to the latest version of Apache'
    },
    'Nginx': {
        'versions': ['1.20.0', '1.19.10', '1.19.9', '1.19.8', '1.19.7', '1.19.6'],
        'severity': SEVERITY_MEDIUM,
        'description': 'Older Nginx versions with known vulnerabilities',
        'remediation': 'Upgrade to the latest version of Nginx'
    }
}

# Insecure services
INSECURE_SERVICES = {
    'Telnet': {
        'ports': [23],
        'severity': SEVERITY_HIGH,
        'description': 'Telnet transmits data in cleartext',
        'remediation': 'Replace Telnet with SSH'
    },
    'FTP': {
        'ports': [21],
        'severity': SEVERITY_MEDIUM,
        'description': 'FTP transmits credentials in cleartext',
        'remediation': 'Use SFTP or FTPS instead'
    },
    'HTTP': {
        'ports': [80, 8080],
        'severity': SEVERITY_LOW,
        'description': 'Unencrypted HTTP traffic',
        'remediation': 'Use HTTPS with proper certificate'
    }
}

class NetworkScanner(BaseScanner):
    """Network scanner implementation.
    
    This class implements a scanner for network infrastructure, including
    port scanning, service detection, and basic vulnerability assessment.
    """
    
    def _init_scanner(self) -> None:
        """Initialize scanner-specific settings.
        
        This method is called by the BaseScanner constructor.
        """
        # Check for required libraries
        if not NMAP_AVAILABLE and not SCAPY_AVAILABLE:
            self.logger.warning("Neither python-nmap nor scapy are available. Limited functionality.")
        
        # Get network scanner configuration
        network_config = self.config.get('network_scan', {})
        
        # Initialize settings
        self.timeout = network_config.get('timeout', DEFAULT_TIMEOUT)
        self.threads = network_config.get('threads', DEFAULT_THREADS)
        self.port_range = network_config.get('port_range', '1-1024')
        self.scan_udp = network_config.get('scan_udp', False)
        self.os_detection = network_config.get('os_detection', False)
        self.service_detection = network_config.get('service_detection', True)
        
        # Initialize nmap scanner if available
        if NMAP_AVAILABLE:
            self.nmap_scanner = nmap.PortScanner()
        else:
            self.nmap_scanner = None
        
        # Initialize scan state
        self.discovered_hosts = set()
        self.open_ports = {}
        self.services = {}
        
        # Initialize vulnerability checks
        self.check_default_creds = network_config.get('check_default_creds', True)
        self.check_outdated_versions = network_config.get('check_outdated_versions', True)
        self.check_weak_encryption = network_config.get('check_weak_encryption', True)
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Perform a network scan on the target.
        
        Args:
            target: The target IP, hostname, or network range (CIDR notation).
            options: Optional scan options.
        
        Returns:
            The scan result.
        """
        # Initialize scan options
        if options is None:
            options = {}
        
        # Override default settings with options
        timeout = options.get('timeout', self.timeout)
        threads = options.get('threads', self.threads)
        port_range = options.get('port_range', self.port_range)
        scan_udp = options.get('scan_udp', self.scan_udp)
        os_detection = options.get('os_detection', self.os_detection)
        service_detection = options.get('service_detection', self.service_detection)
        
        # Start the scan
        scan_result = self.start_scan(target, options)
        
        try:
            # Initialize scan state
            self.discovered_hosts = set()
            self.open_ports = {}
            self.services = {}
            
            # Add scan info
            scan_result.scan_info = {
                'target': target,
                'port_range': port_range,
                'scan_udp': scan_udp,
                'os_detection': os_detection,
                'service_detection': service_detection
            }
            
            # Determine if target is a single host or a network range
            is_network = '/' in target
            
            # Discover hosts if target is a network
            if is_network:
                self._discover_hosts(target, scan_result)
                hosts_to_scan = self.discovered_hosts
            else:
                hosts_to_scan = {target}
            
            # Scan each host
            for host in hosts_to_scan:
                self._scan_host(host, port_range, scan_udp, service_detection, os_detection, timeout, threads, scan_result)
            
            # Scan for vulnerabilities
            self._scan_for_vulnerabilities(scan_result)
            
            # Complete the scan
            return self.finish_scan(STATUS_COMPLETED)
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {str(e)}")
            scan_result.scan_info['error'] = str(e)
            return self.finish_scan(STATUS_FAILED)
    
    def _discover_hosts(self, network: str, scan_result: ScanResult) -> None:
        """Discover hosts in a network range.
        
        Args:
            network: The network range in CIDR notation.
            scan_result: The scan result to update.
        """
        self.logger.info(f"Discovering hosts in {network}")
        
        # Use different methods based on available libraries
        if SCAPY_AVAILABLE:
            self._discover_hosts_scapy(network, scan_result)
        elif NMAP_AVAILABLE:
            self._discover_hosts_nmap(network, scan_result)
        else:
            self._discover_hosts_socket(network, scan_result)
        
        self.logger.info(f"Discovered {len(self.discovered_hosts)} hosts")
        scan_result.scan_info['hosts_discovered'] = len(self.discovered_hosts)
    
    def _discover_hosts_scapy(self, network: str, scan_result: ScanResult) -> None:
        """Discover hosts using Scapy ARP scanning.
        
        Args:
            network: The network range in CIDR notation.
            scan_result: The scan result to update.
        """
        try:
            # Create ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get response
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Process responses
            for sent, received in result:
                self.discovered_hosts.add(received.psrc)
        except Exception as e:
            self.logger.warning(f"Error discovering hosts with Scapy: {str(e)}")
    
    def _discover_hosts_nmap(self, network: str, scan_result: ScanResult) -> None:
        """Discover hosts using Nmap ping scan.
        
        Args:
            network: The network range in CIDR notation.
            scan_result: The scan result to update.
        """
        try:
            # Run Nmap ping scan
            self.nmap_scanner.scan(hosts=network, arguments='-sn')
            
            # Get all hosts that are up
            for host in self.nmap_scanner.all_hosts():
                if self.nmap_scanner[host].state() == 'up':
                    self.discovered_hosts.add(host)
        except Exception as e:
            self.logger.warning(f"Error discovering hosts with Nmap: {str(e)}")
    
    def _discover_hosts_socket(self, network: str, scan_result: ScanResult) -> None:
        """Discover hosts using basic socket connections.
        
        Args:
            network: The network range in CIDR notation.
            scan_result: The scan result to update.
        """
        try:
            # Parse network range
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Try to connect to common ports on each host
            test_ports = [80, 443, 22, 25]
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for ip in network_obj.hosts():
                    ip_str = str(ip)
                    for port in test_ports:
                        executor.submit(self._check_host_socket, ip_str, port)
        except Exception as e:
            self.logger.warning(f"Error discovering hosts with sockets: {str(e)}")
    
    def _check_host_socket(self, host: str, port: int) -> None:
        """Check if a host is up by attempting a socket connection.
        
        Args:
            host: The host IP address.
            port: The port to connect to.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                self.discovered_hosts.add(host)
        except:
            pass
    
    def _scan_host(self, host: str, port_range: str, scan_udp: bool, service_detection: bool, 
                  os_detection: bool, timeout: int, threads: int, scan_result: ScanResult) -> None:
        """Scan a host for open ports and services.
        
        Args:
            host: The host to scan.
            port_range: The range of ports to scan.
            scan_udp: Whether to scan UDP ports.
            service_detection: Whether to detect services.
            os_detection: Whether to detect the operating system.
            timeout: Connection timeout in seconds.
            threads: Number of threads to use for scanning.
            scan_result: The scan result to update.
        """
        self.logger.info(f"Scanning host {host}")
        
        # Initialize host data
        self.open_ports[host] = {'tcp': [], 'udp': []}
        self.services[host] = {}
        
        # Use different methods based on available libraries
        if NMAP_AVAILABLE:
            self._scan_host_nmap(host, port_range, scan_udp, service_detection, os_detection, scan_result)
        else:
            self._scan_host_socket(host, port_range, timeout, threads, scan_result)
        
        # Log results
        tcp_count = len(self.open_ports[host]['tcp'])
        udp_count = len(self.open_ports[host]['udp'])
        self.logger.info(f"Found {tcp_count} open TCP ports and {udp_count} open UDP ports on {host}")
    
    def _scan_host_nmap(self, host: str, port_range: str, scan_udp: bool, service_detection: bool, 
                        os_detection: bool, scan_result: ScanResult) -> None:
        """Scan a host using Nmap.
        
        Args:
            host: The host to scan.
            port_range: The range of ports to scan.
            scan_udp: Whether to scan UDP ports.
            service_detection: Whether to detect services.
            os_detection: Whether to detect the operating system.
            scan_result: The scan result to update.
        """
        try:
            # Build Nmap arguments
            args = f"-p {port_range}"
            
            if scan_udp:
                args += " -sU"
            
            if service_detection:
                args += " -sV"
            
            if os_detection:
                args += " -O"
            
            # Run Nmap scan
            self.nmap_scanner.scan(hosts=host, arguments=args)
            
            # Process results
            if host in self.nmap_scanner.all_hosts():
                # Get TCP results
                if 'tcp' in self.nmap_scanner[host]:
                    for port, data in self.nmap_scanner[host]['tcp'].items():
                        if data['state'] == 'open':
                            port_int = int(port)
                            self.open_ports[host]['tcp'].append(port_int)
                            
                            # Add service info if available
                            if 'name' in data and data['name'] != '':
                                service_name = data['name']
                                service_version = data.get('product', '') + ' ' + data.get('version', '')
                                self.services[host][port_int] = {
                                    'name': service_name,
                                    'version': service_version.strip(),
                                    'protocol': 'tcp'
                                }
                
                # Get UDP results
                if scan_udp and 'udp' in self.nmap_scanner[host]:
                    for port, data in self.nmap_scanner[host]['udp'].items():
                        if data['state'] == 'open':
                            port_int = int(port)
                            self.open_ports[host]['udp'].append(port_int)
                            
                            # Add service info if available
                            if 'name' in data and data['name'] != '':
                                service_name = data['name']
                                service_version = data.get('product', '') + ' ' + data.get('version', '')
                                self.services[host][port_int] = {
                                    'name': service_name,
                                    'version': service_version.strip(),
                                    'protocol': 'udp'
                                }
                
                # Get OS detection results
                if os_detection and 'osmatch' in self.nmap_scanner[host]:
                    for os_match in self.nmap_scanner[host]['osmatch']:
                        scan_result.scan_info[f"{host}_os"] = os_match['name']
                        break  # Just use the first match
        
        except Exception as e:
            self.logger.warning(f"Error scanning {host} with Nmap: {str(e)}")
    
    def _scan_host_socket(self, host: str, port_range: str, timeout: int, threads: int, scan_result: ScanResult) -> None:
        """Scan a host using socket connections.
        
        Args:
            host: The host to scan.
            port_range: The range of ports to scan.
            timeout: Connection timeout in seconds.
            threads: Number of threads to use for scanning.
            scan_result: The scan result to update.
        """
        try:
            # Parse port range
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                ports = range(start_port, end_port + 1)
            else:
                ports = [int(p) for p in port_range.split(',')]
            
            # Scan ports using thread pool
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in ports:
                    executor.submit(self._check_port_socket, host, port, timeout)
            
            # Try to identify services
            for port in self.open_ports[host]['tcp']:
                if port in COMMON_PORTS:
                    self.services[host][port] = {
                        'name': COMMON_PORTS[port],
                        'version': 'Unknown',
                        'protocol': 'tcp'
                    }
        
        except Exception as e:
            self.logger.warning(f"Error scanning {host} with sockets: {str(e)}")
    
    def _check_port_socket(self, host: str, port: int, timeout: int) -> None:
        """Check if a port is open using a socket connection.
        
        Args:
            host: The host to check.
            port: The port to check.
            timeout: Connection timeout in seconds.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                self.open_ports[host]['tcp'].append(port)
        except:
            pass
    
    def _scan_for_vulnerabilities(self, scan_result: ScanResult) -> None:
        """Scan for vulnerabilities in the discovered services.
        
        Args:
            scan_result: The scan result to update.
        """
        self.logger.info("Starting vulnerability scan")
        
        # Check for open ports
        self._check_open_ports(scan_result)
        
        # Check for insecure services
        self._check_insecure_services(scan_result)
        
        # Check for outdated service versions
        if self.check_outdated_versions:
            self._check_outdated_versions(scan_result)
        
        # Check for default credentials
        if self.check_default_creds:
            self._check_default_credentials(scan_result)
        
        # Check for weak encryption
        if self.check_weak_encryption:
            self._check_weak_encryption(scan_result)
        
        self.logger.info("Vulnerability scan completed")
    
    def _check_open_ports(self, scan_result: ScanResult) -> None:
        """Check for open ports and add them as potential vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        for host, ports in self.open_ports.items():
            # Check TCP ports
            for port in ports['tcp']:
                service_name = "Unknown"
                if port in self.services[host]:
                    service_name = self.services[host][port]['name']
                elif port in COMMON_PORTS:
                    service_name = COMMON_PORTS[port]
                
                # Add as low severity vulnerability
                scan_result.add_vulnerability(
                    name=VULN_OPEN_PORT,
                    description=f"Open TCP port {port} ({service_name})",
                    severity=SEVERITY_INFO,
                    location=f"{host}:{port}/tcp",
                    evidence=f"Service: {service_name}",
                    remediation="Close unused ports or restrict access with a firewall."
                )
            
            # Check UDP ports
            for port in ports['udp']:
                service_name = "Unknown"
                if port in self.services[host]:
                    service_name = self.services[host][port]['name']
                elif port in COMMON_PORTS:
                    service_name = COMMON_PORTS[port]
                
                # Add as low severity vulnerability
                scan_result.add_vulnerability(
                    name=VULN_OPEN_PORT,
                    description=f"Open UDP port {port} ({service_name})",
                    severity=SEVERITY_INFO,
                    location=f"{host}:{port}/udp",
                    evidence=f"Service: {service_name}",
                    remediation="Close unused ports or restrict access with a firewall."
                )
    
    def _check_insecure_services(self, scan_result: ScanResult) -> None:
        """Check for known insecure services.
        
        Args:
            scan_result: The scan result to update.
        """
        for host, services in self.services.items():
            for port, service_info in services.items():
                service_name = service_info['name']
                
                # Check if this is a known insecure service
                for insecure_service, info in INSECURE_SERVICES.items():
                    if service_name.lower() == insecure_service.lower() and port in info['ports']:
                        scan_result.add_vulnerability(
                            name=VULN_INSECURE_SERVICE,
                            description=f"{info['description']} on {host}:{port}",
                            severity=info['severity'],
                            location=f"{host}:{port}/{service_info['protocol']}",
                            evidence=f"Service: {service_name}",
                            remediation=info['remediation']
                        )
    
    def _check_outdated_versions(self, scan_result: ScanResult) -> None:
        """Check for outdated service versions with known vulnerabilities.
        
        Args:
            scan_result: The scan result to update.
        """
        for host, services in self.services.items():
            for port, service_info in services.items():
                service_name = service_info['name']
                service_version = service_info['version']
                
                # Skip if version is unknown
                if service_version == 'Unknown' or not service_version:
                    continue
                
                # Check if this is a known vulnerable version
                for vuln_service, info in VULNERABLE_SERVICES.items():
                    if vuln_service in service_name:
                        for vuln_version in info['versions']:
                            if vuln_version in service_version:
                                scan_result.add_vulnerability(
                                    name=VULN_OUTDATED_SERVICE,
                                    description=f"{info['description']} on {host}:{port}",
                                    severity=info['severity'],
                                    location=f"{host}:{port}/{service_info['protocol']}",
                                    evidence=f"Service: {service_name} {service_version}",
                                    remediation=info['remediation']
                                )
                                break
    
    def _check_default_credentials(self, scan_result: ScanResult) -> None:
        """Check for services with default credentials.
        
        This is a placeholder for a more sophisticated implementation that would
        actually attempt to authenticate with default credentials.
        
        Args:
            scan_result: The scan result to update.
        """
        # This would require actual authentication attempts, which we're not implementing here
        # Just a placeholder for the interface
        pass
    
    def _check_weak_encryption(self, scan_result: ScanResult) -> None:
        """Check for services with weak encryption.
        
        This is a placeholder for a more sophisticated implementation that would
        actually check encryption strength.
        
        Args:
            scan_result: The scan result to update.
        """
        # This would require specialized checks for each protocol, which we're not implementing here
        # Just a placeholder for the interface
        pass
    
    def _apply_stealth_mode(self) -> None:
        """Apply stealth mode settings for network scanning.
        
        This method overrides the base implementation to apply network-specific
        stealth settings.
        """
        super()._apply_stealth_mode()
        
        stealth_config = self.config_manager.get_stealth_config()
        
        # Apply network-specific stealth settings
        self.threads = stealth_config.get('max_threads', 1)  # Reduce threads to avoid detection
        
        # Add random delays between port scans
        self.scan_delay_min = stealth_config.get('scan_delay_min', 1)
        self.scan_delay_max = stealth_config.get('scan_delay_max', 5)
        
        # Use random source ports
        self.use_random_source_ports = stealth_config.get('use_random_source_ports', True)
        
        # Scan ports in random order
        self.randomize_port_order = stealth_config.get('randomize_port_order', True)
        
        self.logger.debug("Applied network-specific stealth settings")
    
    def _apply_ml_enhancements(self) -> None:
        """Apply ML enhancements for network scanning.
        
        This method overrides the base implementation to apply network-specific
        ML enhancements.
        """
        super()._apply_ml_enhancements()
        
        ml_config = self.config_manager.get_ml_config()
        
        # Apply network-specific ML settings
        self.use_ml_for_port_prediction = ml_config.get('use_for_port_prediction', False)
        self.use_ml_for_service_identification = ml_config.get('use_for_service_identification', False)
        
        self.logger.debug("Applied network-specific ML enhancements")