#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol Fuzzer for PhantomFuzzer.

This module provides protocol-specific fuzzing capabilities for the PhantomFuzzer project,
including TCP, UDP, HTTP, and other network protocols.
"""

import socket
import random
import struct
from typing import Dict, List, Tuple, Union, Optional, Any

# Local imports
from phantomfuzzer.fuzzer.fuzzer_base import BaseFuzzer


class ProtocolFuzzer(BaseFuzzer):
    """Protocol fuzzer for network protocols.
    
    This class extends the BaseFuzzer to provide protocol-specific fuzzing
    capabilities for various network protocols including TCP, UDP, HTTP, etc.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the protocol fuzzer.
        
        Args:
            config: Configuration parameters for the fuzzer.
        """
        super().__init__(config)
        
        # Protocol-specific configuration
        self.protocol = self.config.get('protocol', 'tcp').lower()
        self.port = self.config.get('port', 80)
        self.data_size_min = self.config.get('data_size_min', 10)
        self.data_size_max = self.config.get('data_size_max', 1024)
        self.mutation_rate = self.config.get('mutation_rate', 0.1)
        self.use_valid_data = self.config.get('use_valid_data', True)
        
        # Protocol templates
        self.protocol_templates = self.config.get('protocol_templates', {})
        
        # Socket settings
        self.socket = None
        self.socket_timeout = self.config.get('socket_timeout', 5.0)
        
        self.logger.info(f"Initialized ProtocolFuzzer for {self.protocol} protocol")
    
    def _create_socket(self):
        """Create a socket for the specified protocol.
        
        Returns:
            Socket object.
        """
        if self.protocol == 'tcp':
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.protocol == 'udp':
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.logger.error(f"Unsupported protocol: {self.protocol}")
            return None
    
    def _get_template_data(self):
        """Get template data for the current protocol.
        
        Returns:
            Template data as bytes.
        """
        if not self.protocol_templates or self.protocol not in self.protocol_templates:
            # Generate random data if no template is available
            size = random.randint(self.data_size_min, self.data_size_max)
            return bytes([random.randint(0, 255) for _ in range(size)])
        
        # Get template data
        template = self.protocol_templates[self.protocol]
        if isinstance(template, list):
            # If multiple templates are available, choose one randomly
            template = random.choice(template)
        
        # Convert to bytes if it's a string
        if isinstance(template, str):
            return template.encode('utf-8', errors='ignore')
        
        return template
    
    def generate_fuzz_data(self) -> bytes:
        """Generate data for protocol fuzzing.
        
        Returns:
            Fuzzed data as bytes.
        """
        # Get template data
        if self.use_valid_data:
            data = self._get_template_data()
        else:
            # Generate completely random data
            size = random.randint(self.data_size_min, self.data_size_max)
            data = bytes([random.randint(0, 255) for _ in range(size)])
        
        # Apply mutations
        data = self._mutate_data(data)
        
        return data
    
    def _mutate_data(self, data: bytes) -> bytes:
        """Apply mutations to the data.
        
        Args:
            data: Original data as bytes.
            
        Returns:
            Mutated data as bytes.
        """
        # Convert to bytearray for mutation
        data_array = bytearray(data)
        
        # Determine how many bytes to mutate
        num_bytes_to_mutate = max(1, int(len(data_array) * self.mutation_rate))
        
        # Randomly select bytes to mutate
        for _ in range(num_bytes_to_mutate):
            idx = random.randint(0, len(data_array) - 1)
            data_array[idx] = random.randint(0, 255)
        
        return bytes(data_array)
    
    def execute_fuzz(self, fuzz_data: bytes) -> Dict[str, Any]:
        """Execute protocol fuzzing with the provided data.
        
        Args:
            fuzz_data: Data to use for fuzzing.
            
        Returns:
            Dictionary with results of the fuzzing operation.
        """
        if not self.target:
            self.logger.error("No target specified")
            return {'status': 'error', 'message': 'No target specified'}
        
        result = {
            'target': self.target,
            'port': self.port,
            'protocol': self.protocol,
            'data_size': len(fuzz_data),
            'timestamp': self._get_timestamp(),
            'status': 'unknown',
            'response': None,
            'error': None
        }
        
        try:
            # Create socket
            self.socket = self._create_socket()
            if not self.socket:
                result['status'] = 'error'
                result['error'] = f"Failed to create socket for protocol: {self.protocol}"
                return result
            
            # Set timeout
            self.socket.settimeout(self.socket_timeout)
            
            # Connect and send data
            if self.protocol == 'tcp':
                self._execute_tcp_fuzz(fuzz_data, result)
            elif self.protocol == 'udp':
                self._execute_udp_fuzz(fuzz_data, result)
            else:
                result['status'] = 'error'
                result['error'] = f"Unsupported protocol: {self.protocol}"
        
        except socket.timeout:
            result['status'] = 'timeout'
            result['error'] = 'Socket timeout'
        except ConnectionRefusedError:
            result['status'] = 'refused'
            result['error'] = 'Connection refused'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        finally:
            # Close socket
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
        
        return result
    
    def _execute_tcp_fuzz(self, fuzz_data: bytes, result: Dict[str, Any]):
        """Execute TCP fuzzing.
        
        Args:
            fuzz_data: Data to use for fuzzing.
            result: Result dictionary to update.
        """
        # Connect to target
        self.socket.connect((self.target, self.port))
        
        # Send data
        self.socket.sendall(fuzz_data)
        
        # Receive response
        response = b''
        try:
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            # Timeout while receiving is not an error
            pass
        
        # Update result
        result['status'] = 'success'
        result['response'] = response
        result['response_size'] = len(response)
    
    def _execute_udp_fuzz(self, fuzz_data: bytes, result: Dict[str, Any]):
        """Execute UDP fuzzing.
        
        Args:
            fuzz_data: Data to use for fuzzing.
            result: Result dictionary to update.
        """
        # Send data
        self.socket.sendto(fuzz_data, (self.target, self.port))
        
        # Receive response
        try:
            response, addr = self.socket.recvfrom(4096)
            
            # Update result
            result['status'] = 'success'
            result['response'] = response
            result['response_size'] = len(response)
            result['response_addr'] = addr
        except socket.timeout:
            # Timeout is common for UDP, not necessarily an error
            result['status'] = 'timeout'
    
    def _get_timestamp(self):
        """Get current timestamp.
        
        Returns:
            Current timestamp as float.
        """
        import time
        return time.time()