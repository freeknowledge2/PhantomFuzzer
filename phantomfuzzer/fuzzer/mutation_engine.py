#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mutation Engine for PhantomFuzzer.

This module provides mutation strategies for the PhantomFuzzer project,
allowing for intelligent mutation of data during fuzzing operations.
"""

import random
import string
from typing import Dict, List, Tuple, Union, Optional, Any, Callable

# Local imports
from phantomfuzzer.utils.logging import get_logger


class MutationEngine:
    """Mutation engine for fuzzing operations.
    
    This class provides various mutation strategies for different types of data,
    allowing for intelligent and targeted fuzzing operations.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the mutation engine.
        
        Args:
            config: Configuration parameters for the mutation engine.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Mutation configuration
        self.mutation_rate = self.config.get('mutation_rate', 0.1)
        self.max_mutations = self.config.get('max_mutations', 10)
        self.allow_recursive_mutations = self.config.get('allow_recursive_mutations', True)
        self.max_recursive_depth = self.config.get('max_recursive_depth', 3)
        
        # Mutation strategies
        self.strategies = {
            'binary': self._mutate_binary,
            'string': self._mutate_string,
            'number': self._mutate_number,
            'boolean': self._mutate_boolean,
            'array': self._mutate_array,
            'object': self._mutate_object,
            'json': self._mutate_json,
            'xml': self._mutate_xml,
            'http': self._mutate_http,
        }
        
        # Custom strategies from config
        custom_strategies = self.config.get('custom_strategies', {})
        for strategy_name, strategy_func in custom_strategies.items():
            if callable(strategy_func):
                self.strategies[strategy_name] = strategy_func
        
        self.logger.info(f"Initialized MutationEngine with {len(self.strategies)} strategies")
    
    def mutate(self, data: Any, data_type: Optional[str] = None, 
               recursive_depth: int = 0) -> Any:
        """Mutate data based on its type.
        
        Args:
            data: Data to mutate.
            data_type: Type of data to mutate. If None, inferred from data.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated data.
        """
        # Check recursive depth limit
        if recursive_depth > self.max_recursive_depth:
            return data
        
        # Infer data type if not provided
        if data_type is None:
            data_type = self._infer_data_type(data)
        
        # Get mutation strategy
        strategy = self.strategies.get(data_type)
        if not strategy:
            self.logger.warning(f"No mutation strategy for data type: {data_type}")
            return data
        
        # Apply mutation
        try:
            return strategy(data, recursive_depth)
        except Exception as e:
            self.logger.error(f"Error during mutation: {str(e)}")
            return data
    
    def _infer_data_type(self, data: Any) -> str:
        """Infer the type of data.
        
        Args:
            data: Data to infer type for.
            
        Returns:
            Inferred data type as string.
        """
        if isinstance(data, bytes) or isinstance(data, bytearray):
            return 'binary'
        elif isinstance(data, str):
            # Try to detect if it's JSON, XML, or HTTP
            if data.strip().startswith('{') and data.strip().endswith('}'):
                return 'json'
            elif data.strip().startswith('<') and data.strip().endswith('>'):
                return 'xml'
            elif data.startswith('GET ') or data.startswith('POST ') or '\r\n\r\n' in data:
                return 'http'
            else:
                return 'string'
        elif isinstance(data, (int, float)):
            return 'number'
        elif isinstance(data, bool):
            return 'boolean'
        elif isinstance(data, list) or isinstance(data, tuple):
            return 'array'
        elif isinstance(data, dict):
            return 'object'
        else:
            return 'string'  # Default to string
    
    def _should_mutate(self) -> bool:
        """Determine if a mutation should occur based on mutation rate.
        
        Returns:
            True if mutation should occur, False otherwise.
        """
        return random.random() < self.mutation_rate
    
    def _mutate_binary(self, data: bytes, recursive_depth: int) -> bytes:
        """Mutate binary data.
        
        Args:
            data: Binary data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated binary data.
        """
        # Convert to bytearray for mutation
        data_array = bytearray(data)
        
        # Determine how many bytes to mutate
        num_bytes_to_mutate = max(1, int(len(data_array) * self.mutation_rate))
        num_bytes_to_mutate = min(num_bytes_to_mutate, self.max_mutations)
        
        # Randomly select bytes to mutate
        for _ in range(num_bytes_to_mutate):
            if not data_array:
                break
                
            idx = random.randint(0, len(data_array) - 1)
            mutation_type = random.choice(['flip', 'random', 'increment', 'decrement'])
            
            if mutation_type == 'flip':
                # Flip bits
                bit_position = random.randint(0, 7)
                data_array[idx] ^= (1 << bit_position)
            elif mutation_type == 'random':
                # Replace with random byte
                data_array[idx] = random.randint(0, 255)
            elif mutation_type == 'increment':
                # Increment byte
                data_array[idx] = (data_array[idx] + 1) % 256
            elif mutation_type == 'decrement':
                # Decrement byte
                data_array[idx] = (data_array[idx] - 1) % 256
        
        return bytes(data_array)
    
    def _mutate_string(self, data: str, recursive_depth: int) -> str:
        """Mutate string data.
        
        Args:
            data: String data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated string data.
        """
        if not data:
            return data
        
        # Convert to list for mutation
        chars = list(data)
        
        # Determine how many characters to mutate
        num_chars_to_mutate = max(1, int(len(chars) * self.mutation_rate))
        num_chars_to_mutate = min(num_chars_to_mutate, self.max_mutations)
        
        # Randomly select characters to mutate
        for _ in range(num_chars_to_mutate):
            mutation_type = random.choice(['replace', 'insert', 'delete', 'swap'])
            
            if mutation_type == 'replace' and chars:
                # Replace character
                idx = random.randint(0, len(chars) - 1)
                chars[idx] = random.choice(string.printable)
            elif mutation_type == 'insert' and len(chars) < 1000:  # Prevent excessive growth
                # Insert character
                idx = random.randint(0, len(chars))
                chars.insert(idx, random.choice(string.printable))
            elif mutation_type == 'delete' and len(chars) > 1:
                # Delete character
                idx = random.randint(0, len(chars) - 1)
                chars.pop(idx)
            elif mutation_type == 'swap' and len(chars) > 1:
                # Swap characters
                idx1 = random.randint(0, len(chars) - 1)
                idx2 = random.randint(0, len(chars) - 1)
                chars[idx1], chars[idx2] = chars[idx2], chars[idx1]
        
        return ''.join(chars)
    
    def _mutate_number(self, data: Union[int, float], recursive_depth: int) -> Union[int, float]:
        """Mutate numeric data.
        
        Args:
            data: Numeric data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated numeric data.
        """
        mutation_type = random.choice(['add', 'subtract', 'multiply', 'divide', 'negate', 'random', 'boundary'])
        
        if mutation_type == 'add':
            # Add a random value
            if isinstance(data, int):
                return data + random.randint(-100, 100)
            else:  # float
                return data + random.uniform(-100.0, 100.0)
        elif mutation_type == 'subtract':
            # Subtract a random value
            if isinstance(data, int):
                return data - random.randint(-100, 100)
            else:  # float
                return data - random.uniform(-100.0, 100.0)
        elif mutation_type == 'multiply':
            # Multiply by a random value
            if isinstance(data, int):
                return data * random.randint(-10, 10)
            else:  # float
                return data * random.uniform(-10.0, 10.0)
        elif mutation_type == 'divide':
            # Divide by a random value (avoid division by zero)
            divisor = 0
            while divisor == 0:
                if isinstance(data, int):
                    divisor = random.randint(-10, 10)
                else:  # float
                    divisor = random.uniform(-10.0, 10.0)
            return data / divisor
        elif mutation_type == 'negate':
            # Negate the value
            return -data
        elif mutation_type == 'random':
            # Replace with a random value
            if isinstance(data, int):
                return random.randint(-1000000, 1000000)
            else:  # float
                return random.uniform(-1000000.0, 1000000.0)
        elif mutation_type == 'boundary':
            # Replace with a boundary value
            boundaries = [0, 1, -1, 2**31-1, -2**31, 2**63-1, -2**63, float('inf'), float('-inf'), float('nan')]
            return random.choice(boundaries)
    
    def _mutate_boolean(self, data: bool, recursive_depth: int) -> bool:
        """Mutate boolean data.
        
        Args:
            data: Boolean data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated boolean data.
        """
        # Simply flip the boolean value
        return not data
    
    def _mutate_array(self, data: List[Any], recursive_depth: int) -> List[Any]:
        """Mutate array data.
        
        Args:
            data: Array data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated array data.
        """
        if not data:
            return data
        
        # Create a copy of the array
        result = data.copy()
        
        # Determine mutation operations
        mutation_ops = []
        if random.random() < 0.3 and len(result) > 0:  # 30% chance to remove an element
            mutation_ops.append('remove')
        if random.random() < 0.3 and len(result) < 100:  # 30% chance to add an element
            mutation_ops.append('add')
        if random.random() < 0.3 and len(result) > 1:  # 30% chance to swap elements
            mutation_ops.append('swap')
        if random.random() < 0.5 and len(result) > 0 and self.allow_recursive_mutations:  # 50% chance to mutate an element
            mutation_ops.append('mutate')
        
        # Apply mutations
        for op in mutation_ops:
            if op == 'remove' and result:
                # Remove a random element
                idx = random.randint(0, len(result) - 1)
                result.pop(idx)
            elif op == 'add':
                # Add a random element
                if result:
                    # Use an existing element as template
                    template = random.choice(result)
                    data_type = self._infer_data_type(template)
                    new_element = self.mutate(template, data_type, recursive_depth + 1)
                else:
                    # Create a new element
                    new_element = random.choice([0, '', False, [], {}])
                
                idx = random.randint(0, len(result))
                result.insert(idx, new_element)
            elif op == 'swap' and len(result) > 1:
                # Swap two random elements
                idx1 = random.randint(0, len(result) - 1)
                idx2 = random.randint(0, len(result) - 1)
                result[idx1], result[idx2] = result[idx2], result[idx1]
            elif op == 'mutate' and result:
                # Mutate a random element
                idx = random.randint(0, len(result) - 1)
                element = result[idx]
                data_type = self._infer_data_type(element)
                result[idx] = self.mutate(element, data_type, recursive_depth + 1)
        
        return result
    
    def _mutate_object(self, data: Dict[str, Any], recursive_depth: int) -> Dict[str, Any]:
        """Mutate object (dictionary) data.
        
        Args:
            data: Object data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated object data.
        """
        if not data:
            return data
        
        # Create a copy of the object
        result = data.copy()
        
        # Determine mutation operations
        mutation_ops = []
        if random.random() < 0.3 and result:  # 30% chance to remove a key
            mutation_ops.append('remove')
        if random.random() < 0.3 and len(result) < 100:  # 30% chance to add a key
            mutation_ops.append('add')
        if random.random() < 0.3:  # 30% chance to modify a key
            mutation_ops.append('modify_key')
        if random.random() < 0.5 and result and self.allow_recursive_mutations:  # 50% chance to mutate a value
            mutation_ops.append('mutate_value')
        
        # Apply mutations
        for op in mutation_ops:
            if op == 'remove' and result:
                # Remove a random key
                key = random.choice(list(result.keys()))
                del result[key]
            elif op == 'add':
                # Add a new key-value pair
                new_key = self._generate_random_key(result)
                
                if result:
                    # Use an existing value as template
                    template_value = random.choice(list(result.values()))
                    data_type = self._infer_data_type(template_value)
                    new_value = self.mutate(template_value, data_type, recursive_depth + 1)
                else:
                    # Create a new value
                    new_value = random.choice([0, '', False, [], {}])
                
                result[new_key] = new_value
            elif op == 'modify_key' and result:
                # Modify a random key
                old_key = random.choice(list(result.keys()))
                new_key = self._mutate_string(old_key, recursive_depth + 1)
                
                # Ensure the new key is unique
                while new_key in result and new_key != old_key:
                    new_key = self._mutate_string(old_key, recursive_depth + 1)
                
                # Update the key
                if new_key != old_key:
                    result[new_key] = result[old_key]
                    del result[old_key]
            elif op == 'mutate_value' and result:
                # Mutate a random value
                key = random.choice(list(result.keys()))
                value = result[key]
                data_type = self._infer_data_type(value)
                result[key] = self.mutate(value, data_type, recursive_depth + 1)
        
        return result
    
    def _generate_random_key(self, obj: Dict[str, Any]) -> str:
        """Generate a random key that doesn't exist in the object.
        
        Args:
            obj: Object to generate key for.
            
        Returns:
            Random unique key.
        """
        # Common field names
        common_keys = ['id', 'name', 'type', 'value', 'data', 'count', 'index', 'key', 'code', 'status', 'message']
        
        # Try a common key first
        if random.random() < 0.7 and common_keys:  # 70% chance to use a common key
            key = random.choice(common_keys)
            # Add a random suffix if the key already exists
            if key in obj:
                key += '_' + ''.join(random.choices(string.ascii_lowercase, k=5))
            return key
        
        # Generate a random key
        key_length = random.randint(3, 15)
        key = ''.join(random.choices(string.ascii_lowercase + '_', k=key_length))
        
        # Ensure the key is unique
        while key in obj:
            key = ''.join(random.choices(string.ascii_lowercase + '_', k=key_length))
        
        return key
    
    def _mutate_json(self, data: str, recursive_depth: int) -> str:
        """Mutate JSON string data.
        
        Args:
            data: JSON string data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated JSON string data.
        """
        import json
        
        try:
            # Parse JSON
            json_data = json.loads(data)
            
            # Mutate the parsed data
            data_type = 'object' if isinstance(json_data, dict) else 'array'
            mutated_data = self.mutate(json_data, data_type, recursive_depth + 1)
            
            # Convert back to JSON string
            return json.dumps(mutated_data)
        except json.JSONDecodeError:
            # If JSON parsing fails, mutate as a regular string
            return self._mutate_string(data, recursive_depth)
    
    def _mutate_xml(self, data: str, recursive_depth: int) -> str:
        """Mutate XML string data.
        
        Args:
            data: XML string data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated XML string data.
        """
        # For simplicity, just mutate as a string
        # A more sophisticated implementation would parse the XML and mutate the structure
        return self._mutate_string(data, recursive_depth)
    
    def _mutate_http(self, data: str, recursive_depth: int) -> str:
        """Mutate HTTP request/response data.
        
        Args:
            data: HTTP data to mutate.
            recursive_depth: Current depth in recursive mutations.
            
        Returns:
            Mutated HTTP data.
        """
        # Split into headers and body
        parts = data.split('\r\n\r\n', 1)
        
        if len(parts) == 2:
            headers, body = parts
            
            # Mutate headers
            headers = self._mutate_string(headers, recursive_depth)
            
            # Mutate body based on content type
            if 'Content-Type: application/json' in headers:
                body = self._mutate_json(body, recursive_depth)
            elif 'Content-Type: application/xml' in headers or 'Content-Type: text/xml' in headers:
                body = self._mutate_xml(body, recursive_depth)
            else:
                body = self._mutate_string(body, recursive_depth)
            
            return headers + '\r\n\r\n' + body
        else:
            # If can't split, mutate as a regular string
            return self._mutate_string(data, recursive_depth)