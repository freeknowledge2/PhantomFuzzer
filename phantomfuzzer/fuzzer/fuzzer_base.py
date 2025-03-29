#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base Fuzzer Class for PhantomFuzzer.

This module provides the foundation for all fuzzer types in the PhantomFuzzer project,
including common functionality for configuration, logging, and result tracking.
"""

import os
import time
import random
import uuid
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any, Callable
from abc import ABC, abstractmethod

# Local imports
from phantomfuzzer.utils.logging import get_logger


class BaseFuzzer(ABC):
    """Base class for all fuzzer implementations.
    
    This abstract class defines the common interface and functionality for all
    fuzzer types in the PhantomFuzzer project. Specialized fuzzers should inherit
    from this class and implement the required abstract methods.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the base fuzzer.
        
        Args:
            config: Configuration parameters for the fuzzer.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.target = self.config.get('target', None)
        self.timeout = self.config.get('timeout', 30)  # Default timeout in seconds
        self.max_retries = self.config.get('max_retries', 3)
        self.delay_between_requests = self.config.get('delay', 0.5)  # Default delay in seconds
        self.random_delay = self.config.get('random_delay', False)
        self.min_delay = self.config.get('min_delay', 0.1)
        self.max_delay = self.config.get('max_delay', 2.0)
        
        # Fuzzing parameters
        self.fuzz_iterations = self.config.get('iterations', 100)
        self.fuzz_seed = self.config.get('seed', None)
        if self.fuzz_seed is not None:
            random.seed(self.fuzz_seed)
        
        # Result tracking
        self.results = []
        self.session_id = str(uuid.uuid4())
        self.start_time = None
        self.end_time = None
        
        self.logger.info(f"Initialized {self.__class__.__name__} with session ID: {self.session_id}")
    
    def set_target(self, target: str) -> None:
        """Set the target for fuzzing.
        
        Args:
            target: Target to fuzz (URL, API endpoint, etc.)
        """
        self.target = target
        self.logger.info(f"Target set to: {target}")
    
    def get_delay(self) -> float:
        """Get the delay to use between requests.
        
        Returns:
            Delay in seconds.
        """
        if self.random_delay:
            return random.uniform(self.min_delay, self.max_delay)
        return self.delay_between_requests
    
    @abstractmethod
    def generate_fuzz_data(self) -> Any:
        """Generate data for fuzzing.
        
        This method should be implemented by subclasses to generate
        appropriate fuzzing data for the specific fuzzer type.
        
        Returns:
            Data to use for fuzzing.
        """
        pass
    
    @abstractmethod
    def execute_fuzz(self, fuzz_data: Any) -> Dict[str, Any]:
        """Execute a single fuzzing operation.
        
        This method should be implemented by subclasses to perform
        the actual fuzzing operation with the provided data.
        
        Args:
            fuzz_data: Data to use for fuzzing.
            
        Returns:
            Dictionary with results of the fuzzing operation.
        """
        pass
    
    def track_result(self, result: Dict[str, Any]) -> None:
        """Track a fuzzing result.
        
        Args:
            result: Result of a fuzzing operation.
        """
        self.results.append(result)
    
    def run(self, iterations: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run the fuzzer for the specified number of iterations.
        
        Args:
            iterations: Number of fuzzing iterations to perform.
                        If None, use the value from config.
        
        Returns:
            List of results from all fuzzing operations.
        """
        if self.target is None:
            self.logger.error("No target specified. Call set_target() first.")
            return []
        
        iterations = iterations or self.fuzz_iterations
        self.logger.info(f"Starting fuzzing session with {iterations} iterations")
        
        self.start_time = time.time()
        self.results = []
        
        try:
            for i in range(iterations):
                self.logger.debug(f"Fuzzing iteration {i+1}/{iterations}")
                
                # Generate fuzz data
                fuzz_data = self.generate_fuzz_data()
                
                # Execute fuzzing
                result = self.execute_fuzz(fuzz_data)
                
                # Track result
                self.track_result(result)
                
                # Apply delay between requests
                if i < iterations - 1:  # No need to delay after the last iteration
                    time.sleep(self.get_delay())
        
        except KeyboardInterrupt:
            self.logger.info("Fuzzing interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during fuzzing: {str(e)}")
        
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        self.logger.info(f"Fuzzing session completed in {duration:.2f} seconds")
        
        return self.results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the fuzzing session.
        
        Returns:
            Dictionary with summary information.
        """
        if not self.start_time or not self.end_time:
            return {
                'session_id': self.session_id,
                'status': 'Not run',
                'iterations': 0,
                'duration': 0,
                'results': []
            }
        
        return {
            'session_id': self.session_id,
            'status': 'Completed',
            'target': self.target,
            'iterations': len(self.results),
            'duration': self.end_time - self.start_time,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'results': self.results
        }
    
    def save_results(self, output_path: Union[str, Path]) -> bool:
        """Save fuzzing results to a file.
        
        Args:
            output_path: Path to save results to.
            
        Returns:
            True if successful, False otherwise.
        """
        import json
        
        try:
            output_path = Path(output_path)
            
            # Create directory if it doesn't exist
            output_dir = output_path.parent
            if not output_dir.exists():
                output_dir.mkdir(parents=True)
            
            # Save summary as JSON
            with open(output_path, 'w') as f:
                json.dump(self.get_summary(), f, indent=2)
            
            self.logger.info(f"Results saved to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            return False