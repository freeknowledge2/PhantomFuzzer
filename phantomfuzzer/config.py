#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration management for PhantomFuzzer.

This module handles loading, validating, and accessing configuration settings
for all components of PhantomFuzzer, including scanner, fuzzer, ML, and stealth
capabilities.
"""

import os
import sys
import yaml
import json
import logging
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

# Default configuration file path
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'default.yml')

class ConfigValidationError(Exception):
    """Exception raised for configuration validation errors."""
    pass

class ConfigManager:
    """Manages configuration for PhantomFuzzer.
    
    This class handles loading configuration from files, validating the configuration,
    and providing access to configuration settings for different components.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, the default
                configuration file will be used.
        """
        self.config: Dict[str, Any] = {}
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from the specified file.
        
        Raises:
            FileNotFoundError: If the configuration file does not exist.
            yaml.YAMLError: If the configuration file is not valid YAML.
        """
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            self.validate_config()
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {self.config_path}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing configuration file: {e}")
            raise
    
    def validate_config(self) -> None:
        """Validate the configuration.
        
        Ensures that all required configuration settings are present and valid.
        
        Raises:
            ConfigValidationError: If the configuration is invalid.
        """
        required_sections = ['general', 'scanner', 'fuzzer', 'ml', 'stealth', 'payload', 'wordlists']
        
        for section in required_sections:
            if section not in self.config:
                raise ConfigValidationError(f"Missing required configuration section: {section}")
        
        # Validate general section
        if 'log_level' not in self.config['general']:
            raise ConfigValidationError("Missing required configuration: general.log_level")
        
        # Validate scanner section
        if 'modes' not in self.config['scanner']:
            raise ConfigValidationError("Missing required configuration: scanner.modes")
        
        # Additional validation can be added as needed
    
    def get_config(self) -> Dict[str, Any]:
        """Get the complete configuration.
        
        Returns:
            The complete configuration dictionary.
        """
        return self.config
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a specific section of the configuration.
        
        Args:
            section: The section to retrieve.
        
        Returns:
            The configuration section.
        
        Raises:
            KeyError: If the section does not exist.
        """
        if section not in self.config:
            raise KeyError(f"Configuration section not found: {section}")
        return self.config[section]
    
    def get_value(self, path: str, default: Any = None) -> Any:
        """Get a specific configuration value using a dot-separated path.
        
        Args:
            path: The dot-separated path to the configuration value.
            default: The default value to return if the path does not exist.
        
        Returns:
            The configuration value, or the default if the path does not exist.
        
        Example:
            >>> config.get_value('scanner.web_scan.crawl_depth')
            3
        """
        parts = path.split('.')
        value = self.config
        
        try:
            for part in parts:
                value = value[part]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_value(self, path: str, value: Any) -> None:
        """Set a specific configuration value using a dot-separated path.
        
        Args:
            path: The dot-separated path to the configuration value.
            value: The value to set.
        
        Example:
            >>> config.set_value('scanner.web_scan.crawl_depth', 5)
        """
        parts = path.split('.')
        config = self.config
        
        for i, part in enumerate(parts[:-1]):
            if part not in config:
                config[part] = {}
            config = config[part]
        
        config[parts[-1]] = value
    
    def save_config(self, path: Optional[str] = None) -> None:
        """Save the current configuration to a file.
        
        Args:
            path: The path to save the configuration to. If None, the current
                configuration path will be used.
        
        Raises:
            IOError: If the configuration file cannot be written.
        """
        save_path = path or self.config_path
        
        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except IOError as e:
            logging.error(f"Error saving configuration file: {e}")
            raise
    
    def merge_config(self, config: Dict[str, Any]) -> None:
        """Merge another configuration dictionary into the current configuration.
        
        Args:
            config: The configuration dictionary to merge.
        """
        self._merge_dicts(self.config, config)
        self.validate_config()
    
    def _merge_dicts(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Recursively merge two dictionaries.
        
        Args:
            target: The target dictionary to merge into.
            source: The source dictionary to merge from.
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._merge_dicts(target[key], value)
            else:
                target[key] = value
    
    # Convenience methods for accessing specific sections
    
    def get_general_config(self) -> Dict[str, Any]:
        """Get the general configuration section.
        
        Returns:
            The general configuration section.
        """
        return self.get_section('general')
    
    def get_scanner_config(self) -> Dict[str, Any]:
        """Get the scanner configuration section.
        
        Returns:
            The scanner configuration section.
        """
        return self.get_section('scanner')
    
    def get_fuzzer_config(self) -> Dict[str, Any]:
        """Get the fuzzer configuration section.
        
        Returns:
            The fuzzer configuration section.
        """
        return self.get_section('fuzzer')
    
    def get_ml_config(self) -> Dict[str, Any]:
        """Get the ML configuration section.
        
        Returns:
            The ML configuration section.
        """
        return self.get_section('ml')
    
    def get_stealth_config(self) -> Dict[str, Any]:
        """Get the stealth configuration section.
        
        Returns:
            The stealth configuration section.
        """
        return self.get_section('stealth')
    
    def get_payload_config(self) -> Dict[str, Any]:
        """Get the payload configuration section.
        
        Returns:
            The payload configuration section.
        """
        return self.get_section('payload')
    
    def get_wordlists_config(self) -> Dict[str, Any]:
        """Get the wordlists configuration section.
        
        Returns:
            The wordlists configuration section.
        """
        return self.get_section('wordlists')

# Global configuration instance
_config_instance = None

def get_config(config_path: Optional[str] = None) -> ConfigManager:
    """Get the global configuration instance.
    
    Args:
        config_path: Path to the configuration file. If None, the default
            configuration file will be used. This is only used if the global
            configuration instance has not been initialized yet.
    
    Returns:
        The global configuration instance.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager(config_path)
    return _config_instance

def reset_config() -> None:
    """Reset the global configuration instance."""
    global _config_instance
    _config_instance = None