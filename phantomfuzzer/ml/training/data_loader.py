#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Data Loader for ML Training.

This module provides utilities for loading and preprocessing data
for training machine learning models in PhantomFuzzer.
"""

import os
import glob
import random
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union, Any, Set

# Local imports
from phantomfuzzer.utils.logging import get_logger


class DataLoader:
    """Data loader for machine learning model training.
    
    This class handles loading and preprocessing data for training
    machine learning models, particularly for anomaly detection.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the data loader.
        
        Args:
            config: Configuration parameters for data loading.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.benign_ratio = self.config.get('benign_ratio', 0.7)
        self.max_files = self.config.get('max_files', 10000)
        self.file_extensions = self.config.get('file_extensions', None)  # None means all extensions
        self.min_file_size = self.config.get('min_file_size', 10)  # bytes
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10 MB
        
        # Cache to avoid duplicate files
        self.file_hashes: Set[str] = set()
    
    def load_dataset(self, 
                     benign_dirs: List[Union[str, Path]], 
                     malicious_dirs: Optional[List[Union[str, Path]]] = None) -> Tuple[List[str], Optional[List[str]]]:
        """Load a dataset of benign and optionally malicious files.
        
        Args:
            benign_dirs: List of directories containing benign files.
            malicious_dirs: Optional list of directories containing malicious files.
            
        Returns:
            A tuple of (benign_files, malicious_files) where each is a list of file paths.
            If malicious_dirs is None, malicious_files will be None.
        """
        # Load benign files
        benign_files = self._load_files_from_dirs(benign_dirs)
        self.logger.info(f"Loaded {len(benign_files)} benign files")
        
        # Load malicious files if provided
        malicious_files = None
        if malicious_dirs:
            malicious_files = self._load_files_from_dirs(malicious_dirs)
            self.logger.info(f"Loaded {len(malicious_files)} malicious files")
        
        return benign_files, malicious_files
        
    def preprocess_files(self, 
                       benign_files: List[Union[str, Path]], 
                       malicious_files: Optional[List[Union[str, Path]]] = None) -> List[Dict[str, Any]]:
        """Preprocess files for training.
        
        Args:
            benign_files: List of paths to benign files.
            malicious_files: Optional list of paths to malicious files.
            
        Returns:
            A list of preprocessed data items, each containing file path and features.
        """
        dataset = []
        
        # Process benign files
        for file_path in benign_files:
            try:
                item = {
                    'file_path': str(file_path),
                    'label': 0  # 0 for benign
                }
                dataset.append(item)
            except Exception as e:
                self.logger.error(f"Error preprocessing benign file {file_path}: {str(e)}")
        
        # Process malicious files if provided
        if malicious_files:
            for file_path in malicious_files:
                try:
                    item = {
                        'file_path': str(file_path),
                        'label': 1  # 1 for malicious
                    }
                    dataset.append(item)
                except Exception as e:
                    self.logger.error(f"Error preprocessing malicious file {file_path}: {str(e)}")
        
        self.logger.info(f"Preprocessed {len(dataset)} files")
        return dataset
    
    def _load_files_from_dirs(self, directories: List[Union[str, Path]]) -> List[str]:
        """Load files from a list of directories.
        
        Args:
            directories: List of directories to load files from.
            
        Returns:
            List of file paths.
        """
        files = []
        self.file_hashes.clear()
        
        for directory in directories:
            directory = Path(directory)
            if not directory.exists() or not directory.is_dir():
                self.logger.warning(f"Directory {directory} does not exist or is not a directory")
                continue
                
            # Get all files in the directory (recursively)
            pattern = '**/*' if self.file_extensions is None else f"**/*.{{{','.join(self.file_extensions)}}}"
            for file_path in directory.glob(pattern):
                if len(files) >= self.max_files:
                    self.logger.info(f"Reached maximum number of files ({self.max_files})")
                    break
                    
                if not file_path.is_file():
                    continue
                    
                # Check file size
                file_size = file_path.stat().st_size
                if file_size < self.min_file_size or file_size > self.max_file_size:
                    continue
                    
                # Check if we've already seen this file (by hash)
                if self._is_duplicate(file_path):
                    continue
                    
                files.append(str(file_path))
                
        return files
    
    def _is_duplicate(self, file_path: Path) -> bool:
        """Check if a file is a duplicate based on its hash.
        
        Args:
            file_path: Path to the file to check.
            
        Returns:
            True if the file is a duplicate, False otherwise.
        """
        try:
            # Calculate file hash
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            
            # Check if we've seen this hash before
            if file_hash in self.file_hashes:
                return True
                
            # Add hash to set
            self.file_hashes.add(file_hash)
            return False
            
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            return True  # Treat as duplicate to skip problematic files
    
    def split_dataset(self, 
                      files: List[str], 
                      train_ratio: float = 0.8, 
                      val_ratio: float = 0.1, 
                      test_ratio: float = 0.1) -> Tuple[List[str], List[str], List[str]]:
        """Split a dataset into training, validation, and test sets.
        
        Args:
            files: List of file paths.
            train_ratio: Ratio of files to use for training.
            val_ratio: Ratio of files to use for validation.
            test_ratio: Ratio of files to use for testing.
            
        Returns:
            A tuple of (train_files, val_files, test_files).
        """
        # Ensure ratios sum to 1
        total_ratio = train_ratio + val_ratio + test_ratio
        if abs(total_ratio - 1.0) > 1e-6:
            self.logger.warning(f"Ratios do not sum to 1 ({total_ratio}), normalizing")
            train_ratio /= total_ratio
            val_ratio /= total_ratio
            test_ratio /= total_ratio
            
        # Shuffle files
        shuffled_files = files.copy()
        random.shuffle(shuffled_files)
        
        # Calculate split indices
        n_files = len(shuffled_files)
        train_end = int(n_files * train_ratio)
        val_end = train_end + int(n_files * val_ratio)
        
        # Split dataset
        train_files = shuffled_files[:train_end]
        val_files = shuffled_files[train_end:val_end]
        test_files = shuffled_files[val_end:]
        
        self.logger.info(f"Split dataset: {len(train_files)} train, {len(val_files)} validation, {len(test_files)} test")
        
        return train_files, val_files, test_files
    
    def balance_dataset(self, 
                        benign_files: List[str], 
                        malicious_files: List[str], 
                        benign_ratio: Optional[float] = None) -> Tuple[List[str], List[str]]:
        """Balance a dataset of benign and malicious files.
        
        Args:
            benign_files: List of benign file paths.
            malicious_files: List of malicious file paths.
            benign_ratio: Ratio of benign files in the final dataset.
                If None, use the default ratio from config.
                
        Returns:
            A tuple of (balanced_benign_files, balanced_malicious_files).
        """
        if benign_ratio is None:
            benign_ratio = self.benign_ratio
            
        # Calculate target counts
        total_files = min(len(benign_files) + len(malicious_files), self.max_files)
        target_benign = int(total_files * benign_ratio)
        target_malicious = total_files - target_benign
        
        # Sample files
        balanced_benign = random.sample(benign_files, min(target_benign, len(benign_files)))
        balanced_malicious = random.sample(malicious_files, min(target_malicious, len(malicious_files)))
        
        self.logger.info(f"Balanced dataset: {len(balanced_benign)} benign, {len(balanced_malicious)} malicious")
        
        return balanced_benign, balanced_malicious
    
    def get_file_metadata(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Get metadata for a file.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Dictionary of file metadata.
        """
        file_path = Path(file_path)
        
        try:
            # Get file stats
            stats = file_path.stat()
            
            # Get file extension
            extension = file_path.suffix.lower()[1:] if file_path.suffix else ''
            
            # Get file type using magic
            file_type = 'unknown'
            try:
                import magic
                file_type = magic.from_file(str(file_path))
            except ImportError:
                self.logger.warning("python-magic not installed, file type detection limited")
                
            # Return metadata
            return {
                'path': str(file_path),
                'size': stats.st_size,
                'modified_time': stats.st_mtime,
                'extension': extension,
                'type': file_type
            }
            
        except Exception as e:
            self.logger.error(f"Error getting metadata for {file_path}: {str(e)}")
            return {
                'path': str(file_path),
                'error': str(e)
            }
