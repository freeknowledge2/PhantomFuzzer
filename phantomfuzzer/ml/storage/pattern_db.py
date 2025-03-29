#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pattern Database for Machine Learning Models.

This module provides a database for storing, retrieving, and managing patterns
used in machine learning models for anomaly detection and pattern recognition.
"""

import os
import json
import time
import difflib
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any, Set
from datetime import datetime

# Local imports
from phantomfuzzer.utils.logging import get_logger


class PatternDatabase:
    """Database for storing and managing patterns.
    
    This class provides functionality for loading, storing, retrieving,
    and managing patterns used in machine learning models.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the pattern database.
        
        Args:
            config: Configuration parameters for the database.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.data_dir = self.config.get('data_dir', 
                                        str(Path('/home/concrete/Documents/A-tools/PhantomFuzzer/data/patterns')))
        self.db_file = self.config.get('db_file', 'pattern_db.json')
        self.base_patterns_file = self.config.get('base_patterns_file', 'base_patterns.txt')
        
        # Create data directory if it doesn't exist
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize the database
        self.patterns = {}
        self.load_database()
        
    def load_database(self) -> None:
        """Load the pattern database from disk."""
        db_path = Path(self.data_dir) / self.db_file
        
        # Load existing database if it exists
        if db_path.exists():
            try:
                with open(db_path, 'r') as f:
                    self.patterns = json.load(f)
                self.logger.info(f"Loaded {len(self.patterns)} patterns from database")
            except Exception as e:
                self.logger.error(f"Error loading pattern database: {str(e)}")
                self.patterns = {}
        
        # Load base patterns if database is empty
        if not self.patterns:
            self._load_base_patterns()
    
    def _load_base_patterns(self) -> None:
        """Load patterns from the base patterns file."""
        base_patterns_path = Path(self.data_dir) / self.base_patterns_file
        
        if not base_patterns_path.exists():
            self.logger.warning(f"Base patterns file not found: {base_patterns_path}")
            return
        
        try:
            with open(base_patterns_path, 'r') as f:
                lines = f.readlines()
            
            # Process each line
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip comments and empty lines
                    self.add_pattern(
                        pattern=line,
                        source='base_patterns',
                        confidence=0.8,  # Default confidence for base patterns
                        metadata={'type': 'base', 'description': 'Base pattern from initial dataset'}
                    )
            
            self.logger.info(f"Loaded {len(lines)} patterns from base patterns file")
            self.save_database()  # Save the loaded patterns to the database
            
        except Exception as e:
            self.logger.error(f"Error loading base patterns: {str(e)}")
    
    def save_database(self) -> None:
        """Save the pattern database to disk."""
        db_path = Path(self.data_dir) / self.db_file
        
        try:
            with open(db_path, 'w') as f:
                json.dump(self.patterns, f, indent=2)
            self.logger.info(f"Saved {len(self.patterns)} patterns to database")
        except Exception as e:
            self.logger.error(f"Error saving pattern database: {str(e)}")
    
    def add_pattern(self, pattern: str, source: str = 'unknown', 
                   confidence: float = 0.5, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Add a new pattern to the database.
        
        Args:
            pattern: The pattern string to add.
            source: The source of the pattern (e.g., 'scan', 'user', 'ml').
            confidence: Confidence score for the pattern (0.0 to 1.0).
            metadata: Additional metadata for the pattern.
            
        Returns:
            The ID of the added pattern.
        """
        # Generate a unique ID for the pattern
        pattern_id = hashlib.md5(pattern.encode()).hexdigest()
        
        # Check if pattern already exists
        if pattern_id in self.patterns:
            self.logger.info(f"Pattern already exists: {pattern}")
            return pattern_id
        
        # Create pattern entry
        timestamp = datetime.now().isoformat()
        pattern_entry = {
            'pattern': pattern,
            'source': source,
            'confidence': max(0.0, min(1.0, confidence)),  # Clamp to [0.0, 1.0]
            'created_at': timestamp,
            'updated_at': timestamp,
            'usage_count': 0,
            'metadata': metadata or {}
        }
        
        # Add to database
        self.patterns[pattern_id] = pattern_entry
        self.logger.info(f"Added new pattern: {pattern}")
        
        # Save the updated database
        self.save_database()
        
        return pattern_id
    
    def get_pattern(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        """Get a pattern by its ID.
        
        Args:
            pattern_id: The ID of the pattern to retrieve.
            
        Returns:
            The pattern entry or None if not found.
        """
        return self.patterns.get(pattern_id)
    
    def get_pattern_by_value(self, pattern: str) -> Optional[Dict[str, Any]]:
        """Get a pattern by its value.
        
        Args:
            pattern: The pattern string to retrieve.
            
        Returns:
            The pattern entry or None if not found.
        """
        pattern_id = hashlib.md5(pattern.encode()).hexdigest()
        return self.get_pattern(pattern_id)
    
    def update_pattern(self, pattern_id: str, 
                      confidence: Optional[float] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update a pattern in the database.
        
        Args:
            pattern_id: The ID of the pattern to update.
            confidence: New confidence score for the pattern.
            metadata: New or updated metadata for the pattern.
            
        Returns:
            True if the pattern was updated, False otherwise.
        """
        if pattern_id not in self.patterns:
            self.logger.warning(f"Pattern not found: {pattern_id}")
            return False
        
        # Update pattern entry
        if confidence is not None:
            self.patterns[pattern_id]['confidence'] = max(0.0, min(1.0, confidence))
        
        if metadata is not None:
            self.patterns[pattern_id]['metadata'].update(metadata)
        
        self.patterns[pattern_id]['updated_at'] = datetime.now().isoformat()
        self.logger.info(f"Updated pattern: {pattern_id}")
        
        # Save the updated database
        self.save_database()
        
        return True
    
    def delete_pattern(self, pattern_id: str) -> bool:
        """Delete a pattern from the database.
        
        Args:
            pattern_id: The ID of the pattern to delete.
            
        Returns:
            True if the pattern was deleted, False otherwise.
        """
        if pattern_id not in self.patterns:
            self.logger.warning(f"Pattern not found: {pattern_id}")
            return False
        
        # Delete pattern entry
        del self.patterns[pattern_id]
        self.logger.info(f"Deleted pattern: {pattern_id}")
        
        # Save the updated database
        self.save_database()
        
        return True
    
    def find_similar_patterns(self, pattern: str, threshold: float = 0.8) -> List[Dict[str, Any]]:
        """Find patterns similar to the given pattern.
        
        Args:
            pattern: The pattern string to compare with.
            threshold: Similarity threshold (0.0 to 1.0).
            
        Returns:
            List of similar pattern entries.
        """
        similar_patterns = []
        
        for pattern_id, pattern_entry in self.patterns.items():
            similarity = difflib.SequenceMatcher(
                None, pattern, pattern_entry['pattern']
            ).ratio()
            
            if similarity >= threshold:
                similar_patterns.append({
                    'id': pattern_id,
                    'entry': pattern_entry,
                    'similarity': similarity
                })
        
        # Sort by similarity (descending)
        similar_patterns.sort(key=lambda x: x['similarity'], reverse=True)
        
        return similar_patterns
    
    def get_patterns_by_source(self, source: str) -> List[Dict[str, Any]]:
        """Get patterns by their source.
        
        Args:
            source: The source to filter by.
            
        Returns:
            List of pattern entries from the specified source.
        """
        return [
            {'id': pattern_id, 'entry': pattern_entry}
            for pattern_id, pattern_entry in self.patterns.items()
            if pattern_entry['source'] == source
        ]
    
    def get_patterns_by_confidence(self, min_confidence: float = 0.0, 
                                 max_confidence: float = 1.0) -> List[Dict[str, Any]]:
        """Get patterns within a confidence range.
        
        Args:
            min_confidence: Minimum confidence score.
            max_confidence: Maximum confidence score.
            
        Returns:
            List of pattern entries within the confidence range.
        """
        return [
            {'id': pattern_id, 'entry': pattern_entry}
            for pattern_id, pattern_entry in self.patterns.items()
            if min_confidence <= pattern_entry['confidence'] <= max_confidence
        ]
    
    def increment_usage_count(self, pattern_id: str) -> bool:
        """Increment the usage count for a pattern.
        
        Args:
            pattern_id: The ID of the pattern.
            
        Returns:
            True if the usage count was incremented, False otherwise.
        """
        if pattern_id not in self.patterns:
            self.logger.warning(f"Pattern not found: {pattern_id}")
            return False
        
        # Increment usage count
        self.patterns[pattern_id]['usage_count'] += 1
        self.patterns[pattern_id]['updated_at'] = datetime.now().isoformat()
        
        # Save the updated database periodically (e.g., every 10 increments)
        if self.patterns[pattern_id]['usage_count'] % 10 == 0:
            self.save_database()
        
        return True
    
    def get_most_used_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most frequently used patterns.
        
        Args:
            limit: Maximum number of patterns to return.
            
        Returns:
            List of most used pattern entries.
        """
        # Sort patterns by usage count (descending)
        sorted_patterns = sorted(
            [{'id': pid, 'entry': pentry} for pid, pentry in self.patterns.items()],
            key=lambda x: x['entry']['usage_count'],
            reverse=True
        )
        
        return sorted_patterns[:limit]
    
    def export_patterns(self, output_file: Optional[str] = None) -> str:
        """Export patterns to a text file.
        
        Args:
            output_file: Path to the output file. If None, a default name is used.
            
        Returns:
            Path to the exported file.
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"patterns_export_{timestamp}.txt"
        
        output_path = Path(self.data_dir) / output_file
        
        try:
            with open(output_path, 'w') as f:
                f.write("# PhantomFuzzer Pattern Database Export\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Total Patterns: {len(self.patterns)}\n\n")
                
                for pattern_id, pattern_entry in self.patterns.items():
                    f.write(f"{pattern_entry['pattern']}\n")
            
            self.logger.info(f"Exported {len(self.patterns)} patterns to {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Error exporting patterns: {str(e)}")
            return ""
    
    def import_patterns(self, input_file: str, source: str = 'import') -> int:
        """Import patterns from a text file.
        
        Args:
            input_file: Path to the input file.
            source: Source to assign to imported patterns.
            
        Returns:
            Number of patterns imported.
        """
        input_path = Path(input_file)
        
        if not input_path.exists():
            self.logger.error(f"Input file not found: {input_path}")
            return 0
        
        try:
            with open(input_path, 'r') as f:
                lines = f.readlines()
            
            # Process each line
            imported_count = 0
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip comments and empty lines
                    self.add_pattern(
                        pattern=line,
                        source=source,
                        confidence=0.5,  # Default confidence for imported patterns
                        metadata={'type': 'imported', 'source_file': str(input_path)}
                    )
                    imported_count += 1
            
            self.logger.info(f"Imported {imported_count} patterns from {input_path}")
            return imported_count
            
        except Exception as e:
            self.logger.error(f"Error importing patterns: {str(e)}")
            return 0
