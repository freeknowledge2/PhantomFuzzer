#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example script demonstrating the usage of the PatternDatabase.

This script shows how to use the PatternDatabase class to manage patterns
for anomaly detection and pattern recognition.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import PhantomFuzzer modules
from phantomfuzzer.ml.storage.pattern_db import PatternDatabase
from phantomfuzzer.ml.models.pattern_recognizer import PatternRecognizer


def main():
    """Run the pattern database example."""
    print("=== PhantomFuzzer Pattern Database Example ===")
    
    # Initialize the pattern database
    print("\nInitializing pattern database...")
    pattern_db = PatternDatabase()
    
    # Display pattern count
    pattern_count = len(pattern_db.patterns)
    print(f"Loaded {pattern_count} patterns from database")
    
    # Add a new pattern
    print("\nAdding a new pattern...")
    new_pattern = "admin_backup.zip"
    pattern_id = pattern_db.add_pattern(
        pattern=new_pattern,
        source='example',
        confidence=0.9,
        metadata={'type': 'backup_file', 'risk': 'high', 'description': 'Admin backup file'}
    )
    print(f"Added pattern with ID: {pattern_id}")
    
    # Find similar patterns
    print("\nFinding similar patterns...")
    similar_patterns = pattern_db.find_similar_patterns(new_pattern, threshold=0.7)
    print(f"Found {len(similar_patterns)} similar patterns:")
    for i, p in enumerate(similar_patterns[:5], 1):  # Show top 5
        print(f"  {i}. {p['entry']['pattern']} (similarity: {p['similarity']:.2f})")
    
    # Get patterns by confidence
    print("\nGetting high-confidence patterns...")
    high_confidence = pattern_db.get_patterns_by_confidence(min_confidence=0.8)
    print(f"Found {len(high_confidence)} high-confidence patterns")
    for i, p in enumerate(high_confidence[:5], 1):  # Show top 5
        print(f"  {i}. {p['entry']['pattern']} (confidence: {p['entry']['confidence']:.2f})")
    
    # Update pattern confidence
    print("\nUpdating pattern confidence...")
    pattern_db.update_pattern(pattern_id, confidence=0.95)
    updated_pattern = pattern_db.get_pattern(pattern_id)
    print(f"Updated confidence: {updated_pattern['confidence']}")
    
    # Increment usage count
    print("\nIncrementing usage count...")
    pattern_db.increment_usage_count(pattern_id)
    updated_pattern = pattern_db.get_pattern(pattern_id)
    print(f"New usage count: {updated_pattern['usage_count']}")
    
    # Export patterns
    print("\nExporting patterns...")
    export_path = pattern_db.export_patterns()
    print(f"Exported patterns to: {export_path}")
    
    # Integration with PatternRecognizer
    print("\nIntegrating with PatternRecognizer...")
    
    # Create a simple function to check if a file matches any pattern
    def check_file_against_patterns(file_path, pattern_db):
        """Check if a file matches any pattern in the database."""
        file_name = Path(file_path).name
        
        # Check for exact matches
        pattern_entry = pattern_db.get_pattern_by_value(file_name)
        if pattern_entry:
            return True, pattern_entry
        
        # Check for similar patterns
        similar_patterns = pattern_db.find_similar_patterns(file_name, threshold=0.8)
        if similar_patterns:
            return True, similar_patterns[0]['entry']
        
        return False, None
    
    # Example files
    example_files = [
        "admin.zip",
        "normal_file.txt",
        "config.bak",
        "admin_backup.zip"
    ]
    
    print("\nChecking example files against patterns:")
    for file in example_files:
        matches, pattern = check_file_against_patterns(file, pattern_db)
        if matches:
            print(f"  {file}: MATCH! Pattern: {pattern['pattern']} (confidence: {pattern['confidence']:.2f})")
        else:
            print(f"  {file}: No match")
    
    print("\n=== Pattern Database Example Complete ===")


if __name__ == "__main__":
    main()
