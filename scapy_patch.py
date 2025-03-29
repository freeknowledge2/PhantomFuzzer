#!/usr/bin/env python3
"""
Patch script for Scapy to suppress cryptography warnings.
This script should be run during the Docker build process.
"""
import os
import sys
import re
import warnings

# Find the scapy installation directory
try:
    import scapy
    scapy_dir = os.path.dirname(scapy.__file__)
    ipsec_file = os.path.join(scapy_dir, 'layers', 'ipsec.py')
    
    if not os.path.exists(ipsec_file):
        print(f"Error: Could not find {ipsec_file}")
        sys.exit(1)
    
    # Read the file content
    with open(ipsec_file, 'r') as f:
        content = f.read()
    
    # Check if already patched
    if "warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)" in content:
        print(f"File {ipsec_file} already patched")
        sys.exit(0)
    
    # Find the position after all __future__ imports
    future_imports = re.findall(r'from __future__ import .*?\n', content)
    if future_imports:
        # Get the position after the last __future__ import
        last_future_import = future_imports[-1]
        position = content.find(last_future_import) + len(last_future_import)
        
        # Insert our warning suppression code after all __future__ imports
        new_content = content[:position] + \
                     "\n# Added by PhantomFuzzer to suppress cryptography warnings\nimport warnings\nfrom cryptography.utils import CryptographyDeprecationWarning\nwarnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)\n\n" + \
                     content[position:]
    else:
        # No __future__ imports, add at the beginning
        new_content = """# Added by PhantomFuzzer to suppress cryptography warnings
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

""" + content
    
    # Write the modified content back
    with open(ipsec_file, 'w') as f:
        f.write(new_content)
    
    print(f"Successfully patched {ipsec_file} to suppress cryptography warnings")
    
except ImportError:
    print("Error: Scapy module not found")
    sys.exit(1)
except Exception as e:
    print(f"Error: {str(e)}")
    sys.exit(1)
