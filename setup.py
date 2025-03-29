#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# Core dependencies only - minimal set needed for basic functionality
# For full functionality, refer to requirements.txt
core_requirements = [
    "pyyaml",
    "click",
    "requests"
]

setup(
    name="phantomfuzzer",
    version="0.1.0",
    description="PhantomFuzzer: Advanced Security Testing Toolkit",
    author="Ghost Security",
    author_email="info@phantomfuzzer.com",
    packages=find_packages(),
    include_package_data=True,
    install_requires=core_requirements,
    entry_points={
        "console_scripts": [
            "phantomfuzzer=phantomfuzzer.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.11",
)
