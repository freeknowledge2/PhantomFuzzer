#!/bin/bash

# PhantomFuzzer wrapper script
# This script forwards commands to the PhantomFuzzer Docker container (command: phantomfuzzer)

# Set environment variables to suppress warnings
export PYTHONWARNINGS="ignore::DeprecationWarning"

# Check if this is a 'man' command
if [[ "$1" == "man" ]]; then
    # For man command, try to use the system man if available
    if command -v man &> /dev/null && [ -f "/usr/local/share/man/man1/phantomfuzzer.1" ]; then
        man phantomfuzzer
    else
        # Fall back to Docker container with improved warning filtering
        # Redirect stderr to a temporary file to filter warnings
        temp_err=$(mktemp)
        docker run --rm \
            -e PYTHONWARNINGS=ignore \
            -e MPLCONFIGDIR=/tmp \
            -e CRYPTOGRAPHY_SUPPRESS_DEPRECATION_WARNINGS=1 \
            phantomfuzzer "$@" 2> "$temp_err"
        
        # Filter out warnings and only show actual errors if any
        if [ -s "$temp_err" ]; then
            grep -v -E "WARNING|Matplotlib|cryptography|Blowfish|TripleDES|CAST5|decrepit|CryptographyDeprecationWarning" "$temp_err" >&2
        fi
        
        # Clean up
        rm -f "$temp_err"
    fi
# Handle volume mounts for current directory when needed
elif [[ "$*" == *"--output"* ]] || [[ "$*" == *"--path"* ]] || [[ "$*" == *"--spec"* ]] || [[ "$*" == *"--target"* ]]; then
    # Run with volume mount and improved warning filtering
    # Redirect stderr to a temporary file to filter warnings
    temp_err=$(mktemp)
    docker run --rm \
        -e PYTHONWARNINGS=ignore \
        -e MPLCONFIGDIR=/tmp \
        -e CRYPTOGRAPHY_SUPPRESS_DEPRECATION_WARNINGS=1 \
        -v "$(pwd):/data/current" \
        phantomfuzzer "$@" 2> "$temp_err"
    
    # Filter out warnings and only show actual errors if any
    if [ -s "$temp_err" ]; then
        grep -v -E "WARNING|Matplotlib|cryptography|Blowfish|TripleDES|CAST5|decrepit|CryptographyDeprecationWarning" "$temp_err" >&2
    fi
    
    # Clean up
    rm -f "$temp_err"
else
    # Run without volume mount and improved warning filtering
    # Redirect stderr to a temporary file to filter warnings
    temp_err=$(mktemp)
    docker run --rm \
        -e PYTHONWARNINGS=ignore \
        -e MPLCONFIGDIR=/tmp \
        -e CRYPTOGRAPHY_SUPPRESS_DEPRECATION_WARNINGS=1 \
        phantomfuzzer "$@" 2> "$temp_err"
    
    # Filter out warnings and only show actual errors if any
    if [ -s "$temp_err" ]; then
        grep -v -E "WARNING|Matplotlib|cryptography|Blowfish|TripleDES|CAST5|decrepit|CryptographyDeprecationWarning" "$temp_err" >&2
    fi
    
    # Clean up
    rm -f "$temp_err"
fi
