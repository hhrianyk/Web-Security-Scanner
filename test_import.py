#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script to verify the imports are working correctly
"""

import sys
import os

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    print("1. Testing OSINTScanner import...")
    from osint_tools import OSINTScanner
    print("✓ Successfully imported OSINTScanner")
except ImportError as e:
    print(f"✗ Failed to import OSINTScanner: {e}")

try:
    print("\n2. Testing vulners_integration module...")
    import vulners_integration
    print("✓ Successfully imported vulners_integration module")
except Exception as e:
    print(f"✗ Error importing vulners_integration: {e}")

try:
    print("\n3. Testing SecurityToolBase import from vulners_integration...")
    from vulners_integration import SecurityToolBase
    print("✓ Successfully imported SecurityToolBase from vulners_integration")
except Exception as e:
    print(f"✗ Error importing SecurityToolBase from vulners_integration: {e}")

print("\nImport tests completed.") 