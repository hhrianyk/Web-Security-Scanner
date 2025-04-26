#!/usr/bin/env python3
"""
Module Testing Script for Security Platform
This script tests the availability and basic functionality of key modules
"""

import os
import sys
import logging
import importlib
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ModuleTester")

# Load environment variables
load_dotenv()

def test_module_import(module_name, required=False):
    """Test if module can be imported"""
    try:
        module = importlib.import_module(module_name)
        logger.info(f"✅ Module {module_name} successfully imported")
        return module
    except ImportError as e:
        if required:
            logger.error(f"❌ Required module {module_name} failed to import: {str(e)}")
            return None
        else:
            logger.warning(f"⚠️ Optional module {module_name} failed to import: {str(e)}")
            return None

def test_ai_vulnerability_scanner():
    """Test AI Vulnerability Scanner module"""
    module = test_module_import("ai_vulnerability_scanner")
    if module:
        try:
            # Basic functionality test
            if hasattr(module, 'AIVulnerabilityScanner'):
                scanner = module.AIVulnerabilityScanner("example.com", "test_reports")
                logger.info(f"✅ AIVulnerabilityScanner class initialized")
                if hasattr(scanner, 'scan_id') and scanner.scan_id:
                    logger.info(f"✅ Scanner ID generated: {scanner.scan_id}")
                return True
            else:
                logger.warning("⚠️ AIVulnerabilityScanner class not found in module")
                return False
        except Exception as e:
            logger.error(f"❌ Error testing AI Vulnerability Scanner: {str(e)}")
            return False
    return False

def test_comprehensive_tester():
    """Test ComprehensiveTester module"""
    module = test_module_import("comprehensive_tester")
    if module:
        try:
            # Basic functionality test
            if hasattr(module, 'ComprehensiveTester'):
                tester = module.ComprehensiveTester("example.com", "test_reports", "test1")
                logger.info(f"✅ ComprehensiveTester class initialized")
                return True
            else:
                logger.warning("⚠️ ComprehensiveTester class not found in module")
                return False
        except Exception as e:
            logger.error(f"❌ Error testing ComprehensiveTester: {str(e)}")
            return False
    return False

def test_vulnerability_reporter():
    """Test Vulnerability Reporter module"""
    module = test_module_import("vulnerability_reporter")
    if module:
        try:
            # Basic functionality test
            if hasattr(module, 'generate_vulnerability_report'):
                logger.info(f"✅ generate_vulnerability_report function available")
                return True
            else:
                logger.warning("⚠️ generate_vulnerability_report function not found in module")
                return False
        except Exception as e:
            logger.error(f"❌ Error testing Vulnerability Reporter: {str(e)}")
            return False
    return False

def main():
    """Main test function"""
    logger.info("Starting module testing...")
    
    # Test base modules (required)
    flask = test_module_import("flask", required=True)
    requests = test_module_import("requests", required=True)
    bs4 = test_module_import("bs4", required=True)
    
    # Test optional modules
    ai_scanner_available = test_ai_vulnerability_scanner()
    comprehensive_tester_available = test_comprehensive_tester()
    vulnerability_reporter_available = test_vulnerability_reporter()
    
    # Log results
    logger.info("\n--- Test Results ---")
    logger.info(f"AI Scanner: {'✅ Available' if ai_scanner_available else '❌ Not Available'}")
    logger.info(f"Comprehensive Tester: {'✅ Available' if comprehensive_tester_available else '❌ Not Available'}")
    logger.info(f"Vulnerability Reporter: {'✅ Available' if vulnerability_reporter_available else '❌ Not Available'}")
    
    # Create results dict for app.py to use
    results = {
        "AI_SCANNER_AVAILABLE": ai_scanner_available,
        "COMPREHENSIVE_TESTER_AVAILABLE": comprehensive_tester_available,
        "VULNERABILITY_REPORTER_AVAILABLE": vulnerability_reporter_available
    }
    
    # Write results to file for app.py to read
    with open("module_test_results.json", "w") as f:
        import json
        json.dump(results, f)
    
    logger.info("Module testing completed!")
    
    return results

if __name__ == "__main__":
    main() 