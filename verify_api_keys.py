#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import sys
import logging
import dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api_verification.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("APIKeyVerification")

def mask_api_key(key):
    """Mask an API key for display"""
    if not key:
        return "Not set"
    if len(key) <= 8:
        return f"{key[:2]}{'*' * (len(key) - 4)}{key[-2:]}"
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"

def load_env_keys():
    """Load API keys from .env file"""
    logger.info("Loading API keys from .env file...")
    
    # Check if .env file exists
    if not os.path.exists(".env"):
        logger.warning(".env file not found")
        return {}
    
    dotenv.load_dotenv()
    
    keys = {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY"),
        "OWASP_AI_SCANNER_KEY": os.getenv("OWASP_AI_SCANNER_KEY"),
        "ARACHNI_AI_KEY": os.getenv("ARACHNI_AI_KEY"),
        "DEEP_EXPLOIT_KEY": os.getenv("DEEP_EXPLOIT_KEY"),
        "SECLISTS_AI_KEY": os.getenv("SECLISTS_AI_KEY"),
        "AI_FUZZER_KEY": os.getenv("AI_FUZZER_KEY"),
        "NEURAL_RECON_KEY": os.getenv("NEURAL_RECON_KEY"),
        "AI_SECURITY_API_KEY": os.getenv("AI_SECURITY_API_KEY")
    }
    
    # Print the keys (masked)
    logger.info("API Keys from .env file:")
    for key_name, key_value in keys.items():
        logger.info(f"  {key_name}: {mask_api_key(key_value)}")
    
    return keys

def load_config_keys():
    """Load API keys from unified_config.json"""
    logger.info("Loading API keys from unified_config.json...")
    
    # Check if config file exists
    if not os.path.exists("unified_config.json"):
        logger.warning("unified_config.json file not found")
        return {}
    
    try:
        with open("unified_config.json", "r") as f:
            config = json.load(f)
        
        keys = {}
        if "ai_analysis" in config and "api_keys" in config["ai_analysis"]:
            keys = {
                "openai": config["ai_analysis"]["api_keys"].get("openai"),
                "anthropic": config["ai_analysis"]["api_keys"].get("anthropic"),
                "gemini": config["ai_analysis"]["api_keys"].get("gemini"),
                "owasp_ai_scanner": config["ai_analysis"]["api_keys"].get("owasp_ai_scanner"),
                "arachni_ai": config["ai_analysis"]["api_keys"].get("arachni_ai"),
                "deep_exploit": config["ai_analysis"]["api_keys"].get("deep_exploit"),
                "seclists_ai": config["ai_analysis"]["api_keys"].get("seclists_ai"),
                "ai_fuzzer": config["ai_analysis"]["api_keys"].get("ai_fuzzer"),
                "neural_recon": config["ai_analysis"]["api_keys"].get("neural_recon"),
                "ai_security": config["ai_analysis"]["api_keys"].get("ai_security")
            }
        
        # Print the keys (masked)
        logger.info("API Keys from unified_config.json:")
        for key_name, key_value in keys.items():
            logger.info(f"  {key_name}: {mask_api_key(key_value)}")
        
        return keys
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing unified_config.json: Invalid JSON format - {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Error loading unified_config.json: {str(e)}")
        return {}

def verify_keys(env_keys, config_keys):
    """Verify API keys are properly configured"""
    logger.info("Verifying API keys configuration...")
    
    all_valid = True
    
    # Core AI model keys
    core_keys = [
        ("OpenAI", env_keys.get("OPENAI_API_KEY"), config_keys.get("openai")),
        ("Anthropic", env_keys.get("ANTHROPIC_API_KEY"), config_keys.get("anthropic")),
        ("Google Gemini", env_keys.get("GEMINI_API_KEY"), config_keys.get("gemini"))
    ]
    
    logger.info("=== Core AI Model Keys ===")
    for name, env_key, config_key in core_keys:
        env_status = "✓ Set" if env_key else "✗ Missing"
        config_status = "✓ Set" if config_key else "✗ Missing"
        
        # Check for placeholder values
        if env_key and env_key.startswith("YOUR_"):
            env_status = "✗ Placeholder"
            all_valid = False
        
        if config_key and config_key.startswith("YOUR_"):
            config_status = "✗ Placeholder"
            all_valid = False
            
        match = "✓ Match" if env_key and config_key and env_key == config_key else "✗ Mismatch"
        
        logger.info(f"{name}: .env: {env_status} | config: {config_status} | {match}")
        
        if not env_key or not config_key or env_key != config_key:
            all_valid = False
    
    # Specialized security tool keys
    sec_keys = [
        ("OWASP AI Scanner", env_keys.get("OWASP_AI_SCANNER_KEY"), config_keys.get("owasp_ai_scanner")),
        ("Arachni AI", env_keys.get("ARACHNI_AI_KEY"), config_keys.get("arachni_ai")),
        ("Deep Exploit", env_keys.get("DEEP_EXPLOIT_KEY"), config_keys.get("deep_exploit")),
        ("SecLists AI", env_keys.get("SECLISTS_AI_KEY"), config_keys.get("seclists_ai")),
        ("AI Fuzzer", env_keys.get("AI_FUZZER_KEY"), config_keys.get("ai_fuzzer")),
        ("Neural Recon", env_keys.get("NEURAL_RECON_KEY"), config_keys.get("neural_recon")),
        ("AI Security", env_keys.get("AI_SECURITY_API_KEY"), config_keys.get("ai_security"))
    ]
    
    logger.info("=== Security Tool Keys ===")
    for name, env_key, config_key in sec_keys:
        env_status = "✓ Set" if env_key else "✗ Missing"
        config_status = "✓ Set" if config_key else "✗ Missing"
        
        # Check for placeholder values
        if env_key and env_key.startswith("YOUR_"):
            env_status = "✗ Placeholder"
            all_valid = False
        
        if config_key and config_key.startswith("YOUR_"):
            config_status = "✗ Placeholder"
            all_valid = False
            
        match = "✓ Match" if env_key and config_key and env_key == config_key else "✗ Mismatch"
        
        logger.info(f"{name}: .env: {env_status} | config: {config_status} | {match}")
        
        if not env_key or not config_key or env_key != config_key:
            all_valid = False
    
    logger.info("=== Overall Configuration ===")
    if all_valid:
        logger.info("✅ All API keys are properly configured and match between .env and unified_config.json")
    else:
        logger.warning("❌ Some API keys are missing, placeholder, or mismatched. Please check the configuration files.")
    
    return all_valid

def create_env_file_if_missing():
    """Create .env file from template if it doesn't exist"""
    if not os.path.exists(".env") and os.path.exists(".env.template"):
        try:
            logger.info("Creating .env file from .env.template")
            with open(".env.template", "r") as template:
                content = template.read()
            
            with open(".env", "w") as env_file:
                env_file.write(content)
                
            logger.info("Created .env file. Please edit it to add your API keys.")
            return True
        except Exception as e:
            logger.error(f"Error creating .env file: {str(e)}")
            return False
    return False

def main():
    """Main function"""
    logger.info("API Keys Verification Tool")
    
    # Create .env file if missing
    if not os.path.exists(".env"):
        if create_env_file_if_missing():
            logger.info("Please edit the .env file with your API keys and run this script again.")
            return False
        else:
            logger.error("Error: .env file not found. Please create it first.")
            return False
    
    # Check if unified_config.json exists
    if not os.path.exists("unified_config.json"):
        logger.error("Error: unified_config.json file not found.")
        return False
    
    # Load keys from both sources
    env_keys = load_env_keys()
    config_keys = load_config_keys()
    
    # Verify keys
    return verify_keys(env_keys, config_keys)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 