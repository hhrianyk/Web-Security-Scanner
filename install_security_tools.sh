#!/bin/bash

echo "Security Tools Installation Script"
echo "================================="

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed or not in the PATH"
    echo "Please install Python 3.8 or higher and try again"
    exit 1
fi

# Check pip installation
if ! command -v pip3 &> /dev/null; then
    echo "pip3 is not installed or not in the PATH"
    echo "Please install pip3 and try again"
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r new_requirements_security_tools.txt
if [ $? -ne 0 ]; then
    echo "Failed to install Python dependencies"
    exit 1
fi

# Create tools directory
echo "Creating tools directory..."
mkdir -p ~/.security_tools

# Install security tools
echo "Installing security tools..."
python3 integrate_security_tools.py --install-all

echo ""
echo "Installation complete!"
echo "Run 'python3 integrate_security_tools.py --test' to verify the installation"
echo "Run 'python3 integrate_security_tools.py --list' to see available tools" 