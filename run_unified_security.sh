#!/bin/bash

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=================================="
echo "Unified Security Assessment System"
echo -e "==================================${NC}"
echo ""

# Check for Python installation
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed or not in the PATH."
    echo -e "Please install Python 3.7 or higher and try again.${NC}"
    exit 1
fi

# Check for the unified security tools file
if [ ! -f "unified_security_tools.py" ]; then
    echo -e "${RED}unified_security_tools.py not found."
    echo -e "Make sure you are running this script from the correct directory.${NC}"
    exit 1
fi

# Make the script executable if it's not
if [ ! -x "unified_security_tools.py" ]; then
    chmod +x unified_security_tools.py
fi

show_menu() {
    echo -e "${YELLOW}What would you like to do?${NC}"
    echo ""
    echo "1. Run a comprehensive security assessment"
    echo "2. Run a quick security assessment"
    echo "3. Start the web interface"
    echo "4. Check environment setup"
    echo "5. Setup the environment"
    echo "6. List available tools"
    echo "7. List available workflows"
    echo "8. Check running assessments"
    echo "9. Exit"
    echo ""
}

run_comprehensive() {
    echo -e "${YELLOW}Enter target URL or IP address:${NC} "
    read target
    echo ""
    echo -e "${GREEN}Running comprehensive security assessment on $target...${NC}"
    python3 unified_security_tools.py "$target" --type full
    echo ""
    echo -e "${GREEN}Assessment complete.${NC}"
    echo ""
    read -p "Press Enter to continue..."
}

run_quick() {
    echo -e "${YELLOW}Enter target URL or IP address:${NC} "
    read target
    echo ""
    echo -e "${GREEN}Running quick security assessment on $target...${NC}"
    python3 unified_security_tools.py "$target" --type quick
    echo ""
    echo -e "${GREEN}Assessment complete.${NC}"
    echo ""
    read -p "Press Enter to continue..."
}

start_web_interface() {
    echo ""
    echo -e "${GREEN}Starting web interface...${NC}"
    # Run in background
    python3 unified_security_tools.py --start-web &
    WEB_PID=$!
    echo ""
    echo -e "${GREEN}Web interface started with PID: $WEB_PID${NC}"
    echo "Press Enter to return to the menu. The web interface will continue running."
    echo "To stop it later, use option 'Stop web interface' from the menu."
    echo ""
    read
}

check_env() {
    echo ""
    echo -e "${GREEN}Checking environment setup...${NC}"
    python3 unified_security_tools.py --check-env
    echo ""
    read -p "Press Enter to continue..."
}

setup_env() {
    echo ""
    echo -e "${GREEN}Setting up the environment...${NC}"
    python3 unified_security_tools.py --setup
    echo ""
    read -p "Press Enter to continue..."
}

list_tools() {
    echo ""
    echo -e "${GREEN}Listing available security tools...${NC}"
    python3 unified_security_tools.py --list-tools
    echo ""
    read -p "Press Enter to continue..."
}

list_workflows() {
    echo ""
    echo -e "${GREEN}Listing available workflows...${NC}"
    python3 unified_security_tools.py --list-workflows
    echo ""
    read -p "Press Enter to continue..."
}

check_assessments() {
    echo ""
    echo -e "${GREEN}Listing completed assessments...${NC}"
    python3 unified_security_tools.py --list-assessments
    echo ""
    echo -e "${YELLOW}Enter assessment ID to view details (or press Enter to go back):${NC} "
    read id
    if [ ! -z "$id" ]; then
        echo ""
        python3 unified_security_tools.py --show-assessment "$id"
        echo ""
    fi
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    clear
    echo -e "${BLUE}=================================="
    echo "Unified Security Assessment System"
    echo -e "==================================${NC}"
    echo ""
    show_menu
    read -p "Enter your choice (1-9): " choice
    
    case $choice in
        1) run_comprehensive ;;
        2) run_quick ;;
        3) start_web_interface ;;
        4) check_env ;;
        5) setup_env ;;
        6) list_tools ;;
        7) list_workflows ;;
        8) check_assessments ;;
        9) 
            echo ""
            echo -e "${GREEN}Exiting Unified Security Assessment System...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please try again.${NC}"
            read -p "Press Enter to continue..."
            ;;
    esac
done 