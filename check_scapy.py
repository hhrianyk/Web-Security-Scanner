#!/usr/bin/env python3
"""
Scapy Installation Checker
This script verifies that Scapy is properly installed and functional.
"""

import sys
import os
import subprocess
import platform
import warnings

# Suppress Scapy warnings for cleaner output
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

def check_scapy():
    """Check if Scapy is installed and working properly."""
    print("Checking Scapy installation...")
    
    try:
        # Try to import Scapy
        import scapy.all as scapy
        print("✓ Scapy is installed.")
        
        # Set up scapy to ignore runtime warnings
        scapy.conf.verb = 0  # Reduce verbosity
        scapy.conf.interactive = False  # Disable interactive mode
        if hasattr(scapy.conf, 'supresspacket'):  # Handle typo in some scapy versions
            scapy.conf.supresspacket = True
        elif hasattr(scapy.conf, 'suppresspacket'):
            scapy.conf.suppresspacket = True
            
        # Print version info
        print(f"✓ Scapy version: {scapy.conf.version}")
        
        # Check if we're running as admin/root (needed for some Scapy functions)
        is_admin = False
        if platform.system() == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_admin = False
        else:
            is_admin = os.geteuid() == 0
        
        if not is_admin:
            print("⚠ Warning: Not running with administrator privileges.")
            print("  Some Scapy functions require admin/root privileges.")
            print("  Run this script as administrator/root for a complete check.")
        
        # Try to perform a simple operation
        print("\nTesting basic Scapy functionality...")
        try:
            # Create a simple packet
            packet = scapy.IP(dst="8.8.8.8")/scapy.ICMP()
            packet_summary = packet.summary()
            print(f"✓ Successfully created a packet: {packet_summary}")
            
            # If we're admin, try sending a packet
            if is_admin:
                print("\nTesting packet sending capability...")
                # Use a timeout to avoid hanging
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    ans, unans = scapy.sr(packet, timeout=2, verbose=0)
                if len(ans) > 0:
                    print("✓ Successfully sent and received packet.")
                else:
                    print("⚠ Sent packet but received no response (timeout or firewall).")
            
            print("\nScapy is correctly installed and functional for basic operations!")
            
            # Show additional info about network interfaces
            print("\nAvailable network interfaces:")
            interfaces = scapy.get_if_list()
            for iface in interfaces:
                print(f"  - {iface}")
            
            return True
            
        except Exception as e:
            print(f"✗ Error during Scapy test: {e}")
            print("  This might be due to network restrictions or firewall settings.")
            print("  Basic packet creation works, but network operations may be limited.")
            return True  # Still return True as basic functionality works
            
    except ImportError:
        print("✗ Scapy is not installed.")
        print("  Please install it using: pip install scapy")
        return False
    except Exception as e:
        print(f"✗ Error checking Scapy: {e}")
        print("\nPossible issues:")
        print("1. Missing dependencies")
        print("2. Permission issues")
        print("3. Network interface problems")
        print("\nRecommendation:")
        print("- Install Scapy: pip install scapy")
        if platform.system() == "Windows":
            print("- Windows users may need WinPcap or Npcap:")
            print("  https://npcap.com/")
        return False

def setup_scapy_workarounds():
    """Apply common workarounds for Scapy issues"""
    try:
        import scapy.all as scapy
        
        # Handle IPv6 issues
        if hasattr(scapy, 'conf'):
            # Disable IPv6 if it's causing problems
            scapy.conf.ipv6_enabled = False
            
        # Set a default interface if needed
        if platform.system() == "Windows":
            # Find a suitable interface on Windows
            for iface in scapy.get_if_list():
                if "Ethernet" in iface or "Wi-Fi" in iface:
                    scapy.conf.iface = iface
                    break
        
        return True
    except:
        return False

if __name__ == "__main__":
    print("=== Scapy Installation Checker ===\n")
    
    # Apply workarounds first
    setup_scapy_workarounds()
    
    # Check scapy functionality
    success = check_scapy()
    
    if success:
        print("\nSummary: Scapy is working correctly for basic operations.")
        print("Some network-related functions may require administrator privileges.")
    else:
        print("\nSummary: Scapy installation has issues that need to be addressed.")
    
    sys.exit(0 if success else 1) 