#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from create_logo import create_security_logo
from security_improvements import generate_security_report

def main():
    print("Generating security improvement report...")
    
    # First, create the logo
    try:
        create_security_logo()
        print("Logo generated successfully.")
    except Exception as e:
        print(f"Error generating logo: {str(e)}")
        print("Continuing without logo...")
    
    # Generate the report
    try:
        report_path = generate_security_report()
        print(f"Report generated successfully: {report_path}")
        print(f"Full path: {os.path.abspath(report_path)}")
    except Exception as e:
        print(f"Error generating report: {str(e)}")

if __name__ == "__main__":
    main() 