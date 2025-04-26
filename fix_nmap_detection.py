#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NMAP Detection Fix Script
-----------------------
This script ensures that Nmap is properly detected by the unified security interface.
It modifies the check_installation method in the NmapScanner class to improve detection.
"""

import os
import sys
import re
import subprocess
import shutil
from pathlib import Path
import platform

def backup_file(file_path):
    """Create a backup of the original file."""
    backup_path = f"{file_path}.bak"
    try:
        shutil.copy2(file_path, backup_path)
        print(f"Создана резервная копия файла: {backup_path}")
        return True
    except Exception as e:
        print(f"Ошибка при создании резервной копии: {str(e)}")
        return False

def modify_security_tools_integration():
    """Modify the security_tools_integration.py file to improve Nmap detection."""
    file_path = "security_tools_integration.py"
    
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден!")
        return False
    
    # Backup the original file
    if not backup_file(file_path):
        return False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Define the pattern to find the check_installation method in NmapScanner class
        nmap_check_pattern = r'def check_installation\(self\):\s+"""Check if Nmap is installed"""\s+return self\.nmap_path is not None'
        
        # Define the improved check_installation method
        improved_check = '''def check_installation(self):
        """Check if Nmap is installed"""
        # First check if nmap_path is already set
        if self.nmap_path:
            return True
            
        # Try to find nmap in PATH
        self.nmap_path = shutil.which("nmap")
        if self.nmap_path:
            return True
            
        # Check common installation directories on Windows
        if platform.system().lower() == "windows":
            common_paths = [
                "C:\\\\Program Files\\\\Nmap\\\\nmap.exe",
                "C:\\\\Program Files (x86)\\\\Nmap\\\\nmap.exe",
                os.path.join(os.environ.get("ProgramFiles", "C:\\\\Program Files"), "Nmap", "nmap.exe"),
                os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\\\Program Files (x86)"), "Nmap", "nmap.exe")
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    self.nmap_path = path
                    return True
        
        return False'''
        
        # Replace the check_installation method with the improved version
        modified_content = re.sub(nmap_check_pattern, improved_check, content)
        
        # Check if the content was actually modified
        if modified_content == content:
            print("Не удалось найти метод check_installation в классе NmapScanner для замены.")
            print("Попробуем найти класс NmapScanner и добавить улучшенный метод.")
            
            # Try to find the NmapScanner class
            nmap_class_pattern = r'class NmapScanner\(SecurityToolBase\):'
            if re.search(nmap_class_pattern, content):
                print("Класс NmapScanner найден. Попытка добавления улучшенного метода check_installation.")
                
                # Find the proper position to insert the improved check_installation method
                class_match = re.search(nmap_class_pattern, content)
                if class_match:
                    class_pos = class_match.end()
                    
                    # Find the position after the class docstring
                    docstring_end = content.find('"""', class_pos + 10) + 3
                    if docstring_end > class_pos + 3:
                        # Insert the improved check_installation method
                        lines = content.splitlines()
                        indent = 4  # Assume 4 spaces indent
                        
                        # Find the next method in the class
                        next_method_pattern = r'\n\s+def\s+\w+\('
                        next_method_match = re.search(next_method_pattern, content[docstring_end:])
                        
                        if next_method_match:
                            next_method_pos = docstring_end + next_method_match.start()
                            
                            # Insert the improved check_installation method before the next method
                            indented_improved_check = "\n" + "\n".join(("    " + line) for line in improved_check.splitlines())
                            modified_content = content[:next_method_pos] + indented_improved_check + content[next_method_pos:]
                            print("Улучшенный метод check_installation добавлен в класс NmapScanner.")
                        else:
                            print("Не удалось найти подходящее место для вставки метода check_installation.")
                            return False
                    else:
                        print("Не удалось найти конец docstring в классе NmapScanner.")
                        return False
                else:
                    print("Не удалось определить позицию для вставки метода check_installation.")
                    return False
            else:
                print("Класс NmapScanner не найден в файле security_tools_integration.py")
                return False
        
        # Write the modified content back to the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(modified_content)
        
        print(f"Файл {file_path} успешно модифицирован для улучшения обнаружения Nmap!")
        return True
    
    except Exception as e:
        print(f"Ошибка при модификации файла: {str(e)}")
        return False

def test_nmap_installed():
    """Test if Nmap is installed."""
    try:
        nmap_path = shutil.which("nmap")
        if nmap_path:
            # Nmap in PATH
            result = subprocess.run(["nmap", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                version = result.stdout.decode('utf-8', errors='ignore').strip().split('\n')[0]
                print(f"✅ Nmap найден в PATH: {nmap_path}")
                print(f"   Версия: {version}")
                return True, nmap_path, version
        
        # Check common installation directories on Windows
        if platform.system().lower() == "windows":
            common_paths = [
                "C:\\Program Files\\Nmap\\nmap.exe",
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Nmap", "nmap.exe"),
                os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Nmap", "nmap.exe")
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    result = subprocess.run([path, "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if result.returncode == 0:
                        version = result.stdout.decode('utf-8', errors='ignore').strip().split('\n')[0]
                        print(f"✅ Nmap найден по пути: {path}")
                        print(f"   Версия: {version}")
                        return True, path, version
        
        print("❌ Nmap не найден в системе.")
        return False, None, None
    
    except Exception as e:
        print(f"❌ Ошибка при проверке Nmap: {str(e)}")
        return False, None, None

def add_nmap_to_path():
    """Add Nmap to the system PATH."""
    if platform.system().lower() != "windows":
        print("Автоматическое добавление в PATH поддерживается только для Windows.")
        return False
    
    # Try to find the Nmap installation directory
    common_dirs = [
        "C:\\Program Files\\Nmap",
        "C:\\Program Files (x86)\\Nmap",
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Nmap"),
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Nmap")
    ]
    
    nmap_dir = None
    for directory in common_dirs:
        if os.path.exists(os.path.join(directory, "nmap.exe")):
            nmap_dir = directory
            break
    
    if not nmap_dir:
        print("❌ Не удалось найти директорию установки Nmap.")
        return False
    
    # Create a batch script to add Nmap to PATH temporarily and permanently
    try:
        with open("add_nmap_to_path.bat", "w") as f:
            f.write(f"""@echo off
echo Adding Nmap to PATH temporarily for this session...
set PATH=%PATH%;{nmap_dir}
echo.

echo Adding Nmap to PATH permanently...
setx PATH "%PATH%;{nmap_dir}" /M
echo.

echo PATH updated. Changes will be fully applied after system restart.
echo You can test if Nmap is in PATH by running: nmap -V
echo.
pause
""")
        
        print(f"✅ Создан файл add_nmap_to_path.bat для добавления Nmap в PATH.")
        print(f"   Путь Nmap для добавления: {nmap_dir}")
        
        # Ask if user wants to run the batch file
        print("\nХотите запустить add_nmap_to_path.bat сейчас? (д/н)")
        choice = input().lower()
        if choice.startswith('д'):
            subprocess.run(["cmd.exe", "/c", "add_nmap_to_path.bat"])
            return True
        else:
            print("Вы можете запустить add_nmap_to_path.bat позже для добавления Nmap в PATH.")
            return True
    
    except Exception as e:
        print(f"❌ Ошибка при создании batch файла: {str(e)}")
        return False

def main():
    print("=" * 60)
    print("NMAP Detection Fix для Unified Security Interface")
    print("=" * 60)
    print("Этот скрипт исправляет обнаружение Nmap в системе безопасности.")
    print()
    
    # Test if Nmap is installed
    nmap_installed, nmap_path, nmap_version = test_nmap_installed()
    
    if not nmap_installed:
        print("\nNmap не обнаружен в системе. Чтобы установить Nmap:")
        print("1. Запустите install_nmap.bat или install_and_test_nmap.bat")
        print("2. После установки может потребоваться перезагрузка компьютера")
        print("3. Запустите этот скрипт снова после установки Nmap")
        
        print("\nХотите запустить установщик Nmap сейчас? (д/н)")
        choice = input().lower()
        if choice.startswith('д'):
            if os.path.exists("install_and_test_nmap.bat"):
                subprocess.run(["cmd.exe", "/c", "install_and_test_nmap.bat"])
            elif os.path.exists("install_nmap.bat"):
                subprocess.run(["cmd.exe", "/c", "install_nmap.bat"])
            else:
                print("Файлы установщика не найдены. Пожалуйста, скачайте Nmap с https://nmap.org/download.html")
        
        print("\nЗапустите этот скрипт снова после установки Nmap.")
        input("Нажмите Enter для выхода...")
        return
    
    # If Nmap is installed but not in PATH, offer to add it
    if nmap_installed and nmap_path and not shutil.which("nmap"):
        print("\nNmap установлен, но не найден в PATH системы.")
        print("Для правильной работы с unified_security_interface.py, рекомендуется добавить Nmap в PATH.")
        
        add_to_path = input("Хотите добавить Nmap в PATH? (д/н): ").lower()
        if add_to_path.startswith('д'):
            add_nmap_to_path()
    
    # Modify security_tools_integration.py to improve Nmap detection
    print("\nИсправление обнаружения Nmap в файле security_tools_integration.py...")
    if os.path.exists("security_tools_integration.py"):
        if modify_security_tools_integration():
            print("✅ Успешно исправлен метод обнаружения Nmap!")
        else:
            print("❌ Не удалось исправить метод обнаружения Nmap.")
    else:
        print("❌ Файл security_tools_integration.py не найден.")
    
    print("\nРабота скрипта завершена.")
    print("После перезагрузки компьютера убедитесь, что Nmap корректно обнаруживается системой.")
    print("Для проверки запустите: python test_nmap.py")
    
    input("\nНажмите Enter для выхода...")

if __name__ == "__main__":
    main() 