#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NMAP Test Script
---------------
Simple script to test if Nmap is properly installed and working.
"""

import subprocess
import sys
import importlib.util

def test_nmap_binary():
    """Test if the Nmap binary is installed and working."""
    print("Проверка установки Nmap...")
    
    try:
        result = subprocess.run(["nmap", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            version = result.stdout.decode('utf-8', errors='ignore').strip().split('\n')[0]
            print(f"✅ Nmap установлен: {version}")
            return True
        else:
            print("❌ Nmap установлен, но возникла ошибка при проверке версии.")
            print(f"Ошибка: {result.stderr.decode('utf-8', errors='ignore')}")
            return False
    except FileNotFoundError:
        print("❌ Nmap не найден в системе.")
        print("Убедитесь, что Nmap установлен и добавлен в PATH.")
        print("Возможно, требуется перезагрузка компьютера после установки.")
        return False

def test_python_nmap():
    """Test if the python-nmap library is installed and working."""
    print("\nПроверка библиотеки python-nmap...")
    
    if importlib.util.find_spec("nmap") is not None:
        print("✅ Библиотека python-nmap установлена.")
        
        try:
            import nmap
            scanner = nmap.PortScanner()
            print("✅ Библиотека python-nmap работает корректно.")
            return True
        except Exception as e:
            print(f"❌ Ошибка при использовании библиотеки python-nmap: {str(e)}")
            return False
    else:
        print("❌ Библиотека python-nmap не установлена.")
        print("Установите её с помощью команды: pip install python-nmap")
        return False

def run_simple_scan():
    """Run a simple scan if Nmap is available."""
    if not test_nmap_binary():
        return
    
    print("\nЗапуск простого сканирования localhost...")
    
    try:
        # Scan only a few common ports to make it quick
        result = subprocess.run(
            ["nmap", "-F", "127.0.0.1"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        
        if result.returncode == 0:
            output = result.stdout.decode('utf-8', errors='ignore')
            print("\nРезультаты сканирования:")
            print("-" * 40)
            print(output)
            print("-" * 40)
            print("✅ Сканирование выполнено успешно!")
        else:
            print("❌ Ошибка при выполнении сканирования.")
            print(f"Ошибка: {result.stderr.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"❌ Исключение при выполнении сканирования: {str(e)}")

def main():
    print("=" * 50)
    print("Тестирование установки Nmap")
    print("=" * 50)
    
    nmap_ok = test_nmap_binary()
    python_nmap_ok = test_python_nmap()
    
    if nmap_ok:
        run_simple_scan()
    
    print("\nИтоги тестирования:")
    print("-" * 20)
    print(f"Nmap: {'✅ Установлен' if nmap_ok else '❌ Не установлен или не работает'}")
    print(f"python-nmap: {'✅ Установлен' if python_nmap_ok else '❌ Не установлен или не работает'}")
    
    if not nmap_ok:
        print("\nРекомендации:")
        print("1. Перезагрузите компьютер после установки Nmap")
        print("2. Убедитесь, что Nmap добавлен в PATH")
        print("3. Попробуйте переустановить Nmap с помощью install_nmap.bat")
    
    input("\nНажмите Enter для выхода...")

if __name__ == "__main__":
    main() 