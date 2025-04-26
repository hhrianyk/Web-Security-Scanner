#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
import subprocess
import platform
import nmap
import ssl
import requests
import threading
import queue
import ipaddress
from scapy.all import ARP, Ether, srp
import time
import logging
import random
import json
import sys
import dns.resolver

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedNetworkScanner:
    """Расширенный модуль для сетевого сканирования и анализа"""
    
    def __init__(self, target_host=None, target_network=None):
        self.target_host = target_host
        self.target_network = target_network
        self.results = {
            "network_topology": {},
            "open_ports": {},
            "service_detection": {},
            "ssl_analysis": {},
            "network_devices": [],
            "route_analysis": {},
            "packets_analysis": {}
        }
        self.nm = nmap.PortScanner()
    
    def run_full_network_scan(self, target=None):
        """Выполнить полное сканирование сети"""
        if target:
            self.target_host = target
        
        if not self.target_host and not self.target_network:
            raise ValueError("Необходимо указать целевой хост или сеть")
        
        logger.info(f"Начало полного сетевого сканирования для {self.target_host or self.target_network}")
        
        # Запустить все сканирования параллельно для ускорения
        threads = []
        scan_functions = [
            self.scan_ports_and_services,
            self.analyze_ssl_configuration,
            self.discover_network_devices,
            self.analyze_network_routes,
            self.analyze_network_packets
        ]
        
        for func in scan_functions:
            thread = threading.Thread(target=func)
            thread.start()
            threads.append(thread)
        
        # Дожидаемся завершения всех потоков
        for thread in threads:
            thread.join()
            
        logger.info("Полное сетевое сканирование завершено")
        return self.results
    
    def scan_ports_and_services(self):
        """Расширенное сканирование портов с обнаружением сервисов"""
        logger.info("Сканирование портов и сервисов...")
        try:
            # Сканирование 1000 наиболее распространенных портов с обнаружением версий служб
            self.nm.scan(self.target_host, arguments='-sS -sV -O --top-ports 1000')
            
            open_ports = {}
            service_detection = {}
            
            for host in self.nm.all_hosts():
                open_ports[host] = []
                service_detection[host] = {}
                
                for proto in self.nm[host].all_protocols():
                    ports = sorted(self.nm[host][proto].keys())
                    
                    for port in ports:
                        service_info = self.nm[host][proto][port]
                        if service_info['state'] == 'open':
                            port_info = {
                                'port': port,
                                'protocol': proto,
                                'state': service_info['state']
                            }
                            open_ports[host].append(port_info)
                            
                            service_detection[host][port] = {
                                'name': service_info.get('name', 'unknown'),
                                'product': service_info.get('product', ''),
                                'version': service_info.get('version', ''),
                                'extrainfo': service_info.get('extrainfo', '')
                            }
                
                # Определение ОС, если возможно
                if 'osmatch' in self.nm[host]:
                    service_detection[host]['os_detection'] = []
                    for os_match in self.nm[host]['osmatch']:
                        service_detection[host]['os_detection'].append({
                            'name': os_match.get('name', ''),
                            'accuracy': os_match.get('accuracy', '')
                        })
            
            self.results["open_ports"] = open_ports
            self.results["service_detection"] = service_detection
            logger.info(f"Обнаружено {sum(len(ports) for host, ports in open_ports.items())} открытых портов")
            
        except Exception as e:
            logger.error(f"Ошибка при сканировании портов: {str(e)}")
            self.results["scan_error"] = str(e)
    
    def analyze_ssl_configuration(self):
        """Анализ SSL/TLS конфигурации для обнаружения уязвимостей"""
        logger.info("Анализ SSL/TLS конфигурации...")
        try:
            if not self.target_host:
                logger.warning("Хост не указан, SSL/TLS анализ пропущен")
                return
                
            ssl_info = {}
            
            # Проверяем поддержку различных протоколов
            protocols = [
                ssl.PROTOCOL_TLSv1,
                ssl.PROTOCOL_TLSv1_1,
                ssl.PROTOCOL_TLSv1_2,
                ssl.PROTOCOL_TLSv1_3
            ]
            protocol_names = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
            
            supported_protocols = {}
            for i, protocol in enumerate(protocols):
                try:
                    context = ssl.SSLContext(protocol)
                    with socket.create_connection((self.target_host, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                            supported_protocols[protocol_names[i]] = True
                            # Получаем информацию о сертификате
                            if i == len(protocols) - 1:  # Берем сертификат только для последнего успешного протокола
                                cert = ssock.getpeercert()
                                ssl_info['certificate'] = {
                                    'subject': dict(x[0] for x in cert['subject']),
                                    'issuer': dict(x[0] for x in cert['issuer']),
                                    'version': cert['version'],
                                    'notBefore': cert['notBefore'],
                                    'notAfter': cert['notAfter'],
                                    'serialNumber': cert.get('serialNumber', ''),
                                }
                                ssl_info['cipher'] = ssock.cipher()
                except:
                    supported_protocols[protocol_names[i]] = False
            
            ssl_info['supported_protocols'] = supported_protocols
            
            # Проверяем уязвимости
            vulnerabilities = []
            
            # Проверка на старые уязвимые протоколы
            if supported_protocols.get('TLSv1', False) or supported_protocols.get('TLSv1.1', False):
                vulnerabilities.append({
                    'name': 'Outdated TLS Protocol',
                    'description': 'Поддержка устаревших протоколов TLSv1.0 или TLSv1.1, которые имеют известные уязвимости',
                    'severity': 'Medium',
                    'remediation': 'Отключить поддержку TLSv1.0 и TLSv1.1, оставив только TLSv1.2 и выше'
                })
            
            ssl_info['vulnerabilities'] = vulnerabilities
            self.results["ssl_analysis"] = ssl_info
            
            logger.info(f"Анализ SSL/TLS завершен, обнаружено {len(vulnerabilities)} уязвимостей")
            
        except Exception as e:
            logger.error(f"Ошибка при анализе SSL/TLS: {str(e)}")
            self.results["ssl_analysis"] = {"error": str(e)}
    
    def discover_network_devices(self):
        """Обнаружение сетевых устройств"""
        logger.info("Обнаружение сетевых устройств...")
        try:
            if not self.target_network:
                # Если сеть не указана явно, попробуем определить локальную сеть
                if self.target_host:
                    ip = socket.gethostbyname(self.target_host)
                    # Предполагаем, что маска /24
                    network = '.'.join(ip.split('.')[:3]) + '.0/24'
                    self.target_network = network
                else:
                    logger.warning("Сеть не указана, обнаружение устройств пропущено")
                    return
            
            devices = []
            
            # Используем ARP-запросы для обнаружения устройств
            try:
                network = ipaddress.ip_network(self.target_network, strict=False)
                arp = ARP(pdst=str(network))
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                result = srp(packet, timeout=3, verbose=0)[0]
                
                for sent, received in result:
                    devices.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc
                    })
            except:
                logger.warning("Невозможно выполнить ARP-сканирование, используем альтернативный метод")
                # Альтернативный метод - сканирование nmap
                self.nm.scan(hosts=self.target_network, arguments='-sn')
                for host in self.nm.all_hosts():
                    if 'mac' in self.nm[host]['addresses']:
                        devices.append({
                            'ip': host,
                            'mac': self.nm[host]['addresses']['mac']
                        })
                    else:
                        devices.append({
                            'ip': host,
                            'mac': 'Unknown'
                        })
            
            # Определение типа устройства по MAC
            for device in devices:
                if device['mac'] != 'Unknown':
                    # Упрощенная проверка по первым байтам MAC
                    mac_prefix = device['mac'].replace(':', '').replace('-', '').lower()[:6]
                    # Это очень упрощенно, в реальности нужна база данных OUI
                    vendor_prefixes = {
                        '000c29': 'VMware',
                        '001c42': 'Parallels',
                        '0026bb': 'Apple',
                        '001801': 'Hewlett-Packard',
                        'ac7a4d': 'Cisco',
                        '7c8274': 'Cisco Meraki'
                    }
                    device['vendor'] = vendor_prefixes.get(mac_prefix, 'Unknown')
                    
                    # Пытаемся определить тип устройства по открытым портам
                    try:
                        device_scanner = nmap.PortScanner()
                        device_scanner.scan(device['ip'], '22,23,80,443,8080,8443')
                        
                        if device['ip'] in device_scanner.all_hosts():
                            open_ports = []
                            for proto in device_scanner[device['ip']].all_protocols():
                                ports = device_scanner[device['ip']][proto].keys()
                                for port in ports:
                                    if device_scanner[device['ip']][proto][port]['state'] == 'open':
                                        open_ports.append(port)
                            
                            device['open_ports'] = open_ports
                            
                            # Простая эвристика для определения типа устройства
                            if 23 in open_ports:
                                device['device_type'] = 'Network Device (Telnet enabled)'
                            elif 22 in open_ports and 80 in open_ports:
                                device['device_type'] = 'Network Device or Server'
                            elif 80 in open_ports or 443 in open_ports:
                                device['device_type'] = 'Web Server/Device'
                            else:
                                device['device_type'] = 'Unknown'
                    except:
                        device['device_type'] = 'Could not determine'
                
            self.results["network_devices"] = devices
            logger.info(f"Обнаружено {len(devices)} сетевых устройств")
            
        except Exception as e:
            logger.error(f"Ошибка при обнаружении сетевых устройств: {str(e)}")
            self.results["network_devices"] = {"error": str(e)}
    
    def analyze_network_routes(self):
        """Анализ сетевых маршрутов"""
        logger.info("Анализ сетевых маршрутов...")
        try:
            route_analysis = {}
            
            if not self.target_host:
                logger.warning("Хост не указан, анализ маршрутов пропущен")
                return
                
            # Traceroute для анализа маршрута к цели
            if platform.system().lower() == 'windows':
                # Windows
                process = subprocess.Popen(['tracert', '-d', '-w', '1000', self.target_host], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, error = process.communicate()
                
                route_analysis['traceroute'] = []
                for line in output.split('\n'):
                    # Парсинг вывода tracert
                    if line.strip() and line[0].isdigit():
                        parts = line.strip().split()
                        hop = parts[0].replace('.', '')
                        # Извлекаем IP-адреса из строки
                        ips = []
                        for part in parts[1:]:
                            if part[0].isdigit() and '.' in part:
                                ips.append(part)
                        
                        if ips:
                            route_analysis['traceroute'].append({
                                'hop': hop,
                                'ip': ips[0] if ips else 'Request timed out',
                                'time_ms': parts[-1] if parts[-1] != 'out' else 'Timeout'
                            })
            else:
                # Linux/Mac
                process = subprocess.Popen(['traceroute', '-n', '-w', '1', self.target_host], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, error = process.communicate()
                
                route_analysis['traceroute'] = []
                for line in output.split('\n')[1:]:  # Пропускаем заголовок
                    if line.strip():
                        parts = line.strip().split()
                        hop = parts[0].replace(':', '')
                        
                        # Извлекаем IP и время
                        ip = parts[1] if parts[1] != '*' else 'Request timed out'
                        time_ms = parts[2].replace('ms', '') if len(parts) > 2 and parts[2] != '*' else 'Timeout'
                        
                        route_analysis['traceroute'].append({
                            'hop': hop,
                            'ip': ip,
                            'time_ms': time_ms
                        })
            
            # Определение "необычных" маршрутов
            suspicious_hops = []
            for i, hop in enumerate(route_analysis.get('traceroute', [])):
                if hop['ip'] != 'Request timed out':
                    # Проверка на географическую аномалию требует внешней базы GeoIP
                    # Здесь просто помечаем "интересные" IP
                    if '10.' not in hop['ip'] and '192.168.' not in hop['ip'] and '172.' not in hop['ip']:
                        if i > 0 and i < len(route_analysis.get('traceroute', [])) - 1:
                            suspicious_hops.append(hop)
            
            route_analysis['suspicious_hops'] = suspicious_hops
            self.results["route_analysis"] = route_analysis
            
            logger.info(f"Анализ маршрутов завершен, обнаружено {len(route_analysis.get('traceroute', []))} хопов")
            
        except Exception as e:
            logger.error(f"Ошибка при анализе маршрутов: {str(e)}")
            self.results["route_analysis"] = {"error": str(e)}
    
    def analyze_network_packets(self, packet_count=100, timeout=30):
        """Анализ сетевых пакетов для обнаружения аномалий"""
        logger.info("Анализ сетевых пакетов...")
        try:
            # В демонстрационных целях просто выполним пинг и проанализируем задержки
            packet_analysis = {
                'packet_capture': 'disabled',  # Для реальной реализации нужно использовать libpcap/tcpdump/wireshark
                'ping_analysis': {}
            }
            
            if not self.target_host:
                logger.warning("Хост не указан, анализ пакетов пропущен")
                return
                
            # Ping-анализ
            ping_times = []
            packet_loss = 0
            
            if platform.system().lower() == 'windows':
                count_param = '-n'
            else:
                count_param = '-c'
            
            process = subprocess.Popen(['ping', count_param, str(packet_count), self.target_host], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = process.communicate()
            
            for line in output.split('\n'):
                if 'time=' in line or 'время=' in line:
                    # Извлекаем значение времени
                    try:
                        time_str = line.split('time=')[1].split()[0].replace('ms', '').strip()
                        ping_times.append(float(time_str))
                    except:
                        try:
                            time_str = line.split('время=')[1].split()[0].replace('мс', '').strip()
                            ping_times.append(float(time_str))
                        except:
                            continue
                elif 'Request timed out' in line or 'превышен интервал' in line:
                    packet_loss += 1
            
            if ping_times:
                packet_analysis['ping_analysis'] = {
                    'min_time': min(ping_times),
                    'max_time': max(ping_times),
                    'avg_time': sum(ping_times) / len(ping_times),
                    'standard_deviation': (sum((x - (sum(ping_times) / len(ping_times))) ** 2 for x in ping_times) / len(ping_times)) ** 0.5,
                    'packet_loss_percent': (packet_loss / packet_count) * 100
                }
                
                # Анализ джиттера (нестабильности задержки)
                jitter = 0
                for i in range(1, len(ping_times)):
                    jitter += abs(ping_times[i] - ping_times[i-1])
                
                if len(ping_times) > 1:
                    packet_analysis['ping_analysis']['jitter'] = jitter / (len(ping_times) - 1)
                else:
                    packet_analysis['ping_analysis']['jitter'] = 0
                
                # Обнаружение аномалий
                anomalies = []
                avg_time = packet_analysis['ping_analysis']['avg_time']
                std_dev = packet_analysis['ping_analysis']['standard_deviation']
                
                # Помечаем задержки выше среднего + 2*стандартное отклонение как аномалии
                threshold = avg_time + 2 * std_dev
                for i, time in enumerate(ping_times):
                    if time > threshold:
                        anomalies.append({
                            'packet_number': i + 1,
                            'time': time,
                            'threshold': threshold,
                            'deviation_factor': (time - avg_time) / std_dev
                        })
                
                packet_analysis['ping_analysis']['anomalies'] = anomalies
                
                # Сетевая стабильность
                if packet_analysis['ping_analysis']['packet_loss_percent'] > 5:
                    packet_analysis['network_stability'] = 'Unstable (high packet loss)'
                elif packet_analysis['ping_analysis']['jitter'] > 10:
                    packet_analysis['network_stability'] = 'Unstable (high jitter)'
                elif std_dev > avg_time * 0.5:
                    packet_analysis['network_stability'] = 'Unstable (high variance)'
                else:
                    packet_analysis['network_stability'] = 'Stable'
            
            self.results["packets_analysis"] = packet_analysis
            
            logger.info(f"Анализ сетевых пакетов завершен")
            
        except Exception as e:
            logger.error(f"Ошибка при анализе пакетов: {str(e)}")
            self.results["packets_analysis"] = {"error": str(e)}

    def scan_network_topology(self):
        """Создание карты сетевой топологии"""
        logger.info("Анализ сетевой топологии...")
        try:
            if not self.target_network:
                logger.warning("Сеть не указана, анализ топологии пропущен")
                return
            
            # Для демонстрации создадим упрощенную топологию
            # В реальности нужны дополнительные инструменты и права
            topology = {
                'nodes': [],
                'connections': []
            }
            
            # Получаем устройства из предыдущего сканирования
            devices = self.results.get("network_devices", [])
            if not devices or 'error' in devices:
                logger.warning("Нет данных об устройствах, сканирование устройств...")
                self.discover_network_devices()
                devices = self.results.get("network_devices", [])
            
            # Добавляем узлы в топологию
            for i, device in enumerate(devices):
                if isinstance(device, dict) and 'ip' in device:
                    node = {
                        'id': i,
                        'ip': device['ip'],
                        'mac': device.get('mac', 'Unknown'),
                        'type': device.get('device_type', 'Unknown'),
                        'vendor': device.get('vendor', 'Unknown')
                    }
                    topology['nodes'].append(node)
            
            # Создаем простые связи для демонстрации
            # В реальности нужны трассировки между узлами
            for i in range(len(topology['nodes'])):
                for j in range(i+1, min(i+3, len(topology['nodes']))):
                    connection = {
                        'source': i,
                        'target': j,
                        'type': 'network',
                        'latency': round(10 + 30 * random.random(), 2)  # Случайная задержка для демонстрации
                    }
                    topology['connections'].append(connection)
            
            self.results["network_topology"] = topology
            logger.info(f"Анализ топологии завершен, обнаружено {len(topology['nodes'])} узлов")
            
        except Exception as e:
            logger.error(f"Ошибка при анализе топологии: {str(e)}")
            self.results["network_topology"] = {"error": str(e)}
            
# Дополнительные инструменты

def scan_wifi_networks():
    """Сканирование Wi-Fi сетей (требует административные права)"""
    wifi_networks = []
    
    try:
        if platform.system().lower() == 'windows':
            # Windows
            process = subprocess.Popen(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = process.communicate()
            
            current_network = {}
            for line in output.split('\n'):
                line = line.strip()
                if 'SSID' in line and ':' in line and 'BSSID' not in line:
                    if current_network:
                        wifi_networks.append(current_network)
                    current_network = {'ssid': line.split(':')[1].strip()}
                elif 'Authentication' in line and ':' in line:
                    current_network['authentication'] = line.split(':')[1].strip()
                elif 'Encryption' in line and ':' in line:
                    current_network['encryption'] = line.split(':')[1].strip()
                elif 'Signal' in line and ':' in line:
                    current_network['signal'] = line.split(':')[1].strip()
                elif 'BSSID' in line and ':' in line:
                    current_network['bssid'] = line.split(':')[1].strip()
                    
            if current_network:
                wifi_networks.append(current_network)
                
        elif platform.system().lower() == 'linux':
            # Linux с использованием iwlist
            process = subprocess.Popen(['sudo', 'iwlist', 'scanning'], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = process.communicate()
            
            current_network = {}
            for line in output.split('\n'):
                line = line.strip()
                if 'Cell' in line and 'Address' in line:
                    if current_network:
                        wifi_networks.append(current_network)
                    current_network = {'bssid': line.split('Address:')[1].strip()}
                elif 'ESSID' in line:
                    current_network['ssid'] = line.split(':')[1].strip().replace('"', '')
                elif 'Quality' in line:
                    current_network['signal'] = line.split('Signal level=')[1].split()[0] if 'Signal level=' in line else ''
                elif 'Encryption key' in line:
                    current_network['encryption'] = 'On' if 'on' in line.lower() else 'Off'
                elif 'IE: IEEE 802.11i/WPA2' in line:
                    current_network['authentication'] = 'WPA2'
                elif 'IE: WPA' in line:
                    current_network['authentication'] = 'WPA'
                    
            if current_network:
                wifi_networks.append(current_network)
    except Exception as e:
        logger.error(f"Ошибка при сканировании Wi-Fi: {str(e)}")
        return {"error": str(e)}
        
    # Анализ безопасности
    for network in wifi_networks:
        security_score = 0
        security_issues = []
        
        # Проверка шифрования
        if 'encryption' in network:
            if network['encryption'] == 'Off' or network['encryption'] == 'None':
                security_score = 0
                security_issues.append('Незашифрованная сеть')
            else:
                # Проверка метода аутентификации
                if 'authentication' in network:
                    if network['authentication'] == 'Open' or network['authentication'] == 'None':
                        security_score = 0
                        security_issues.append('Открытая аутентификация')
                    elif 'WEP' in network['authentication']:
                        security_score = 1
                        security_issues.append('Использует устаревшее шифрование WEP')
                    elif 'WPA' in network['authentication'] and 'WPA2' not in network['authentication'] and 'WPA3' not in network['authentication']:
                        security_score = 2
                        security_issues.append('Использует устаревшее шифрование WPA')
                    elif 'WPA2' in network['authentication']:
                        security_score = 4
                    elif 'WPA3' in network['authentication']:
                        security_score = 5
        
        network['security_score'] = security_score
        network['security_issues'] = security_issues
    
    return {
        "wifi_networks": wifi_networks,
        "vulnerable_networks": [net for net in wifi_networks if net.get('security_score', 5) < 3]
    }

def check_dns_security(domain):
    """Проверка безопасности DNS-конфигурации"""
    dns_security = {
        "domain": domain,
        "records": {},
        "issues": []
    }
    
    try:
        # Проверяем основные записи
        record_types = ['A', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_security["records"][record_type] = [str(rdata) for rdata in answers]
            except Exception:
                dns_security["records"][record_type] = []
        
        # Проверяем DNSSEC
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            dns_security["dnssec"] = True
        except Exception:
            dns_security["dnssec"] = False
            dns_security["issues"].append({
                "issue": "DNSSEC не настроен",
                "severity": "Medium",
                "description": "Отсутствие DNSSEC позволяет проводить DNS-спуфинг и атаки типа 'человек посередине'",
                "recommendation": "Настроить DNSSEC для защиты от подмены DNS-записей"
            })
        
        # Проверяем CAA-записи (Certificate Authority Authorization)
        try:
            answers = dns.resolver.resolve(domain, 'CAA')
            dns_security["caa_records"] = [str(rdata) for rdata in answers]
        except Exception:
            dns_security["caa_records"] = []
            dns_security["issues"].append({
                "issue": "CAA-записи отсутствуют",
                "severity": "Low",
                "description": "CAA-записи помогают контролировать, какие удостоверяющие центры могут выдавать сертификаты для вашего домена",
                "recommendation": "Настроить CAA-записи для контроля выдачи SSL/TLS-сертификатов"
            })
        
        # Проверяем SPF, DKIM, DMARC
        email_security = {
            "spf": False,
            "dmarc": False,
            "dkim": False
        }
        
        # SPF
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                if "v=spf1" in str(record):
                    email_security["spf"] = True
                    break
        except Exception:
            pass
        
        if not email_security["spf"]:
            dns_security["issues"].append({
                "issue": "SPF-запись отсутствует",
                "severity": "Medium",
                "description": "Отсутствие SPF-записи позволяет злоумышленникам подделывать электронные письма от вашего домена",
                "recommendation": "Настроить SPF-запись для защиты от подделки отправителя"
            })
        
        # DMARC
        try:
            dmarc_records = dns.resolver.resolve("_dmarc." + domain, 'TXT')
            for record in dmarc_records:
                if "v=DMARC1" in str(record):
                    email_security["dmarc"] = True
                    break
        except Exception:
            pass
        
        if not email_security["dmarc"]:
            dns_security["issues"].append({
                "issue": "DMARC-запись отсутствует",
                "severity": "Medium",
                "description": "Отсутствие DMARC снижает защиту от фишинга и спуфинга доменного имени",
                "recommendation": "Настроить DMARC-запись для улучшения фильтрации почты и получения отчетов"
            })
        
        # DKIM (проверка существования селектора, точный анализ требует знания селектора)
        try:
            dkim_records = dns.resolver.resolve("default._domainkey." + domain, 'TXT')
            email_security["dkim"] = True
        except Exception:
            try:
                dkim_records = dns.resolver.resolve("mail._domainkey." + domain, 'TXT')
                email_security["dkim"] = True
            except Exception:
                pass
        
        if not email_security["dkim"]:
            dns_security["issues"].append({
                "issue": "DKIM-запись не обнаружена",
                "severity": "Medium",
                "description": "Отсутствие DKIM снижает защиту от подделки электронной почты",
                "recommendation": "Настроить DKIM для цифровой подписи и аутентификации писем"
            })
            
        dns_security["email_security"] = email_security
        
    except Exception as e:
        dns_security["error"] = str(e)
    
    return dns_security

def scan_bluetooth_devices(duration=10):
    """Сканирование Bluetooth-устройств (требует соответствующее оборудование)"""
    # Это демонстрационная функция, реальное сканирование требует специальных библиотек
    # Например, PyBluez для Python
    
    demo_devices = [
        {"address": "00:11:22:33:44:55", "name": "Smartphone", "rssi": -65, "type": "Mobile"},
        {"address": "AA:BB:CC:DD:EE:FF", "name": "Bluetooth Speaker", "rssi": -70, "type": "Audio"},
        {"address": "11:22:33:44:55:66", "name": "Smartwatch", "rssi": -75, "type": "Wearable"}
    ]
    
    return {
        "bluetooth_devices": demo_devices,
        "scan_duration": duration
    }

class NetworkSecurityAnalyzer:
    """Комплексный анализатор сетевой безопасности"""
    
    def __init__(self):
        self.scanner = AdvancedNetworkScanner()
        self.results = {}
    
    def analyze_target(self, target_host, scan_network=False):
        """Выполнить полный анализ безопасности целевого хоста"""
        self.results = {
            "target": target_host,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "network_security": {},
            "dns_security": {},
            "ssl_security": {},
            "additional_services": {}
        }
        
        # Базовое сканирование сети
        if scan_network:
            logger.info(f"Запуск полного сетевого сканирования для {target_host}")
            try:
                # Определяем сеть, если нужно просканировать сеть
                ip = socket.gethostbyname(target_host)
                network = '.'.join(ip.split('.')[:3]) + '.0/24'
                self.scanner.target_network = network
            except:
                logger.warning("Не удалось определить сеть, сетевое сканирование будет пропущено")
        
        self.scanner.target_host = target_host
        network_results = self.scanner.run_full_network_scan()
        self.results["network_security"] = network_results
        
        # DNS-безопасность
        try:
            domain = target_host
            if target_host[0].isdigit():
                # Это IP-адрес, пытаемся выполнить обратный DNS-запрос
                domain = socket.gethostbyaddr(target_host)[0]
            
            dns_results = check_dns_security(domain)
            self.results["dns_security"] = dns_results
        except Exception as e:
            logger.error(f"Ошибка анализа DNS: {str(e)}")
            self.results["dns_security"] = {"error": str(e)}
        
        # Если в сети есть Wi-Fi, сканируем его
        if scan_network and platform.system().lower() in ['windows', 'linux']:
            try:
                wifi_results = scan_wifi_networks()
                self.results["additional_services"]["wifi"] = wifi_results
            except Exception as e:
                logger.error(f"Ошибка сканирования Wi-Fi: {str(e)}")
                self.results["additional_services"]["wifi"] = {"error": str(e)}
        
        # Демонстрационное сканирование Bluetooth
        try:
            bluetooth_results = scan_bluetooth_devices()
            self.results["additional_services"]["bluetooth"] = bluetooth_results
        except Exception as e:
            logger.error(f"Ошибка сканирования Bluetooth: {str(e)}")
            self.results["additional_services"]["bluetooth"] = {"error": str(e)}
        
        logger.info(f"Анализ безопасности для {target_host} завершен")
        return self.results
    
    def generate_security_report(self, output_file=None):
        """Генерация отчета по безопасности"""
        if not self.results:
            raise ValueError("Нет результатов для генерации отчета, сначала запустите analyze_target()")
        
        report = {
            "summary": {
                "target": self.results.get("target", "Unknown"),
                "timestamp": self.results.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                "vulnerabilities": [],
                "security_score": 0,
                "recommendations": []
            },
            "details": self.results
        }
        
        # Собираем все уязвимости
        vulnerabilities = []
        
        # Проверяем SSL-уязвимости
        ssl_analysis = self.results.get("network_security", {}).get("ssl_analysis", {})
        if ssl_analysis and "vulnerabilities" in ssl_analysis:
            vulnerabilities.extend(ssl_analysis["vulnerabilities"])
        
        # Проверяем DNS-уязвимости
        dns_security = self.results.get("dns_security", {})
        if dns_security and "issues" in dns_security:
            vulnerabilities.extend(dns_security["issues"])
        
        # Проверяем уязвимости Wi-Fi
        wifi_results = self.results.get("additional_services", {}).get("wifi", {})
        if wifi_results and "vulnerable_networks" in wifi_results:
            for network in wifi_results["vulnerable_networks"]:
                vulnerabilities.append({
                    "issue": f"Небезопасная Wi-Fi сеть: {network.get('ssid', 'Unknown')}",
                    "severity": "High" if network.get('security_score', 0) < 2 else "Medium",
                    "description": f"Сеть использует небезопасную конфигурацию: {', '.join(network.get('security_issues', ['Unknown']))}",
                    "recommendation": "Обновить настройки безопасности сети или избегать ее использования"
                })
        
        # Проверяем открытые порты
        open_ports = self.results.get("network_security", {}).get("open_ports", {})
        for host, ports in open_ports.items():
            for port_info in ports:
                port = port_info.get("port")
                if port in [21, 23, 25, 53, 137, 139, 445, 3389]:
                    service_name = self.results.get("network_security", {}).get("service_detection", {}).get(host, {}).get(port, {}).get("name", "unknown")
                    vulnerabilities.append({
                        "issue": f"Открытый порт {port}/{service_name}",
                        "severity": "High" if port in [23, 3389] else "Medium",
                        "description": f"Обнаружен потенциально опасный открытый порт {port} ({service_name}) на {host}",
                        "recommendation": f"Закройте порт {port} или ограничьте доступ к нему, если это возможно"
                    })
        
        report["summary"]["vulnerabilities"] = vulnerabilities
        
        # Оценка безопасности
        security_score = 100
        for vuln in vulnerabilities:
            if vuln.get("severity") == "Critical":
                security_score -= 20
            elif vuln.get("severity") == "High":
                security_score -= 10
            elif vuln.get("severity") == "Medium":
                security_score -= 5
            elif vuln.get("severity") == "Low":
                security_score -= 2
        
        report["summary"]["security_score"] = max(0, security_score)
        
        # Формируем рекомендации
        recommendations = []
        for vuln in vulnerabilities:
            if "recommendation" in vuln:
                recommendations.append({
                    "priority": "High" if vuln.get("severity") in ["Critical", "High"] else "Medium" if vuln.get("severity") == "Medium" else "Low",
                    "recommendation": vuln["recommendation"],
                    "issue": vuln["issue"]
                })
        
        # Добавляем общие рекомендации
        if not any(r["recommendation"] == "Регулярное сканирование безопасности" for r in recommendations):
            recommendations.append({
                "priority": "Medium",
                "recommendation": "Регулярное сканирование безопасности",
                "issue": "Профилактическая мера"
            })
        
        report["summary"]["recommendations"] = recommendations
        
        # Сохраняем отчет, если указан файл
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Отчет сохранен в {output_file}")
        
        return report

# Пример использования
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        analyzer = NetworkSecurityAnalyzer()
        results = analyzer.analyze_target(target)
        report = analyzer.generate_security_report("network_security_report.json")
        
        print(f"Безопасность: {report['summary']['security_score']}/100")
        print(f"Обнаружено уязвимостей: {len(report['summary']['vulnerabilities'])}")
        print(f"Отчет сохранен в network_security_report.json")
    else:
        print("Использование: python network_tools.py <целевой_хост>") 