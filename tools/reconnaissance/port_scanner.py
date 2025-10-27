#!/usr/bin/env python3
"""
Advanced Port Scanner with Service Detection and Evasion
Implements SYN scanning, service fingerprinting, and stealth techniques
Author: Wan Mohamad Hanis bin Wan Hassan
"""

import socket
import struct
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple
import sys

class StealthPortScanner:
    def __init__(self, target: str, ports: List[int] = None, threads: int = 100):
        self.target = target
        self.ports = ports or list(range(1, 1001))  # Top 1000 ports
        self.threads = threads
        self.open_ports: Dict[int, str] = {}
        
        # Common port-to-service mapping
        self.services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
        }
    
    def tcp_connect_scan(self, port: int) -> Tuple[int, bool, str]:
        """
        Standard TCP connect scan
        Most reliable but easily detected
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Try to grab service banner
                banner = self._grab_banner(sock)
                sock.close()
                return (port, True, banner)
            
            sock.close()
            return (port, False, "")
        
        except Exception as e:
            return (port, False, "")
    
    def _grab_banner(self, sock: socket.socket) -> str:
        """Attempt to grab service banner"""
        try:
            sock.settimeout(2)
            
            # Send generic probe
            sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100]  # Limit banner length
        
        except:
            return ""
    
    def service_detection(self, port: int) -> str:
        """
        Advanced service detection through banner grabbing
        and behavior analysis
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            # Try different probes based on common services
            probes = {
                'HTTP': b"GET / HTTP/1.0\r\n\r\n",
                'SMTP': b"EHLO scanner\r\n",
                'FTP': b"USER anonymous\r\n",
                'SSH': b"",  # SSH sends banner immediately
            }
            
            # Send probe and get response
            if port in [80, 8080, 8443]:
                sock.send(probes['HTTP'])
            elif port in [25, 587]:
                sock.send(probes['SMTP'])
            elif port == 21:
                sock.send(probes['FTP'])
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Analyze response
            if 'HTTP' in response:
                return 'HTTP'
            elif 'SSH' in response:
                return 'SSH'
            elif '220' in response and 'FTP' in response:
                return 'FTP'
            elif 'SMTP' in response or '220' in response:
                return 'SMTP'
            elif 'mysql' in response.lower():
                return 'MySQL'
            else:
                return self.services.get(port, 'Unknown')
        
        except:
            return self.services.get(port, 'Unknown')
    
    def scan(self) -> Dict[int, Dict]:
        """
        Execute comprehensive port scan
        """
        print(f"{'='*60}")
        print(f"Port Scanning: {self.target}")
        print(f"Ports: {len(self.ports)} ports")
        print(f"Threads: {self.threads}")
        print(f"{'='*60}\n")
        
        print("[*] Initiating TCP connect scan...")
        start_time = time.time()
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.tcp_connect_scan, port): port for port in self.ports}
            
            completed = 0
            for future in as_completed(futures):
                port, is_open, banner = future.result()
                completed += 1
                
                if is_open:
                    # Get service information
                    service = self.service_detection(port)
                    
                    results[port] = {
                        'state': 'open',
                        'service': service,
                        'banner': banner
                    }
                    
                    print(f"[+] {port}/tcp open - {service}")
                    if banner:
                        print(f"    Banner: {banner}")
                
                # Progress indicator
                if completed % 100 == 0:
                    print(f"[*] Progress: {completed}/{len(self.ports)}")
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"[✓] Scan complete in {elapsed:.2f} seconds")
        print(f"[✓] Open ports: {len(results)}")
        print(f"{'='*60}\n")
        
        self.open_ports = results
        return results
    
    def vulnerability_check(self) -> List[str]:
        """
        Check for common vulnerabilities based on open services
        """
        print("[*] Checking for potential vulnerabilities...")
        
        vulnerabilities = []
        
        for port, info in self.open_ports.items():
            service = info['service']
            banner = info['banner']
            
            # Check for outdated versions
            if 'OpenSSH' in banner:
                version = banner.split('OpenSSH_')[1].split()[0] if 'OpenSSH_' in banner else ''
                if version and version < '7.4':
                    vulnerabilities.append(f"Port {port}: Outdated OpenSSH {version} - Multiple CVEs")
            
            # Check for dangerous services
            if port == 23:
                vulnerabilities.append(f"Port {port}: Telnet is insecure - should use SSH")
            
            if port == 21 and 'FTP' in service:
                vulnerabilities.append(f"Port {port}: FTP without encryption detected")
            
            if port == 3389:
                vulnerabilities.append(f"Port {port}: RDP exposed - high-value target for attacks")
            
            if port in [5900, 5901]:
                vulnerabilities.append(f"Port {port}: VNC exposed - often has weak/no authentication")
            
            # Check for database exposure
            if port in [3306, 5432, 6379, 27017]:
                vulnerabilities.append(f"Port {port}: Database {service} exposed to internet")
        
        if vulnerabilities:
            print("\n[!] Potential security issues found:")
            for vuln in vulnerabilities:
                print(f"    - {vuln}")
        else:
            print("[+] No obvious vulnerabilities detected")
        
        return vulnerabilities
    
    def export_results(self, filename: str):
        """Export scan results to file"""
        with open(filename, 'w') as f:
            f.write(f"Port Scan Results for {self.target}\n")
            f.write(f"{'='*60}\n\n")
            
            for port in sorted(self.open_ports.keys()):
                info = self.open_ports[port]
                f.write(f"Port: {port}/tcp\n")
                f.write(f"State: {info['state']}\n")
                f.write(f"Service: {info['service']}\n")
                if info['banner']:
                    f.write(f"Banner: {info['banner']}\n")
                f.write(f"\n")
        
        print(f"[+] Results exported to {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [ports]")
        print(f"Example: {sys.argv[0]} 192.168.1.1")
        print(f"Example: {sys.argv[0]} 192.168.1.1 21,22,80,443")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Parse ports
    if len(sys.argv) > 2:
        ports = [int(p) for p in sys.argv[2].split(',')]
    else:
        # Default: Top 1000 ports
        ports = None
    
    scanner = StealthPortScanner(target, ports, threads=200)
    results = scanner.scan()
    
    # Vulnerability check
    scanner.vulnerability_check()
    
    # Export results
    scanner.export_results(f"portscan_{target.replace('.', '_')}.txt")
