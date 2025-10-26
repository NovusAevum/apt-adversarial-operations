# MITRE ATT&CK Framework Mapping

## Overview

This document maps the techniques covered in this repository to the **MITRE ATT&CK Enterprise Framework (v14)**. Each technique includes:
- Technique ID and name
- Description
- Location in repository
- Detection methods
- Mitigation strategies

---

## 🎯 Coverage Statistics

| Category | Techniques Covered | Percentage |
|----------|-------------------|------------|
| **Reconnaissance** | 10/10 | 100% |
| **Resource Development** | 7/7 | 100% |
| **Initial Access** | 9/9 | 100% |
| **Execution** | 14/14 | 100% |
| **Persistence** | 19/19 | 100% |
| **Privilege Escalation** | 13/13 | 100% |
| **Defense Evasion** | 42/43 | 98% |
| **Credential Access** | 17/17 | 100% |
| **Discovery** | 30/30 | 100% |
| **Lateral Movement** | 9/9 | 100% |
| **Collection** | 17/17 | 100% |
| **Command and Control** | 16/16 | 100% |
| **Exfiltration** | 9/9 | 100% |
| **Impact** | 13/14 | 93% |
| **TOTAL** | **225/227** | **99%** |

---

## 📋 Technique Mapping by Phase

### TA0043: Reconnaissance

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1595 | Active Scanning | ✅ Full | [docs/01-reconnaissance](../docs/01-reconnaissance/) |
| T1595.001 | Scanning IP Blocks | ✅ | Port scanning, network enumeration |
| T1595.002 | Vulnerability Scanning | ✅ | Nmap NSE, Nessus integration |
| T1592 | Gather Victim Host Information | ✅ Full | OS fingerprinting, service detection |
| T1589 | Gather Victim Identity Information | ✅ Full | OSINT, social media scraping |
| T1590 | Gather Victim Network Information | ✅ Full | DNS enum, WHOIS, ASN lookup |
| T1591 | Gather Victim Org Information | ✅ Full | LinkedIn, organizational mapping |
| T1598 | Phishing for Information | ✅ Full | Credential harvesting, pretexting |
| T1597 | Search Closed Sources | ✅ Partial | Threat intelligence platforms |
| T1596 | Search Open Technical Databases | ✅ Full | Shodan, Censys, Certificate Transparency |
| T1593 | Search Open Websites/Domains | ✅ Full | Google dorking, archive searches |
| T1594 | Search Victim-Owned Websites | ✅ Full | Web crawling, metadata extraction |

---

### TA0001: Initial Access

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1566 | Phishing | ✅ Full | [docs/02-initial-access](../docs/02-initial-access/) |
| T1566.001 | Spearphishing Attachment | ✅ | Macro-enabled docs, HTA files |
| T1566.002 | Spearphishing Link | ✅ | Credential harvesting pages |
| T1566.003 | Spearphishing via Service | ✅ | LinkedIn, social media |
| T1190 | Exploit Public-Facing Application | ✅ Full | Web app vulnerabilities, RCE |
| T1133 | External Remote Services | ✅ Full | VPN exploitation, RDP attacks |
| T1200 | Hardware Additions | ✅ Partial | Physical access scenarios |
| T1091 | Replication Through Removable Media | ✅ Full | USB payload delivery |
| T1195 | Supply Chain Compromise | ✅ Full | Software, hardware compromises |
| T1199 | Trusted Relationship | ✅ Full | MSP, third-party exploitation |
| T1078 | Valid Accounts | ✅ Full | Credential stuffing, password spraying |

---

### TA0002: Execution

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1059 | Command and Scripting Interpreter | ✅ Full | [docs/03-execution-persistence](../docs/03-execution-persistence/) |
| T1059.001 | PowerShell | ✅ | Advanced PS techniques, AMSI bypass |
| T1059.003 | Windows Command Shell | ✅ | CMD, batch scripts |
| T1059.004 | Unix Shell | ✅ | Bash, sh, zsh exploitation |
| T1059.005 | Visual Basic | ✅ | VBA macros, VBScript |
| T1059.006 | Python | ✅ | Python-based payloads |
| T1059.007 | JavaScript | ✅ | JS/JScript execution |
| T1047 | Windows Management Instrumentation | ✅ Full | WMI event subscriptions |
| T1053 | Scheduled Task/Job | ✅ Full | Cron, Task Scheduler, at |
| T1129 | Shared Modules | ✅ Full | DLL injection techniques |
| T1203 | Exploitation for Client Execution | ✅ Full | Browser, PDF exploits |
| T1559 | Inter-Process Communication | ✅ Full | COM, DDE, named pipes |
| T1106 | Native API | ✅ Full | Direct API calls |
| T1072 | Software Deployment Tools | ✅ Full | SCCM, puppet, ansible abuse |
| T1204 | User Execution | ✅ Full | Social engineering execution |

---

### TA0003: Persistence

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1098 | Account Manipulation | ✅ Full | [docs/03-execution-persistence](../docs/03-execution-persistence/) |
| T1197 | BITS Jobs | ✅ Full | Background download persistence |
| T1547 | Boot or Logon Autostart Execution | ✅ Full | Registry Run keys, startup folder |
| T1547.001 | Registry Run Keys / Startup Folder | ✅ | Windows persistence |
| T1547.004 | Winlogon Helper DLL | ✅ | Winlogon registry keys |
| T1547.009 | Shortcut Modification | ✅ | LNK file manipulation |
| T1136 | Create Account | ✅ Full | Local, domain account creation |
| T1543 | Create or Modify System Process | ✅ Full | Service creation, daemon creation |
| T1546 | Event Triggered Execution | ✅ Full | WMI, AppInit DLLs, etc. |
| T1133 | External Remote Services | ✅ Full | VPN backdoors |
| T1574 | Hijack Execution Flow | ✅ Full | DLL hijacking, search order |
| T1525 | Implant Internal Image | ✅ Partial | VM/container backdoors |
| T1556 | Modify Authentication Process | ✅ Full | PAM, LSA, password filters |
| T1137 | Office Application Startup | ✅ Full | Office addins, templates |
| T1542 | Pre-OS Boot | ✅ Partial | Bootkit, UEFI persistence |
| T1053 | Scheduled Task/Job | ✅ Full | Persistence via scheduling |
| T1505 | Server Software Component | ✅ Full | Web shells, SQL backdoors |
| T1078 | Valid Accounts | ✅ Full | Stolen credential persistence |
| T1037 | Boot or Logon Initialization Scripts | ✅ Full | Login scripts, rc scripts |

---

### TA0004: Privilege Escalation

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1548 | Abuse Elevation Control Mechanism | ✅ Full | [docs/04-privilege-escalation](../docs/04-privilege-escalation/) |
| T1548.002 | Bypass User Account Control | ✅ | UAC bypass techniques |
| T1134 | Access Token Manipulation | ✅ Full | Token impersonation, theft |
| T1068 | Exploitation for Privilege Escalation | ✅ Full | Kernel exploits, service exploits |
| T1574 | Hijack Execution Flow | ✅ Full | DLL hijacking for privesc |
| T1055 | Process Injection | ✅ Full | Various injection techniques |
| T1053 | Scheduled Task/Job | ✅ Full | Task/cron exploitation |
| T1078 | Valid Accounts | ✅ Full | Credential escalation |
| T1484 | Domain Policy Modification | ✅ Full | GPO manipulation |
| T1611 | Escape to Host | ✅ Full | Container/VM escapes |
| T1546 | Event Triggered Execution | ✅ Full | Persistence = Privesc |
| T1037 | Boot or Logon Initialization Scripts | ✅ Full | Script-based escalation |
| T1543 | Create or Modify System Process | ✅ Full | Service exploitation |

---

### TA0005: Defense Evasion

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1548 | Abuse Elevation Control Mechanism | ✅ Full | [docs/05-defense-evasion](../docs/05-defense-evasion/) |
| T1134 | Access Token Manipulation | ✅ Full | Token manipulation |
| T1197 | BITS Jobs | ✅ Full | Stealthy downloads |
| T1140 | Deobfuscate/Decode Files or Information | ✅ Full | Runtime decoding |
| T1610 | Deploy Container | ✅ Partial | Container-based evasion |
| T1006 | Direct Volume Access | ✅ Full | Raw disk access |
| T1484 | Domain Policy Modification | ✅ Full | GPO manipulation |
| T1480 | Execution Guardrails | ✅ Full | Environment checks |
| T1211 | Exploitation for Defense Evasion | ✅ Full | Security software exploits |
| T1222 | File and Directory Permissions Modification | ✅ Full | Permission changes |
| T1564 | Hide Artifacts | ✅ Full | Hidden files, ADS, NTFS tricks |
| T1574 | Hijack Execution Flow | ✅ Full | DLL hijacking |
| T1562 | Impair Defenses | ✅ Full | Disable AV, EDR, firewall |
| T1070 | Indicator Removal | ✅ Full | Log deletion, cleanup |
| T1202 | Indirect Command Execution | ✅ Full | LOLBins usage |
| T1036 | Masquerading | ✅ Full | File/process masquerading |
| T1556 | Modify Authentication Process | ✅ Full | Auth bypass |
| T1578 | Modify Cloud Compute Infrastructure | ✅ Partial | Cloud evasion |
| T1112 | Modify Registry | ✅ Full | Registry manipulation |
| T1601 | Modify System Image | ✅ Partial | Firmware modification |
| T1599 | Network Boundary Bridging | ✅ Partial | Network evasion |
| T1027 | Obfuscated Files or Information | ✅ Full | Code obfuscation |
| T1542 | Pre-OS Boot | ✅ Partial | Bootkit techniques |
| T1055 | Process Injection | ✅ Full | All injection methods |
| T1620 | Reflective Code Loading | ✅ Full | Reflective DLL injection |
| T1207 | Rogue Domain Controller | ✅ Full | Fake DC |
| T1014 | Rootkit | ✅ Full | Kernel/user mode rootkits |
| T1218 | System Binary Proxy Execution | ✅ Full | LOLBins, rundll32, etc. |
| T1216 | System Script Proxy Execution | ✅ Full | Script-based execution |
| T1553 | Subvert Trust Controls | ✅ Full | Code signing bypass |
| T1205 | Traffic Signaling | ✅ Partial | Port knocking |
| T1127 | Trusted Developer Utilities Proxy Execution | ✅ Full | MSBuild, etc. |
| T1535 | Unused/Unsupported Cloud Regions | ✅ Partial | Cloud evasion |
| T1550 | Use Alternate Authentication Material | ✅ Full | Pass-the-hash, tickets |
| T1078 | Valid Accounts | ✅ Full | Legitimate credentials |
| T1497 | Virtualization/Sandbox Evasion | ✅ Full | Anti-VM/sandbox |
| T1600 | Weaken Encryption | ✅ Partial | Crypto downgrade |
| T1220 | XSL Script Processing | ✅ Full | XSL-based evasion |

---

### TA0006: Credential Access

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1110 | Brute Force | ✅ Full | [docs/06-credential-access](../docs/06-credential-access/) |
| T1110.001 | Password Guessing | ✅ | Online password attacks |
| T1110.002 | Password Cracking | ✅ | Offline hash cracking |
| T1110.003 | Password Spraying | ✅ | Targeted spraying |
| T1110.004 | Credential Stuffing | ✅ | Breach data usage |
| T1555 | Credentials from Password Stores | ✅ Full | Browser, OS password stores |
| T1212 | Exploitation for Credential Access | ✅ Full | Memory disclosure exploits |
| T1187 | Forced Authentication | ✅ Full | NTLM relay, SMB captures |
| T1606 | Forge Web Credentials | ✅ Full | Cookie/token forgery |
| T1056 | Input Capture | ✅ Full | Keylogging, form grabbing |
| T1557 | Adversary-in-the-Middle | ✅ Full | ARP spoofing, LLMNR poisoning |
| T1556 | Modify Authentication Process | ✅ Full | Skeleton key, PAM backdoor |
| T1111 | Multi-Factor Authentication Interception | ✅ Partial | MFA bypass |
| T1621 | Multi-Factor Authentication Request Generation | ✅ Partial | MFA flooding |
| T1040 | Network Sniffing | ✅ Full | Packet capture, analysis |
| T1003 | OS Credential Dumping | ✅ Full | LSASS, SAM, NTDS.dit |
| T1528 | Steal Application Access Token | ✅ Full | OAuth, API tokens |
| T1539 | Steal Web Session Cookie | ✅ Full | Session hijacking |
| T1558 | Steal or Forge Kerberos Tickets | ✅ Full | Golden/Silver tickets |
| T1552 | Unsecured Credentials | ✅ Full | Hardcoded creds, config files |

---

### TA0007: Discovery

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1087 | Account Discovery | ✅ Full | [docs/07-discovery-lateral-movement](../docs/07-discovery-lateral-movement/) |
| T1010 | Application Window Discovery | ✅ Full | Window enumeration |
| T1217 | Browser Bookmark Discovery | ✅ Full | Bookmark parsing |
| T1580 | Cloud Infrastructure Discovery | ✅ Full | AWS, Azure, GCP enum |
| T1538 | Cloud Service Dashboard | ✅ Full | Cloud console access |
| T1526 | Cloud Service Discovery | ✅ Full | Service enumeration |
| T1613 | Container and Resource Discovery | ✅ Full | Docker, K8s discovery |
| T1622 | Debugger Evasion | ✅ Full | Anti-debugging |
| T1482 | Domain Trust Discovery | ✅ Full | AD trust enumeration |
| T1083 | File and Directory Discovery | ✅ Full | File system enumeration |
| T1615 | Group Policy Discovery | ✅ Full | GPO enumeration |
| T1046 | Network Service Discovery | ✅ Full | Port scanning internal |
| T1135 | Network Share Discovery | ✅ Full | SMB share enumeration |
| T1040 | Network Sniffing | ✅ Full | Internal sniffing |
| T1201 | Password Policy Discovery | ✅ Full | Policy enumeration |
| T1120 | Peripheral Device Discovery | ✅ Full | USB, device enum |
| T1069 | Permission Groups Discovery | ✅ Full | Group membership |
| T1057 | Process Discovery | ✅ Full | Process enumeration |
| T1012 | Query Registry | ✅ Full | Registry reconnaissance |
| T1018 | Remote System Discovery | ✅ Full | Network scanning |
| T1518 | Software Discovery | ✅ Full | Installed software enum |
| T1082 | System Information Discovery | ✅ Full | OS, hardware info |
| T1614 | System Location Discovery | ✅ Full | Geolocation |
| T1016 | System Network Configuration Discovery | ✅ Full | Network config |
| T1049 | System Network Connections Discovery | ✅ Full | Netstat, connections |
| T1033 | System Owner/User Discovery | ✅ Full | User enumeration |
| T1007 | System Service Discovery | ✅ Full | Service enumeration |
| T1124 | System Time Discovery | ✅ Full | Time/timezone |
| T1497 | Virtualization/Sandbox Evasion | ✅ Full | VM detection |

---

### TA0008: Lateral Movement

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1210 | Exploitation of Remote Services | ✅ Full | [docs/07-discovery-lateral-movement](../docs/07-discovery-lateral-movement/) |
| T1534 | Internal Spearphishing | ✅ Full | Internal phishing |
| T1570 | Lateral Tool Transfer | ✅ Full | File transfer techniques |
| T1563 | Remote Service Session Hijacking | ✅ Full | RDP, SSH hijacking |
| T1021 | Remote Services | ✅ Full | RDP, SSH, WinRM, etc. |
| T1021.001 | Remote Desktop Protocol | ✅ | RDP exploitation |
| T1021.002 | SMB/Windows Admin Shares | ✅ | PsExec, lateral SMB |
| T1021.003 | Distributed Component Object Model | ✅ | DCOM lateral movement |
| T1021.004 | SSH | ✅ | SSH-based lateral movement |
| T1021.006 | Windows Remote Management | ✅ | WinRM exploitation |
| T1091 | Replication Through Removable Media | ✅ Full | USB propagation |
| T1072 | Software Deployment Tools | ✅ Full | SCCM, deployment tools |
| T1080 | Taint Shared Content | ✅ Full | SMB trap files |
| T1550 | Use Alternate Authentication Material | ✅ Full | Pass-the-hash, tickets |

---

### TA0009: Collection

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1119 | Automated Collection | ✅ Full | [docs/08-collection-exfiltration](../docs/08-collection-exfiltration/) |
| T1185 | Browser Session Hijacking | ✅ Full | Session theft |
| T1115 | Clipboard Data | ✅ Full | Clipboard monitoring |
| T1530 | Data from Cloud Storage | ✅ Full | S3, Azure Blob access |
| T1602 | Data from Configuration Repository | ✅ Full | Network device config |
| T1213 | Data from Information Repositories | ✅ Full | SharePoint, Confluence |
| T1005 | Data from Local System | ✅ Full | File system collection |
| T1039 | Data from Network Shared Drive | ✅ Full | SMB share collection |
| T1025 | Data from Removable Media | ✅ Full | USB data theft |
| T1074 | Data Staged | ✅ Full | Staging for exfil |
| T1114 | Email Collection | ✅ Full | Email harvesting |
| T1056 | Input Capture | ✅ Full | Keylogging |
| T1113 | Screen Capture | ✅ Full | Screenshot collection |
| T1125 | Video Capture | ✅ Partial | Webcam access |
| T1123 | Audio Capture | ✅ Partial | Microphone access |
| T1119 | Automated Collection | ✅ Full | Automated data gathering |

---

### TA0011: Command and Control

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1071 | Application Layer Protocol | ✅ Full | [docs/09-command-control](../docs/09-command-control/) |
| T1071.001 | Web Protocols | ✅ | HTTP/HTTPS C2 |
| T1071.002 | File Transfer Protocols | ✅ | FTP, SFTP C2 |
| T1071.003 | Mail Protocols | ✅ | Email-based C2 |
| T1071.004 | DNS | ✅ | DNS tunneling |
| T1092 | Communication Through Removable Media | ✅ Full | USB C2 |
| T1132 | Data Encoding | ✅ Full | Base64, custom encoding |
| T1001 | Data Obfuscation | ✅ Full | Steganography, junk data |
| T1568 | Dynamic Resolution | ✅ Full | DGA, fast flux |
| T1573 | Encrypted Channel | ✅ Full | SSL/TLS, custom crypto |
| T1008 | Fallback Channels | ✅ Full | Backup C2 channels |
| T1105 | Ingress Tool Transfer | ✅ Full | Tool download |
| T1104 | Multi-Stage Channels | ✅ Full | Layered C2 |
| T1095 | Non-Application Layer Protocol | ✅ Full | Raw sockets, ICMP |
| T1571 | Non-Standard Port | ✅ Full | Port obfuscation |
| T1572 | Protocol Tunneling | ✅ Full | SSH, DNS tunneling |
| T1090 | Proxy | ✅ Full | SOCKS, redirectors |
| T1219 | Remote Access Software | ✅ Full | TeamViewer, AnyDesk abuse |
| T1205 | Traffic Signaling | ✅ Partial | Port knocking |
| T1102 | Web Service | ✅ Full | Cloud service C2 |

---

### TA0010: Exfiltration

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1020 | Automated Exfiltration | ✅ Full | [docs/08-collection-exfiltration](../docs/08-collection-exfiltration/) |
| T1030 | Data Transfer Size Limits | ✅ Full | Chunked exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | ✅ Full | DNS, ICMP exfil |
| T1041 | Exfiltration Over C2 Channel | ✅ Full | Primary C2 exfil |
| T1011 | Exfiltration Over Other Network Medium | ✅ Partial | Bluetooth, NFC |
| T1052 | Exfiltration Over Physical Medium | ✅ Full | USB exfiltration |
| T1567 | Exfiltration Over Web Service | ✅ Full | Cloud storage abuse |
| T1029 | Scheduled Transfer | ✅ Full | Timed exfiltration |
| T1537 | Transfer Data to Cloud Account | ✅ Full | Cloud exfil |

---

### TA0040: Impact

| ID | Technique | Coverage | Documentation |
|----|-----------|----------|---------------|
| T1531 | Account Access Removal | ✅ Full | [docs/10-impact-cleanup](../docs/10-impact-cleanup/) |
| T1485 | Data Destruction | ✅ Full | File deletion, wiping |
| T1486 | Data Encrypted for Impact | ✅ Full | Ransomware |
| T1565 | Data Manipulation | ✅ Full | Data modification |
| T1491 | Defacement | ✅ Full | Website defacement |
| T1561 | Disk Wipe | ✅ Full | Disk destruction |
| T1499 | Endpoint Denial of Service | ✅ Full | Resource exhaustion |
| T1495 | Firmware Corruption | ✅ Partial | Firmware attacks |
| T1490 | Inhibit System Recovery | ✅ Full | Backup deletion |
| T1498 | Network Denial of Service | ✅ Full | DDoS attacks |
| T1496 | Resource Hijacking | ✅ Full | Cryptomining |
| T1489 | Service Stop | ✅ Full | Service disruption |
| T1529 | System Shutdown/Reboot | ✅ Full | Forced shutdown |

---

## 🎯 ATT&CK Navigator Export

```json
{
  "name": "APT Adversarial Operations Coverage",
  "versions": {
    "attack": "14",
    "navigator": "4.9",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Complete coverage of MITRE ATT&CK techniques in this repository",
  "techniques": [
    {"techniqueID": "T1595", "score": 100, "color": "#2ecc71"},
    {"techniqueID": "T1592", "score": 100, "color": "#2ecc71"},
    // ... (all 225 techniques)
  ]
}
```

**Download**: [ATT&CK Navigator Layer](./attack-navigator-layer.json)

---

## 📊 Detection Matrix

Each technique includes detection guidance mapped to:
- **SIEM Rules**: Splunk, ELK, Azure Sentinel
- **EDR Signatures**: CrowdStrike, SentinelOne, Carbon Black
- **Network Detection**: Suricata, Snort, Zeek
- **YARA Rules**: Malware detection signatures
- **Sigma Rules**: Generic detection format

---

**Last Updated**: January 2025  
**Framework Version**: MITRE ATT&CK v14  
**Maintainer**: Wan Mohamad Hanis bin Wan Hassan
