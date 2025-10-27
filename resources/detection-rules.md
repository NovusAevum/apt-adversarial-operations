# Detection Rules & Threat Hunting

## Overview

This document provides comprehensive detection rules, SIEM queries, and threat hunting techniques for identifying APT activity across all attack phases.

---

## 🔍 SIEM Detection Rules

### Sigma Rules

**Suspicious PowerShell with AMSI Bypass**
```yaml
title: PowerShell AMSI Bypass Detected
id: f4bbd493-b796-416e-bbf2-121235348529
status: production
description: Detects PowerShell execution attempting to bypass AMSI
author: Wan Mohamad Hanis
date: 2025/01/27
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'amsiInitFailed'
            - 'System.Management.Automation.AmsiUtils'
            - '[Ref].Assembly.GetType'
    condition: selection
falsepositives:
    - Security testing tools
    - Red team exercises
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001
```

**Credential Dumping via Mimikatz**
```yaml
title: Mimikatz Credential Dumping Activity
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
description: Detects credential dumping using Mimikatz or similar tools
logsource:
    product: windows
    service: security
detection:
    selection_lsass:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess: '0x1010'
    selection_sekurlsa:
        EventID: 4688
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'kerberos::golden'
    condition: selection_lsass or selection_sekurlsa
falsepositives:
    - Legitimate password managers
level: critical
```

**Lateral Movement via PsExec**
```yaml
title: PsExec Lateral Movement Detected
id: b1c2d3e4-f5a6-7b8c-9d0e-1f2a3b4c5d6e
status: production
description: Detects lateral movement using PsExec or similar tools
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5140
        ShareName: '\\*\ADMIN$'
    filter:
        SubjectUserName|endswith: '$'  # Filter computer accounts
    condition: selection and not filter
falsepositives:
    - Administrative scripts
    - System management tools
level: medium
```

---

## 📊 Splunk Queries

**Beaconing Detection**
```spl
index=proxy OR index=firewall
| stats count, values(bytes_out) as bytes_out by src_ip, dest_ip, dest_port
| where count > 100
| eval variance=stdev(bytes_out)/avg(bytes_out)
| where variance < 0.1
| table src_ip, dest_ip, dest_port, count, variance
| sort -count
```

**Suspicious Process Trees**
```spl
index=windows EventCode=4688
| eval parent_process=lower(ParentProcessName)
| eval process=lower(NewProcessName)
| search (parent_process="*powershell.exe" AND process="*cmd.exe")
    OR (parent_process="*winword.exe" AND process="*powershell.exe")
    OR (parent_process="*excel.exe" AND process="*cmd.exe")
| table _time, Computer, SubjectUserName, parent_process, process, CommandLine
```

**Kerberoasting Detection**
```spl
index=windows EventCode=4769
| where Service_Name!="krbtgt" AND Service_Name!="*$" 
| where Ticket_Encryption_Type="0x17"
| stats count by Service_Name, Account_Name, src_ip
| where count > 10
```

---

## 🔎 KQL Queries (Azure Sentinel)

**Credential Access Detection**
```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType in (3, 10)  // Network or RDP
| summarize LogonCount=count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where LogonCount > 50  // Suspicious volume
| join kind=inner (
    SecurityEvent
    | where EventID == 4625  // Failed logon
    | summarize FailCount=count() by Account, IpAddress, bin(TimeGenerated, 1h)
) on Account, IpAddress, TimeGenerated
| where FailCount > 10
| project TimeGenerated, Account, IpAddress, LogonCount, FailCount
```

**C2 Beacon Detection**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize 
    ConnectionCount=count(),
    AvgBytes=avg(SentBytes),
    StdDevBytes=stdev(SentBytes)
    by SourceIP, DestinationIP, DestinationPort, bin(TimeGenerated, 5m)
| where ConnectionCount > 10
| extend CoefficientOfVariation = StdDevBytes / AvgBytes
| where CoefficientOfVariation < 0.3  // Low variation = beaconing
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, ConnectionCount, CoefficientOfVariation
```

---

## 🎯 YARA Rules

**Cobalt Strike Beacon Detection**
```yara
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon in memory or on disk"
        author = "Wan Mohamad Hanis"
        date = "2025-01-27"
        severity = "critical"
    
    strings:
        $beacon_str1 = "%s as %s\\%s: %d" ascii
        $beacon_str2 = "beacon.dll" ascii
        $beacon_str3 = "ReflectiveLoader" ascii
        $beacon_hex1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 }
        $beacon_hex2 = { 4C 8B DC 49 89 5B 08 49 89 6B 10 }
        $mz_header = { 4D 5A }
    
    condition:
        $mz_header at 0 and
        filesize < 500KB and
        (2 of ($beacon_str*) or 1 of ($beacon_hex*))
}
```

**Mimikatz Detection**
```yara
rule Mimikatz_Binary {
    meta:
        description = "Detects Mimikatz binary or memory artifacts"
        author = "Wan Mohamad Hanis"
        severity = "critical"
    
    strings:
        $s1 = "gentilkiwi" ascii wide
        $s2 = "sekurlsa" ascii wide
        $s3 = "kerberos" ascii wide
        $s4 = "lsadump" ascii wide
        $s5 = "privilege::debug" ascii wide
    
    condition:
        3 of them
}
```

---

## 🔥 Suricata/Snort Rules

**DNS Tunneling Detection**
```
alert dns any any -> any any (msg:"DNS Tunneling - Excessive Subdomain Length"; 
    dns_query; content:"."; depth:255; 
    pcre:"/^[a-zA-Z0-9]{50,}\./"; 
    threshold:type limit, track by_src, count 1, seconds 60; 
    classtype:bad-unknown; sid:1000001; rev:1;)
```

**Suspicious HTTPS Beaconing**
```
alert tcp any any -> any 443 (msg:"Potential C2 Beaconing Pattern"; 
    flow:established,to_server; 
    threshold:type both, track by_src, count 100, seconds 300; 
    detection_filter:track by_src, count 100, seconds 300; 
    classtype:trojan-activity; sid:1000002; rev:1;)
```

---

## 🎪 Threat Hunting Queries

### Hunt 1: Suspicious Registry Persistence
```powershell
# PowerShell hunt for suspicious Run keys
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Where-Object { $_.PSObject.Properties.Value -match "(temp|appdata|programdata)" } |
    Select-Object PSPath, PSChildName, *
```

### Hunt 2: Unusual Network Connections
```python
# Python script to identify beaconing patterns
import pandas as pd

def detect_beaconing(connections_df):
    """
    Analyze network connections for beaconing patterns
    connections_df: DataFrame with columns [timestamp, src_ip, dst_ip, bytes]
    """
    # Group by source and destination
    grouped = connections_df.groupby(['src_ip', 'dst_ip'])
    
    beacons = []
    for (src, dst), group in grouped:
        if len(group) < 20:  # Need sufficient samples
            continue
        
        # Calculate time deltas
        group = group.sort_values('timestamp')
        time_deltas = group['timestamp'].diff().dt.total_seconds()
        
        # Calculate coefficient of variation
        mean_delta = time_deltas.mean()
        std_delta = time_deltas.std()
        cv = std_delta / mean_delta if mean_delta > 0 else 0
        
        # Low CV indicates regular beaconing
        if cv < 0.3 and mean_delta < 300:  # Less than 5 min intervals
            beacons.append({
                'src_ip': src,
                'dst_ip': dst,
                'connections': len(group),
                'mean_interval': mean_delta,
                'cv': cv
            })
    
    return pd.DataFrame(beacons)
```

### Hunt 3: Living Off the Land Binaries
```spl
index=windows EventCode=4688
| search NewProcessName="*\\certutil.exe" OR NewProcessName="*\\bitsadmin.exe" 
    OR NewProcessName="*\\mshta.exe" OR NewProcessName="*\\regsvr32.exe"
| where CommandLine!=""
| stats count by NewProcessName, CommandLine, SubjectUserName, Computer
```

---

## 📈 Behavioral Analytics

### Anomaly Detection Models

**User Behavior Analytics (UBA)**
```python
from sklearn.ensemble import IsolationForest
import numpy as np

def detect_user_anomalies(user_activity):
    """
    Detect anomalous user behavior using Isolation Forest
    
    user_activity: array of features [login_time, failed_logins, 
                   data_accessed, privilege_escalations]
    """
    model = IsolationForest(contamination=0.1, random_state=42)
    
    # Train on historical normal behavior
    model.fit(user_activity)
    
    # Predict anomalies (-1 = anomaly, 1 = normal)
    predictions = model.predict(user_activity)
    anomaly_scores = model.score_samples(user_activity)
    
    return predictions, anomaly_scores
```

---

## 🛡️ EDR Detection Logic

**Endpoint Detection Rules**

```json
{
  "rule_name": "Process_Injection_Detected",
  "description": "Detects process injection techniques",
  "severity": "high",
  "conditions": {
    "process_operations": [
      "VirtualAllocEx",
      "WriteProcessMemory",
      "CreateRemoteThread"
    ],
    "sequence": "within_5_seconds",
    "target_process": "not_self"
  },
  "actions": [
    "alert",
    "block_process",
    "collect_memory_dump"
  ]
}
```

---

## 📋 Detection Coverage Matrix

| MITRE Technique | Sigma | Splunk | KQL | YARA | Suricata |
|----------------|-------|--------|-----|------|----------|
| T1059.001 PowerShell | ✅ | ✅ | ✅ | ✅ | ❌ |
| T1003 Credential Dumping | ✅ | ✅ | ✅ | ✅ | ❌ |
| T1021 Lateral Movement | ✅ | ✅ | ✅ | ❌ | ❌ |
| T1071 C2 Communication | ❌ | ✅ | ✅ | ❌ | ✅ |
| T1055 Process Injection | ✅ | ✅ | ✅ | ✅ | ❌ |
| T1048 DNS Tunneling | ❌ | ✅ | ✅ | ❌ | ✅ |

---

**Author**: Wan Mohamad Hanis bin Wan Hassan  
**Last Updated**: January 2025  
**Version**: 1.0
