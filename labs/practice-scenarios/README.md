# APT Practice Scenarios & Labs

## 🎯 Overview

Hands-on practice scenarios simulating real-world APT operations. Each lab provides practical experience with techniques covered in the main documentation.

---

## Lab 1: Initial Access & Execution

### Scenario
Gain initial access to a corporate network through spear-phishing and establish command execution capability.

### Objectives
1. Craft convincing phishing email
2. Create weaponized Office document
3. Establish reverse shell
4. Enumerate system information

### Setup
```bash
# Victim machine: Windows 10
# Attacker machine: Kali Linux
# Network: 192.168.1.0/24
```

### Steps
```powershell
# 1. Create malicious macro document
# 2. Setup listener: nc -lvnp 4444
# 3. Send phishing email
# 4. Wait for execution
# 5. Enumerate: systeminfo, whoami /all
```

---

## Lab 2: Privilege Escalation

### Scenario
Escalate from standard user to SYSTEM privileges using multiple techniques.

### Techniques Practiced
- Token impersonation
- UAC bypass
- Service exploitation
- Kernel exploits

---

## Lab 3: Credential Harvesting

### Scenario
Extract credentials from compromised system using multiple methods.

### Objectives
1. Dump LSASS memory
2. Extract browser passwords
3. Capture network authentication
4. Crack retrieved hashes

---

## Lab 4: Lateral Movement

### Scenario
Move from initial compromised host to domain controller.

### Techniques
- Pass-the-Hash
- PSExec lateral movement
- WMI execution
- RDP hijacking

---

## Lab 5: Data Exfiltration

### Scenario
Locate sensitive data and exfiltrate through various covert channels.

### Methods
- DNS tunneling
- HTTPS exfiltration
- Steganography
- Cloud storage abuse

---

## Lab 6: Ransomware Simulation

### Scenario
Simulate ransomware attack in isolated environment.

### Components
1. File encryption
2. Shadow copy deletion
3. Ransom note deployment
4. Network propagation

**WARNING**: Only in isolated lab environment!

---

## Lab 7: APT Campaign Simulation

### Full Kill Chain Exercise
Simulate complete APT campaign from reconnaissance to impact.

### Phases
1. OSINT reconnaissance
2. Initial access via phishing
3. Establish C2
4. Privilege escalation
5. Credential harvesting
6. Lateral movement
7. Data exfiltration
8. Persistence
9. Cover tracks

---

## Virtual Lab Setup

### Required Infrastructure
```
┌─────────────────────────────────────────┐
│         Virtual Lab Network             │
│                                         │
│  ┌──────────┐      ┌──────────┐       │
│  │  Domain  │      │  Web     │       │
│  │Controller│──────│  Server  │       │
│  └──────────┘      └──────────┘       │
│       │                 │              │
│       │                 │              │
│  ┌──────────┐      ┌──────────┐       │
│  │ Workstation │──│ Workstation │     │
│  │    (Victim) │  │   (Victim)  │     │
│  └──────────┘      └──────────┘       │
│                                         │
│            │                            │
│       ┌────────────┐                   │
│       │  Attacker  │                   │
│       │   (Kali)   │                   │
│       └────────────┘                   │
└─────────────────────────────────────────┘
```

### Setup Scripts
```bash
# Deploy lab with Vagrant
vagrant up

# Or Docker Compose
docker-compose up -d

# Configure vulnerable environment
./setup_lab.sh
```

---

## Assessment & Scoring

### Evaluation Criteria
- **Stealth**: Detection evasion
- **Speed**: Time to objective
- **Coverage**: Techniques utilized
- **Documentation**: Reporting quality

---

**Return to**: [Main Documentation](../README.md)