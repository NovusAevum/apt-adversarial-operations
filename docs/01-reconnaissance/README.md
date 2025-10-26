# Phase 1: Reconnaissance & Intelligence Gathering

## 🎯 Overview

Reconnaissance is the **foundation of every successful APT operation**. This phase involves gathering intelligence about target infrastructure, personnel, and security posture without triggering defensive systems.

### MITRE ATT&CK Mapping
- **Primary Tactic**: Reconnaissance (TA0043)
- **Techniques Covered**: T1595, T1592, T1589, T1590, T1591, T1598, T1597, T1596, T1593, T1594

---

## 📚 Reconnaissance Phases

### Phase 1A: Passive OSINT (Days-Weeks, Minimal Risk)
- DNS enumeration and subdomain discovery
- WHOIS intelligence gathering
- Certificate transparency logs
- Social media intelligence
- Public document metadata analysis

### Phase 1B: Active Scanning (Hours-Days, Low-Medium Risk)
- Port scanning with evasion techniques
- Service version detection
- Vulnerability identification
- Web application fingerprinting

### Phase 1C: Social Engineering Recon (Weeks-Months, Medium-High Risk)
- LinkedIn organizational mapping
- Email harvesting and format detection
- Personnel targeting and profiling

### Phase 1D: Infrastructure Mapping (Weeks, Low-Medium Risk)
- Cloud asset discovery (AWS, Azure, GCP)
- CDN and WAF identification
- Third-party service enumeration

---

## 🛠️ Essential Tools

### OSINT Frameworks
- **Maltego** - Visual link analysis and data mining
- **Shodan** - Internet-connected device search engine
- **Censys** - Internet-wide scanning and analysis
- **SpiderFoot** - Automated OSINT collection
- **theHarvester** - Email and subdomain harvesting
- **Recon-ng** - Modular reconnaissance framework

### DNS Reconnaissance
- **dnsenum** - DNS enumeration tool
- **dnsrecon** - DNS reconnaissance
- **fierce** - DNS scanner
- **sublist3r** - Subdomain enumeration
- **Amass** - In-depth attack surface mapping

### Web Reconnaissance
- **Burp Suite** - Web application security testing
- **OWASP ZAP** - Web app scanner
- **Nikto** - Web server scanner
- **WhatWeb** - Web technology identifier
- **Wappalyzer** - Technology profiler

---

## 🎯 Practical Exercises

### Exercise 1: Complete Domain Reconnaissance
Perform comprehensive reconnaissance on a target domain (use your own or authorized test domain):

```bash
#!/bin/bash
# Automated reconnaissance script
TARGET="example.com"
OUTPUT="./recon_${TARGET}"

mkdir -p $OUTPUT

# DNS enumeration
dnsenum --enum $TARGET -o $OUTPUT/dns_enum.txt
dnsrecon -d $TARGET -t std -x $OUTPUT/dnsrecon.xml

# Subdomain discovery
amass enum -d $TARGET -o $OUTPUT/amass_subdomains.txt
sublist3r -d $TARGET -o $OUTPUT/sublist3r.txt

# Port scanning
nmap -sV -sC -oA $OUTPUT/nmap_scan $TARGET

# Web technology detection
whatweb $TARGET > $OUTPUT/whatweb.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > $OUTPUT/cert_transparency.txt

echo "[✓] Reconnaissance complete! Results in $OUTPUT/"
```

### Exercise 2: Cloud Asset Discovery
```python
#!/usr/bin/env python3
import requests

def find_s3_buckets(domain):
    """Discover publicly accessible S3 buckets"""
    buckets = [
        domain, f"{domain}-backup", f"{domain}-assets",
        f"{domain}-dev", f"{domain}-prod", f"{domain}-staging"
    ]
    
    for bucket in buckets:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            r = requests.head(url, timeout=5)
            if r.status_code in [200, 403]:
                print(f"[+] Found: {bucket}")
                # Test for public access
                test = requests.get(f"{url}/", timeout=5)
                if test.status_code == 200:
                    print(f"[!] PUBLICLY ACCESSIBLE: {bucket}")
        except:
            pass

# Usage
find_s3_buckets("targetcompany")
```

---

## 🔒 Operational Security (OPSEC)

### Reconnaissance OPSEC Guidelines

1. **Use VPN/Proxy Chains**
   - Never conduct reconnaissance from your real IP
   - Rotate IPs frequently
   - Use commercial VPN services or TOR

2. **Timing and Rate Limiting**
   - Slow down automated scans
   - Mimic human behavior patterns
   - Spread activities across time zones

3. **User Agent Randomization**
   - Rotate browser user agents
   - Match common legitimate traffic
   - Avoid suspicious patterns

4. **Avoid Attribution**
   - Don't reuse infrastructure
   - Separate operations by target
   - Clean metadata from documents

### Detection Avoidance

```python
# Example: Slow, randomized scanning
import time
import random

def slow_scan(targets, delay_min=30, delay_max=300):
    """Scan with random delays to avoid detection"""
    for target in targets:
        # Randomize delay
        delay = random.randint(delay_min, delay_max)
        print(f"[*] Scanning {target} (waiting {delay}s)")
        
        # Perform scan
        scan_target(target)
        
        # Wait before next scan
        time.sleep(delay)
```

---

## 📊 Deliverables

After Phase 1, you should have:

- ✅ Complete DNS record inventory
- ✅ Subdomain enumeration results
- ✅ Email addresses and formats
- ✅ Organizational structure map
- ✅ Technology stack identification
- ✅ Open ports and services
- ✅ Cloud asset inventory
- ✅ Potential vulnerabilities list
- ✅ Attack surface diagram

---

## 🎓 Advanced Topics

### Certificate Transparency Abuse
```python
import requests

def ct_subdomain_enum(domain):
    """Leverage CT logs for subdomain discovery"""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=30)
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '').replace('*.', '')
            if domain in name:
                subdomains.add(name)
        return sorted(subdomains)
    except:
        return []
```

### Shodan Dorking
```python
import shodan

# Common Shodan dorks for reconnaissance
dorks = [
    f'hostname:{domain}',
    f'ssl:{domain}',
    f'org:"{organization}"',
    'port:22,3389 country:US',
    'product:apache,nginx'
]

# Usage requires Shodan API key
# api = shodan.Shodan(API_KEY)
# results = api.search(dorks[0])
```

---

**Next Phase**: [Initial Access →](../02-initial-access/README.md)

**Previous Phase**: [← Project Overview](../../README.md)
