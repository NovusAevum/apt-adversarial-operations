#!/usr/bin/env python3
"""
Advanced Subdomain Enumeration Tool
Combines multiple techniques: DNS brute force, certificate transparency, web scraping
Author: Wan Mohamad Hanis bin Wan Hassan
"""

import dns.resolver
import requests
import concurrent.futures
import json
from typing import Set, List
import time
import sys

class SubdomainEnumerator:
    def __init__(self, domain: str, wordlist: str = None, threads: int = 50):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
        # Default subdomain wordlist
        self.wordlist = wordlist or self._default_wordlist()
    
    def _default_wordlist(self) -> List[str]:
        """Common subdomain names"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'dev', 'staging',
            'test', 'admin', 'portal', 'beta', 'demo', 'vpn', 'remote', 'git', 'gitlab',
            'jenkins', 'jira', 'confluence', 'wiki', 'docs', 'cdn', 'static', 'assets',
            'img', 'images', 'files', 'upload', 'downloads', 'shop', 'store', 'blog',
            'forum', 'support', 'help', 'secure', 'ssl', 'cloud', 'app', 'apps', 'mobile',
            'm', 'wap', 'status', 'monitor', 'prometheus', 'grafana', 'kibana', 'elastic'
        ]
    
    def dns_bruteforce(self) -> Set[str]:
        """Brute force subdomains using DNS queries"""
        print(f"[*] Starting DNS brute force with {len(self.wordlist)} words...")
        
        def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            try:
                self.resolver.resolve(subdomain, 'A')
                return subdomain
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(check_subdomain, self.wordlist)
            
        found = set(filter(None, results))
        self.subdomains.update(found)
        
        print(f"[+] DNS brute force found {len(found)} subdomains")
        return found
    
    def certificate_transparency(self) -> Set[str]:
        """Query certificate transparency logs"""
        print("[*] Querying certificate transparency logs...")
        
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    # Split by newlines (certificate may have multiple SANs)
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain.endswith(self.domain):
                            self.subdomains.add(subdomain)
                
                print(f"[+] Certificate transparency found {len(self.subdomains)} subdomains")
        
        except Exception as e:
            print(f"[!] Certificate transparency error: {e}")
        
        return self.subdomains
    
    def search_engine_discovery(self) -> Set[str]:
        """Use search engines to find subdomains"""
        print("[*] Searching via Google dorking...")
        
        # Google dork to find subdomains
        query = f"site:*.{self.domain}"
        
        # Note: Actual implementation would use Google Custom Search API
        # or scrape results (with rate limiting and CAPTCHA handling)
        print("[*] Search engine discovery requires API key (not implemented in demo)")
        
        return set()
    
    def dns_zone_transfer(self) -> Set[str]:
        """Attempt DNS zone transfer (rarely successful)"""
        print("[*] Attempting DNS zone transfer...")
        
        try:
            # Get nameservers for domain
            ns_records = self.resolver.resolve(self.domain, 'NS')
            
            for ns in ns_records:
                ns_str = str(ns).rstrip('.')
                print(f"[*] Trying zone transfer on {ns_str}")
                
                try:
                    import dns.zone
                    import dns.query
                    
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, self.domain))
                    
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.domain}"
                        self.subdomains.add(subdomain)
                    
                    print(f"[!] ZONE TRANSFER SUCCESSFUL on {ns_str}!")
                    return self.subdomains
                
                except Exception as e:
                    print(f"[*] Zone transfer failed on {ns_str}")
        
        except Exception as e:
            print(f"[!] Could not query nameservers: {e}")
        
        return set()
    
    def enumerate(self) -> Set[str]:
        """Run all enumeration methods"""
        print(f"{'='*60}")
        print(f"Subdomain Enumeration: {self.domain}")
        print(f"{'='*60}\n")
        
        # Method 1: Certificate Transparency (fast, reliable)
        self.certificate_transparency()
        
        # Method 2: DNS brute force
        self.dns_bruteforce()
        
        # Method 3: Zone transfer attempt
        self.dns_zone_transfer()
        
        # Method 4: Search engines
        # self.search_engine_discovery()
        
        print(f"\n{'='*60}")
        print(f"[✓] Total unique subdomains found: {len(self.subdomains)}")
        print(f"{'='*60}\n")
        
        return self.subdomains
    
    def export_results(self, filename: str):
        """Export results to file"""
        with open(filename, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"[+] Results exported to {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        print(f"Example: {sys.argv[0]} example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    enumerator = SubdomainEnumerator(domain, threads=100)
    subdomains = enumerator.enumerate()
    
    # Display results
    print("\nDiscovered subdomains:")
    for subdomain in sorted(subdomains):
        print(f"  - {subdomain}")
    
    # Export to file
    enumerator.export_results(f"subdomains_{domain}.txt")
