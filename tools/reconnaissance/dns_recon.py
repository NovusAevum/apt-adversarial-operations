#!/usr/bin/env python3
"""
Advanced DNS Reconnaissance Tool
Enterprise-grade DNS enumeration with multiple techniques
Author: Wan Mohamad Hanis bin Wan Hassan
"""

import dns.resolver
import dns.query
import dns.zone
import concurrent.futures
import argparse
import logging
import json
from typing import List, Dict, Set
from datetime import datetime

class DNSReconPro:
    """Professional DNS reconnaissance framework"""
    
    def __init__(self, domain: str, nameservers: List[str] = None, verbose: bool = False):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        
        self.results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'records': {},
            'subdomains': set(),
            'nameservers': [],
            'mail_servers': [],
            'zone_transfer': False
        }
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
    
    def query_record_type(self, record_type: str) -> List[str]:
        """Query specific DNS record type with error handling"""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            records = [str(rdata) for rdata in answers]
            self.results['records'][record_type] = records
            self.logger.info(f"✓ Found {len(records)} {record_type} records")
            return records
        except dns.resolver.NXDOMAIN:
            self.logger.error(f"✗ Domain {self.domain} does not exist")
            return []
        except dns.resolver.NoAnswer:
            self.logger.debug(f"○ No {record_type} records found")
            return []
        except dns.exception.Timeout:
            self.logger.warning(f"⚠ Timeout querying {record_type}")
            return []
        except Exception as e:
            self.logger.error(f"✗ Error querying {record_type}: {e}")
            return []
    
    def comprehensive_enum(self) -> Dict:
        """Enumerate all common DNS record types"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
        
        self.logger.info(f"Starting comprehensive enumeration for {self.domain}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(record_types)) as executor:
            futures = {
                executor.submit(self.query_record_type, rtype): rtype 
                for rtype in record_types
            }
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    rtype = futures[future]
                    self.logger.error(f"Failed to process {rtype}: {e}")
        
        # Extract nameservers and mail servers for further analysis
        self.results['nameservers'] = self.results['records'].get('NS', [])
        self.results['mail_servers'] = self.results['records'].get('MX', [])
        
        return self.results
    
    def attempt_zone_transfer(self) -> bool:
        """Attempt AXFR zone transfer on all nameservers"""
        nameservers = self.results.get('nameservers', [])
        
        if not nameservers:
            self.logger.warning("⚠ No nameservers found for zone transfer attempt")
            return False
        
        self.logger.info(f"Attempting zone transfer on {len(nameservers)} nameservers")
        
        for ns in nameservers:
            try:
                # Remove trailing dot if present
                ns_clean = ns.rstrip('.')
                
                self.logger.debug(f"Trying AXFR on {ns_clean}")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, self.domain))
                
                # Zone transfer successful!
                self.logger.critical(f"🚨 ZONE TRANSFER SUCCESSFUL on {ns_clean}!")
                self.results['zone_transfer'] = True
                
                # Extract all records from zone
                zone_records = []
                for name, node in zone.nodes.items():
                    record_name = f"{name}.{self.domain}" if name.to_text() != '@' else self.domain
                    for rdataset in node.rdatasets:
                        zone_records.append({
                            'name': record_name,
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'data': [str(rdata) for rdata in rdataset]
                        })
                        # Add to subdomains
                        if record_name != self.domain:
                            self.results['subdomains'].add(record_name)
                
                self.results['zone_transfer_data'] = zone_records
                return True
                
            except dns.exception.FormError:
                self.logger.debug(f"✗ Zone transfer refused by {ns_clean}")
            except Exception as e:
                self.logger.debug(f"✗ Zone transfer failed on {ns_clean}: {e}")
        
        self.logger.info("○ Zone transfer not possible on any nameserver")
        return False
    
    def subdomain_bruteforce(self, wordlist_file: str = None, max_workers: int = 50) -> Set[str]:
        """Bruteforce subdomains using wordlist"""
        
        # Default common subdomains
        default_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'vpn', 'portal', 'api',
            'admin', 'dev', 'staging', 'test', 'prod', 'production', 'uat', 'demo', 'beta',
            'blog', 'forum', 'shop', 'store', 'cdn', 'static', 'media', 'assets', 'images',
            'm', 'mobile', 'remote', 'ssh', 'git', 'svn', 'jenkins', 'gitlab', 'jira'
        ]
        
        # Load wordlist if provided
        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(wordlist)} subdomains from {wordlist_file}")
            except Exception as e:
                self.logger.error(f"Failed to load wordlist: {e}")
                wordlist = default_subdomains
        else:
            wordlist = default_subdomains
        
        self.logger.info(f"Bruteforcing {len(wordlist)} potential subdomains...")
        
        discovered = set()
        
        def check_subdomain(sub):
            try:
                fqdn = f"{sub}.{self.domain}"
                answers = self.resolver.resolve(fqdn, 'A')
                return fqdn, [str(rdata) for rdata in answers]
            except:
                return None, None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            
            for future in concurrent.futures.as_completed(futures):
                fqdn, ips = future.result()
                if fqdn:
                    discovered.add(fqdn)
                    self.results['subdomains'].add(fqdn)
                    self.logger.info(f"✓ Discovered: {fqdn} -> {', '.join(ips)}")
        
        self.logger.info(f"Discovered {len(discovered)} subdomains via bruteforce")
        return discovered
    
    def certificate_transparency(self) -> Set[str]:
        """Query certificate transparency logs for subdomains"""
        import requests
        
        self.logger.info("Querying Certificate Transparency logs...")
        
        subdomains = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                for entry in response.json():
                    name_value = entry.get('name_value', '').lower()
                    # Handle multi-line and wildcard entries
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain and subdomain.endswith(self.domain):
                            subdomains.add(subdomain)
                            self.results['subdomains'].add(subdomain)
                
                self.logger.info(f"✓ Found {len(subdomains)} subdomains via Certificate Transparency")
        except Exception as e:
            self.logger.error(f"✗ Certificate Transparency lookup failed: {e}")
        
        return subdomains
    
    def export_results(self, format: str = 'json', filename: str = None):
        """Export results to file"""
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"dns_recon_{self.domain}_{timestamp}.{format}"
        
        # Convert sets to lists for JSON serialization
        export_data = self.results.copy()
        export_data['subdomains'] = sorted(list(export_data['subdomains']))
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            self.logger.info(f"✓ Results exported to {filename}")
        
        elif format == 'txt':
            with open(filename, 'w') as f:
                f.write(f"DNS Reconnaissance Results for {self.domain}\n")
                f.write(f"Timestamp: {export_data['timestamp']}\n")
                f.write("=" * 70 + "\n\n")
                
                for rtype, records in export_data['records'].items():
                    f.write(f"\n{rtype} Records:\n")
                    for record in records:
                        f.write(f"  {record}\n")
                
                if export_data['subdomains']:
                    f.write(f"\n\nDiscovered Subdomains ({len(export_data['subdomains'])}):\n")
                    for subdomain in sorted(export_data['subdomains']):
                        f.write(f"  {subdomain}\n")
            
            self.logger.info(f"✓ Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced DNS Reconnaissance Tool - Enterprise Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic enumeration
  python dns_recon.py -d example.com
  
  # Full reconnaissance with all techniques
  python dns_recon.py -d example.com --full
  
  # Subdomain bruteforce with custom wordlist
  python dns_recon.py -d example.com -w subdomains.txt
  
  # Export results to JSON
  python dns_recon.py -d example.com --full -o results.json
        '''
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-ns', '--nameservers', nargs='+', help='Custom nameservers')
    parser.add_argument('-w', '--wordlist', help='Subdomain wordlist file')
    parser.add_argument('--full', action='store_true', help='Run all reconnaissance techniques')
    parser.add_argument('--zone-transfer', action='store_true', help='Attempt zone transfer')
    parser.add_argument('--ct', action='store_true', help='Query Certificate Transparency')
    parser.add_argument('--bruteforce', action='store_true', help='Bruteforce subdomains')
    parser.add_argument('-o', '--output', help='Output file (JSON or TXT)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads for bruteforce')
    
    args = parser.parse_args()
    
    # Initialize reconnaissance
    recon = DNSReconPro(args.domain, args.nameservers, args.verbose)
    
    # Comprehensive enumeration
    recon.comprehensive_enum()
    
    # Optional techniques
    if args.full or args.zone_transfer:
        recon.attempt_zone_transfer()
    
    if args.full or args.ct:
        recon.certificate_transparency()
    
    if args.full or args.bruteforce:
        recon.subdomain_bruteforce(args.wordlist, args.threads)
    
    # Export results
    if args.output:
        format = 'json' if args.output.endswith('.json') else 'txt'
        recon.export_results(format, args.output)
    else:
        # Print summary
        print("\n" + "=" * 70)
        print(f"DNS Reconnaissance Summary for {args.domain}")
        print("=" * 70)
        print(f"\n✓ Records found: {sum(len(v) for v in recon.results['records'].values())}")
        print(f"✓ Nameservers: {len(recon.results['nameservers'])}")
        print(f"✓ Mail servers: {len(recon.results['mail_servers'])}")
        print(f"✓ Subdomains discovered: {len(recon.results['subdomains'])}")
        
        if recon.results['subdomains']:
            print(f"\nSubdomains:")
            for subdomain in sorted(recon.results['subdomains']):
                print(f"  • {subdomain}")


if __name__ == "__main__":
    main()
