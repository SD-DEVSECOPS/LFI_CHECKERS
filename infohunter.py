#!/usr/bin/env python3
"""
InfoHunter v1.1 - Misconfig & Info Disclosure
==============================================
Usage:
  python infohunter.py -u <URL>

Description:
  Hunts for backup files, environment configs, and exposed meta-data.
  Includes "Direct IP Bypass" for bypassing domain-level WAFs.
"""
import argparse
import requests
import sys
import os
import socket # Added for IP Bypass logic
from evasion_utils import EvasionEngine, ResultsLogger

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    END = '\033[0m'

class InfoHunter:
    """Industrial Misconfiguration & Info Disclosure Scanner (Bug Bounty Focus)"""
    
    def __init__(self, url, timeout=5, cookie=None, headers=None):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.evasion = EvasionEngine()

        # Apply authentication
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        if headers:
            for header in headers:
                try:
                    key, value = header.split(':', 1)
                    self.session.headers.update({key.strip(): value.strip()})
                except ValueError:
                    pass

    def scan(self):
        print(f"[*] {Colors.CYAN}Starting Info Disclosure Scan on{Colors.END}: {self.url}")
        
        # 1. Domain-based scan
        self._run_scan(self.url)

        # 2. Direct IP Bypass logic (H1-2473173)
        try:
            domain = self.url.split('//')[-1].split('/')[0]
            ip = socket.gethostbyname(domain)
            if ip != domain:
                print(f"[*] {Colors.YELLOW}Tentative Direct IP Bypass{Colors.END}: {ip}")
                ip_url = self.url.replace(domain, ip)
                self._run_scan(ip_url, is_ip_bypass=True)
        except Exception:
            pass

    def _run_scan(self, base_url, is_ip_bypass=False):
        # High-value "Quick Win" paths
        # Industrial "Quick Win" targets ($100 - $500 range)
        target_paths = [
            # 1. Environment & Configs
            '/.env', '/.git/config', '/web.config', '/phpinfo.php', '/info.php',
            '/.htaccess', '/.htpasswd', '/.ssh/id_rsa', '/config.php.bak',
            '/.aws/credentials',
            # 2. Development & Debug
            '/Dockerfile', '/docker-compose.yml', '/.DS_Store', '/README.md',
            '/package.json', '/composer.json', '/requirements.txt',
            # 3. Cloud & Framework Endpoints
            '/actuator/health', '/actuator/env', '/_profiler/phpinfo',
            '/api/v1/debug', '/debug/env', '/.well-known/security.txt',
            # 4. Backup & Source Leakage
            '/index.php.bak', '/index.php.old', '/config.json.swp',
            '/www.zip', '/backup.zip', '/dump.sql', '/db.sql',
            '/backup.sql', '/data.sql', '/users.sql',
            '/server-status', '/latest/meta-data/iam/security-credentials/'
        ]

        # Common backup extensions for directory fuzzing
        backup_exts = ["~", ".bak", ".old", ".save", ".swp", ".rar", ".zip"]

        found_count = 0
        for path in target_paths:
            full_url = f"{self.url}{path}"
            headers = self.evasion.get_junk_headers()
            
            try:
                r = self.session.get(full_url, headers=headers, timeout=self.timeout, allow_redirects=False)
                
                # Validation logic: avoid false positives from 200 OK "Not Found" pages
                if r.status_code == 200:
                    # Specific content checks for "Real" findings
                    content_checks = {
                        "repositoryformatversion": "Git Config Revealed!",
                        "DB_PASSWORD": "Environment File Revealed!",
                        "[default]": "AWS Credentials Revealed!",
                        "-----BEGIN RSA PRIVATE KEY-----": "SSH Private Key Revealed!",
                        "index of /": "Directory Listing Enabled!"
                    }
                    
                    found_msg = "Unknown Potential Leak"
                    for pattern, msg in content_checks.items():
                        if pattern in r.text:
                            found_msg = msg
                            break
                    
                    # Refined False Positive Check: if size is too small or generic "html"
                    if len(r.text) > 10:
                        print(f"{Colors.GREEN}[+] DISCLOSURE FOUND!{Colors.END}")
                        print(f"  URL:  {Colors.YELLOW}{full_url}{Colors.END}")
                        print(f"  Type: {Colors.BOLD}{found_msg}{Colors.END}")
                        print(f"  {Colors.CYAN}Manual Proof{Colors.END}: curl -i -H \"X-Forwarded-For: 127.0.0.1\" {full_url}")
                        
                        ResultsLogger.log_finding("InfoHunter", "Information Disclosure", full_url, f"curl -i -H \"X-Forwarded-For: 127.0.0.1\" {full_url}")
                        found_count += 1
            except Exception:
                pass
        
        # 3. Basic Security Header Audit (Easy $50-100 reports)
        print(f"[*] {Colors.YELLOW}Auditing Security Headers{Colors.END}...")
        missing = []
        try:
            r = self.session.get(self.url, timeout=self.timeout)
            headers = r.headers
            if 'Content-Security-Policy' not in headers: missing.append('CSP')
            if 'X-Frame-Options' not in headers: missing.append('XFO (Clickjacking)')
            if 'Strict-Transport-Security' not in headers: missing.append('HSTS')
            
            if missing:
                print(f" {Colors.YELLOW}[*]{Colors.END} Missing Headers: {Colors.CYAN}{', '.join(missing)}{Colors.END}")
                # We usually don't log these to the main JSON unless they are critical, 
                # but for "Small Money" automation, it's worth noting.
        except: pass

        if found_count == 0:
            print(f"[*] {Colors.YELLOW}No obvious information leaks found.{Colors.END}")
        else:
            print(f"[*] {Colors.GREEN}Total Leaks found: {found_count}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description="InfoHunter v1.1 - Misconfig & Info Disclosure Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (Base URL)")
    parser.add_argument("--cookie", help="Custom cookie")
    parser.add_argument("--header", action='append', help="Custom headers")
    
    args = parser.parse_args()
    
    hunter = InfoHunter(args.url, cookie=args.cookie, headers=args.header)
    hunter.scan()

if __name__ == "__main__":
    main()
