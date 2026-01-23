#!/usr/bin/env python3
"""
AccessChecker v1.0 - Industrial IDOR & Access Control Scanner
==============================================================
Usage:
  python access_checker.py -u <URL> -p <PARAM>

Description:
  Hunts for Broken Access Control (IDOR) by manipulating IDs/UUIDs
  and checking for leaked private data or cross-user access.
"""
import sys
import argparse
import requests
from evasion_utils import EvasionEngine, ResultsLogger

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    END = '\033[0m'

class AccessChecker:
    def __init__(self, url, method='GET', timeout=5, cookie=None, headers=None):
        self.url = url
        self.method = method
        self.timeout = timeout
        self.session = requests.Session()

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

    def test_idor(self, param_name, current_val):
        print(f"[*] {Colors.CYAN}Testing IDOR on Param{Colors.END}: {param_name} (Current: {current_val})")
        
        # Variations for ID manipulation
        variations = []
        try:
            val_int = int(current_val)
            variations = [str(val_int - 1), str(val_int + 1), "0", "1", "9999"]
        except:
            # If UUID or Alpha, try basic swaps
            variations = ["admin", "root", "test", "0"]

        for val in variations:
            test_params = {param_name: val}
            try:
                if self.method == 'GET':
                    r = self.session.get(self.url, params=test_params, timeout=self.timeout)
                else:
                    r = self.session.post(self.url, data=test_params, timeout=self.timeout)

                # Detection: checking for sensitive data leakage
                # In real context, we'd compare against a baseline response
                indicators = ["email", "password", "hash", "ssn", "address", "phone"]
                if any(ind in r.text.lower() for ind in indicators):
                    if r.status_code == 200 and len(r.text) > 50:
                        print(f"\n{Colors.GREEN}[+] POTENTIAL IDOR FOUND!{Colors.END}")
                        print(f"  Parameter: {Colors.BOLD}{param_name}{Colors.END}")
                        print(f"  Modified Value: {Colors.YELLOW}{val}{Colors.END}")
                        
                        proof_cmd = f"curl -i \"{self.url}?{param_name}={val}\""
                        print(f"  {Colors.CYAN}Manual Proof{Colors.END}: {proof_cmd}")
                        
                        ResultsLogger.log_finding("AccessChecker", "IDOR / Broken Access Control", self.url, proof_cmd)
                        return True
            except: pass
        return False

def main():
    parser = argparse.ArgumentParser(description="AccessChecker v1.0 - Industrial IDOR Scanner")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-r", "--request", help="Raw request file (Burp-style)")
    parser.add_argument("-p", "--param", help="Target parameter for IDOR")
    parser.add_argument("-v", "--value", help="Initial value for manipulation")
    parser.add_argument("-e", "--encode", choices=['none', 'url', 'double', 'unicode', 'all'], default='none', help="Global Evasion Encoding")
    parser.add_argument("--cookie", help="Custom cookie")
    parser.add_argument("--header", action='append', help="Custom headers")
    
    args = parser.parse_args()
    url = args.url
    if args.request:
        req = EvasionEngine.parse_request_file(args.request)
        if req: url = req['url']
        
    if not url:
        parser.print_help()
        sys.exit(1)

    checker = AccessChecker(url, cookie=args.cookie, headers=args.header)
    checker.test_idor(args.param, args.value)

if __name__ == "__main__":
    main()
