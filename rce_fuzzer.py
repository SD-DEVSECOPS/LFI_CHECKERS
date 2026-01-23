#!/usr/bin/env python3
"""
RCE-Fuzzer v1.1 - Industrial RCE Suite
======================================
Tests for Template Injection (SSTI) and safe Command Injection proofs.
"""
import requests
import argparse
import sys
from evasion_utils import EvasionEngine, ResultsLogger

class Colors:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class RCEFuzzer:
    def __init__(self, url, method='GET', cookie=None, headers=None):
        self.url = url
        self.method = method.upper()
        self.session = requests.Session()
        if cookie: self.session.headers.update({'Cookie': cookie})
        if headers:
            for h in headers:
                try:
                    k, v = h.split(':', 1)
                    self.session.headers.update({k.strip(): v.strip()})
                except: pass

    def test_ssti(self, param, current_params):
        """Proof-based SSTI discovery (No RCE by default)"""
        # Safe math proof: {{7*7}} -> 49
        payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "[[7*7]]"]
        print(f"[*] Testing {Colors.YELLOW}SSTI{Colors.END} on {param}...")
        
        for p in payloads:
            current_params[param] = p
            try:
                if self.method == 'GET': r = self.session.get(self.url, params=current_params)
                else: r = self.session.post(self.url, data=current_params)
                
                if "49" in r.text and "7*7" not in r.text:
                    print(f"  {Colors.GREEN}[+]{Colors.END} Found SSTI: {Colors.CYAN}{p}{Colors.END}")
                    desc = "The application is vulnerable to Server-Side Template Injection. " \
                           "Providing a mathematical expression resulted in the server rendering the result (49)."
                    ResultsLogger.log_finding("RCE-Fuzzer", "Template Injection (SSTI)", self.url, 
                                             f"Payload: {p}", vector=f"Param: {param}", description=desc)
                    return True
            except: pass
        return False

def main():
    parser = argparse.ArgumentParser(description="RCE-Fuzzer v1.1 - Industrial RCE Suite")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-r", "--request", help="Raw request file (Burp-style)")
    parser.add_argument("-p", "--param", help="Target parameter for SSTI/Deserialization")
    parser.add_argument("-e", "--encode", choices=['none', 'url', 'double', 'unicode', 'all'], default='none', help="Global Evasion Encoding")
    parser.add_argument("--cookie", help="Custom cookie")
    parser.add_argument("--header", action='append', help="Custom headers")
    
    args = parser.parse_args()
    
    url = args.url
    headers = {}
    data = None
    method = 'GET'
    
    if args.request:
        print(f"[*] {Colors.CYAN}Parsing request file{Colors.END}: {args.request}")
        req = EvasionEngine.parse_request_file(args.request)
        if req:
            url, method, headers, data = req['url'], req['method'], req['headers'], req['data']
        else: sys.exit(1)
        
    if not url:
        parser.print_help()
        sys.exit(1)
        
    fuzzer = RCEFuzzer(url, method=method, cookie=args.cookie, headers=args.header)
    if headers: fuzzer.session.headers.update(headers)
    
    params = [args.param] if args.param else ["id", "user", "name", "email", "query", "search"]
    for p in params:
        fuzzer.test_ssti(p, {p: "test"})

if __name__ == "__main__":
    main()
