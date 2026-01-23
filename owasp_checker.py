#!/usr/bin/env python3
"""
OT10-Scanner: Master Runner Framework
=====================================
Usage:
  python owasp_checker.py -u <URL> [-sqli] [-lfi] [-ssrf] [-misconfig] [-All]
"""
import argparse
import sys
import subprocess
import os
import json
from evasion_utils import EvasionEngine, ResultsLogger

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    END = '\033[0m'

BANNER = f"""{Colors.BLUE}
  ██████╗ ████████╗ ██╗ ██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██╔═══██╗╚══██╔══╝███║██╔═████╗      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║   ██║   ██║   ╚██║██║██╔██║█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║   ██║   ██║    ██║██╚████╔╝╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚██████╔╝   ██║    ██║╚██████╔╝      ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═════╝    ╚═╝    ╚═╝ ╚═════╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Colors.END}                               {Colors.BOLD}v1.2 - Industrial OWASP Top 10 Framework{Colors.END}
"""

def run_module(script_name, args_list):
    """Executes a sub-module script"""
    cmd = [sys.executable, script_name] + args_list
    print(f"[*] {Colors.BLUE}Executing Module{Colors.END}: {' '.join(cmd)}")
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"{Colors.RED}[!] Error running module {script_name}: {e}{Colors.END}")

def main():
    ResultsLogger.clear_results()
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="OT-10 Master Runner: Orchestrating Industrial Exploitation",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Define Argument Groups for Professional UI
    target_group = parser.add_argument_group(f'{Colors.BOLD}🎯 INDUSTRIAL TARGETING{Colors.END}')
    auth_group = parser.add_argument_group(f'{Colors.BOLD}🔑 GLOBAL AUTHENTICATION{Colors.END}')
    module_group = parser.add_argument_group(f'{Colors.BOLD}☣️ EXPLOITATION MODULES{Colors.END}')
    stealth_group = parser.add_argument_group(f'{Colors.BOLD}🕵️‍♂️ STEALTH & EXFILTRATION{Colors.END}')
    advanced_group = parser.add_argument_group(f'{Colors.BOLD}⚡ ADVANCED CONTROL{Colors.END}')

    # 1. Industrial Targeting
    target_group.add_argument("-u", "--url", help="Target URL (e.g., http://target.com/file.php)")
    target_group.add_argument("-r", "--request", help="Industrial Request File (Burp/Raw HTTP)")
    target_group.add_argument("-p", "--param", action="append", help="Target unique parameter")
    target_group.add_argument("-e", "--encode", choices=['none', 'url', 'double', 'unicode', 'all'], default='none', help="Global Evasion Encoding")

    # 2. Global Authentication
    auth_group.add_argument("--cookie", help="Custom cookie for authenticated scans")
    auth_group.add_argument("--header", action='append', help="Custom headers (can be used multiple times)")

    # 3. Exploitation Modules
    module_group.add_argument("-sqli", action="store_true", help="Trigger SD-QLi (SQL Injection)")
    module_group.add_argument("-lfi", action="store_true", help="Trigger LFiller (LFI/Traversal)")
    module_group.add_argument("-ssrf", action="store_true", help="Trigger SSRFPro (SSRF/Metadata)")
    module_group.add_argument("-misconfig", action="store_true", help="Trigger InfoHunter (Misconfigs)")
    module_group.add_argument("-rce", action="store_true", help="Trigger RCE-Fuzzer (SSTI/Upload)")
    module_group.add_argument("-All", action="store_true", help="Execute full industrial suite")

    # 4. Stealth & Exfiltration
    stealth_group.add_argument("-w", "--webshell", action="store_true", help="Deploy randomized secure WebShell via LFI")
    stealth_group.add_argument("-lh", "--lhost", help="Local IP for reverse shell")
    stealth_group.add_argument("-lp", "--lport", type=int, default=4444, help="Local Port for reverse shell")
    stealth_group.add_argument("-ex", "--external", help="External callback for Blind SSRF")

    # 5. Advanced Control
    advanced_group.add_argument("--extra", help="Pass direct flags to sub-modules (e.g., '--extra \"--dbs\"')")

    args = parser.parse_args()

    if not args.url and not args.request:
        parser.print_help()
        sys.exit(1)

    url = args.url
    extra_args = []
    
    # Collect all flags to pass down
    if args.request: extra_args += ["-r", args.request]
    if args.encode != 'none': extra_args += ["-e", args.encode]
    if args.cookie: extra_args += ["--cookie", args.cookie]
    if args.header:
        for head in args.header: extra_args += ["--header", head]
    if args.lhost:
        extra_args += ["--lhost", args.lhost]
        extra_args += ["--lport", str(args.lport)]
    if args.webshell: extra_args += ["-w"]
    if args.param:
        for p in args.param: extra_args += ["-p", p]
    if args.extra:
        # Split extra arguments and append
        extra_args += args.extra.split()

    # Module Execution Logic
    target_args = ["-u", url] if url else []
    
    if args.sqli or args.All:
        run_module("sd-qli.py", target_args + extra_args)

    if args.lfi or args.All:
        run_module("lfiller.py", target_args + extra_args)

    if args.ssrf or args.All:
        ssrf_args = target_args + extra_args
        if args.external: ssrf_args += ["-ex", args.external]
        run_module("ssrf_pro.py", ssrf_args)

    if args.misconfig or args.All:
        run_module("infohunter.py", target_args + extra_args)

    if args.rce or args.All:
        run_module("rce_fuzzer.py", target_args + extra_args)

    display_summary(url or "request_file")

def display_summary(target_url):
    """Consolidated Audit Summary with Manual Proofs & Persistence"""
    if not os.path.exists("audit_results.json"):
        print(f"\n[*] {Colors.YELLOW}No industrial vulnerabilities detected during this run.{Colors.END}")
        return

    try:
        with open("audit_results.json", "r") as f:
            findings = json.load(f)
    except:
        return

    try:
        # Robust domain extraction
        clean_url = target_url.replace('http://', '').replace('https://', '')
        domain = clean_url.split('/')[0].replace(':', '_')
        if not os.path.exists(domain):
            os.makedirs(domain)
    except:
        domain = "general_results"
        if not os.path.exists(domain): os.makedirs(domain)

    print("\n" + "="*80)
    print(f"{Colors.BOLD}{Colors.GREEN}CONSOLIDATED AUDIT REPORT - {len(findings)} FINDINGS{Colors.END}")
    print("="*80)

    for i, finding in enumerate(findings, 1):
        print(f"\n{Colors.BOLD}[{i}] {finding['type']}{Colors.END}")
        print(f"  Module: {Colors.CYAN}{finding['module']}{Colors.END}")
        print(f"  Target: {Colors.YELLOW}{finding['url']}{Colors.END}")
        if finding.get('vector'):
            print(f"  {Colors.BOLD}Vector:{Colors.END} {finding['vector']}")
        print(f"  {Colors.BOLD}Manual Proof:{Colors.END} {finding['proof']}")

        report_file = os.path.join(domain, f"bounty_{i}.txt")
        with open(report_file, "w") as rf:
            rf.write(f"VULNERABILITY REPORT #{i}\n")
            rf.write("="*30 + "\n")
            rf.write(f"Type:   {finding['type']}\n")
            rf.write(f"Module: {finding['module']}\n")
            rf.write(f"Target: {finding['url']}\n")
            if finding.get('vector'): rf.write(f"Vector: {finding['vector']}\n")
            if finding.get('description'): rf.write(f"\nDESCRIPTION:\n{finding['description']}\n")
            rf.write("\nMANUAL REPRODUCTION STEPS:\n")
            rf.write("-" * 25 + "\n")
            rf.write(f"1. Proof of Concept Command:\n   {finding['proof']}\n")
            rf.write(f"2. Observe the results.\n")
            rf.write("\nCreated by OT10-Scanner Industrial Suite\n")

    print(f"\n[*] {Colors.GREEN}All findings saved to directory{Colors.END}: {domain}/")
    print("\n" + "="*80)
    print(f"{Colors.BOLD}AUDIT COMPLETE{Colors.END}")
    print("="*80)

if __name__ == "__main__":
    main()
