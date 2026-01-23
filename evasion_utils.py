import json
import os
import urllib.parse
from threading import Lock

class EvasionEngine:
    @staticmethod
    def parse_request_file(file_path):
        """Ultra-robust request parser. Optimized for atypical whitespace/formatting."""
        try:
            if not os.path.exists(file_path):
                return None
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_content = f.read()
            
            if not raw_content.strip(): return None
            
            all_lines = [l.strip() for l in raw_content.splitlines()]
            valid_lines = [l for l in all_lines if l]
            
            if not valid_lines: return None
            
            req_line = valid_lines[0]
            req_parts = req_line.split()
            if len(req_parts) < 2: return None
            method = req_parts[0]
            path = req_parts[1]
            
            headers = {}
            host = ""
            for line in valid_lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
                    if k.strip().lower() == 'host':
                        host = v.strip()
            
            body = ""
            if '\r\n\r\n' in raw_content:
                body = raw_content.split('\r\n\r\n', 1)[1].strip()
            elif '\n\n' in raw_content and '\n\nHost:' not in raw_content: 
                body = raw_content.split('\n\n', 1)[1].strip()
            
            if not body or (method == 'POST' and '=' not in body):
                for line in valid_lines[1:]:
                    if '=' in line and ':' not in line:
                        body = line
                        break
            
            if not host and 'Host' in headers: host = headers['Host']
            
            schema = "https://" if "443" in host else "http://"
            if path.startswith('http'):
                url = path
            elif not host:
                url = path
            else:
                sep = "" if path.startswith('/') else "/"
                url = f"{schema}{host}{sep}{path}"
            
            return {
                'url': url,
                'method': method,
                'headers': headers,
                'data': body if body else None
            }
        except Exception:
            return None

class ResultsLogger:
    lock = Lock()
    results_file = "audit_results.json"

    @classmethod
    def clear_results(cls):
        if os.path.exists(cls.results_file):
            os.remove(cls.results_file)

    @classmethod
    def log_finding(cls, module, type, url, proof, vector="", description=""):
        with cls.lock:
            findings = []
            if os.path.exists(cls.results_file):
                try:
                    with open(cls.results_file, "r") as f:
                        findings = json.load(f)
                except:
                    findings = []
            
            finding = {
                "module": module,
                "type": type,
                "url": url,
                "proof": proof,
                "vector": vector,
                "description": description
            }
            
            # Avoid exact duplicates
            if finding not in findings:
                findings.append(finding)
                with open(cls.results_file, "w") as f:
                    json.dump(findings, f, indent=4)
