# OT10-Scanner: Industrial OWASP Top 10 Framework

OT10-Scanner is a modular, industrial-grade automated security auditing framework designed specifically for Bug Bounty hunters. It orchestrates a suite of specialized modules to hunt for OWASP Top 10 vulnerabilities with a heavy focus on WAF evasion and actionable proofs.

## 🚀 Key Features

- **Industrial Orchestration**: A single master runner (`owasp_checker.py`) that manages high-tier specialized modules.
- **Advanced Evasion Engine**: Over 150+ payload variations using multi-layer encoding (Double-URL, Unicode, HPP) and junk header injection.
- **WAF Fingerprinting**: Built-in detection for Cloudflare, Akamai, Imperva, AWS WAF, and more.
- **Consolidated Reporting**: Domain-specific persistence that auto-generates folders and individual bounty reports with manual reproduction proofs.
- **Safety First**: Non-destructive, read-only logic with strict exfiltration limits (e.g., max 20 records for SQLi).
- **Global Auth Support**: Single-flag cookie and header injection across all modules.

## 🛠️ Specialized Modules

| Module | Core Capability | Status |
| :--- | :--- | :--- |
| `sd-qli.py` | Advanced SQL Injection (Error, Time, Boolean) | 🛡️ Shielded |
| `ssrf_pro.py` | SSRF & Redirect Bypass (Cloud Metadata, IP Obfuscation) | ☁️ Cloud-Ready |
| `lfiller.py` | Advanced LFI/RCE (Log & SSH Poisoning, PHP Wrappers) | ☣️ V2.0 High-Impact |
| `infohunter.py` | Misconfig & Info Disclosure "Quick Wins" | 💸 Profitable |
| `access_checker.py` | IDOR & Broken Access Control Discovery | 🔑 Critical |
| `rce_fuzzer.py` | SSTI & Safe File Upload Probes | ⚡ High-Impact |

## 📖 Usage Examples

### 1. Full Audit Suite (The "Carpet Bomb")
Run all modules with advanced evasion:
```bash
python owasp_checker.py -u http://target.com -All -e all -lh <IP> -w
```

### 2. Authenticated LFI Scan
```bash
python owasp_checker.py -u http://target.com -lfi --cookie "session=123"
```

### 3. Blind SSRF with External Callback
```bash
python owasp_checker.py -u http://target.com -ssrf -ex your.callback.server.com
```

### 4. Custom Parameter Targeting
```bash
python owasp_checker.py -u http://target.com -lfi -p "water" -p "source"
```

### 5. Targeted SQL Injection
```bash
python owasp_checker.py -u http://target.com -sqli --extra "--dbs --dump"
```

## 🛡️ Safety & Responsibility

This tool is built for **authorized security auditing only**. 
- It uses **read-only** logic.
- It **does not** delete, modify, or corrupt data.
- It **limits** data exfiltration to the minimal proof required for a bounty report.

## 📜 License
*Created by Antigravity - Advanced Agentic Coding Team*
