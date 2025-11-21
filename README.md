# 🔍 LFI Scanner

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Security](https://img.shields.io/badge/Security-Tool-red)
![Open Source](https://img.shields.io/badge/Open-Source-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**Advanced Local File Inclusion (LFI) vulnerability detection tool written in Python.**

---

## 🚀 Overview

LFI Scanner is a powerful and efficient tool designed to detect Local File Inclusion vulnerabilities in web applications. It automates the process of testing various LFI payloads across multiple targets with parallel processing capabilities.

### What is LFI?
Local File Inclusion (LFI) is a web vulnerability that allows attackers to include local files on the server through the web application. This can lead to:
- Sensitive information disclosure
- Remote code execution
- System compromise

## ✨ Features

- 🎯 **Comprehensive Payload Testing**: 50+ LFI payloads for Linux, Windows, and PHP applications
- 🔍 **High Performance**: Multi-threaded scanning with configurable thread count
- 🔍 **Smart Detection**: Automatic parameter discovery and intelligent vulnerability detection
- 📊 **Detailed Reporting**: Comprehensive reports with evidence and statistics
- 🛡️ **Stealth Options**: Custom User-Agents and configurable timeouts
- 🎨 **User-Friendly**: Colored console output with verbose logging options
- 🔧 **Flexible Input**: Support for single URLs and bulk target files

## 📦 Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Install
```bash
# Clone the repository
git clone https://github.com/r7al38/lfi-scanner.git
cd lfi-scanner

# Install dependencies
pip3 install -r requirements.txt

# Make script executable (Linux/Mac)
chmod +x lfi_scanner.py
```

## 🚀 Usage
```bash
# Scan a single URL
python3 lfi_scanner.py http://example.com/page.php?file=test

# Scan multiple URLs from file
python3 lfi_scanner.py -f targets.txt

# Verbose mode with custom threads
python3 lfi_scanner.py http://example.com -t 20 -v
```

## 🚀 Advanced Usage
```bash
# Comprehensive scan with output report
python3 lfi_scanner.py http://example.com -t 15 --timeout 10 -v -o scan_report.txt

# Scan with custom User-Agent
python3 lfi_scanner.py http://example.com --user-agent "Mozilla/5.0 (Custom Scanner)"

# Scan from file with specific output
python3 lfi_scanner.py -f targets.txt -o results.txt --timeout 5
```

## 🚀 Output
```bash
╔══════════════════════════════════════════════════════════════╗
║                         LFI SCANNER                          ║
║                    Developed by r7al38                       ║
║                        Version 1.0                           ║
╚══════════════════════════════════════════════════════════════╝

[*] Starting LFI scan on 1 target(s)
[*] Threads: 10, Timeout: 10s
[*] Scanning: http://vulnerable-site.com/include.php?page=index
[*] Found parameters: page, file, template
[+] Found 2 potential LFI vulnerabilities in http://vulnerable-site.com/include.php?page=index
[*] Scan completed in 4.23 seconds

====================================================
LFI SCAN REPORT
====================================================
Scan Date: 2024-01-15 14:30:22
Total Vulnerabilities: 2

Vulnerability #1
----------------------------------------
URL: http://vulnerable-site.com/include.php?page=../../../../etc/passwd
Parameter: page
Payload: ../../../../etc/passwd
Evidence: Found indicator: root:x:0:0:
Status Code: 200
Response Length: 1524
```



