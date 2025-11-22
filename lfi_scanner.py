#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LFI Scanner - Local File Inclusion Vulnerability Detection Tool
Developer: r7al38
Version: 1.0
"""

import requests
import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from payloads import LFI_PAYLOADS, LFI_INDICATORS
import random

class Colors:
    """colors"""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class LFIScanner:
    def __init__(self, threads=10, timeout=10, user_agent=None, verbose=False):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.results = []
        
        # User-Agent
        self.user_agent = user_agent or self.get_random_user_agent()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
    
    def get_random_user_agent(self):
        """random User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0'
        ]
        return random.choice(user_agents)
    
    def print_banner(self):
        
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════╗
║          ██╗     ███████╗  ██████╗        ║
║          ██║     ██╔════╝    ██║          ║
║          ██║     █████╗      ██║          ║
║          ██║     ██╔══╝      ██║          ║
║          ███████╗██║       ██████╗        ║
║          ╚══════╝╚═╝       ══════╝        ║
║                                           ║
║         Local File Inclusion Scanner      ║
║             Developed by r7al38           ║
║                 Version 1.0               ║
╚═══════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def log(self, message, level="info"):
        
        if level == "info":
            print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")
        elif level == "success":
            print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")
        elif level == "warning":
            print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")
        elif level == "error":
            print(f"{Colors.RED}[-]{Colors.RESET} {message}")
        elif level == "verbose" and self.verbose:
            print(f"{Colors.CYAN}[~]{Colors.RESET} {message}")
    
    def test_lfi_payload(self, url, param, payload):
        """اختبار payload LFI واحد"""
        try:
            # Creat URL with payload
            test_url = f"{url}?{param}={payload}"
            
            if self.verbose:
                self.log(f"Testing: {test_url}", "verbose")
            
            # 
            response = self.session.get(
                test_url, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # التحقق من وجود مؤشرات LFI
            is_vulnerable, evidence = self.check_lfi_indicators(response.text, payload)
            
            if is_vulnerable:
                return {
                    'url': test_url,
                    'param': param,
                    'payload': payload,
                    'evidence': evidence,
                    'status_code': response.status_code,
                    'response_length': len(response.text)
                }
            
        except requests.RequestException as e:
            if self.verbose:
                self.log(f"Request failed: {e}", "verbose")
        except Exception as e:
            if self.verbose:
                self.log(f"Error: {e}", "verbose")
        
        return None
    
    def check_lfi_indicators(self, response_text, payload):
        """التحقق من مؤشرات LFI في النص"""
        response_lower = response_text.lower()
        
        for indicator in LFI_INDICATORS:
            if indicator.lower() in response_lower:
                return True, f"Found indicator: {indicator}"
        
        # التحقق من محتويات ملفات النظام
        file_indicators = {
            '/etc/passwd': ['root:', 'daemon:', 'bin:'],
            '/etc/hosts': ['localhost', '127.0.0.1'],
            '/proc/version': ['linux version', 'gcc version'],
            '/etc/group': ['root:', 'wheel:', 'admin:'],
            '/etc/shadow': ['root:$', 'bin:$'],
            '/etc/issue': ['ubuntu', 'debian', 'centos'],
            '/proc/self/environ': ['path=', 'pwd='],
            '/windows/win.ini': ['[fonts]', '[extensions]'],
            'c:\\windows\\win.ini': ['[fonts]', '[extensions]']
        }
        
        for file, indicators in file_indicators.items():
            if file in payload.lower():
                for ind in indicators:
                    if ind.lower() in response_lower:
                        return True, f"File content detected: {ind}"
        
        # التحقق من أخطاء PHP
        php_errors = [
            'failed to open stream',
            'no such file or directory',
            'file not found',
            'warning: include',
            'warning: require'
        ]
        
        for error in php_errors:
            if error in response_lower:
                return True, f"PHP error: {error}"
        
        return False, ""
    
    def discover_parameters(self, url):
        """اكتشاف المعلمات في URL"""
        params = []
        
        # معلمات شائعة لـ LFI
        common_params = [
            'file', 'page', 'path', 'template', 'load', 'include',
            'doc', 'document', 'view', 'content', 'filename', 'template',
            'pg', 'p', 'q', 'cat', 'dir', 'display', 'read', 'loc'
        ]
        
        # إضافة المعلمات من الـ URL نفسه
        parsed = urlparse(url)
        if parsed.query:
            from urllib.parse import parse_qs
            query_params = parse_qs(parsed.query)
            params.extend(query_params.keys())
        
        # إضافة المعلمات الشائعة
        params.extend(common_params)
        
        # إزالة التكرارات
        return list(set(params))
    
    def scan_url(self, url):
        """فحص URL واحد لثغرات LFI"""
        self.log(f"Scanning: {url}")
        
        # اكتشاف المعلمات
        params = self.discover_parameters(url)
        
        if not params:
            self.log("No parameters found to test", "warning")
            return []
        
        self.log(f"Found parameters: {', '.join(params)}")
        
        vulnerabilities = []
        tested_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for param in params:
                for payload in LFI_PAYLOADS:
                    future = executor.submit(self.test_lfi_payload, url, param, payload)
                    futures.append(future)
                    tested_count += 1
            
            # جمع النتائج
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
        
        self.log(f"Tested {tested_count} payloads on {url}")
        return vulnerabilities
    
    def scan_multiple_urls(self, urls):
        """فحص قائمة من URLs"""
        all_vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                    
                    if vulnerabilities:
                        self.log(f"Found {len(vulnerabilities)} vulnerabilities in {url}", "success")
                    else:
                        self.log(f"No vulnerabilities found in {url}")
                        
                except Exception as e:
                    self.log(f"Error scanning {url}: {e}", "error")
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities, output_file=None):
        """إنشاء تقرير بالنتائج"""
        if not vulnerabilities:
            self.log("No vulnerabilities found", "warning")
            return
        
        self.log(f"Found {len(vulnerabilities)} potential LFI vulnerabilities!", "success")
        
        report = []
        report.append("=" * 80)
        report.append("LFI SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Vulnerabilities: {len(vulnerabilities)}")
        report.append("")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(f"Vulnerability #{i}")
            report.append("-" * 40)
            report.append(f"URL: {vuln['url']}")
            report.append(f"Parameter: {vuln['param']}")
            report.append(f"Payload: {vuln['payload']}")
            report.append(f"Evidence: {vuln['evidence']}")
            report.append(f"Status Code: {vuln['status_code']}")
            report.append(f"Response Length: {vuln['response_length']}")
            report.append("")
        
        # عرض النتائج على الشاشة
        for line in report:
            print(line)
        
        # حفظ في ملف إذا طلب
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(report))
                self.log(f"Report saved to: {output_file}", "success")
            except Exception as e:
                self.log(f"Failed to save report: {e}", "error")
        
        return report
    
    def run(self, targets, output_file=None):
        """تشغيل الفحص"""
        self.print_banner()
        
        start_time = time.time()
        
        if isinstance(targets, str):
            targets = [targets]
        
        self.log(f"Starting LFI scan on {len(targets)} target(s)")
        self.log(f"Threads: {self.threads}, Timeout: {self.timeout}s")
        
        vulnerabilities = self.scan_multiple_urls(targets)
        
        scan_time = time.time() - start_time
        self.log(f"Scan completed in {scan_time:.2f} seconds")
        
        self.generate_report(vulnerabilities, output_file)
        
        return vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='LFI Scanner - Local File Inclusion Detection Tool')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    if not args.target and not args.file:
        parser.print_help()
        return
    
    # تحميل الأهداف
    targets = []
    
    if args.target:
        targets.append(args.target)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        except FileNotFoundError:
            print(f"{Colors.RED}[-] File not found: {args.file}{Colors.RESET}")
            return
    
    if not targets:
        print(f"{Colors.RED}[-] No valid targets specified{Colors.RESET}")
        return
    
    # تشغيل الماسح
    scanner = LFIScanner(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        verbose=args.verbose
    )
    
    try:
        scanner.run(targets, args.output)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Unexpected error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
