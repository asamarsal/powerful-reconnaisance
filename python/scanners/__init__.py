"""Bug Bounty Toolkit - Scanner Modules.

This package provides complete vulnerability scanners for common web
application security issues including XSS, SQLi, LFI, SSTI, IDOR, SSRF,
CORS misconfigurations, and JWT vulnerabilities.

Usage:
    from scanners import XSSScanner, SQLiScanner, LFIScanner
    from scanners import SSTIScanner, IDORScanner, SSRFScanner
    from scanners import CORSScanner, JWTScanner

    # Initialize scanner
    xss = XSSScanner()
    findings = xss.scan_reflected('https://target.com/search', {'q': 'test'})
"""

from .xss_scanner import XSSScanner
from .sqli_scanner import SQLiScanner
from .lfi_scanner import LFIScanner
from .ssti_scanner import SSTIScanner
from .idor_scanner import IDORScanner
from .ssrf_scanner import SSRFScanner
from .cors_scanner import CORSScanner
from .jwt_scanner import JWTScanner

__all__ = [
    'XSSScanner',
    'SQLiScanner',
    'LFIScanner',
    'SSTIScanner',
    'IDORScanner',
    'SSRFScanner',
    'CORSScanner',
    'JWTScanner',
]
