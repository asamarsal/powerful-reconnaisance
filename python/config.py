"""
Configuration settings for the bug bounty reconnaissance toolkit.

Contains all default settings for timeouts, threading, proxy configuration,
output paths, user agents, and scanner-specific options.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict


# Base paths
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
WORDLISTS_DIR = BASE_DIR / "wordlists"
TEMPLATES_DIR = BASE_DIR / "templates"

# Ensure output directory exists
OUTPUT_DIR.mkdir(exist_ok=True)


@dataclass
class HttpConfig:
    """HTTP client configuration."""
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    verify_ssl: bool = False
    follow_redirects: bool = True
    max_redirects: int = 10
    rate_limit: float = 0.1  # seconds between requests
    max_concurrent: int = 50


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    enabled: bool = False
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    socks5_proxy: Optional[str] = None
    rotate_proxies: bool = False
    proxy_list: List[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    """Scanner configuration."""
    threads: int = 10
    timeout: int = 30
    max_depth: int = 3
    scope_strict: bool = True
    follow_redirects: bool = True
    store_responses: bool = False


@dataclass
class FuzzerConfig:
    """Fuzzer configuration."""
    threads: int = 20
    timeout: int = 15
    delay: float = 0.0
    match_codes: List[int] = field(default_factory=lambda: [200, 201, 202, 204, 301, 302, 307, 401, 403, 405, 500])
    filter_codes: List[int] = field(default_factory=list)
    filter_sizes: List[int] = field(default_factory=list)
    wordlist: str = "common.txt"
    extensions: List[str] = field(default_factory=lambda: [".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".json", ".xml", ".txt", ".bak", ".old", ".conf"])


@dataclass
class BypassConfig:
    """Bypass scanner configuration."""
    threads: int = 10
    timeout: int = 20
    test_all_methods: bool = True
    test_headers: bool = True
    test_path_traversal: bool = True
    test_encoding: bool = True
    success_codes: List[int] = field(default_factory=lambda: [200, 201, 202, 204])


@dataclass
class SecretsConfig:
    """Secrets scanner configuration."""
    scan_js: bool = True
    scan_html: bool = True
    scan_json: bool = True
    scan_responses: bool = True
    max_file_size: int = 5 * 1024 * 1024  # 5MB
    entropy_threshold: float = 4.5


@dataclass
class ReconConfig:
    """Reconnaissance configuration."""
    enumerate_subdomains: bool = True
    port_scan: bool = False
    technology_detection: bool = True
    dns_resolution: bool = True
    whois_lookup: bool = True
    crawl_depth: int = 2


@dataclass
class OutputConfig:
    """Output configuration."""
    output_dir: str = str(OUTPUT_DIR)
    format: str = "json"  # json, csv, html
    verbose: bool = True
    color: bool = True
    save_responses: bool = False
    log_file: Optional[str] = None


# User-Agent rotation list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# Default headers for requests
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}

# Common bypass headers
BYPASS_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "X-Host",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "X-ProxyUser-Ip",
    "True-Client-IP",
    "Cluster-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Azure-ClientIP",
]

# Bypass header values to try
BYPASS_IPS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.0.1",
    "192.168.1.1",
    "::1",
    "0177.0.0.1",
    "0x7f000001",
    "2130706433",
]

# Secret patterns for scanning
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "google_api_key": r"AIza[0-9A-Za-z\\-_]{35}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "stripe_key": r"(?:r|s)k_live_[0-9a-zA-Z]{24}",
    "jwt_token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "generic_api_key": r"(?i)(?:api[_-]?key|apikey|api_secret|api_token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,64}['\"]",
    "generic_secret": r"(?i)(?:secret|password|passwd|pwd|token)['\"]?\s*[:=]\s*['\"][^\s'\"]{8,64}['\"]",
    "authorization_bearer": r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    "authorization_basic": r"(?i)basic\s+[a-zA-Z0-9+/]+=*",
    "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
    "s3_bucket": r"(?:s3://|https?://[a-zA-Z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z]{2}-[a-z]+-\d\.amazonaws\.com))",
    "heroku_api_key": r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
    "twilio_api_key": r"SK[0-9a-fA-F]{32}",
    "sendgrid_api_key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
}


def get_config() -> Dict:
    """Get the full configuration as a dictionary."""
    return {
        "http": HttpConfig().__dict__,
        "proxy": ProxyConfig().__dict__,
        "scan": ScanConfig().__dict__,
        "fuzzer": FuzzerConfig().__dict__,
        "bypass": BypassConfig().__dict__,
        "secrets": SecretsConfig().__dict__,
        "recon": ReconConfig().__dict__,
        "output": OutputConfig().__dict__,
    }


def load_env_overrides():
    """Load configuration overrides from environment variables."""
    overrides = {}
    prefix = "RECON_"
    for key, value in os.environ.items():
        if key.startswith(prefix):
            config_key = key[len(prefix):].lower()
            overrides[config_key] = value
    return overrides
