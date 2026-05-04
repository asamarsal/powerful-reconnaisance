"""Secret finder - Discovers secrets, API keys, and sensitive data in web pages and JS files."""

import httpx
import re
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set


class SecretFinder:
    """Scans web pages and JavaScript files for exposed secrets and sensitive data."""

    def __init__(self, threads: int = 10, timeout: int = 10, max_js_files: int = 50):
        """
        Initialize SecretFinder.

        Args:
            threads: Number of concurrent threads.
            timeout: HTTP request timeout in seconds.
            max_js_files: Maximum number of JS files to scan.
        """
        self.threads = threads
        self.timeout = timeout
        self.max_js_files = max_js_files
        self.findings: List[Dict[str, Any]] = []
        self.scanned_urls: Set[str] = set()
        self.patterns = self._load_patterns()

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL and its linked JS files for secrets.

        Args:
            url: Target URL to scan for secrets.

        Returns:
            List of found secrets with type, value, url, and line number.
        """
        self.findings = []
        self.scanned_urls = set()
        print(f"[*] Scanning for secrets on: {url}")

        # Fetch main page
        html = self._fetch_url(url)
        if not html:
            print("[-] Could not fetch target URL")
            return self.findings

        # Scan main page content
        print("[*] Scanning main page...")
        page_secrets = self._scan_content(html, url)
        self.findings.extend(page_secrets)

        # Extract and scan JS files
        js_urls = self._extract_js_urls(html, url)
        print(f"[*] Found {len(js_urls)} JavaScript files to scan")

        if js_urls:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for js_url in js_urls[:self.max_js_files]:
                    if js_url not in self.scanned_urls:
                        self.scanned_urls.add(js_url)
                        future = executor.submit(self._scan_js_file, js_url)
                        futures[future] = js_url

                for future in as_completed(futures):
                    js_url = futures[future]
                    try:
                        results = future.result()
                        self.findings.extend(results)
                    except Exception as e:
                        print(f"[-] Error scanning {js_url}: {e}")

        # Deduplicate findings
        self.findings = self._deduplicate(self.findings)

        print(f"[+] Found {len(self.findings)} secrets/sensitive data")
        return self.findings

    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """
        Extract all JavaScript file URLs from HTML content.

        Args:
            html: HTML content to parse.
            base_url: Base URL for resolving relative paths.

        Returns:
            List of absolute JS file URLs.
        """
        js_urls = set()
        parsed_base = urlparse(base_url)

        # Script src attributes
        script_srcs = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE
        )

        # Import statements
        imports = re.findall(
            r'import\s+.*?from\s+["\']([^"\']+\.js)["\']', html
        )

        # Dynamic script loading
        dynamic = re.findall(
            r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html
        )

        # Source map references
        sourcemaps = re.findall(
            r'//[#@]\s*sourceMappingURL=([^\s]+)', html
        )

        all_refs = set(script_srcs + imports + dynamic + sourcemaps)

        for ref in all_refs:
            # Skip data URIs and inline scripts
            if ref.startswith("data:") or ref.startswith("javascript:"):
                continue

            # Resolve relative URLs
            if ref.startswith("//"):
                full_url = f"{parsed_base.scheme}:{ref}"
            elif ref.startswith("/"):
                full_url = f"{parsed_base.scheme}://{parsed_base.netloc}{ref}"
            elif ref.startswith("http"):
                full_url = ref
            else:
                full_url = urljoin(base_url, ref)

            js_urls.add(full_url)

        return list(js_urls)

    def _scan_content(self, content: str, url: str) -> List[Dict[str, Any]]:
        """
        Scan content with regex patterns for secrets.

        Args:
            content: Text content to scan.
            url: Source URL of the content.

        Returns:
            List of found secrets.
        """
        secrets = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern_info in self.patterns:
                pattern_name = pattern_info["name"]
                pattern_regex = pattern_info["regex"]
                severity = pattern_info.get("severity", "medium")

                try:
                    matches = re.finditer(pattern_regex, line)
                    for match in matches:
                        value = match.group(0)

                        # Skip common false positives
                        if self._is_false_positive(value, pattern_name):
                            continue

                        secrets.append({
                            "type": pattern_name,
                            "value": value[:200],  # Truncate long values
                            "url": url,
                            "line": line_num,
                            "severity": severity,
                            "context": line.strip()[:300],
                        })
                except re.error:
                    pass

        return secrets

    def _scan_js_file(self, js_url: str) -> List[Dict[str, Any]]:
        """Fetch and scan a JavaScript file for secrets."""
        content = self._fetch_url(js_url)
        if not content:
            return []
        return self._scan_content(content, js_url)

    def _fetch_url(self, url: str) -> str:
        """Fetch URL content with error handling."""
        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                response = client.get(url)
                if response.status_code == 200:
                    return response.text
        except Exception:
            pass
        return ""

    def _is_false_positive(self, value: str, pattern_name: str) -> bool:
        """Check if a finding is likely a false positive."""
        # Common false positive indicators
        false_positive_values = [
            "example", "test", "sample", "placeholder", "your_",
            "xxx", "000000", "aaaaaa", "123456", "abcdef",
            "INSERT_", "REPLACE_", "YOUR_", "TODO",
        ]

        value_lower = value.lower()
        for fp in false_positive_values:
            if fp.lower() in value_lower:
                return True

        # Too short to be meaningful
        if len(value) < 8 and pattern_name not in ["Internal IP", "IPv6 Address"]:
            return True

        # All same character
        if len(set(value.replace("-", "").replace("_", ""))) <= 2:
            return True

        return False

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        for finding in findings:
            key = f"{finding['type']}:{finding['value']}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

    def _load_patterns(self) -> List[Dict[str, Any]]:
        """Load 30+ regex patterns for secret detection."""
        return [
            # AWS
            {
                "name": "AWS Access Key ID",
                "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                "severity": "critical",
            },
            {
                "name": "AWS Secret Access Key",
                "regex": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                "severity": "critical",
            },
            {
                "name": "AWS MWS Key",
                "regex": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "severity": "critical",
            },
            # GitHub
            {
                "name": "GitHub Token",
                "regex": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
                "severity": "critical",
            },
            {
                "name": "GitHub OAuth",
                "regex": r"(?i)github[_\-\.]?(?:token|key|secret|oauth)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{35,40})['\"]?",
                "severity": "high",
            },
            # Google
            {
                "name": "Google API Key",
                "regex": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "high",
            },
            {
                "name": "Google OAuth ID",
                "regex": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
                "severity": "medium",
            },
            # Stripe
            {
                "name": "Stripe Secret Key",
                "regex": r"sk_live_[0-9a-zA-Z]{24,99}",
                "severity": "critical",
            },
            {
                "name": "Stripe Publishable Key",
                "regex": r"pk_live_[0-9a-zA-Z]{24,99}",
                "severity": "low",
            },
            # Slack
            {
                "name": "Slack Token",
                "regex": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}",
                "severity": "critical",
            },
            {
                "name": "Slack Webhook",
                "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",
                "severity": "high",
            },
            # JWT
            {
                "name": "JSON Web Token",
                "regex": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
                "severity": "high",
            },
            # Private Keys
            {
                "name": "RSA Private Key",
                "regex": r"-----BEGIN RSA PRIVATE KEY-----",
                "severity": "critical",
            },
            {
                "name": "EC Private Key",
                "regex": r"-----BEGIN EC PRIVATE KEY-----",
                "severity": "critical",
            },
            {
                "name": "PGP Private Key",
                "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                "severity": "critical",
            },
            {
                "name": "SSH Private Key",
                "regex": r"-----BEGIN (?:DSA |EC |OPENSSH )?PRIVATE KEY-----",
                "severity": "critical",
            },
            # Database
            {
                "name": "MongoDB URI",
                "regex": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
                "severity": "critical",
            },
            {
                "name": "PostgreSQL URI",
                "regex": r"postgres(?:ql)?://[^\s\"'<>]+",
                "severity": "critical",
            },
            {
                "name": "MySQL URI",
                "regex": r"mysql://[^\s\"'<>]+",
                "severity": "critical",
            },
            {
                "name": "Redis URI",
                "regex": r"redis://[^\s\"'<>]+",
                "severity": "high",
            },
            # Generic API Keys
            {
                "name": "Generic API Key",
                "regex": r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,60})['\"]?",
                "severity": "high",
            },
            {
                "name": "Generic Secret",
                "regex": r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,60})['\"]",
                "severity": "high",
            },
            {
                "name": "Bearer Token",
                "regex": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
                "severity": "high",
            },
            # Cloud Services
            {
                "name": "Heroku API Key",
                "regex": r"(?i)heroku[_\-\.]?api[_\-\.]?key\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
                "severity": "high",
            },
            {
                "name": "Firebase URL",
                "regex": r"https://[a-z0-9-]+\.firebaseio\.com",
                "severity": "medium",
            },
            {
                "name": "Firebase API Key",
                "regex": r"(?i)firebase[_\-\.]?(?:api[_\-\.]?key|key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{35,45})['\"]?",
                "severity": "high",
            },
            # Payment
            {
                "name": "Square Access Token",
                "regex": r"sq0atp-[0-9A-Za-z\-_]{22}",
                "severity": "critical",
            },
            {
                "name": "Square OAuth Secret",
                "regex": r"sq0csp-[0-9A-Za-z\-_]{43}",
                "severity": "critical",
            },
            {
                "name": "PayPal Braintree Token",
                "regex": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
                "severity": "critical",
            },
            # Twilio
            {
                "name": "Twilio API Key",
                "regex": r"SK[0-9a-fA-F]{32}",
                "severity": "high",
            },
            # SendGrid
            {
                "name": "SendGrid API Key",
                "regex": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
                "severity": "high",
            },
            # Mailgun
            {
                "name": "Mailgun API Key",
                "regex": r"key-[0-9a-zA-Z]{32}",
                "severity": "high",
            },
            # Network
            {
                "name": "Internal IP",
                "regex": r"(?:^|[^0-9])((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)",
                "severity": "low",
            },
            {
                "name": "Password in URL",
                "regex": r"(?i)(?:https?|ftp)://[^:]+:([^@]+)@[^\s\"'<>]+",
                "severity": "high",
            },
            # Encryption
            {
                "name": "Encryption Key (Hex)",
                "regex": r"(?i)(?:encryption[_\-\.]?key|aes[_\-\.]?key|secret[_\-\.]?key)\s*[=:]\s*['\"]?([0-9a-fA-F]{32,64})['\"]?",
                "severity": "critical",
            },
            # Miscellaneous
            {
                "name": "Telegram Bot Token",
                "regex": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
                "severity": "high",
            },
            {
                "name": "Discord Bot Token",
                "regex": r"(?:N|M|O)[a-zA-Z0-9]{23,28}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27,38}",
                "severity": "high",
            },
        ]
