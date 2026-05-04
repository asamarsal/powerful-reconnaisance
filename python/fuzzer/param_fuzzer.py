"""Parameter fuzzer - Discovers hidden parameters and fuzzes them with payloads."""

import httpx
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set


class ParamFuzzer:
    """Parameter discovery and fuzzing tool with threading support."""

    def __init__(self, threads: int = 10, timeout: int = 10, delay: float = 0):
        """
        Initialize ParamFuzzer.

        Args:
            threads: Number of concurrent threads for fuzzing.
            timeout: HTTP request timeout in seconds.
            delay: Delay between requests in seconds (rate limiting).
        """
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.findings: List[Dict[str, Any]] = []
        self.error_patterns = [
            r"error",
            r"exception",
            r"warning",
            r"fatal",
            r"syntax",
            r"undefined",
            r"invalid",
            r"sql",
            r"mysql",
            r"postgresql",
            r"oracle",
            r"stack trace",
            r"traceback",
            r"debug",
            r"internal server error",
        ]

    def fuzz(self, url: str, params: List[str], payloads: List[str]) -> List[Dict[str, Any]]:
        """
        Fuzz all parameters with provided payloads.

        Args:
            url: Target URL to fuzz.
            params: List of parameter names to fuzz.
            payloads: List of payload strings to inject.

        Returns:
            List of interesting findings with anomaly details.
        """
        self.findings = []
        print(f"[*] Fuzzing {len(params)} params with {len(payloads)} payloads on: {url}")

        # Get baseline response
        baseline = self._get_baseline(url)
        if not baseline:
            print("[-] Could not get baseline response")
            return self.findings

        baseline_info = {
            "status_code": baseline.status_code,
            "content_length": len(baseline.content),
            "headers": dict(baseline.headers),
        }

        print(f"[*] Baseline: status={baseline_info['status_code']}, length={baseline_info['content_length']}")

        # Generate all test cases
        test_cases = []
        for param in params:
            for payload in payloads:
                test_cases.append((param, payload))

        print(f"[*] Total test cases: {len(test_cases)}")

        # Execute fuzzing with thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for param, payload in test_cases:
                future = executor.submit(self._fuzz_single, url, param, payload, baseline_info)
                futures[future] = (param, payload)

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    print(f"[*] Progress: {completed}/{len(test_cases)}")

                param, payload = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception:
                    pass

        # Sort findings by severity
        self.findings.sort(key=lambda x: x.get("severity", 0), reverse=True)
        print(f"[+] Fuzzing complete. Found {len(self.findings)} interesting responses.")
        return self.findings

    def discover_params(self, url: str) -> List[Dict[str, Any]]:
        """
        Discover hidden parameters by analyzing the page content.

        Args:
            url: Target URL to analyze for hidden parameters.

        Returns:
            List of discovered parameters with source information.
        """
        print(f"[*] Discovering parameters on: {url}")
        discovered: List[Dict[str, Any]] = []
        found_params: Set[str] = set()

        try:
            with httpx.Client(timeout=self.timeout, verify=False) as client:
                response = client.get(url)
                html = response.text

                # Extract from HTML forms
                form_params = re.findall(
                    r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE
                )
                for param in form_params:
                    if param not in found_params:
                        found_params.add(param)
                        discovered.append({
                            "param": param,
                            "source": "html_form",
                            "url": url,
                        })

                # Extract from JavaScript
                js_params = re.findall(
                    r'["\'](\w+)["\']\s*[:=]\s*["\']', html
                )
                for param in js_params:
                    if param not in found_params and len(param) > 2:
                        found_params.add(param)
                        discovered.append({
                            "param": param,
                            "source": "javascript",
                            "url": url,
                        })

                # Extract from URL query strings in page
                url_params = re.findall(
                    r'[?&](\w+)=', html
                )
                for param in url_params:
                    if param not in found_params:
                        found_params.add(param)
                        discovered.append({
                            "param": param,
                            "source": "url_in_page",
                            "url": url,
                        })

                # Extract from data attributes
                data_params = re.findall(
                    r'data-(\w+)[="\s]', html, re.IGNORECASE
                )
                for param in data_params:
                    if param not in found_params:
                        found_params.add(param)
                        discovered.append({
                            "param": param,
                            "source": "data_attribute",
                            "url": url,
                        })

                # Extract from AJAX/fetch calls
                ajax_params = re.findall(
                    r'(?:fetch|ajax|axios|XMLHttpRequest)[^}]*["\'](\w+)["\']', html
                )
                for param in ajax_params:
                    if param not in found_params and len(param) > 2:
                        found_params.add(param)
                        discovered.append({
                            "param": param,
                            "source": "ajax_call",
                            "url": url,
                        })

                # Extract from comments
                comment_params = re.findall(
                    r'<!--[^>]*?(\w+)\s*=', html
                )
                for param in comment_params:
                    if param not in found_params and len(param) > 2:
                        found_params.add(param)
                        discovered.append({
                            "param": param,
                            "source": "html_comment",
                            "url": url,
                        })

                # Extract linked JS files and scan them
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"

                for js_url in js_urls[:10]:  # Limit to 10 JS files
                    if js_url.startswith("//"):
                        js_url = f"{parsed.scheme}:{js_url}"
                    elif js_url.startswith("/"):
                        js_url = base + js_url
                    elif not js_url.startswith("http"):
                        js_url = base + "/" + js_url

                    try:
                        js_response = client.get(js_url)
                        js_content = js_response.text

                        # Find params in JS
                        js_found = re.findall(r'["\'](\w{3,30})["\']', js_content)
                        for param in js_found[:50]:  # Limit per file
                            if param not in found_params and not param[0].isupper():
                                found_params.add(param)
                                discovered.append({
                                    "param": param,
                                    "source": "javascript_file",
                                    "url": js_url,
                                })
                    except Exception:
                        pass

        except Exception as e:
            print(f"[-] Error discovering params: {e}")

        print(f"[+] Discovered {len(discovered)} parameters")
        return discovered

    def _fuzz_single(
        self, url: str, param: str, payload: str, baseline: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Fuzz a single parameter with a single payload and detect anomalies.

        Args:
            url: Target URL.
            param: Parameter name to fuzz.
            payload: Payload to inject.
            baseline: Baseline response info for comparison.

        Returns:
            Finding dict if anomaly detected, None otherwise.
        """
        if self.delay > 0:
            time.sleep(self.delay)

        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        existing_params[param] = [payload]

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing_params, doseq=True)}"

        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                response = client.get(test_url)

                anomalies = self._detect_anomalies(response, baseline)

                if anomalies:
                    severity = self._calculate_severity(anomalies)
                    return {
                        "param": param,
                        "payload": payload,
                        "url": test_url,
                        "status_code": response.status_code,
                        "response_length": len(response.content),
                        "baseline_length": baseline["content_length"],
                        "anomalies": anomalies,
                        "severity": severity,
                        "evidence": "; ".join(anomalies),
                    }
        except Exception:
            pass

        return None

    def _detect_anomalies(self, response: httpx.Response, baseline: Dict[str, Any]) -> List[str]:
        """Detect anomalies by comparing response to baseline."""
        anomalies = []

        # Status code change
        if response.status_code != baseline["status_code"]:
            anomalies.append(f"Status changed: {baseline['status_code']} -> {response.status_code}")

        # Significant length change (>20% difference)
        current_length = len(response.content)
        baseline_length = baseline["content_length"]
        if baseline_length > 0:
            length_diff = abs(current_length - baseline_length) / baseline_length
            if length_diff > 0.2:
                anomalies.append(f"Length change: {baseline_length} -> {current_length} ({length_diff:.0%})")

        # Error messages in response
        body = response.text.lower() if response.text else ""
        for pattern in self.error_patterns:
            if re.search(pattern, body):
                anomalies.append(f"Error pattern found: {pattern}")
                break  # Only report first error pattern

        # Reflection detection
        # Check if common payload markers are reflected
        if any(marker in response.text for marker in ["<script>", "onerror=", "alert(", "' OR ", "\" OR "]):
            anomalies.append("Payload reflection detected")

        # New headers in response
        for header in ["X-Debug", "X-Error", "X-SQL", "Server-Error"]:
            if header.lower() in [h.lower() for h in response.headers.keys()]:
                anomalies.append(f"Interesting header: {header}")

        # Redirect to different location
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get("location", "")
            if location:
                anomalies.append(f"Redirect to: {location}")

        return anomalies

    def _calculate_severity(self, anomalies: List[str]) -> int:
        """Calculate severity score (1-10) based on anomalies."""
        score = 0
        for anomaly in anomalies:
            if "Payload reflection" in anomaly:
                score += 4
            elif "Error pattern" in anomaly:
                score += 3
            elif "Status changed" in anomaly:
                score += 2
            elif "Length change" in anomaly:
                score += 1
            elif "Redirect" in anomaly:
                score += 2
            elif "Interesting header" in anomaly:
                score += 2
        return min(score, 10)

    def _get_baseline(self, url: str) -> Optional[httpx.Response]:
        """Get baseline response for comparison."""
        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                return client.get(url)
        except Exception:
            return None
