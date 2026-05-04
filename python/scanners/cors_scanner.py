"""Complete CORS (Cross-Origin Resource Sharing) Misconfiguration Scanner Module.

Detects various CORS misconfigurations including wildcard origins,
null origin acceptance, credential leakage, and origin reflection.
"""

import re
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

from utils.http_client import HttpClient
from utils.encoder import Encoder


class CORSScanner:
    """CORS Misconfiguration vulnerability scanner."""

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize CORS scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.findings: List[Dict[str, Any]] = []

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """Test for CORS misconfiguration vulnerabilities.

        Args:
            url: Target URL to test

        Returns:
            List of findings
        """
        self.findings = []

        # Run all CORS tests
        self._test_origins(url)
        self._check_credentials(url)
        self._test_methods(url)
        self._test_headers(url)

        return self.findings

    def _test_origins(self, url: str):
        """Test various evil origins for CORS misconfiguration.

        Args:
            url: Target URL
        """
        parsed = urlparse(url)
        target_domain = parsed.netloc
        target_scheme = parsed.scheme

        # Generate evil origins to test
        evil_origins = [
            # Arbitrary origin
            'https://evil.com',
            'http://evil.com',
            # Null origin (sandboxed iframe, file://, data:)
            'null',
            # Subdomain of attacker
            f'https://{target_domain}.evil.com',
            # Prefix match bypass
            f'https://{target_domain}evil.com',
            # Suffix match bypass
            f'https://evil{target_domain}',
            # With target as subdomain of evil
            f'https://{target_domain}.attacker.com',
            # HTTP downgrade
            f'http://{target_domain}',
            # Wildcard subdomain abuse
            f'https://anything.{target_domain}',
            # Special characters
            f'https://{target_domain}%60.evil.com',
            f'https://{target_domain}_.evil.com',
            # Underscore trick
            f'https://evil.com_.{target_domain}',
            # Backtick bypass
            f'https://evil.com`{target_domain}',
            # Tab/newline injection
            f'https://evil.com%09.{target_domain}',
            f'https://evil.com%0d.{target_domain}',
            # Port-based bypass
            f'{target_scheme}://{target_domain}:evil.com',
            # Case variation
            f'https://{target_domain.upper()}',
        ]

        for origin in evil_origins:
            try:
                headers = {'Origin': origin}
                response = self.client.get(url, headers=headers)

                acao = response.headers.get('access-control-allow-origin', '')
                acac = response.headers.get('access-control-allow-credentials', '')

                if not acao:
                    continue

                # Check if our evil origin is reflected
                if acao == origin or acao == '*':
                    severity = 'HIGH'
                    vuln_type = 'CORS Origin Reflection'

                    if acao == '*':
                        vuln_type = 'CORS Wildcard Origin'
                        severity = 'MEDIUM'

                    if origin == 'null':
                        vuln_type = 'CORS Null Origin Accepted'
                        severity = 'HIGH'

                    # Credentials make it critical
                    if acac.lower() == 'true':
                        severity = 'CRITICAL'
                        vuln_type += ' + Credentials'

                    self.findings.append({
                        'type': vuln_type,
                        'severity': severity,
                        'url': url,
                        'parameter': f'Origin: {origin}',
                        'payload': f'Origin: {origin}',
                        'evidence': f"ACAO: {acao}, ACAC: {acac}",
                        'remediation': 'Implement strict origin allowlist. Never reflect arbitrary origins. Do not use Access-Control-Allow-Credentials with wildcard origins.',
                        'curl_command': f"curl -k -H 'Origin: {origin}' '{url}' -I",
                    })

                # Check for partial reflection (subdomain matching issues)
                elif target_domain in acao and acao != f'{target_scheme}://{target_domain}':
                    self.findings.append({
                        'type': 'CORS Weak Origin Validation',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': f'Origin: {origin}',
                        'payload': f'Origin: {origin}',
                        'evidence': f"Reflected ACAO: {acao} for origin: {origin}",
                        'remediation': 'Use exact origin matching. Do not use regex or substring matching for origin validation.',
                        'curl_command': f"curl -k -H 'Origin: {origin}' '{url}' -I",
                    })

            except Exception:
                continue

    def _check_credentials(self, url: str):
        """Check if Access-Control-Allow-Credentials is set with weak origin.

        Args:
            url: Target URL
        """
        try:
            # Test with no origin
            response = self.client.get(url)
            acao = response.headers.get('access-control-allow-origin', '')
            acac = response.headers.get('access-control-allow-credentials', '')

            # Wildcard with credentials is a misconfiguration
            if acao == '*' and acac.lower() == 'true':
                self.findings.append({
                    'type': 'CORS Wildcard with Credentials',
                    'severity': 'HIGH',
                    'url': url,
                    'parameter': 'N/A',
                    'payload': 'No Origin header sent',
                    'evidence': f"ACAO: * with ACAC: true (browsers will block but indicates misconfiguration)",
                    'remediation': 'Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.',
                    'curl_command': f"curl -k '{url}' -I",
                })

            # Test preflight
            preflight_headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': 'X-Custom-Header,Authorization',
            }
            preflight_resp = self.client.request('OPTIONS', url, headers=preflight_headers)

            acam = preflight_resp.headers.get('access-control-allow-methods', '')
            acah = preflight_resp.headers.get('access-control-allow-headers', '')
            acao_preflight = preflight_resp.headers.get('access-control-allow-origin', '')

            if acao_preflight in ('*', 'https://evil.com'):
                dangerous_methods = [m.strip() for m in acam.split(',') if m.strip().upper() in ('PUT', 'DELETE', 'PATCH')]
                if dangerous_methods:
                    self.findings.append({
                        'type': 'CORS Permissive Preflight',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': 'Preflight (OPTIONS)',
                        'payload': 'OPTIONS with evil origin',
                        'evidence': f"Allows methods: {acam}, headers: {acah} for evil origin",
                        'remediation': 'Restrict allowed methods and headers in preflight responses. Validate origin in preflight.',
                        'curl_command': f"curl -k -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: PUT' '{url}' -I",
                    })

        except Exception:
            pass

    def _test_methods(self, url: str):
        """Test for overly permissive allowed methods."""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'DELETE',
            }
            response = self.client.request('OPTIONS', url, headers=headers)

            acam = response.headers.get('access-control-allow-methods', '')
            acao = response.headers.get('access-control-allow-origin', '')

            if acao and 'DELETE' in acam.upper():
                self.findings.append({
                    'type': 'CORS Allows Dangerous Methods',
                    'severity': 'LOW',
                    'url': url,
                    'parameter': 'Access-Control-Allow-Methods',
                    'payload': 'OPTIONS request with DELETE method',
                    'evidence': f"Allowed methods: {acam}",
                    'remediation': 'Only allow necessary HTTP methods in CORS preflight responses.',
                    'curl_command': f"curl -k -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: DELETE' '{url}' -I",
                })

        except Exception:
            pass

    def _test_headers(self, url: str):
        """Test for overly permissive allowed headers."""
        try:
            sensitive_headers = ['Authorization', 'X-API-Key', 'Cookie', 'X-CSRF-Token']

            for header in sensitive_headers:
                headers = {
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': header,
                }
                response = self.client.request('OPTIONS', url, headers=headers)

                acah = response.headers.get('access-control-allow-headers', '')
                acao = response.headers.get('access-control-allow-origin', '')

                if acao and header.lower() in acah.lower():
                    # Only report if origin is also permissive
                    if acao == '*' or acao == 'https://evil.com':
                        self.findings.append({
                            'type': 'CORS Exposes Sensitive Headers',
                            'severity': 'MEDIUM',
                            'url': url,
                            'parameter': 'Access-Control-Allow-Headers',
                            'payload': f'Requested header: {header}',
                            'evidence': f"Allows sensitive header '{header}' for evil origin. ACAH: {acah}",
                            'remediation': 'Restrict allowed headers to only those necessary. Do not allow Authorization or Cookie headers for untrusted origins.',
                            'curl_command': f"curl -k -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Headers: {header}' '{url}' -I",
                        })
                        break  # One finding is enough

        except Exception:
            pass
