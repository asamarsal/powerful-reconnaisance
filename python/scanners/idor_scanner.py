"""Complete IDOR (Insecure Direct Object Reference) Scanner Module.

Detects unauthorized access to resources by manipulating object identifiers
in parameters and URL paths.
"""

import re
import json
import difflib
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from utils.http_client import HttpClient
from utils.encoder import Encoder


class IDORScanner:
    """Insecure Direct Object Reference vulnerability scanner."""

    # Common ID parameter names
    ID_PARAM_PATTERNS = [
        r'^id$', r'^uid$', r'^user_id$', r'^userid$', r'^user$',
        r'^account_id$', r'^accountid$', r'^account$',
        r'^profile_id$', r'^profileid$', r'^profile$',
        r'^order_id$', r'^orderid$', r'^order$',
        r'^doc_id$', r'^docid$', r'^document_id$',
        r'^file_id$', r'^fileid$', r'^file$',
        r'^msg_id$', r'^message_id$', r'^messageid$',
        r'^invoice_id$', r'^invoiceid$', r'^invoice$',
        r'^report_id$', r'^reportid$', r'^report$',
        r'^item_id$', r'^itemid$', r'^item$',
        r'^product_id$', r'^productid$', r'^product$',
        r'^record_id$', r'^recordid$', r'^record$',
        r'^ticket_id$', r'^ticketid$', r'^ticket$',
        r'^comment_id$', r'^commentid$', r'^comment$',
        r'^post_id$', r'^postid$', r'^post$',
        r'^project_id$', r'^projectid$', r'^project$',
        r'^group_id$', r'^groupid$', r'^group$',
        r'^team_id$', r'^teamid$', r'^team$',
        r'^org_id$', r'^orgid$', r'^organization_id$',
        r'^customer_id$', r'^customerid$', r'^customer$',
        r'^employee_id$', r'^employeeid$', r'^employee$',
        r'^num$', r'^no$', r'^number$', r'^ref$', r'^reference$',
        r'.*_id$', r'.*id$',
    ]

    # Sensitive data indicators in responses
    SENSITIVE_INDICATORS = [
        'email', 'phone', 'address', 'ssn', 'social_security',
        'credit_card', 'card_number', 'cvv', 'password', 'secret',
        'token', 'api_key', 'private', 'salary', 'bank_account',
        'routing_number', 'date_of_birth', 'dob', 'passport',
        'license', 'medical', 'health', 'diagnosis',
    ]

    # Path patterns that suggest ID-based access
    PATH_ID_PATTERNS = [
        r'/api/v\d+/\w+/(\d+)',
        r'/api/\w+/(\d+)',
        r'/users?/(\d+)',
        r'/accounts?/(\d+)',
        r'/profiles?/(\d+)',
        r'/orders?/(\d+)',
        r'/documents?/(\d+)',
        r'/files?/(\d+)',
        r'/messages?/(\d+)',
        r'/invoices?/(\d+)',
        r'/reports?/(\d+)',
        r'/items?/(\d+)',
        r'/products?/(\d+)',
        r'/records?/(\d+)',
        r'/tickets?/(\d+)',
        r'/posts?/(\d+)',
        r'/comments?/(\d+)',
        r'/\w+/(\d+)/\w+',
        r'/\w+/([a-f0-9\-]{36})',  # UUID pattern
        r'/\w+/([a-f0-9]{24})',    # MongoDB ObjectId
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize IDOR scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []

    def scan_numeric(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test numeric ID manipulation in parameters.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings
        """
        findings = []

        # Identify ID-like parameters
        id_params = self._find_id_params(params)

        for param_name in id_params:
            original_value = params[param_name]

            # Only test numeric or UUID-like values
            if not self._is_id_value(original_value):
                continue

            # Get baseline response with original ID
            try:
                baseline_resp = self.client.get(url, params=params)
                if baseline_resp.status_code not in (200, 201, 202, 203, 204):
                    continue
            except Exception:
                continue

            # Generate test IDs
            test_ids = self._generate_test_ids(original_value)

            for test_id in test_ids:
                try:
                    test_params = {**params, param_name: test_id}
                    test_resp = self.client.get(url, params=test_params)

                    # Compare responses
                    comparison = self._compare_responses(baseline_resp, test_resp)

                    if comparison['is_idor']:
                        findings.append({
                            'type': 'Insecure Direct Object Reference (IDOR)',
                            'severity': comparison['severity'],
                            'url': url,
                            'parameter': param_name,
                            'payload': f"Original: {original_value} -> Modified: {test_id}",
                            'evidence': comparison['evidence'],
                            'remediation': 'Implement proper authorization checks. Use indirect references (mapping). Verify object ownership before access.',
                            'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                        })
                        break  # One finding per parameter

                except Exception:
                    continue

        return findings

    def scan_path_based(self, url: str) -> List[Dict[str, Any]]:
        """Test path-based IDOR (e.g., /api/users/1 -> /api/users/2).

        Args:
            url: Target URL with ID in path

        Returns:
            List of findings
        """
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        # Find numeric IDs in path
        for pattern in self.PATH_ID_PATTERNS:
            matches = list(re.finditer(pattern, path))
            if not matches:
                continue

            for match in matches:
                original_id = match.group(1)

                # Get baseline response
                try:
                    baseline_resp = self.client.get(url)
                    if baseline_resp.status_code not in (200, 201, 202, 203, 204):
                        continue
                except Exception:
                    continue

                # Generate test IDs
                test_ids = self._generate_test_ids(original_id)

                for test_id in test_ids:
                    # Replace ID in path
                    new_path = path[:match.start(1)] + test_id + path[match.end(1):]
                    new_url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))

                    try:
                        test_resp = self.client.get(new_url)

                        # Compare responses
                        comparison = self._compare_responses(baseline_resp, test_resp)

                        if comparison['is_idor']:
                            findings.append({
                                'type': 'Path-Based IDOR',
                                'severity': comparison['severity'],
                                'url': new_url,
                                'parameter': f"path_id ({original_id})",
                                'payload': f"Original path: {path} -> Modified: {new_path}",
                                'evidence': comparison['evidence'],
                                'remediation': 'Implement authorization middleware. Verify resource ownership. Use session-based access control.',
                                'curl_command': self.client.build_curl_command('GET', new_url),
                            })
                            break

                    except Exception:
                        continue

        return findings

    def _find_id_params(self, params: Dict[str, str]) -> List[str]:
        """Identify ID-like parameters from the parameter dictionary.

        Args:
            params: Dictionary of parameters

        Returns:
            List of parameter names that look like IDs
        """
        id_params = []

        for param_name in params:
            for pattern in self.ID_PARAM_PATTERNS:
                if re.match(pattern, param_name, re.IGNORECASE):
                    id_params.append(param_name)
                    break

        # If no ID params found by name, check values
        if not id_params:
            for param_name, value in params.items():
                if self._is_id_value(value):
                    id_params.append(param_name)

        return id_params

    def _is_id_value(self, value: str) -> bool:
        """Check if a value looks like an ID."""
        # Numeric ID
        if value.isdigit():
            return True
        # UUID
        if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value, re.IGNORECASE):
            return True
        # MongoDB ObjectId
        if re.match(r'^[a-f0-9]{24}$', value, re.IGNORECASE):
            return True
        # Short alphanumeric ID
        if re.match(r'^[a-zA-Z0-9]{4,20}$', value) and any(c.isdigit() for c in value):
            return True
        return False

    def _generate_test_ids(self, original_id: str) -> List[str]:
        """Generate test IDs based on the original ID format.

        Args:
            original_id: The original ID value

        Returns:
            List of test ID values
        """
        test_ids = []

        if original_id.isdigit():
            num = int(original_id)
            # Adjacent IDs
            test_ids.extend([
                str(num + 1),
                str(num - 1),
                str(num + 2),
                str(max(1, num - 2)),
                '1',  # First record (often admin)
                '0',
                str(num + 100),
                str(num + 1000),
            ])
        elif re.match(r'^[a-f0-9]{8}-', original_id, re.IGNORECASE):
            # UUID - try incrementing last segment
            parts = original_id.split('-')
            last_hex = int(parts[-1], 16)
            parts[-1] = format(last_hex + 1, '012x')
            test_ids.append('-'.join(parts))
            parts[-1] = format(max(0, last_hex - 1), '012x')
            test_ids.append('-'.join(parts))
            # Try common UUIDs
            test_ids.append('00000000-0000-0000-0000-000000000001')
        elif re.match(r'^[a-f0-9]{24}$', original_id, re.IGNORECASE):
            # MongoDB ObjectId - increment
            hex_val = int(original_id, 16)
            test_ids.append(format(hex_val + 1, '024x'))
            test_ids.append(format(max(0, hex_val - 1), '024x'))
        else:
            # Generic alphanumeric - try common patterns
            test_ids.extend(['1', '2', 'admin', 'test', '0'])

        return test_ids

    def _compare_responses(self, resp1, resp2) -> Dict[str, Any]:
        """Compare two responses to detect unauthorized access.

        Args:
            resp1: Baseline response (authorized)
            resp2: Test response (potentially unauthorized)

        Returns:
            Dict with comparison results
        """
        result = {
            'is_idor': False,
            'severity': 'MEDIUM',
            'evidence': '',
        }

        # If test response is an error, not IDOR
        if resp2.status_code in (401, 403, 404, 500):
            return result

        # If test response is successful (200-299)
        if 200 <= resp2.status_code < 300:
            # Check if response contains different data (not just the same page)
            if resp1.text == resp2.text:
                return result  # Same content, likely not IDOR

            # Check if response contains meaningful data
            try:
                json2 = resp2.json()
                # JSON response with data suggests IDOR
                if isinstance(json2, dict) and len(json2) > 0:
                    # Check for sensitive data
                    response_str = json.dumps(json2).lower()
                    sensitive_found = [
                        ind for ind in self.SENSITIVE_INDICATORS
                        if ind in response_str
                    ]

                    if sensitive_found:
                        result['is_idor'] = True
                        result['severity'] = 'CRITICAL'
                        result['evidence'] = f"Different user data returned. Sensitive fields found: {', '.join(sensitive_found[:5])}"
                    else:
                        result['is_idor'] = True
                        result['severity'] = 'HIGH'
                        result['evidence'] = f"Different data returned (JSON with {len(json2)} fields). Status: {resp2.status_code}"

                elif isinstance(json2, list) and len(json2) > 0:
                    result['is_idor'] = True
                    result['severity'] = 'HIGH'
                    result['evidence'] = f"List of {len(json2)} items returned for different ID"

            except (json.JSONDecodeError, ValueError):
                # HTML response - compare content
                similarity = difflib.SequenceMatcher(
                    None, resp1.text[:5000], resp2.text[:5000]
                ).ratio()

                if 0.1 < similarity < 0.9:
                    # Different but structured content
                    result['is_idor'] = True
                    result['severity'] = 'MEDIUM'
                    result['evidence'] = f"Different content returned (similarity: {similarity:.2%}). Status: {resp2.status_code}"

                    # Check for sensitive data in HTML
                    response_lower = resp2.text.lower()
                    sensitive_found = [
                        ind for ind in self.SENSITIVE_INDICATORS
                        if ind in response_lower
                    ]
                    if sensitive_found:
                        result['severity'] = 'HIGH'
                        result['evidence'] += f" Sensitive indicators: {', '.join(sensitive_found[:5])}"

        return result

    def scan_all(self, url: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Run all IDOR tests.

        Args:
            url: Target URL
            params: Optional parameters dict

        Returns:
            Combined list of findings
        """
        all_findings = []

        if params:
            all_findings.extend(self.scan_numeric(url, params))

        all_findings.extend(self.scan_path_based(url))

        return all_findings
