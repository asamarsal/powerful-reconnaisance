"""Encoding utilities for payload generation and bypass techniques.

Provides various encoding/decoding functions commonly used in web security testing,
including URL encoding, HTML encoding, Base64, hex, Unicode, JWT encoding,
and IP address format conversions for SSRF bypass.
"""

import base64
import html
import urllib.parse
from typing import List


class Encoder:
    """Encoding/decoding utilities for scanner payloads."""

    @staticmethod
    def url_encode(payload: str, safe: str = '') -> str:
        """Standard URL encoding.

        Args:
            payload: String to encode
            safe: Characters to not encode

        Returns:
            URL-encoded string
        """
        return urllib.parse.quote(payload, safe=safe)

    @staticmethod
    def url_decode(payload: str) -> str:
        """URL decoding.

        Args:
            payload: URL-encoded string

        Returns:
            Decoded string
        """
        return urllib.parse.unquote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encoding for WAF bypass.

        Args:
            payload: String to double-encode

        Returns:
            Double URL-encoded string
        """
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML entity encoding.

        Args:
            payload: String to encode

        Returns:
            HTML-encoded string
        """
        return html.escape(payload)

    @staticmethod
    def html_decode(payload: str) -> str:
        """HTML entity decoding.

        Args:
            payload: HTML-encoded string

        Returns:
            Decoded string
        """
        return html.unescape(payload)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """Full HTML numeric entity encoding.

        Args:
            payload: String to encode

        Returns:
            String with each character as numeric HTML entity
        """
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def html_hex_entity_encode(payload: str) -> str:
        """HTML hex entity encoding.

        Args:
            payload: String to encode

        Returns:
            String with each character as hex HTML entity
        """
        return ''.join(f'&#x{ord(c):x};' for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encoding (\\x format).

        Args:
            payload: String to encode

        Returns:
            Hex-encoded string
        """
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encoding (\\u format).

        Args:
            payload: String to encode

        Returns:
            Unicode-encoded string
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encoding.

        Args:
            payload: String to encode

        Returns:
            Base64-encoded string
        """
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def base64_decode(payload: str) -> str:
        """Base64 decoding.

        Args:
            payload: Base64-encoded string

        Returns:
            Decoded string
        """
        return base64.b64decode(payload.encode()).decode()

    @staticmethod
    def jwt_base64_encode(data: bytes) -> str:
        """Base64url encode for JWT (no padding).

        Args:
            data: Bytes to encode

        Returns:
            Base64url-encoded string without padding
        """
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    @staticmethod
    def jwt_base64_decode(data: str) -> bytes:
        """Base64url decode for JWT (handles missing padding).

        Args:
            data: Base64url-encoded string

        Returns:
            Decoded bytes
        """
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Append null byte for path traversal bypass.

        Args:
            payload: Original payload

        Returns:
            Payload with null byte appended
        """
        return payload + '%00'

    @staticmethod
    def case_swap(payload: str) -> str:
        """Swap case for WAF bypass.

        Args:
            payload: Original payload

        Returns:
            Case-swapped payload
        """
        return payload.swapcase()

    @staticmethod
    def insert_comments(payload: str, comment_style: str = 'sql') -> str:
        """Insert inline comments for WAF bypass.

        Args:
            payload: Original payload
            comment_style: 'sql' for /**/, 'html' for <!---->

        Returns:
            Payload with comments inserted between characters
        """
        if comment_style == 'sql':
            return '/**/'.join(payload)
        elif comment_style == 'html':
            return '<!---->'.join(payload)
        return payload

    @staticmethod
    def ip_to_decimal(ip: str) -> str:
        """Convert IP to decimal notation (SSRF bypass).

        Args:
            ip: IP address string (e.g., '127.0.0.1')

        Returns:
            Decimal representation (e.g., '2130706433')
        """
        parts = ip.split('.')
        return str(int(parts[0]) * 16777216 + int(parts[1]) * 65536 +
                   int(parts[2]) * 256 + int(parts[3]))

    @staticmethod
    def ip_to_hex(ip: str) -> str:
        """Convert IP to hex notation (SSRF bypass).

        Args:
            ip: IP address string (e.g., '127.0.0.1')

        Returns:
            Hex representation (e.g., '0x7f000001')
        """
        parts = ip.split('.')
        return '0x' + ''.join(f'{int(p):02x}' for p in parts)

    @staticmethod
    def ip_to_octal(ip: str) -> str:
        """Convert IP to octal notation (SSRF bypass).

        Args:
            ip: IP address string (e.g., '127.0.0.1')

        Returns:
            Octal representation (e.g., '0177.0.0.01')
        """
        parts = ip.split('.')
        return '.'.join(f'0{int(p):o}' for p in parts)

    @staticmethod
    def ip_to_ipv6(ip: str) -> str:
        """Convert IPv4 to IPv6 mapped notation.

        Args:
            ip: IPv4 address string

        Returns:
            IPv6 mapped representation
        """
        parts = ip.split('.')
        hex_parts = ''.join(f'{int(p):02x}' for p in parts)
        return f'::ffff:{hex_parts[:4]}:{hex_parts[4:]}'

    @staticmethod
    def generate_variations(payload: str) -> List[str]:
        """Generate multiple encoding variations of a payload.

        Args:
            payload: Original payload

        Returns:
            List of encoded variations
        """
        variations = [
            payload,
            Encoder.url_encode(payload),
            Encoder.double_url_encode(payload),
            Encoder.html_encode(payload),
            Encoder.html_entity_encode(payload),
            Encoder.html_hex_entity_encode(payload),
        ]
        return variations

    @staticmethod
    def sql_char_encode(payload: str, db_type: str = 'mysql') -> str:
        """Encode string using SQL CHAR() function.

        Args:
            payload: String to encode
            db_type: Database type ('mysql', 'mssql', 'oracle')

        Returns:
            SQL CHAR() encoded string
        """
        if db_type == 'mysql':
            chars = ','.join(str(ord(c)) for c in payload)
            return f'CHAR({chars})'
        elif db_type == 'mssql':
            return '+'.join(f'CHAR({ord(c)})' for c in payload)
        elif db_type == 'oracle':
            return '||'.join(f'CHR({ord(c)})' for c in payload)
        return payload

    @staticmethod
    def unicode_normalize_bypass(payload: str) -> str:
        """Generate Unicode normalization bypass.

        Args:
            payload: Original payload

        Returns:
            Unicode-normalized bypass string
        """
        # Map common characters to Unicode equivalents
        unicode_map = {
            '<': '\uff1c',  # Fullwidth less-than
            '>': '\uff1e',  # Fullwidth greater-than
            '/': '\u2215',  # Division slash
            '\\': '\uff3c',  # Fullwidth reverse solidus
            "'": '\u2019',  # Right single quotation
            '"': '\u201d',  # Right double quotation
            '.': '\uff0e',  # Fullwidth full stop
        }
        return ''.join(unicode_map.get(c, c) for c in payload)
