"""HTTP client utility for scanner modules.

Provides a robust HTTP client wrapper around httpx with proxy support,
timeout handling, and curl command generation for PoC reproduction.
"""

import httpx
import time
from typing import Optional, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


class HttpClient:
    """Wrapper around httpx for consistent HTTP requests across all scanners."""

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    def __init__(self, timeout: float = 10.0, follow_redirects: bool = True,
                 verify_ssl: bool = False, proxy: Optional[str] = None,
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None):
        """Initialize HTTP client.

        Args:
            timeout: Request timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
            verify_ssl: Whether to verify SSL certificates
            proxy: Optional proxy URL (e.g., http://127.0.0.1:8080)
            cookies: Optional cookies dict
            headers: Optional additional headers
        """
        self.timeout = timeout
        self.follow_redirects = follow_redirects

        merged_headers = {**self.DEFAULT_HEADERS}
        if headers:
            merged_headers.update(headers)

        client_kwargs = {
            "timeout": timeout,
            "follow_redirects": follow_redirects,
            "verify": verify_ssl,
            "headers": merged_headers,
        }

        if cookies:
            client_kwargs["cookies"] = cookies
        if proxy:
            client_kwargs["proxy"] = proxy

        self.client = httpx.Client(**client_kwargs)

    def get(self, url: str, params: Optional[Dict] = None,
            headers: Optional[Dict] = None, **kwargs) -> httpx.Response:
        """Send GET request.

        Args:
            url: Target URL
            params: Optional query parameters
            headers: Optional additional headers

        Returns:
            httpx.Response object
        """
        try:
            return self.client.get(url, params=params, headers=headers, **kwargs)
        except httpx.RequestError as e:
            raise ConnectionError(f"Request failed: {e}")

    def post(self, url: str, data: Optional[Any] = None,
             json: Optional[Dict] = None, headers: Optional[Dict] = None,
             **kwargs) -> httpx.Response:
        """Send POST request.

        Args:
            url: Target URL
            data: Optional form data or raw body
            json: Optional JSON body
            headers: Optional additional headers

        Returns:
            httpx.Response object
        """
        try:
            return self.client.post(url, data=data, json=json, headers=headers, **kwargs)
        except httpx.RequestError as e:
            raise ConnectionError(f"Request failed: {e}")

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Send arbitrary HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, OPTIONS, etc.)
            url: Target URL
            **kwargs: Additional arguments passed to httpx

        Returns:
            httpx.Response object
        """
        try:
            return self.client.request(method, url, **kwargs)
        except httpx.RequestError as e:
            raise ConnectionError(f"Request failed: {e}")

    def timed_get(self, url: str, params: Optional[Dict] = None,
                  **kwargs) -> tuple:
        """GET request that returns (response, elapsed_seconds).

        Useful for time-based blind injection detection.

        Args:
            url: Target URL
            params: Optional query parameters

        Returns:
            Tuple of (httpx.Response, elapsed_time_in_seconds)
        """
        start = time.time()
        try:
            resp = self.client.get(url, params=params, **kwargs)
            elapsed = time.time() - start
            return resp, elapsed
        except httpx.RequestError as e:
            elapsed = time.time() - start
            raise ConnectionError(f"Request failed after {elapsed:.2f}s: {e}")

    def build_curl_command(self, method: str, url: str, params: Optional[Dict] = None,
                           headers: Optional[Dict] = None, data: Optional[Dict] = None) -> str:
        """Generate equivalent curl command for PoC reproduction.

        Args:
            method: HTTP method
            url: Target URL
            params: Optional query parameters
            headers: Optional headers
            data: Optional POST data

        Returns:
            curl command string
        """
        parts = ["curl", "-k"]

        if method.upper() != "GET":
            parts.append(f"-X {method.upper()}")

        if params:
            separator = "&" if "?" in url else "?"
            url = url + separator + urlencode(params)

        parts.append(f"'{url}'")

        if headers:
            for k, v in headers.items():
                parts.append(f"-H '{k}: {v}'")

        if data:
            if isinstance(data, dict):
                parts.append(f"-d '{urlencode(data)}'")
            else:
                parts.append(f"-d '{data}'")

        return " ".join(parts)

    def close(self):
        """Close the HTTP client and release resources."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
