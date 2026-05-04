"""Hidden parameter discovery - Mines for hidden/undocumented parameters."""

import httpx
import hashlib
import time
from urllib.parse import urlparse, urlencode, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set


class ParamMiner:
    """Discovers hidden parameters by testing response differences."""

    def __init__(self, threads: int = 10, timeout: int = 10, batch_size: int = 20):
        """
        Initialize ParamMiner.

        Args:
            threads: Number of concurrent threads.
            timeout: HTTP request timeout in seconds.
            batch_size: Number of params to test per request.
        """
        self.threads = threads
        self.timeout = timeout
        self.batch_size = batch_size
        self.findings: List[Dict[str, Any]] = []

    def mine(self, url: str) -> List[Dict[str, Any]]:
        """
        Discover hidden parameters on the target URL.

        Args:
            url: Target URL to mine for hidden parameters.

        Returns:
            List of discovered parameters with evidence.
        """
        self.findings = []
        print(f"[*] Mining hidden parameters on: {url}")

        # Get baseline
        baseline = self._get_baseline(url)
        if not baseline:
            print("[-] Could not establish baseline")
            return self.findings

        print(f"[*] Baseline: status={baseline['status_code']}, "
              f"length={baseline['content_length']}, hash={baseline['body_hash'][:8]}")

        # Get wordlist
        wordlist = self._get_wordlist()
        print(f"[*] Testing {len(wordlist)} potential parameters...")

        # Split wordlist into batches for initial detection
        batches = [wordlist[i:i + self.batch_size] for i in range(0, len(wordlist), self.batch_size)]

        # Phase 1: Batch testing to find interesting batches
        interesting_params: Set[str] = set()
        print("[*] Phase 1: Batch testing...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for batch in batches:
                future = executor.submit(self._test_params, url, batch, baseline)
                futures[future] = batch

            for future in as_completed(futures):
                batch = futures[future]
                try:
                    result = future.result()
                    if result:
                        # This batch caused a difference, test individually
                        for param in batch:
                            interesting_params.add(param)
                except Exception:
                    pass

        # Phase 2: Individual testing of interesting params
        if interesting_params:
            print(f"[*] Phase 2: Testing {len(interesting_params)} candidates individually...")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for param in interesting_params:
                    future = executor.submit(self._test_single_param, url, param, baseline)
                    futures[future] = param

                for future in as_completed(futures):
                    param = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.findings.append(result)
                    except Exception:
                        pass

        # Sort by confidence
        self.findings.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        print(f"[+] Discovered {len(self.findings)} hidden parameters")
        return self.findings

    def _test_params(self, url: str, params_to_test: List[str], baseline: Dict[str, Any]) -> bool:
        """
        Test if a batch of parameters affects the response.

        Args:
            url: Target URL.
            params_to_test: List of parameter names to test.
            baseline: Baseline response characteristics.

        Returns:
            True if the batch causes a response difference.
        """
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)

        # Add test params with canary values
        for param in params_to_test:
            existing_params[param] = [f"paraminer{hash(param) % 9999}"]

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing_params, doseq=True)}"

        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                response = client.get(test_url)

                # Compare with baseline
                current_hash = hashlib.md5(response.content).hexdigest()
                current_length = len(response.content)

                # Check for differences
                if response.status_code != baseline["status_code"]:
                    return True
                if current_hash != baseline["body_hash"]:
                    # Allow small variations (dynamic content)
                    length_diff = abs(current_length - baseline["content_length"])
                    if length_diff > 50:  # More than 50 bytes difference
                        return True
                    # Check if response contains our canary values
                    for param in params_to_test:
                        canary = f"paraminer{hash(param) % 9999}"
                        if canary in response.text:
                            return True

        except Exception:
            pass

        return False

    def _test_single_param(self, url: str, param: str, baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test a single parameter individually."""
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)

        test_values = ["1", "true", "admin", f"paraminer{hash(param) % 9999}"]
        best_result = None
        best_confidence = 0

        for value in test_values:
            existing_params[param] = [value]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing_params, doseq=True)}"

            try:
                with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                    response = client.get(test_url)

                    confidence = 0
                    evidence = []

                    # Status code change
                    if response.status_code != baseline["status_code"]:
                        confidence += 0.4
                        evidence.append(f"Status changed: {baseline['status_code']} -> {response.status_code}")

                    # Content length change
                    current_length = len(response.content)
                    length_diff = abs(current_length - baseline["content_length"])
                    if length_diff > 100:
                        confidence += 0.3
                        evidence.append(f"Length changed by {length_diff} bytes")
                    elif length_diff > 20:
                        confidence += 0.15
                        evidence.append(f"Minor length change: {length_diff} bytes")

                    # Body hash change
                    current_hash = hashlib.md5(response.content).hexdigest()
                    if current_hash != baseline["body_hash"]:
                        confidence += 0.1
                        evidence.append("Response body changed")

                    # Reflection of value
                    if value in response.text:
                        confidence += 0.3
                        evidence.append(f"Value '{value}' reflected in response")

                    # New headers
                    new_headers = set(response.headers.keys()) - set(baseline.get("headers", {}).keys())
                    if new_headers:
                        confidence += 0.2
                        evidence.append(f"New headers: {', '.join(list(new_headers)[:3])}")

                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_result = {
                            "param": param,
                            "value_tested": value,
                            "url": test_url,
                            "status_code": response.status_code,
                            "response_length": current_length,
                            "baseline_length": baseline["content_length"],
                            "confidence": min(confidence, 1.0),
                            "evidence": evidence,
                            "reflected": value in response.text,
                        }

            except Exception:
                pass

        # Only return if confidence is meaningful
        if best_result and best_confidence >= 0.2:
            return best_result
        return None

    def _get_baseline(self, url: str) -> Optional[Dict[str, Any]]:
        """Get stable baseline response for comparison."""
        try:
            with httpx.Client(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                # Get multiple baselines to account for dynamic content
                responses = []
                for _ in range(3):
                    response = client.get(url)
                    responses.append(response)
                    time.sleep(0.1)

                # Use the most common response
                return {
                    "status_code": responses[0].status_code,
                    "content_length": len(responses[0].content),
                    "body_hash": hashlib.md5(responses[0].content).hexdigest(),
                    "headers": dict(responses[0].headers),
                    "body_sample": responses[0].text[:2000],
                }
        except Exception:
            return None

    def _get_wordlist(self) -> List[str]:
        """Return 500+ common hidden parameter names."""
        return [
            # Authentication & Authorization
            "admin", "auth", "token", "key", "api_key", "apikey", "api-key",
            "secret", "password", "passwd", "pass", "pwd", "login", "user",
            "username", "email", "session", "sessionid", "session_id", "sid",
            "jwt", "bearer", "oauth", "access_token", "refresh_token",
            "auth_token", "authorization", "credential", "credentials",
            # Debug & Development
            "debug", "test", "testing", "dev", "development", "staging",
            "verbose", "trace", "log", "logging", "profiling", "profile",
            "benchmark", "monitor", "monitoring", "diagnostics", "diag",
            "info", "information", "status", "health", "healthcheck",
            "version", "ver", "v", "build", "revision", "env", "environment",
            # Configuration
            "config", "configuration", "settings", "setup", "options",
            "preferences", "prefs", "mode", "type", "format", "output",
            "encoding", "charset", "locale", "lang", "language", "timezone",
            "tz", "region", "country", "currency",
            # Pagination & Filtering
            "page", "p", "pg", "offset", "limit", "size", "count",
            "per_page", "perpage", "page_size", "pagesize", "start",
            "end", "from", "to", "max", "min", "num", "number",
            "sort", "order", "orderby", "order_by", "sortby", "sort_by",
            "direction", "dir", "asc", "desc", "filter", "filters",
            "search", "q", "query", "keyword", "keywords", "term",
            # Content & Display
            "view", "display", "show", "hide", "visible", "hidden",
            "template", "theme", "layout", "style", "css", "render",
            "preview", "draft", "published", "private", "public",
            "include", "exclude", "fields", "select", "columns",
            "expand", "embed", "inline", "raw", "plain", "html",
            "json", "xml", "csv", "pdf", "download", "export",
            # Actions & Operations
            "action", "act", "do", "cmd", "command", "op", "operation",
            "method", "function", "func", "handler", "process",
            "submit", "save", "update", "delete", "remove", "create",
            "add", "edit", "modify", "change", "set", "get", "put",
            "post", "patch", "reset", "clear", "flush", "purge",
            "refresh", "reload", "sync", "import", "upload",
            # Identifiers
            "id", "uid", "uuid", "guid", "ref", "reference", "code",
            "hash", "checksum", "signature", "sig", "nonce", "salt",
            "timestamp", "ts", "time", "date", "datetime", "created",
            "updated", "modified", "expires", "expiry", "ttl",
            # URLs & Paths
            "url", "uri", "href", "link", "src", "source", "dest",
            "destination", "target", "path", "file", "filename",
            "filepath", "dir", "directory", "folder", "location",
            "redirect", "redirect_url", "redirect_uri", "return",
            "return_url", "returnurl", "next", "prev", "previous",
            "back", "continue", "goto", "forward", "callback",
            "callback_url", "webhook", "hook", "endpoint",
            # Network & Security
            "ip", "host", "hostname", "domain", "port", "protocol",
            "proxy", "origin", "referer", "referrer", "xff",
            "x-forwarded-for", "client", "client_id", "client_secret",
            "cors", "csrf", "xsrf", "captcha", "recaptcha",
            "verify", "validate", "check", "confirm", "approve",
            # Data & Content
            "data", "body", "content", "text", "message", "msg",
            "title", "name", "label", "description", "desc", "summary",
            "comment", "note", "notes", "tag", "tags", "category",
            "categories", "group", "groups", "role", "roles",
            "permission", "permissions", "scope", "scopes",
            # Application Specific
            "app", "application", "service", "module", "component",
            "plugin", "addon", "extension", "widget", "feature",
            "flag", "flags", "toggle", "switch", "enable", "disable",
            "enabled", "disabled", "active", "inactive", "on", "off",
            # Database & Storage
            "db", "database", "table", "collection", "bucket",
            "schema", "model", "entity", "record", "row", "column",
            "field", "attribute", "property", "index", "cache",
            "redis", "memcache", "store", "storage",
            # API Specific
            "api", "api_version", "api_key", "app_id", "app_key",
            "client_id", "client_secret", "grant_type", "response_type",
            "scope", "state", "code", "token_type", "expires_in",
            "access_type", "approval_prompt", "login_hint",
            # Headers as params
            "content_type", "content-type", "accept", "accept-language",
            "user-agent", "user_agent", "useragent", "ua",
            # Misc
            "callback", "jsonp", "padding", "wrap", "wrapper",
            "envelope", "pretty", "indent", "compact", "minify",
            "compress", "gzip", "deflate", "chunk", "stream",
            "async", "sync", "blocking", "nonblocking", "timeout",
            "retry", "retries", "delay", "interval", "frequency",
            "rate", "throttle", "burst", "quota", "budget",
            "priority", "weight", "rank", "score", "level",
            "depth", "width", "height", "length", "radius",
            "lat", "lng", "latitude", "longitude", "geo",
            "location", "address", "zip", "postal", "phone",
            "mobile", "fax", "website", "company", "organization",
            # Security Testing
            "bypass", "override", "overwrite", "force", "skip",
            "ignore", "allow", "deny", "block", "whitelist",
            "blacklist", "trusted", "internal", "external",
            "privileged", "elevated", "sudo", "root", "superuser",
            "backdoor", "master", "skeleton", "magic",
            # Framework Specific
            "_method", "__method", "_token", "__token", "_csrf",
            "__csrf", "_session", "__session", "_debug", "__debug",
            "_format", "__format", "_locale", "__locale",
            "XDEBUG_SESSION_START", "XDEBUG_SESSION",
            "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
            "_wpnonce", "wp_nonce", "nonce",
            # GraphQL
            "query", "mutation", "subscription", "variables",
            "operationName", "extensions",
            # Common API params
            "fields", "include", "exclude", "populate", "select",
            "where", "having", "join", "with", "without",
            "before", "after", "since", "until", "between",
            "gt", "gte", "lt", "lte", "eq", "ne", "in", "nin",
            "like", "regex", "match", "contains", "startswith",
            "endswith", "exists", "null", "empty", "blank",
            # Encoding & Format
            "base64", "hex", "binary", "octal", "decimal",
            "utf8", "ascii", "unicode", "escaped", "quoted",
            "urlencoded", "multipart", "form", "formdata",
            # Versioning
            "v1", "v2", "v3", "version", "api_version",
            "schema_version", "protocol_version",
            # Feature flags
            "feature", "experiment", "variant", "ab_test",
            "bucket", "cohort", "segment", "audience",
            # Webhooks & Events
            "event", "events", "trigger", "webhook_url",
            "notification", "notify", "alert", "subscribe",
            "unsubscribe", "channel", "topic", "queue",
            # File operations
            "file", "upload", "attachment", "media", "image",
            "photo", "video", "audio", "document", "archive",
            "extension", "mime", "mimetype", "content_type",
            # Rate limiting
            "rate_limit", "throttle", "quota", "burst",
            "window", "interval", "cooldown",
        ]
