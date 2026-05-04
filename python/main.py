"""
CLI entry point for the bug bounty reconnaissance toolkit.

Provides commands for scanning, bypassing, fuzzing, reconnaissance,
and secrets detection. Each command supports configurable options
for target, type, threads, timeout, proxy, and output.
"""

import sys
import json
import uuid
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich import box

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import (
    ScanConfig, FuzzerConfig, BypassConfig, SecretsConfig, ReconConfig,
    HttpConfig, ProxyConfig, OUTPUT_DIR,
)
from utils.http_client import HttpClient, HttpResponse
from utils.encoder import (
    url_encode, double_url_encode, unicode_encode, html_encode,
    base64_encode, hex_encode, chain_encode, generate_encoded_payloads,
)
from utils.reporter import Reporter, Finding, ScanReport

console = Console()


def get_http_client(proxy: Optional[str], timeout: int) -> HttpClient:
    """Create an HTTP client with the given settings."""
    http_config = HttpConfig(timeout=timeout)
    proxy_config = ProxyConfig()
    if proxy:
        proxy_config.enabled = True
        proxy_config.http_proxy = proxy
        proxy_config.https_proxy = proxy
    return HttpClient(http_config=http_config, proxy_config=proxy_config)


# ============================================================================
# CLI Group
# ============================================================================

@click.group()
@click.version_option(version="1.0.0", prog_name="recon-toolkit")
def cli():
    """Bug Bounty Reconnaissance Toolkit - Python Scanner Suite."""
    pass


# ============================================================================
# SCAN Command
# ============================================================================

@cli.command()
@click.option("--target", "-t", required=True, help="Target URL or domain")
@click.option("--type", "-T", "scan_type", default="full", 
              type=click.Choice(["full", "quick", "deep", "passive", "active"]),
              help="Scan type")
@click.option("--threads", "-n", default=10, help="Number of threads")
@click.option("--timeout", "-to", default=30, help="Request timeout in seconds")
@click.option("--proxy", "-p", default=None, help="Proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--output", "-o", default=None, help="Output file path")
def scan(target: str, scan_type: str, threads: int, timeout: int, proxy: Optional[str], output: Optional[str]):
    """Run a comprehensive scan against a target."""
    reporter = Reporter(verbose=True)
    reporter.banner("RECONNAISSANCE SCANNER", f"Target: {target}")

    scan_id = str(uuid.uuid4())[:8]
    report = reporter.create_report(scan_id=scan_id, target=target, scan_type=scan_type)

    reporter.info(f"Scan ID: {scan_id}")
    reporter.info(f"Type: {scan_type} | Threads: {threads} | Timeout: {timeout}s")
    if proxy:
        reporter.info(f"Proxy: {proxy}")

    client = get_http_client(proxy, timeout)

    try:
        # Initial probe
        reporter.status(f"Probing target: {target}")
        response = client.get(target)

        if response.error:
            reporter.error(f"Failed to reach target: {response.error}")
            return

        reporter.success(f"Target is alive - Status: {response.status_code}")
        report.stats["initial_status"] = response.status_code
        report.stats["server"] = response.headers.get("Server", "Unknown")
        report.stats["content_length"] = response.content_length

        # Check security headers
        reporter.status("Checking security headers...")
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        missing_headers = []
        for header in security_headers:
            if header.lower() not in {k.lower(): v for k, v in response.headers.items()}:
                missing_headers.append(header)

        if missing_headers:
            reporter.finding(
                title=f"Missing security headers: {', '.join(missing_headers[:3])}{'...' if len(missing_headers) > 3 else ''}",
                severity="low",
                url=target,
                description=f"Missing {len(missing_headers)} security headers",
                evidence=", ".join(missing_headers),
                tags=["headers", "security"],
            )
            report.findings.append(reporter._findings[-1])

        # Check for information disclosure
        reporter.status("Checking for information disclosure...")
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")

        if server:
            reporter.finding(
                title=f"Server header disclosed: {server}",
                severity="info",
                url=target,
                evidence=f"Server: {server}",
                tags=["info-disclosure"],
            )
            report.findings.append(reporter._findings[-1])

        if powered_by:
            reporter.finding(
                title=f"Technology disclosed: {powered_by}",
                severity="low",
                url=target,
                evidence=f"X-Powered-By: {powered_by}",
                tags=["info-disclosure"],
            )
            report.findings.append(reporter._findings[-1])

        # Check common paths
        reporter.status("Checking common paths...")
        common_paths = [
            "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
            "/wp-login.php", "/admin", "/api", "/.well-known/security.txt",
            "/swagger.json", "/api/docs", "/graphql",
        ]

        for path in common_paths:
            check_url = target.rstrip("/") + path
            resp = client.get(check_url, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                severity = "medium" if path in ["/.git/HEAD", "/.env"] else "info"
                if resp.status_code == 200 and path in ["/.git/HEAD", "/.env"]:
                    severity = "high"
                reporter.finding(
                    title=f"Path found: {path} [{resp.status_code}]",
                    severity=severity,
                    url=check_url,
                    evidence=f"Status: {resp.status_code}, Size: {resp.content_length}",
                    tags=["path-discovery"],
                )
                report.findings.append(reporter._findings[-1])

        # Finalize
        report = reporter.finalize_report(report)
        report.stats["total_requests"] = client.request_count
        reporter.summary(report)

        # Save results
        output_file = output or f"scan_{scan_id}.json"
        reporter.save_report(report, filename=output_file)

    finally:
        client.close()


# ============================================================================
# BYPASS Command
# ============================================================================

@cli.command()
@click.option("--target", "-t", required=True, help="Target URL to bypass")
@click.option("--type", "-T", "bypass_type", default="403",
              type=click.Choice(["403", "401", "admin", "waf", "all"]),
              help="Bypass type")
@click.option("--threads", "-n", default=10, help="Number of threads")
@click.option("--timeout", "-to", default=20, help="Request timeout in seconds")
@click.option("--proxy", "-p", default=None, help="Proxy URL")
@click.option("--output", "-o", default=None, help="Output file path")
def bypass(target: str, bypass_type: str, threads: int, timeout: int, proxy: Optional[str], output: Optional[str]):
    """Attempt to bypass access controls (403/401/WAF)."""
    from config import BYPASS_HEADERS, BYPASS_IPS

    reporter = Reporter(verbose=True)
    reporter.banner("ACCESS BYPASS SCANNER", f"Target: {target}")

    scan_id = str(uuid.uuid4())[:8]
    report = reporter.create_report(scan_id=scan_id, target=target, scan_type=f"bypass-{bypass_type}")

    reporter.info(f"Bypass type: {bypass_type} | Threads: {threads}")

    client = get_http_client(proxy, timeout)

    try:
        # Baseline request
        reporter.status("Getting baseline response...")
        baseline = client.get(target)
        reporter.info(f"Baseline: {baseline.status_code} ({baseline.content_length} bytes)")
        report.stats["baseline_status"] = baseline.status_code

        bypasses_found = 0

        # Header-based bypasses
        reporter.status("Testing header-based bypasses...")
        for header in BYPASS_HEADERS:
            for ip in BYPASS_IPS[:5]:  # Test top 5 IPs per header
                resp = client.get(target, headers={header: ip})
                if resp.status_code == 200 and baseline.status_code in [401, 403]:
                    bypasses_found += 1
                    reporter.finding(
                        title=f"Header bypass successful: {header}: {ip}",
                        severity="high",
                        url=target,
                        evidence=f"Status changed from {baseline.status_code} to {resp.status_code}",
                        tags=["bypass", "header"],
                        metadata={"header": header, "value": ip},
                    )
                    report.findings.append(reporter._findings[-1])

        # Method-based bypasses
        reporter.status("Testing HTTP method bypasses...")
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
        for method in methods:
            resp = client.request(method, target)
            if resp.status_code == 200 and baseline.status_code in [401, 403, 405]:
                bypasses_found += 1
                reporter.finding(
                    title=f"Method bypass: {method} returns {resp.status_code}",
                    severity="medium",
                    url=target,
                    evidence=f"{method} {target} -> {resp.status_code}",
                    tags=["bypass", "method"],
                )
                report.findings.append(reporter._findings[-1])

        # Path-based bypasses
        reporter.status("Testing path-based bypasses...")
        from urllib.parse import urlparse
        parsed = urlparse(target)
        path = parsed.path.rstrip("/")
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        path_mutations = [
            f"{path}/",
            f"{path}/.",
            f"{path}//",
            f"{path}/..",
            f"{path}%20",
            f"{path}%09",
            f"{path}%00",
            f"{path}..;/",
            f"{path};",
            f"{path}?",
            f"{path}#",
            f"{path}.json",
            f"{path}.html",
            f"/{path.lstrip('/')}",
            f"//{path.lstrip('/')}",
        ]

        for mutated_path in path_mutations:
            test_url = base_url + mutated_path
            resp = client.get(test_url)
            if resp.status_code == 200 and baseline.status_code in [401, 403]:
                bypasses_found += 1
                reporter.finding(
                    title=f"Path bypass: {mutated_path}",
                    severity="high",
                    url=test_url,
                    evidence=f"Status: {resp.status_code}, Size: {resp.content_length}",
                    tags=["bypass", "path"],
                )
                report.findings.append(reporter._findings[-1])

        # Finalize
        report.stats["bypasses_found"] = bypasses_found
        report.stats["total_requests"] = client.request_count
        report = reporter.finalize_report(report)
        reporter.summary(report)

        output_file = output or f"bypass_{scan_id}.json"
        reporter.save_report(report, filename=output_file)

    finally:
        client.close()


# ============================================================================
# FUZZ Command
# ============================================================================

@cli.command()
@click.option("--target", "-t", required=True, help="Target URL with FUZZ keyword")
@click.option("--type", "-T", "fuzz_type", default="dir",
              type=click.Choice(["dir", "param", "vhost", "header", "custom"]),
              help="Fuzz type")
@click.option("--threads", "-n", default=20, help="Number of threads")
@click.option("--timeout", "-to", default=15, help="Request timeout in seconds")
@click.option("--proxy", "-p", default=None, help="Proxy URL")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--wordlist", "-w", default=None, help="Wordlist file path")
def fuzz(target: str, fuzz_type: str, threads: int, timeout: int, proxy: Optional[str], output: Optional[str], wordlist: Optional[str]):
    """Fuzz URLs, parameters, virtual hosts, or headers."""
    reporter = Reporter(verbose=True)
    reporter.banner("FUZZER", f"Target: {target}")

    scan_id = str(uuid.uuid4())[:8]
    report = reporter.create_report(scan_id=scan_id, target=target, scan_type=f"fuzz-{fuzz_type}")

    reporter.info(f"Fuzz type: {fuzz_type} | Threads: {threads}")

    # Default wordlist if none provided
    default_words = [
        "admin", "api", "backup", "config", "dashboard", "db", "debug",
        "dev", "docs", "download", "env", "files", "graphql", "health",
        "help", "hidden", "images", "include", "internal", "js", "json",
        "login", "logs", "manage", "metrics", "monitor", "old", "panel",
        "private", "public", "readme", "redirect", "register", "reset",
        "robots.txt", "rss", "search", "secret", "server-status", "setup",
        "sitemap.xml", "staging", "static", "status", "swagger", "system",
        "temp", "test", "tmp", "token", "upload", "user", "users", "v1",
        "v2", "version", "web", "wp-admin", "wp-content", "wp-login.php",
        "xmlrpc.php", ".git", ".env", ".htaccess", "package.json",
        "composer.json", "web.config", "crossdomain.xml",
    ]

    words = default_words
    if wordlist:
        wordlist_path = Path(wordlist)
        if wordlist_path.exists():
            words = [line.strip() for line in wordlist_path.read_text().splitlines() if line.strip() and not line.startswith("#")]
            reporter.info(f"Loaded {len(words)} words from {wordlist}")
        else:
            reporter.warning(f"Wordlist not found: {wordlist}, using defaults")

    reporter.info(f"Wordlist size: {len(words)}")

    client = get_http_client(proxy, timeout)
    found_count = 0

    try:
        # Get baseline for filtering
        reporter.status("Getting baseline for filtering...")
        baseline_url = target.replace("FUZZ", "thispagedoesnotexist12345")
        baseline = client.get(baseline_url)
        baseline_size = baseline.content_length
        baseline_status = baseline.status_code

        reporter.info(f"Baseline: {baseline_status} ({baseline_size} bytes)")

        # Fuzz
        reporter.status("Fuzzing...")
        results_table = []

        for i, word in enumerate(words):
            if "FUZZ" in target:
                test_url = target.replace("FUZZ", word)
            else:
                test_url = target.rstrip("/") + "/" + word

            resp = client.get(test_url, allow_redirects=False)

            # Filter out baseline-matching responses
            if resp.status_code == baseline_status and resp.content_length == baseline_size:
                continue

            # Filter 404s
            if resp.status_code == 404:
                continue

            if resp.status_code in [200, 201, 202, 204, 301, 302, 307, 401, 403, 405, 500]:
                found_count += 1
                severity = "info"
                if resp.status_code == 200:
                    severity = "low"
                if resp.status_code in [401, 403]:
                    severity = "medium"

                reporter.finding(
                    title=f"[{resp.status_code}] /{word} ({resp.content_length} bytes)",
                    severity=severity,
                    url=test_url,
                    evidence=f"Status: {resp.status_code}, Size: {resp.content_length}, Words: {resp.words}",
                    tags=["fuzz", fuzz_type],
                )
                report.findings.append(reporter._findings[-1])
                results_table.append([str(resp.status_code), word, str(resp.content_length), f"{resp.elapsed:.2f}s"])

            # Progress indicator
            if (i + 1) % 50 == 0:
                reporter.status(f"Progress: {i + 1}/{len(words)} ({found_count} found)")

        # Print results table
        if results_table:
            reporter.table(
                title="Fuzz Results",
                columns=["Status", "Path", "Size", "Time"],
                rows=results_table,
            )

        # Finalize
        report.stats["total_words"] = len(words)
        report.stats["found_count"] = found_count
        report.stats["total_requests"] = client.request_count
        report = reporter.finalize_report(report)
        reporter.summary(report)

        output_file = output or f"fuzz_{scan_id}.json"
        reporter.save_report(report, filename=output_file)

    finally:
        client.close()


# ============================================================================
# RECON Command
# ============================================================================

@cli.command()
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--type", "-T", "recon_type", default="full",
              type=click.Choice(["full", "subdomain", "tech", "dns", "whois"]),
              help="Recon type")
@click.option("--threads", "-n", default=10, help="Number of threads")
@click.option("--timeout", "-to", default=30, help="Request timeout in seconds")
@click.option("--proxy", "-p", default=None, help="Proxy URL")
@click.option("--output", "-o", default=None, help="Output file path")
def recon(target: str, recon_type: str, threads: int, timeout: int, proxy: Optional[str], output: Optional[str]):
    """Perform reconnaissance on a target domain."""
    import socket
    try:
        import dns.resolver
        has_dns = True
    except ImportError:
        has_dns = False

    try:
        import tldextract
        has_tld = True
    except ImportError:
        has_tld = False

    reporter = Reporter(verbose=True)
    reporter.banner("RECONNAISSANCE", f"Target: {target}")

    scan_id = str(uuid.uuid4())[:8]
    report = reporter.create_report(scan_id=scan_id, target=target, scan_type=f"recon-{recon_type}")

    reporter.info(f"Recon type: {recon_type} | Threads: {threads}")

    client = get_http_client(proxy, timeout)

    try:
        # Domain info
        if has_tld:
            extracted = tldextract.extract(target)
            domain = f"{extracted.domain}.{extracted.suffix}"
            reporter.info(f"Domain: {domain}")
            reporter.info(f"Subdomain: {extracted.subdomain or '(none)'}")
            report.stats["domain"] = domain
        else:
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]

        # DNS Resolution
        reporter.status("Resolving DNS...")
        try:
            ips = socket.gethostbyname_ex(domain)
            reporter.info(f"IP Addresses: {', '.join(ips[2])}")
            report.stats["ip_addresses"] = ips[2]

            for ip in ips[2]:
                reporter.finding(
                    title=f"DNS Resolution: {domain} -> {ip}",
                    severity="info",
                    url=domain,
                    evidence=f"A record: {ip}",
                    tags=["dns", "recon"],
                )
                report.findings.append(reporter._findings[-1])
        except socket.gaierror as e:
            reporter.warning(f"DNS resolution failed: {e}")

        # DNS Records (if dnspython available)
        if has_dns and recon_type in ["full", "dns"]:
            reporter.status("Querying DNS records...")
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    for rdata in answers:
                        reporter.finding(
                            title=f"DNS {rtype}: {str(rdata)[:80]}",
                            severity="info",
                            url=domain,
                            evidence=f"{rtype} record: {str(rdata)}",
                            tags=["dns", rtype.lower()],
                        )
                        report.findings.append(reporter._findings[-1])
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                except Exception:
                    pass

        # Subdomain enumeration
        if recon_type in ["full", "subdomain"]:
            reporter.status("Enumerating subdomains...")
            common_subdomains = [
                "www", "mail", "ftp", "admin", "api", "dev", "staging",
                "test", "blog", "shop", "app", "m", "mobile", "cdn",
                "static", "assets", "img", "images", "media", "docs",
                "portal", "vpn", "remote", "git", "gitlab", "jenkins",
                "ci", "jira", "confluence", "wiki", "support", "help",
                "status", "monitor", "grafana", "kibana", "elastic",
            ]

            found_subdomains = []
            for sub in common_subdomains:
                subdomain = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(subdomain)
                    found_subdomains.append((subdomain, ip))
                    reporter.finding(
                        title=f"Subdomain found: {subdomain} ({ip})",
                        severity="info",
                        url=subdomain,
                        evidence=f"Resolves to: {ip}",
                        tags=["subdomain", "recon"],
                    )
                    report.findings.append(reporter._findings[-1])
                except socket.gaierror:
                    pass

            report.stats["subdomains_found"] = len(found_subdomains)

            if found_subdomains:
                reporter.table(
                    title="Discovered Subdomains",
                    columns=["Subdomain", "IP Address"],
                    rows=[[s, ip] for s, ip in found_subdomains],
                )

        # Technology detection
        if recon_type in ["full", "tech"]:
            reporter.status("Detecting technologies...")
            url = target if target.startswith("http") else f"https://{target}"
            resp = client.get(url)

            if not resp.error:
                techs = []
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                if "x-powered-by" in headers_lower:
                    techs.append(("X-Powered-By", headers_lower["x-powered-by"]))
                if "server" in headers_lower:
                    techs.append(("Server", headers_lower["server"]))
                if "x-aspnet-version" in headers_lower:
                    techs.append(("ASP.NET", headers_lower["x-aspnet-version"]))

                # Check body for common frameworks
                body_lower = resp.body.lower()
                tech_signatures = {
                    "WordPress": ["wp-content", "wp-includes", "wordpress"],
                    "React": ["react", "_next/static", "__next"],
                    "Angular": ["ng-version", "angular"],
                    "Vue.js": ["vue.js", "vuejs", "__vue"],
                    "jQuery": ["jquery"],
                    "Bootstrap": ["bootstrap"],
                    "Laravel": ["laravel", "csrf-token"],
                    "Django": ["csrfmiddlewaretoken", "django"],
                    "Express": ["express"],
                }

                for tech, signatures in tech_signatures.items():
                    for sig in signatures:
                        if sig in body_lower:
                            techs.append(("Framework", tech))
                            break

                for category, tech in techs:
                    reporter.finding(
                        title=f"Technology detected: {tech} ({category})",
                        severity="info",
                        url=url,
                        tags=["technology", "recon"],
                    )
                    report.findings.append(reporter._findings[-1])

                report.stats["technologies"] = [t[1] for t in techs]

        # Finalize
        report.stats["total_requests"] = client.request_count
        report = reporter.finalize_report(report)
        reporter.summary(report)

        output_file = output or f"recon_{scan_id}.json"
        reporter.save_report(report, filename=output_file)

    finally:
        client.close()


# ============================================================================
# SECRETS Command
# ============================================================================

@cli.command()
@click.option("--target", "-t", required=True, help="Target URL to scan for secrets")
@click.option("--type", "-T", "secret_type", default="all",
              type=click.Choice(["all", "api_keys", "tokens", "credentials", "urls"]),
              help="Secret type to search for")
@click.option("--threads", "-n", default=10, help="Number of threads")
@click.option("--timeout", "-to", default=30, help="Request timeout in seconds")
@click.option("--proxy", "-p", default=None, help="Proxy URL")
@click.option("--output", "-o", default=None, help="Output file path")
def secrets(target: str, secret_type: str, threads: int, timeout: int, proxy: Optional[str], output: Optional[str]):
    """Scan for exposed secrets, API keys, and sensitive data."""
    import re
    from config import SECRET_PATTERNS

    reporter = Reporter(verbose=True)
    reporter.banner("SECRETS SCANNER", f"Target: {target}")

    scan_id = str(uuid.uuid4())[:8]
    report = reporter.create_report(scan_id=scan_id, target=target, scan_type=f"secrets-{secret_type}")

    reporter.info(f"Secret type: {secret_type} | Threads: {threads}")

    client = get_http_client(proxy, timeout)
    secrets_found = 0

    try:
        # Determine which patterns to use
        if secret_type == "all":
            patterns = SECRET_PATTERNS
        elif secret_type == "api_keys":
            patterns = {k: v for k, v in SECRET_PATTERNS.items() if "key" in k or "api" in k}
        elif secret_type == "tokens":
            patterns = {k: v for k, v in SECRET_PATTERNS.items() if "token" in k or "jwt" in k or "bearer" in k}
        elif secret_type == "credentials":
            patterns = {k: v for k, v in SECRET_PATTERNS.items() if "secret" in k or "password" in k or "private" in k}
        elif secret_type == "urls":
            patterns = {k: v for k, v in SECRET_PATTERNS.items() if "url" in k or "bucket" in k or "firebase" in k}
        else:
            patterns = SECRET_PATTERNS

        reporter.info(f"Scanning with {len(patterns)} patterns")

        # Fetch main page
        reporter.status(f"Fetching: {target}")
        response = client.get(target)

        if response.error:
            reporter.error(f"Failed to fetch target: {response.error}")
            return

        # Scan main page
        reporter.status("Scanning response for secrets...")
        for pattern_name, pattern in patterns.items():
            try:
                matches = re.findall(pattern, response.body)
                for match in matches:
                    secrets_found += 1
                    match_str = match if isinstance(match, str) else match[0] if match else ""
                    # Truncate long matches
                    display_match = match_str[:80] + "..." if len(match_str) > 80 else match_str
                    reporter.finding(
                        title=f"Secret found: {pattern_name}",
                        severity="high",
                        url=target,
                        description=f"Pattern: {pattern_name}",
                        evidence=display_match,
                        tags=["secret", pattern_name],
                    )
                    report.findings.append(reporter._findings[-1])
            except re.error:
                pass

        # Scan JavaScript files
        reporter.status("Looking for JavaScript files...")
        js_pattern = r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
        js_files = re.findall(js_pattern, response.body)

        if js_files:
            reporter.info(f"Found {len(js_files)} JavaScript files")

            for js_url in js_files[:20]:  # Limit to 20 JS files
                # Resolve relative URLs
                if js_url.startswith("//"):
                    js_url = "https:" + js_url
                elif js_url.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(target)
                    js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                elif not js_url.startswith("http"):
                    js_url = target.rstrip("/") + "/" + js_url

                js_response = client.get(js_url)
                if js_response.error or js_response.status_code != 200:
                    continue

                for pattern_name, pattern in patterns.items():
                    try:
                        matches = re.findall(pattern, js_response.body)
                        for match in matches:
                            secrets_found += 1
                            match_str = match if isinstance(match, str) else match[0] if match else ""
                            display_match = match_str[:80] + "..." if len(match_str) > 80 else match_str
                            reporter.finding(
                                title=f"Secret in JS: {pattern_name}",
                                severity="high",
                                url=js_url,
                                description=f"Found in JavaScript file",
                                evidence=display_match,
                                tags=["secret", "javascript", pattern_name],
                            )
                            report.findings.append(reporter._findings[-1])
                    except re.error:
                        pass

        # Check common sensitive endpoints
        reporter.status("Checking sensitive endpoints...")
        sensitive_paths = [
            "/api/config", "/api/settings", "/config.json", "/env.json",
            "/.env", "/debug", "/info", "/actuator/env",
            "/api/v1/config", "/__debug__",
        ]

        for path in sensitive_paths:
            check_url = target.rstrip("/") + path
            resp = client.get(check_url)
            if resp.status_code == 200 and resp.content_length > 0:
                # Scan the response for secrets
                for pattern_name, pattern in patterns.items():
                    try:
                        matches = re.findall(pattern, resp.body)
                        for match in matches:
                            secrets_found += 1
                            match_str = match if isinstance(match, str) else match[0] if match else ""
                            display_match = match_str[:80] + "..." if len(match_str) > 80 else match_str
                            reporter.finding(
                                title=f"Secret at {path}: {pattern_name}",
                                severity="critical",
                                url=check_url,
                                description=f"Sensitive endpoint exposed with secrets",
                                evidence=display_match,
                                tags=["secret", "endpoint", pattern_name],
                            )
                            report.findings.append(reporter._findings[-1])
                    except re.error:
                        pass

        # Finalize
        report.stats["secrets_found"] = secrets_found
        report.stats["js_files_scanned"] = len(js_files[:20])
        report.stats["total_requests"] = client.request_count
        report = reporter.finalize_report(report)
        reporter.summary(report)

        output_file = output or f"secrets_{scan_id}.json"
        reporter.save_report(report, filename=output_file)

    finally:
        client.close()


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    cli()
