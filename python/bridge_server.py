"""
Bridge Server - FastAPI server for the bug bounty reconnaissance toolkit.

Provides a REST API interface to all scanner modules, allowing integration
with other tools and automation pipelines. Runs scans as background tasks
and stores results for retrieval.
"""

import sys
import uuid
import time
import asyncio
import re
import socket
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import (
    HttpConfig, ProxyConfig, SECRET_PATTERNS, BYPASS_HEADERS, BYPASS_IPS,
)
from utils.http_client import HttpClient
from utils.encoder import generate_encoded_payloads, chain_encode
from utils.reporter import Reporter, Finding, ScanReport

# ============================================================================
# App Setup
# ============================================================================

app = FastAPI(
    title="Recon Toolkit Bridge Server",
    description="REST API for bug bounty reconnaissance toolkit",
    version="1.0.0",
)

# In-memory results store
results_store: Dict[str, Dict[str, Any]] = {}

# Thread pool for running scans
executor = ThreadPoolExecutor(max_workers=10)


# ============================================================================
# Request/Response Models
# ============================================================================

class ScanRequest(BaseModel):
    """Request model for scan endpoint."""
    target: str = Field(..., description="Target URL or domain")
    scan_type: str = Field(default="full", description="Scan type: full, quick, deep, passive, active")
    params: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters")
    options: Dict[str, Any] = Field(default_factory=dict, description="Scan options (threads, timeout, proxy)")


class BypassRequest(BaseModel):
    """Request model for bypass endpoints."""
    target: str = Field(..., description="Target URL to bypass")
    methods: List[str] = Field(default_factory=lambda: ["headers", "methods", "paths"], description="Bypass methods to try")
    options: Dict[str, Any] = Field(default_factory=dict, description="Options (timeout, proxy)")


class SecretsRequest(BaseModel):
    """Request model for secrets endpoint."""
    target: str = Field(..., description="Target URL to scan")
    patterns: List[str] = Field(default_factory=lambda: ["all"], description="Pattern categories to use")
    scan_js: bool = Field(default=True, description="Whether to scan JavaScript files")
    options: Dict[str, Any] = Field(default_factory=dict, description="Options (timeout, proxy)")


class FuzzRequest(BaseModel):
    """Request model for fuzz endpoint."""
    target: str = Field(..., description="Target URL with FUZZ keyword")
    wordlist: List[str] = Field(default_factory=list, description="Words to fuzz with")
    fuzz_type: str = Field(default="dir", description="Fuzz type: dir, param, vhost, header")
    options: Dict[str, Any] = Field(default_factory=dict, description="Options (threads, timeout, proxy, extensions)")


class ScanResult(BaseModel):
    """Response model for scan results."""
    scan_id: str
    status: str
    target: str
    scan_type: str
    started_at: str
    completed_at: Optional[str] = None
    duration: Optional[float] = None
    findings: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {}
    errors: List[str] = []


# ============================================================================
# Helper Functions
# ============================================================================

def get_client(options: Dict[str, Any]) -> HttpClient:
    """Create an HTTP client from options."""
    timeout = options.get("timeout", 30)
    proxy = options.get("proxy")

    http_config = HttpConfig(timeout=timeout)
    proxy_config = ProxyConfig()
    if proxy:
        proxy_config.enabled = True
        proxy_config.http_proxy = proxy
        proxy_config.https_proxy = proxy

    return HttpClient(http_config=http_config, proxy_config=proxy_config)


def update_result(scan_id: str, **kwargs):
    """Update a scan result in the store."""
    if scan_id in results_store:
        results_store[scan_id].update(kwargs)


# ============================================================================
# Background Task Functions
# ============================================================================

def run_scan_task(scan_id: str, target: str, scan_type: str, params: Dict, options: Dict):
    """Run a comprehensive scan as a background task."""
    findings = []
    errors = []
    stats = {}

    client = get_client(options)

    try:
        # Initial probe
        response = client.get(target)
        if response.error:
            errors.append(f"Failed to reach target: {response.error}")
            update_result(scan_id, status="error", errors=errors,
                         completed_at=datetime.utcnow().isoformat())
            return

        stats["initial_status"] = response.status_code
        stats["server"] = response.headers.get("Server", "Unknown")
        stats["content_length"] = response.content_length

        # Security headers check
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
        ]
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        missing = [h for h in security_headers if h.lower() not in headers_lower]

        if missing:
            findings.append({
                "title": f"Missing security headers ({len(missing)})",
                "severity": "low",
                "url": target,
                "evidence": ", ".join(missing),
                "tags": ["headers", "security"],
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Server disclosure
        server = response.headers.get("Server", "")
        if server:
            findings.append({
                "title": f"Server disclosed: {server}",
                "severity": "info",
                "url": target,
                "evidence": f"Server: {server}",
                "tags": ["info-disclosure"],
                "timestamp": datetime.utcnow().isoformat(),
            })

        # Common paths
        common_paths = [
            "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
            "/admin", "/api", "/swagger.json", "/graphql",
            "/.well-known/security.txt", "/wp-login.php",
        ]

        for path in common_paths:
            check_url = target.rstrip("/") + path
            resp = client.get(check_url, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                severity = "info"
                if resp.status_code == 200 and path in ["/.git/HEAD", "/.env"]:
                    severity = "high"
                elif resp.status_code == 403:
                    severity = "info"
                findings.append({
                    "title": f"Path found: {path} [{resp.status_code}]",
                    "severity": severity,
                    "url": check_url,
                    "evidence": f"Status: {resp.status_code}, Size: {resp.content_length}",
                    "tags": ["path-discovery"],
                    "timestamp": datetime.utcnow().isoformat(),
                })

        stats["total_requests"] = client.request_count
        stats["paths_checked"] = len(common_paths)

    except Exception as e:
        errors.append(str(e))
    finally:
        client.close()

    # Update results
    now = datetime.utcnow().isoformat()
    started = results_store[scan_id]["started_at"]
    start_dt = datetime.fromisoformat(started)
    duration = (datetime.utcnow() - start_dt).total_seconds()

    update_result(
        scan_id,
        status="completed",
        findings=findings,
        stats=stats,
        errors=errors,
        completed_at=now,
        duration=duration,
    )


def run_bypass_task(scan_id: str, target: str, bypass_type: str, methods: List[str], options: Dict):
    """Run bypass scan as a background task."""
    findings = []
    errors = []
    stats = {}

    client = get_client(options)

    try:
        # Baseline
        baseline = client.get(target)
        if baseline.error:
            errors.append(f"Failed to reach target: {baseline.error}")
            update_result(scan_id, status="error", errors=errors,
                         completed_at=datetime.utcnow().isoformat())
            return

        stats["baseline_status"] = baseline.status_code
        stats["baseline_size"] = baseline.content_length
        bypasses_found = 0

        # Header bypasses
        if "headers" in methods:
            for header in BYPASS_HEADERS:
                for ip in BYPASS_IPS[:5]:
                    resp = client.get(target, headers={header: ip})
                    if resp.status_code == 200 and baseline.status_code in [401, 403]:
                        bypasses_found += 1
                        findings.append({
                            "title": f"Header bypass: {header}: {ip}",
                            "severity": "high",
                            "url": target,
                            "evidence": f"Status changed {baseline.status_code} -> {resp.status_code}",
                            "tags": ["bypass", "header"],
                            "metadata": {"header": header, "value": ip},
                            "timestamp": datetime.utcnow().isoformat(),
                        })

        # Method bypasses
        if "methods" in methods:
            http_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
            for method in http_methods:
                resp = client.request(method, target)
                if resp.status_code == 200 and baseline.status_code in [401, 403, 405]:
                    bypasses_found += 1
                    findings.append({
                        "title": f"Method bypass: {method} -> {resp.status_code}",
                        "severity": "medium",
                        "url": target,
                        "evidence": f"{method} returns {resp.status_code}",
                        "tags": ["bypass", "method"],
                        "timestamp": datetime.utcnow().isoformat(),
                    })

        # Path bypasses
        if "paths" in methods:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            path = parsed.path.rstrip("/")
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            path_mutations = [
                f"{path}/", f"{path}/.", f"{path}//", f"{path}/..",
                f"{path}%20", f"{path}%09", f"{path}%00",
                f"{path}..;/", f"{path};", f"{path}.json",
            ]

            for mutated in path_mutations:
                test_url = base_url + mutated
                resp = client.get(test_url)
                if resp.status_code == 200 and baseline.status_code in [401, 403]:
                    bypasses_found += 1
                    findings.append({
                        "title": f"Path bypass: {mutated}",
                        "severity": "high",
                        "url": test_url,
                        "evidence": f"Status: {resp.status_code}, Size: {resp.content_length}",
                        "tags": ["bypass", "path"],
                        "timestamp": datetime.utcnow().isoformat(),
                    })

        stats["bypasses_found"] = bypasses_found
        stats["total_requests"] = client.request_count

    except Exception as e:
        errors.append(str(e))
    finally:
        client.close()

    now = datetime.utcnow().isoformat()
    started = results_store[scan_id]["started_at"]
    start_dt = datetime.fromisoformat(started)
    duration = (datetime.utcnow() - start_dt).total_seconds()

    update_result(
        scan_id,
        status="completed",
        findings=findings,
        stats=stats,
        errors=errors,
        completed_at=now,
        duration=duration,
    )


def run_secrets_task(scan_id: str, target: str, patterns_filter: List[str], scan_js: bool, options: Dict):
    """Run secrets scan as a background task."""
    findings = []
    errors = []
    stats = {}

    client = get_client(options)

    try:
        # Determine patterns
        if "all" in patterns_filter:
            patterns = SECRET_PATTERNS
        else:
            patterns = {}
            for category in patterns_filter:
                for k, v in SECRET_PATTERNS.items():
                    if category in k:
                        patterns[k] = v
            if not patterns:
                patterns = SECRET_PATTERNS

        # Fetch main page
        response = client.get(target)
        if response.error:
            errors.append(f"Failed to fetch target: {response.error}")
            update_result(scan_id, status="error", errors=errors,
                         completed_at=datetime.utcnow().isoformat())
            return

        secrets_found = 0

        # Scan main page
        for pattern_name, pattern in patterns.items():
            try:
                matches = re.findall(pattern, response.body)
                for match in matches:
                    secrets_found += 1
                    match_str = match if isinstance(match, str) else match[0] if match else ""
                    findings.append({
                        "title": f"Secret found: {pattern_name}",
                        "severity": "high",
                        "url": target,
                        "evidence": match_str[:100],
                        "tags": ["secret", pattern_name],
                        "timestamp": datetime.utcnow().isoformat(),
                    })
            except re.error:
                pass

        # Scan JS files
        js_scanned = 0
        if scan_js:
            js_pattern = r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
            js_files = re.findall(js_pattern, response.body)

            for js_url in js_files[:15]:
                if js_url.startswith("//"):
                    js_url = "https:" + js_url
                elif js_url.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(target)
                    js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                elif not js_url.startswith("http"):
                    js_url = target.rstrip("/") + "/" + js_url

                js_resp = client.get(js_url)
                if js_resp.error or js_resp.status_code != 200:
                    continue

                js_scanned += 1
                for pattern_name, pattern in patterns.items():
                    try:
                        matches = re.findall(pattern, js_resp.body)
                        for match in matches:
                            secrets_found += 1
                            match_str = match if isinstance(match, str) else match[0] if match else ""
                            findings.append({
                                "title": f"Secret in JS: {pattern_name}",
                                "severity": "high",
                                "url": js_url,
                                "evidence": match_str[:100],
                                "tags": ["secret", "javascript", pattern_name],
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                    except re.error:
                        pass

        stats["secrets_found"] = secrets_found
        stats["js_files_scanned"] = js_scanned
        stats["patterns_used"] = len(patterns)
        stats["total_requests"] = client.request_count

    except Exception as e:
        errors.append(str(e))
    finally:
        client.close()

    now = datetime.utcnow().isoformat()
    started = results_store[scan_id]["started_at"]
    start_dt = datetime.fromisoformat(started)
    duration = (datetime.utcnow() - start_dt).total_seconds()

    update_result(
        scan_id,
        status="completed",
        findings=findings,
        stats=stats,
        errors=errors,
        completed_at=now,
        duration=duration,
    )


def run_fuzz_task(scan_id: str, target: str, wordlist: List[str], fuzz_type: str, options: Dict):
    """Run fuzzing as a background task."""
    findings = []
    errors = []
    stats = {}

    # Default wordlist if empty
    if not wordlist:
        wordlist = [
            "admin", "api", "backup", "config", "dashboard", "db", "debug",
            "dev", "docs", "download", "env", "files", "graphql", "health",
            "hidden", "images", "include", "internal", "js", "json", "login",
            "logs", "manage", "metrics", "monitor", "old", "panel", "private",
            "public", "readme", "register", "reset", "robots.txt", "search",
            "secret", "server-status", "setup", "sitemap.xml", "staging",
            "static", "status", "swagger", "system", "temp", "test", "tmp",
            "token", "upload", "user", "users", "v1", "v2", "version",
            "web", "wp-admin", "wp-content", ".git", ".env", ".htaccess",
        ]

    client = get_client(options)

    try:
        # Baseline
        baseline_url = target.replace("FUZZ", "nonexistentpath99999")
        baseline = client.get(baseline_url)
        baseline_size = baseline.content_length
        baseline_status = baseline.status_code

        stats["baseline_status"] = baseline_status
        stats["baseline_size"] = baseline_size
        stats["wordlist_size"] = len(wordlist)

        found_count = 0

        for word in wordlist:
            if "FUZZ" in target:
                test_url = target.replace("FUZZ", word)
            else:
                test_url = target.rstrip("/") + "/" + word

            resp = client.get(test_url, allow_redirects=False)

            # Filter
            if resp.status_code == baseline_status and resp.content_length == baseline_size:
                continue
            if resp.status_code == 404:
                continue

            if resp.status_code in [200, 201, 202, 204, 301, 302, 307, 401, 403, 405, 500]:
                found_count += 1
                severity = "info"
                if resp.status_code == 200:
                    severity = "low"
                if resp.status_code in [401, 403]:
                    severity = "medium"

                findings.append({
                    "title": f"[{resp.status_code}] /{word}",
                    "severity": severity,
                    "url": test_url,
                    "evidence": f"Status: {resp.status_code}, Size: {resp.content_length}, Words: {resp.words}",
                    "tags": ["fuzz", fuzz_type],
                    "timestamp": datetime.utcnow().isoformat(),
                })

        stats["found_count"] = found_count
        stats["total_requests"] = client.request_count

    except Exception as e:
        errors.append(str(e))
    finally:
        client.close()

    now = datetime.utcnow().isoformat()
    started = results_store[scan_id]["started_at"]
    start_dt = datetime.fromisoformat(started)
    duration = (datetime.utcnow() - start_dt).total_seconds()

    update_result(
        scan_id,
        status="completed",
        findings=findings,
        stats=stats,
        errors=errors,
        completed_at=now,
        duration=duration,
    )


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "recon-toolkit-bridge",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "active_scans": sum(1 for r in results_store.values() if r["status"] == "running"),
        "total_scans": len(results_store),
    }


@app.get("/results/{scan_id}")
async def get_results(scan_id: str):
    """Get results for a specific scan by ID."""
    if scan_id not in results_store:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found")
    return results_store[scan_id]


@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a comprehensive scan.

    Runs the scan as a background task and returns a scan_id for result retrieval.
    """
    scan_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()

    # Initialize result entry
    results_store[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": request.target,
        "scan_type": request.scan_type,
        "started_at": now,
        "completed_at": None,
        "duration": None,
        "findings": [],
        "stats": {},
        "errors": [],
    }

    # Run scan in background
    background_tasks.add_task(
        run_scan_task,
        scan_id=scan_id,
        target=request.target,
        scan_type=request.scan_type,
        params=request.params,
        options=request.options,
    )

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": f"Scan started against {request.target}",
        "results_url": f"/results/{scan_id}",
    }


@app.post("/bypass/admin")
async def bypass_admin(request: BypassRequest, background_tasks: BackgroundTasks):
    """
    Attempt to bypass admin panel access controls.

    Tests header manipulation, HTTP method overrides, and path mutations.
    """
    scan_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()

    results_store[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": request.target,
        "scan_type": "bypass-admin",
        "started_at": now,
        "completed_at": None,
        "duration": None,
        "findings": [],
        "stats": {},
        "errors": [],
    }

    background_tasks.add_task(
        run_bypass_task,
        scan_id=scan_id,
        target=request.target,
        bypass_type="admin",
        methods=request.methods,
        options=request.options,
    )

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": f"Admin bypass scan started against {request.target}",
        "results_url": f"/results/{scan_id}",
    }


@app.post("/bypass/403")
async def bypass_403(request: BypassRequest, background_tasks: BackgroundTasks):
    """
    Attempt to bypass 403 Forbidden responses.

    Tests various techniques including headers, methods, path manipulation, and encoding.
    """
    scan_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()

    results_store[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": request.target,
        "scan_type": "bypass-403",
        "started_at": now,
        "completed_at": None,
        "duration": None,
        "findings": [],
        "stats": {},
        "errors": [],
    }

    background_tasks.add_task(
        run_bypass_task,
        scan_id=scan_id,
        target=request.target,
        bypass_type="403",
        methods=request.methods,
        options=request.options,
    )

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": f"403 bypass scan started against {request.target}",
        "results_url": f"/results/{scan_id}",
    }


@app.post("/secrets/find")
async def find_secrets(request: SecretsRequest, background_tasks: BackgroundTasks):
    """
    Scan target for exposed secrets, API keys, and sensitive data.

    Scans HTML responses, JavaScript files, and common sensitive endpoints.
    """
    scan_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()

    results_store[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": request.target,
        "scan_type": "secrets",
        "started_at": now,
        "completed_at": None,
        "duration": None,
        "findings": [],
        "stats": {},
        "errors": [],
    }

    background_tasks.add_task(
        run_secrets_task,
        scan_id=scan_id,
        target=request.target,
        patterns_filter=request.patterns,
        scan_js=request.scan_js,
        options=request.options,
    )

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": f"Secrets scan started against {request.target}",
        "results_url": f"/results/{scan_id}",
    }


@app.post("/fuzz")
async def start_fuzz(request: FuzzRequest, background_tasks: BackgroundTasks):
    """
    Start a fuzzing scan.

    Fuzzes the target URL using the provided wordlist, replacing the FUZZ keyword.
    """
    scan_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()

    results_store[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": request.target,
        "scan_type": f"fuzz-{request.fuzz_type}",
        "started_at": now,
        "completed_at": None,
        "duration": None,
        "findings": [],
        "stats": {},
        "errors": [],
    }

    background_tasks.add_task(
        run_fuzz_task,
        scan_id=scan_id,
        target=request.target,
        wordlist=request.wordlist,
        fuzz_type=request.fuzz_type,
        options=request.options,
    )

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": f"Fuzz scan started against {request.target}",
        "results_url": f"/results/{scan_id}",
    }


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    print("[*] Starting Recon Toolkit Bridge Server...")
    print("[*] API docs available at: http://127.0.0.1:8899/docs")
    print("[*] Health check: http://127.0.0.1:8899/health")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8899,
        log_level="info",
    )
