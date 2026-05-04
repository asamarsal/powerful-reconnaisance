import { httpGet, httpPost, httpRequest } from '../../../utils/http-client.js';
import { URLParser } from '../../input/url-parser.js';
import { generateId } from '../../../utils/helpers.js';
import logger from '../../../utils/logger.js';

/**
 * Comprehensive Web Application Scanner
 * Covers ALL web vulnerability categories with precise detection
 */
export class WebScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.safe = options.safe || false;
    this.deep = options.deep || false;
    this.findings = [];
  }

  /**
   * Run all web vulnerability checks
   */
  async scan(url, options = {}) {
    const parsed = URLParser.parse(url);
    if (!parsed) return [];

    const params = await this._getAllParams(url, parsed);
    const baseResponse = await httpGet(url, { timeout: this.timeout });
    const context = { url, parsed, params, baseResponse, baseBody: typeof baseResponse.data === 'string' ? baseResponse.data : '' };

    const scanModules = [
      // Injection
      { name: 'XSS (Reflected)', fn: () => this._scanXSS(context) },
      { name: 'SQL Injection', fn: () => this._scanSQLi(context) },
      { name: 'NoSQL Injection', fn: () => this._scanNoSQLi(context) },
      { name: 'Command Injection', fn: () => this._scanCMDi(context) },
      { name: 'SSTI', fn: () => this._scanSSTI(context) },
      { name: 'CRLF Injection', fn: () => this._scanCRLF(context) },
      { name: 'XXE', fn: () => this._scanXXE(context) },
      { name: 'LFI / Path Traversal', fn: () => this._scanLFI(context) },
      // Access Control
      { name: 'IDOR', fn: () => this._scanIDOR(context) },
      { name: 'Open Redirect', fn: () => this._scanOpenRedirect(context) },
      { name: 'SSRF', fn: () => this._scanSSRF(context) },
      // Configuration
      { name: 'CORS Misconfiguration', fn: () => this._scanCORS(context) },
      { name: 'Security Headers', fn: () => this._scanHeaders(context) },
      { name: 'Host Header Injection', fn: () => this._scanHostHeader(context) },
      { name: 'Clickjacking', fn: () => this._scanClickjacking(context) },
      // Information
      { name: 'Sensitive Data Exposure', fn: () => this._scanInfoExposure(context) },
      { name: 'Directory Listing', fn: () => this._scanDirListing(context) },
      { name: 'Exposed Files', fn: () => this._scanExposedFiles(context) },
    ];

    for (const mod of scanModules) {
      try {
        logger.info(`  [${mod.name}] Scanning...`);
        const results = await mod.fn();
        if (results.length > 0) {
          this.findings.push(...results);
          results.forEach(r => logger.vuln(r.severity, `    FOUND: ${r.title}`));
        }
      } catch (e) {
        logger.debug(`  [${mod.name}] Error: ${e.message}`);
      }
    }

    return this.findings;
  }

  // ═══════════════════════════════════════════════════════════
  // XSS SCANNER
  // ═══════════════════════════════════════════════════════════
  async _scanXSS(ctx) {
    const findings = [];
    const payloads = [
      { v: '<script>alert(document.domain)</script>', ctx: 'html' },
      { v: '"><img src=x onerror=alert(1)>', ctx: 'attr-break' },
      { v: "' onmouseover='alert(1)", ctx: 'attr-event' },
      { v: '<svg/onload=alert(1)>', ctx: 'svg' },
      { v: '{{constructor.constructor("alert(1)")()}}', ctx: 'angular' },
      { v: '${alert(1)}', ctx: 'template-literal' },
      { v: 'javascript:alert(1)', ctx: 'href' },
    ];

    for (const [param] of Object.entries(ctx.params)) {
      const marker = `xss${Math.random().toString(36).slice(2, 8)}`;
      const reflectCheck = await this._inject(ctx, param, marker);
      if (!reflectCheck.body.includes(marker)) continue;

      for (const p of payloads) {
        const result = await this._inject(ctx, param, p.v);
        if (result.body.includes(p.v)) {
          findings.push(this._createFinding({
            type: 'xss', title: `Reflected XSS via parameter "${param}"`,
            severity: 'high', url: ctx.url, parameter: param,
            payload: p.v, context: p.ctx,
            evidence: `Payload reflected unencoded in response body`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} - Payload found at position ${result.body.indexOf(p.v)}`,
            remediation: 'Implement context-aware output encoding. Use Content-Security-Policy header.',
            cwe: 'CWE-79', owasp: 'A03:2021 Injection',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SQL INJECTION SCANNER
  // ═══════════════════════════════════════════════════════════
  async _scanSQLi(ctx) {
    const findings = [];
    const errorPatterns = {
      MySQL: [/SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySQLSyntaxError/i],
      PostgreSQL: [/PostgreSQL.*ERROR/i, /pg_query/i, /PSQLException/i],
      MSSQL: [/Driver.*SQL Server/i, /OLE DB.*SQL Server/i, /Unclosed quotation/i],
      Oracle: [/ORA-\d{5}/i, /oracle.*driver/i],
      SQLite: [/SQLite.*error/i, /sqlite3\./i, /SQLITE_ERROR/i],
    };

    const payloads = [
      { v: "'", desc: 'Single quote' },
      { v: "' OR '1'='1", desc: 'OR bypass' },
      { v: "' UNION SELECT NULL--", desc: 'UNION' },
      { v: "1' AND SLEEP(3)--", desc: 'Time-based (MySQL)', timeBased: true, delay: 3 },
      { v: "1'; WAITFOR DELAY '0:0:3'--", desc: 'Time-based (MSSQL)', timeBased: true, delay: 3 },
      { v: "1' AND pg_sleep(3)--", desc: 'Time-based (PostgreSQL)', timeBased: true, delay: 3 },
    ];

    for (const [param] of Object.entries(ctx.params)) {
      for (const p of payloads) {
        if (p.timeBased) {
          const start = Date.now();
          await this._inject(ctx, param, p.v, { timeout: (p.delay + 5) * 1000 });
          const elapsed = Date.now() - start;
          if (elapsed >= p.delay * 900) {
            findings.push(this._createFinding({
              type: 'sqli-time-blind', title: `Time-based Blind SQL Injection in "${param}"`,
              severity: 'critical', url: ctx.url, parameter: param,
              payload: p.v, evidence: `Response delayed ${elapsed}ms (expected ${p.delay}s). DB: ${p.desc}`,
              request: `GET ${ctx.url.split('?')[0]}?${param}=${encodeURIComponent(p.v)}`,
              response: `Response time: ${elapsed}ms vs baseline ~${Date.now() - start - elapsed}ms`,
              remediation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL.',
              cwe: 'CWE-89', owasp: 'A03:2021 Injection',
            }));
            break;
          }
        } else {
          const result = await this._inject(ctx, param, p.v);
          for (const [db, patterns] of Object.entries(errorPatterns)) {
            for (const pattern of patterns) {
              if (pattern.test(result.body)) {
                findings.push(this._createFinding({
                  type: 'sqli-error', title: `Error-based SQL Injection in "${param}" (${db})`,
                  severity: 'critical', url: ctx.url, parameter: param,
                  payload: p.v, evidence: `${db} error message detected in response`,
                  request: `GET ${result.testUrl}`,
                  response: `HTTP ${result.status} - SQL error pattern matched`,
                  remediation: 'Use parameterized queries. Disable verbose error messages in production.',
                  cwe: 'CWE-89', owasp: 'A03:2021 Injection',
                }));
                break;
              }
            }
          }
          if (findings.some(f => f.parameter === param && f.type.startsWith('sqli'))) break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // NoSQL INJECTION
  // ═══════════════════════════════════════════════════════════
  async _scanNoSQLi(ctx) {
    const findings = [];
    const payloads = [
      { v: '{"$gt":""}', desc: 'MongoDB $gt operator' },
      { v: '[$ne]=1', desc: 'Array $ne operator' },
      { v: '{"$regex":".*"}', desc: 'MongoDB $regex' },
    ];

    for (const [param] of Object.entries(ctx.params)) {
      const baseline = await this._inject(ctx, param, 'normalvalue123');
      for (const p of payloads) {
        const result = await this._inject(ctx, param, p.v);
        if (result.status === 200 && Math.abs(result.body.length - baseline.body.length) > 100) {
          findings.push(this._createFinding({
            type: 'nosqli', title: `NoSQL Injection in "${param}"`,
            severity: 'critical', url: ctx.url, parameter: param,
            payload: p.v, evidence: `Response differs significantly with NoSQL operator (${p.desc})`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} (${result.body.length} bytes vs baseline ${baseline.body.length} bytes)`,
            remediation: 'Validate and sanitize input. Use ODM/ORM with strict schemas. Disable $where operator.',
            cwe: 'CWE-943', owasp: 'A03:2021 Injection',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // COMMAND INJECTION
  // ═══════════════════════════════════════════════════════════
  async _scanCMDi(ctx) {
    const findings = [];
    const payloads = [
      { v: ';sleep 5', delay: 5, desc: 'Unix semicolon + sleep' },
      { v: '|sleep 5', delay: 5, desc: 'Unix pipe + sleep' },
      { v: '$(sleep 5)', delay: 5, desc: 'Unix subshell + sleep' },
      { v: '`sleep 5`', delay: 5, desc: 'Unix backtick + sleep' },
    ];

    for (const [param] of Object.entries(ctx.params)) {
      for (const p of payloads) {
        const start = Date.now();
        await this._inject(ctx, param, `test${p.v}`, { timeout: (p.delay + 8) * 1000 });
        const elapsed = Date.now() - start;
        if (elapsed >= p.delay * 900) {
          findings.push(this._createFinding({
            type: 'cmdi', title: `OS Command Injection in "${param}"`,
            severity: 'critical', url: ctx.url, parameter: param,
            payload: p.v, evidence: `Time delay ${elapsed}ms confirms command execution (${p.desc})`,
            request: `GET ${ctx.url.split('?')[0]}?${param}=test${encodeURIComponent(p.v)}`,
            response: `Response delayed by ~${Math.round(elapsed / 1000)}s`,
            remediation: 'Never pass user input to system commands. Use allowlists and parameterized APIs.',
            cwe: 'CWE-78', owasp: 'A03:2021 Injection',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SSTI (Server-Side Template Injection)
  // ═══════════════════════════════════════════════════════════
  async _scanSSTI(ctx) {
    const findings = [];
    const payloads = [
      { v: '{{7*7}}', expect: '49', engine: 'Jinja2/Twig/Nunjucks' },
      { v: '${7*7}', expect: '49', engine: 'Freemarker/Velocity/Mako' },
      { v: '<%= 7*7 %>', expect: '49', engine: 'ERB/EJS' },
      { v: '#{7*7}', expect: '49', engine: 'Pebble/Slim' },
      { v: '{{7*\'7\'}}', expect: '7777777', engine: 'Jinja2 (confirmed)' },
    ];

    for (const [param] of Object.entries(ctx.params)) {
      for (const p of payloads) {
        const result = await this._inject(ctx, param, p.v);
        if (result.body.includes(p.expect) && !ctx.baseBody.includes(p.expect)) {
          findings.push(this._createFinding({
            type: 'ssti', title: `Server-Side Template Injection in "${param}" (${p.engine})`,
            severity: 'critical', url: ctx.url, parameter: param,
            payload: p.v, evidence: `Expression ${p.v} evaluated to ${p.expect} (Engine: ${p.engine})`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} - Contains "${p.expect}" in body`,
            remediation: 'Use logic-less templates. Sandbox template execution. Never pass user input as template code.',
            cwe: 'CWE-1336', owasp: 'A03:2021 Injection',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // CRLF INJECTION
  // ═══════════════════════════════════════════════════════════
  async _scanCRLF(ctx) {
    const findings = [];
    for (const [param] of Object.entries(ctx.params)) {
      const payload = '%0d%0aX-Injected:true';
      const result = await this._inject(ctx, param, `test${payload}`, { followRedirects: false });
      if (result.headers['x-injected'] === 'true') {
        findings.push(this._createFinding({
          type: 'crlf', title: `CRLF Injection / HTTP Response Splitting in "${param}"`,
          severity: 'high', url: ctx.url, parameter: param,
          payload, evidence: 'Custom header "X-Injected: true" injected into response',
          request: `GET ${result.testUrl}`,
          response: `HTTP ${result.status} - Header X-Injected: true present`,
          remediation: 'Strip or encode CR (\\r) and LF (\\n) characters from user input used in headers.',
          cwe: 'CWE-113', owasp: 'A03:2021 Injection',
        }));
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // XXE
  // ═══════════════════════════════════════════════════════════
  async _scanXXE(ctx) {
    const findings = [];
    const xxePayload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>';
    try {
      const resp = await httpPost(ctx.url, xxePayload, { timeout: this.timeout, contentType: 'application/xml' });
      const body = typeof resp.data === 'string' ? resp.data : '';
      if (body.includes('root:') || body.includes('daemon:')) {
        findings.push(this._createFinding({
          type: 'xxe', title: 'XML External Entity (XXE) Injection',
          severity: 'critical', url: ctx.url, parameter: 'XML Body',
          payload: xxePayload, evidence: '/etc/passwd content returned in response',
          request: `POST ${ctx.url}\nContent-Type: application/xml\n\n${xxePayload}`,
          response: `HTTP ${resp.status} - File content in body`,
          remediation: 'Disable external entity processing. Use JSON instead of XML where possible.',
          cwe: 'CWE-611', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    } catch { /* skip */ }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // LFI / PATH TRAVERSAL
  // ═══════════════════════════════════════════════════════════
  async _scanLFI(ctx) {
    const findings = [];
    const fileParams = ['file', 'path', 'page', 'include', 'template', 'doc', 'load', 'lang', 'module', 'view'];
    const payloads = [
      { v: '../../../../etc/passwd', indicator: 'root:', os: 'Linux' },
      { v: '....//....//....//etc/passwd', indicator: 'root:', os: 'Linux (bypass)' },
      { v: '..\\..\\..\\windows\\win.ini', indicator: '[fonts]', os: 'Windows' },
      { v: 'php://filter/convert.base64-encode/resource=index.php', indicator: 'PD9', os: 'PHP Wrapper' },
    ];

    const testParams = Object.keys(ctx.params).filter(p => fileParams.some(fp => p.toLowerCase().includes(fp)));
    if (testParams.length === 0 && Object.keys(ctx.params).length > 0) {
      testParams.push(Object.keys(ctx.params)[0]); // Test first param anyway
    }

    for (const param of testParams) {
      for (const p of payloads) {
        const result = await this._inject(ctx, param, p.v);
        if (result.body.includes(p.indicator)) {
          findings.push(this._createFinding({
            type: 'lfi', title: `Local File Inclusion / Path Traversal in "${param}"`,
            severity: 'critical', url: ctx.url, parameter: param,
            payload: p.v, evidence: `File content indicator "${p.indicator}" found (${p.os})`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} - File content in response`,
            remediation: 'Use allowlist for file paths. Never use user input directly in file operations.',
            cwe: 'CWE-22', owasp: 'A01:2021 Broken Access Control',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // IDOR
  // ═══════════════════════════════════════════════════════════
  async _scanIDOR(ctx) {
    const findings = [];
    const idParams = ['id', 'uid', 'user_id', 'account_id', 'order_id', 'doc_id', 'file_id', 'profile_id'];
    const testParams = Object.entries(ctx.params).filter(([k, v]) =>
      idParams.some(ip => k.toLowerCase().includes(ip)) && /^\d+$/.test(v)
    );

    for (const [param, value] of testParams) {
      const numVal = parseInt(value);
      const testIds = [numVal - 1, numVal + 1, 1, 0];
      for (const testId of testIds) {
        if (testId === numVal || testId < 0) continue;
        const result = await this._inject(ctx, param, String(testId));
        if (result.status === 200 && result.body.length > 100 &&
            Math.abs(result.body.length - ctx.baseBody.length) < ctx.baseBody.length * 0.5) {
          findings.push(this._createFinding({
            type: 'idor', title: `Potential IDOR in "${param}" (ID: ${value} → ${testId})`,
            severity: 'high', url: ctx.url, parameter: param,
            payload: String(testId), evidence: `Accessing ID=${testId} returns valid data (${result.body.length} bytes)`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} (${result.body.length} bytes) - Different resource accessible`,
            remediation: 'Implement proper authorization checks. Verify resource ownership server-side.',
            cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // OPEN REDIRECT
  // ═══════════════════════════════════════════════════════════
  async _scanOpenRedirect(ctx) {
    const findings = [];
    const redirectParams = ['redirect', 'url', 'next', 'return', 'goto', 'dest', 'redir', 'returnUrl', 'continue', 'forward'];
    const payloads = ['https://evil.com', '//evil.com', '/\\evil.com', 'https://evil.com%00.example.com'];

    const testParams = Object.keys(ctx.params).filter(p => redirectParams.some(rp => p.toLowerCase().includes(rp)));

    for (const param of testParams) {
      for (const payload of payloads) {
        const result = await this._inject(ctx, param, payload, { followRedirects: false, maxRedirects: 0 });
        const location = result.headers['location'] || '';
        if (location.includes('evil.com') || (result.status >= 300 && result.status < 400 && location.includes('evil'))) {
          findings.push(this._createFinding({
            type: 'open-redirect', title: `Open Redirect via "${param}"`,
            severity: 'medium', url: ctx.url, parameter: param,
            payload, evidence: `Redirects to: ${location}`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} Location: ${location}`,
            remediation: 'Use allowlist for redirect destinations. Validate redirect URLs server-side.',
            cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SSRF
  // ═══════════════════════════════════════════════════════════
  async _scanSSRF(ctx) {
    const findings = [];
    const urlParams = ['url', 'uri', 'src', 'source', 'link', 'fetch', 'proxy', 'callback', 'img', 'image', 'load'];
    const testParams = Object.keys(ctx.params).filter(p => urlParams.some(up => p.toLowerCase().includes(up)));

    const targets = [
      { v: 'http://169.254.169.254/latest/meta-data/', indicator: 'ami-id', desc: 'AWS Metadata' },
      { v: 'http://127.0.0.1:22', indicator: 'SSH', desc: 'Internal SSH' },
      { v: 'http://[::1]/', indicator: '', desc: 'IPv6 localhost' },
    ];

    for (const param of testParams) {
      for (const t of targets) {
        const result = await this._inject(ctx, param, t.v);
        if (t.indicator && result.body.includes(t.indicator)) {
          findings.push(this._createFinding({
            type: 'ssrf', title: `SSRF via "${param}" - ${t.desc}`,
            severity: 'critical', url: ctx.url, parameter: param,
            payload: t.v, evidence: `Internal resource "${t.indicator}" accessible via ${t.desc}`,
            request: `GET ${result.testUrl}`,
            response: `HTTP ${result.status} - Internal data in response`,
            remediation: 'Validate and sanitize URLs. Use allowlists. Block internal IP ranges.',
            cwe: 'CWE-918', owasp: 'A10:2021 SSRF',
          }));
          break;
        }
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // CORS MISCONFIGURATION
  // ═══════════════════════════════════════════════════════════
  async _scanCORS(ctx) {
    const findings = [];
    const origins = ['https://evil.com', 'null', `https://${ctx.parsed.hostname}.evil.com`];

    for (const origin of origins) {
      const resp = await httpGet(ctx.url, { headers: { 'Origin': origin }, timeout: this.timeout });
      const acao = resp.headers['access-control-allow-origin'];
      const acac = resp.headers['access-control-allow-credentials'];

      if (acao === origin || acao === '*') {
        findings.push(this._createFinding({
          type: 'cors-misconfig', title: `CORS Misconfiguration - Origin "${origin}" reflected`,
          severity: acac === 'true' ? 'high' : 'medium', url: ctx.url, parameter: `Origin: ${origin}`,
          payload: origin, evidence: `ACAO: ${acao}${acac ? ', ACAC: true' : ''}`,
          request: `GET ${ctx.url}\nOrigin: ${origin}`,
          response: `Access-Control-Allow-Origin: ${acao}\n${acac ? 'Access-Control-Allow-Credentials: true' : ''}`,
          remediation: 'Validate Origin header against allowlist. Never reflect arbitrary origins with credentials.',
          cwe: 'CWE-942', owasp: 'A05:2021 Security Misconfiguration',
        }));
        break;
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SECURITY HEADERS
  // ═══════════════════════════════════════════════════════════
  async _scanHeaders(ctx) {
    const findings = [];
    const h = ctx.baseResponse.headers;
    const checks = [
      { key: 'strict-transport-security', name: 'HSTS', sev: 'medium' },
      { key: 'content-security-policy', name: 'Content-Security-Policy', sev: 'medium' },
      { key: 'x-frame-options', name: 'X-Frame-Options', sev: 'medium' },
      { key: 'x-content-type-options', name: 'X-Content-Type-Options', sev: 'low' },
    ];

    for (const c of checks) {
      if (!h[c.key]) {
        findings.push(this._createFinding({
          type: 'missing-header', title: `Missing Security Header: ${c.name}`,
          severity: c.sev, url: ctx.url, parameter: c.key,
          payload: 'N/A', evidence: `Header "${c.name}" is not present in the response`,
          request: `GET ${ctx.url}`, response: `Headers checked - ${c.name} missing`,
          remediation: `Add "${c.name}" header to all responses.`,
          cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    }

    // Info disclosure
    if (h['server']) {
      findings.push(this._createFinding({
        type: 'info-disclosure', title: `Server Version Disclosure: ${h['server']}`,
        severity: 'info', url: ctx.url, parameter: 'Server header',
        payload: 'N/A', evidence: `Server: ${h['server']}`,
        request: `GET ${ctx.url}`, response: `Server: ${h['server']}`,
        remediation: 'Remove or obfuscate the Server header.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HOST HEADER INJECTION
  // ═══════════════════════════════════════════════════════════
  async _scanHostHeader(ctx) {
    const findings = [];
    const resp = await httpRequest('GET', ctx.url, {
      headers: { 'Host': 'evil.com', 'X-Forwarded-Host': 'evil.com' }, timeout: this.timeout,
    });
    const body = typeof resp.data === 'string' ? resp.data : '';
    if (body.includes('evil.com')) {
      findings.push(this._createFinding({
        type: 'host-header-injection', title: 'Host Header Injection',
        severity: 'high', url: ctx.url, parameter: 'Host / X-Forwarded-Host',
        payload: 'evil.com', evidence: 'Injected host value reflected in response body',
        request: `GET ${ctx.url}\nHost: evil.com`, response: `HTTP ${resp.status} - "evil.com" in body`,
        remediation: 'Validate Host header. Use server-configured hostname for URL generation.',
        cwe: 'CWE-644', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // CLICKJACKING
  // ═══════════════════════════════════════════════════════════
  async _scanClickjacking(ctx) {
    const findings = [];
    const h = ctx.baseResponse.headers;
    if (!h['x-frame-options'] && !h['content-security-policy']?.includes('frame-ancestors')) {
      findings.push(this._createFinding({
        type: 'clickjacking', title: 'Clickjacking - Missing Frame Protection',
        severity: 'medium', url: ctx.url, parameter: 'X-Frame-Options / CSP frame-ancestors',
        payload: '<iframe src="TARGET_URL"></iframe>', evidence: 'Page can be framed by any origin',
        request: `GET ${ctx.url}`, response: 'No X-Frame-Options or CSP frame-ancestors header',
        remediation: 'Add X-Frame-Options: DENY or CSP frame-ancestors directive.',
        cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SENSITIVE DATA / INFO EXPOSURE
  // ═══════════════════════════════════════════════════════════
  async _scanInfoExposure(ctx) {
    const findings = [];
    const secretPatterns = [
      { regex: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
      { regex: /ghp_[A-Za-z0-9_]{36}/g, name: 'GitHub Token' },
      { regex: /sk_live_[0-9a-zA-Z]{24}/g, name: 'Stripe Secret Key' },
      { regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, name: 'Private Key' },
      { regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, name: 'JWT Token' },
      { regex: /mongodb(\+srv)?:\/\/[^\s"']+/g, name: 'MongoDB URI' },
      { regex: /postgres(ql)?:\/\/[^\s"']+/g, name: 'PostgreSQL URI' },
    ];

    for (const p of secretPatterns) {
      const matches = ctx.baseBody.match(p.regex);
      if (matches) {
        findings.push(this._createFinding({
          type: 'secret-leakage', title: `Secret Leakage: ${p.name}`,
          severity: 'critical', url: ctx.url, parameter: 'Response Body',
          payload: 'N/A', evidence: `Found ${p.name}: ${matches[0].substring(0, 20)}...`,
          request: `GET ${ctx.url}`, response: `${p.name} found in page source`,
          remediation: 'Remove secrets from client-side code. Use environment variables. Rotate exposed credentials.',
          cwe: 'CWE-200', owasp: 'A02:2021 Cryptographic Failures',
        }));
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // DIRECTORY LISTING
  // ═══════════════════════════════════════════════════════════
  async _scanDirListing(ctx) {
    const findings = [];
    const paths = ['/', '/images/', '/uploads/', '/backup/', '/admin/', '/api/', '/.git/', '/config/'];
    const indicators = ['Index of', 'Directory listing', 'Parent Directory', '[To Parent Directory]'];

    for (const path of paths) {
      const testUrl = `${URLParser.getBaseUrl(ctx.url)}${path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';
      if (resp.status === 200 && indicators.some(i => body.includes(i))) {
        findings.push(this._createFinding({
          type: 'directory-listing', title: `Directory Listing Enabled: ${path}`,
          severity: 'medium', url: testUrl, parameter: 'Path',
          payload: path, evidence: `Directory listing found at ${path}`,
          request: `GET ${testUrl}`, response: `HTTP 200 - "Index of" in response`,
          remediation: 'Disable directory listing in web server configuration.',
          cwe: 'CWE-548', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // EXPOSED FILES
  // ═══════════════════════════════════════════════════════════
  async _scanExposedFiles(ctx) {
    const findings = [];
    const files = [
      { path: '/.env', indicator: 'DB_', sev: 'critical', desc: 'Environment file' },
      { path: '/.git/config', indicator: '[core]', sev: 'critical', desc: 'Git config' },
      { path: '/robots.txt', indicator: 'Disallow', sev: 'info', desc: 'Robots.txt' },
      { path: '/phpinfo.php', indicator: 'PHP Version', sev: 'high', desc: 'PHP Info' },
      { path: '/server-status', indicator: 'Apache Server Status', sev: 'high', desc: 'Apache Status' },
      { path: '/wp-config.php.bak', indicator: 'DB_NAME', sev: 'critical', desc: 'WP Config Backup' },
      { path: '/.DS_Store', indicator: null, sev: 'low', desc: 'macOS DS_Store' },
      { path: '/crossdomain.xml', indicator: 'cross-domain-policy', sev: 'low', desc: 'Flash crossdomain' },
    ];

    const baseUrl = URLParser.getBaseUrl(ctx.url);
    for (const f of files) {
      const testUrl = `${baseUrl}${f.path}`;
      const resp = await httpGet(testUrl, { timeout: 5000 });
      const body = typeof resp.data === 'string' ? resp.data : '';
      if (resp.status === 200 && (f.indicator === null || body.includes(f.indicator))) {
        findings.push(this._createFinding({
          type: 'exposed-file', title: `Exposed Sensitive File: ${f.path} (${f.desc})`,
          severity: f.sev, url: testUrl, parameter: 'Path',
          payload: f.path, evidence: `File accessible at ${f.path}`,
          request: `GET ${testUrl}`, response: `HTTP 200 - ${f.desc} content found`,
          remediation: `Block access to ${f.path} in web server configuration.`,
          cwe: 'CWE-538', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    }
    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HELPER METHODS
  // ═══════════════════════════════════════════════════════════
  async _inject(ctx, param, value, opts = {}) {
    const baseUrl = ctx.url.split('?')[0];
    const testParams = { ...ctx.params, [param]: value };
    const testUrl = URLParser.buildUrl(baseUrl, testParams);
    const response = await httpGet(testUrl, { timeout: opts.timeout || this.timeout, ...opts });
    return {
      testUrl,
      status: response.status,
      headers: response.headers || {},
      body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data || ''),
    };
  }

  async _getAllParams(url, parsed) {
    const params = { ...parsed.params };
    try {
      const resp = await httpGet(url, { timeout: this.timeout });
      const html = typeof resp.data === 'string' ? resp.data : '';
      for (const m of html.matchAll(/<input[^>]*name=["']([^"']+)["'][^>]*/gi)) params[m[1]] = 'test';
      for (const m of html.matchAll(/href=["'][^"']*\?([^"'#]+)["']/gi)) {
        for (const [k] of new URLSearchParams(m[1])) params[k] = 'test';
      }
    } catch { /* skip */ }
    return params;
  }

  _createFinding(data) {
    return {
      id: generateId(data.type.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 4)),
      ...data,
      timestamp: new Date().toISOString(),
    };
  }
}

export default WebScanner;
