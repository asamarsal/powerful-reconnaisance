import { XSSScanner } from '../../core/hunter/xss-scanner.js';
import { SQLiDetector } from '../../core/hunter/sqli-detector.js';
import { SSRFChecker } from '../../core/hunter/ssrf-checker.js';
import { ProxyRotator } from '../../core/proxy/proxy-rotator.js';
import { httpGet } from '../../utils/http-client.js';
import { URLParser } from '../../core/input/url-parser.js';
import logger from '../../utils/logger.js';
import { saveResults, formatDuration, generateId } from '../../utils/helpers.js';
import { join } from 'path';
import config from '../../../config/default.js';

/**
 * Handle hunt command - targeted vulnerability hunting
 */
export async function handleHunt(options) {
  if (!options.target) {
    logger.error('Please specify a target with -t <url>');
    return;
  }

  const startTime = Date.now();
  const target = options.target;
  const types = options.types ? options.types.split(',').map(t => t.trim()) : null;
  const allTypes = ['xss', 'sqli', 'ssrf', 'redirect', 'cors', 'headers', 'auth', 'lfi', 'idor', 'ssti'];
  const scanTypes = options.full ? allTypes : (types || ['xss', 'sqli', 'ssrf', 'cors', 'headers']);

  logger.info(`[Hunt] Target: ${target}`);
  logger.info(`[Hunt] Types: ${scanTypes.join(', ')}`);
  logger.info(`[Hunt] Mode: ${options.deep ? 'Deep' : 'Standard'}${options.safe ? ' (Safe)' : ''}`);
  logger.divider();

  // Initialize proxy if needed
  if (options.proxy) {
    const rotator = new ProxyRotator();
    await rotator.initialize();
    logger.success(`Proxy ready: ${rotator.getStats().working} proxies`);
  }

  const allFindings = [];
  const scanOptions = {
    timeout: 10000,
    safe: options.safe || false,
    deep: options.deep || false,
  };

  // Discover parameters first
  logger.info('[Hunt] Discovering parameters and endpoints...');
  const params = await discoverParameters(target);
  logger.info(`[Hunt] Found ${Object.keys(params).length} parameters`);

  // Run scanners based on selected types
  for (const type of scanTypes) {
    try {
      switch (type) {
        case 'xss': {
          logger.info('\n[XSS] Starting XSS scan...');
          const scanner = new XSSScanner(scanOptions);
          const findings = await scanner.scan(target, scanOptions);
          allFindings.push(...findings);
          logger.info(`[XSS] Found ${findings.length} potential XSS`);
          break;
        }

        case 'sqli': {
          logger.info('\n[SQLi] Starting SQL Injection scan...');
          const scanner = new SQLiDetector(scanOptions);
          const findings = await scanner.scan(target, scanOptions);
          allFindings.push(...findings);
          logger.info(`[SQLi] Found ${findings.length} potential SQLi`);
          break;
        }

        case 'ssrf': {
          logger.info('\n[SSRF] Starting SSRF scan...');
          const scanner = new SSRFChecker(scanOptions);
          const findings = await scanner.scan(target, scanOptions);
          allFindings.push(...findings);
          logger.info(`[SSRF] Found ${findings.length} potential SSRF`);
          break;
        }

        case 'cors': {
          logger.info('\n[CORS] Checking CORS misconfiguration...');
          const findings = await scanCORS(target);
          allFindings.push(...findings);
          logger.info(`[CORS] Found ${findings.length} CORS issues`);
          break;
        }

        case 'headers': {
          logger.info('\n[Headers] Analyzing security headers...');
          const findings = await scanHeaders(target);
          allFindings.push(...findings);
          logger.info(`[Headers] Found ${findings.length} header issues`);
          break;
        }

        case 'redirect': {
          logger.info('\n[Redirect] Checking open redirects...');
          const findings = await scanRedirects(target, params);
          allFindings.push(...findings);
          logger.info(`[Redirect] Found ${findings.length} open redirects`);
          break;
        }

        case 'lfi': {
          logger.info('\n[LFI] Checking Local File Inclusion...');
          const findings = await scanLFI(target, params);
          allFindings.push(...findings);
          logger.info(`[LFI] Found ${findings.length} LFI vulnerabilities`);
          break;
        }

        default:
          logger.debug(`[Hunt] Scanner for '${type}' not yet implemented in Node.js`);
          if (options.engine === 'python' || options.engine === 'both') {
            logger.info(`[Hunt] Use --engine python for ${type} scanning`);
          }
      }
    } catch (error) {
      logger.error(`[${type.toUpperCase()}] Error: ${error.message}`);
    }
  }

  // Summary
  const elapsed = Date.now() - startTime;
  logger.divider();
  logger.success(`\nHunt complete! Duration: ${formatDuration(elapsed)}`);
  logger.info(`Total findings: ${allFindings.length}`);

  if (allFindings.length > 0) {
    const severities = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    allFindings.forEach(f => severities[f.severity || 'info']++);

    logger.info('\nSeverity:');
    Object.entries(severities).forEach(([sev, count]) => {
      if (count > 0) logger.vuln(sev, `  ${sev.toUpperCase()}: ${count}`);
    });

    logger.info('\nDetails:');
    allFindings.forEach(f => {
      logger.vuln(f.severity, `  [${f.type}] ${f.parameter || f.issue || ''}`);
      if (f.evidence) logger.info(`    Evidence: ${f.evidence.substring(0, 100)}`);
    });
  }

  // Save
  const outputFile = options.output || join(config.paths.output, `hunt-${Date.now()}.json`);
  saveResults(outputFile, {
    timestamp: new Date().toISOString(),
    target,
    duration: formatDuration(elapsed),
    scanTypes,
    totalFindings: allFindings.length,
    findings: allFindings,
  });
  logger.success(`Results saved to: ${outputFile}`);
}

/**
 * Discover parameters from target page
 */
async function discoverParameters(url) {
  const params = {};
  try {
    const response = await httpGet(url, { timeout: 10000 });
    const html = typeof response.data === 'string' ? response.data : '';

    // From URL
    const parsed = URLParser.parse(url);
    if (parsed) Object.assign(params, parsed.params);

    // From forms
    const inputs = html.matchAll(/<input[^>]*name=["']([^"']+)["'][^>]*/gi);
    for (const match of inputs) params[match[1]] = 'test';

    // From links
    const links = html.matchAll(/href=["'][^"']*\?([^"'#]+)["']/gi);
    for (const match of links) {
      const urlParams = new URLSearchParams(match[1]);
      for (const [key] of urlParams) params[key] = 'test';
    }
  } catch { /* skip */ }
  return params;
}

/**
 * CORS misconfiguration scanner
 */
async function scanCORS(url) {
  const findings = [];
  const origins = [
    'https://evil.com',
    'null',
    `https://${new URL(url.startsWith('http') ? url : `https://${url}`).hostname}.evil.com`,
    'https://attacker.com',
  ];

  for (const origin of origins) {
    try {
      const response = await httpGet(url, {
        headers: { 'Origin': origin },
        timeout: 10000,
      });

      const acao = response.headers['access-control-allow-origin'];
      const acac = response.headers['access-control-allow-credentials'];

      if (acao === origin || acao === '*') {
        findings.push({
          id: generateId('CORS'),
          type: 'cors-misconfiguration',
          severity: acac === 'true' ? 'high' : 'medium',
          url,
          issue: `Origin "${origin}" reflected in ACAO header`,
          evidence: `Access-Control-Allow-Origin: ${acao}${acac ? ', Allow-Credentials: true' : ''}`,
          parameter: `Origin: ${origin}`,
          timestamp: new Date().toISOString(),
        });
      }
    } catch { /* skip */ }
  }

  return findings;
}

/**
 * Security headers scanner
 */
async function scanHeaders(url) {
  const findings = [];
  try {
    const response = await httpGet(url, { timeout: 10000 });
    const headers = response.headers;

    const checks = [
      { header: 'strict-transport-security', name: 'HSTS', severity: 'medium' },
      { header: 'content-security-policy', name: 'CSP', severity: 'medium' },
      { header: 'x-frame-options', name: 'X-Frame-Options', severity: 'medium' },
      { header: 'x-content-type-options', name: 'X-Content-Type-Options', severity: 'low' },
      { header: 'x-xss-protection', name: 'X-XSS-Protection', severity: 'low' },
      { header: 'referrer-policy', name: 'Referrer-Policy', severity: 'low' },
      { header: 'permissions-policy', name: 'Permissions-Policy', severity: 'low' },
    ];

    for (const check of checks) {
      if (!headers[check.header]) {
        findings.push({
          id: generateId('HDR'),
          type: 'missing-security-header',
          severity: check.severity,
          url,
          issue: `Missing ${check.name} header`,
          evidence: `Header "${check.header}" not present in response`,
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Info disclosure
    if (headers['server']) {
      findings.push({
        id: generateId('HDR'),
        type: 'information-disclosure',
        severity: 'info',
        url,
        issue: `Server header discloses: ${headers['server']}`,
        evidence: `Server: ${headers['server']}`,
        timestamp: new Date().toISOString(),
      });
    }
    if (headers['x-powered-by']) {
      findings.push({
        id: generateId('HDR'),
        type: 'information-disclosure',
        severity: 'low',
        url,
        issue: `X-Powered-By discloses: ${headers['x-powered-by']}`,
        evidence: `X-Powered-By: ${headers['x-powered-by']}`,
        timestamp: new Date().toISOString(),
      });
    }
  } catch { /* skip */ }

  return findings;
}

/**
 * Open redirect scanner
 */
async function scanRedirects(url, params) {
  const findings = [];
  const redirectParams = ['redirect', 'url', 'next', 'return', 'goto', 'dest', 'redir', 'returnUrl', 'return_url'];
  const payloads = ['https://evil.com', '//evil.com', '/\\evil.com', 'https://evil.com%00.example.com'];

  const parsed = URLParser.parse(url);
  if (!parsed) return findings;

  const paramsToTest = Object.keys(params).filter(p => redirectParams.some(rp => p.toLowerCase().includes(rp)));

  for (const param of paramsToTest) {
    for (const payload of payloads) {
      try {
        const testParams = { ...parsed.params, [param]: payload };
        const testUrl = URLParser.buildUrl(url.split('?')[0], testParams);
        const response = await httpGet(testUrl, { timeout: 10000, followRedirects: false, maxRedirects: 0 });

        const location = response.headers['location'] || '';
        if (location.includes('evil.com')) {
          findings.push({
            id: generateId('REDIR'),
            type: 'open-redirect',
            severity: 'medium',
            url,
            parameter: param,
            payload,
            evidence: `Redirects to: ${location}`,
            timestamp: new Date().toISOString(),
          });
          break; // One payload is enough per param
        }
      } catch { /* skip */ }
    }
  }

  return findings;
}

/**
 * LFI scanner
 */
async function scanLFI(url, params) {
  const findings = [];
  const lfiParams = ['file', 'path', 'page', 'include', 'doc', 'template', 'load', 'read', 'lang', 'module'];
  const payloads = [
    { value: '../../../../etc/passwd', indicator: 'root:', os: 'linux' },
    { value: '....//....//....//etc/passwd', indicator: 'root:', os: 'linux' },
    { value: '..\\..\\..\\windows\\win.ini', indicator: '[fonts]', os: 'windows' },
    { value: '/etc/passwd', indicator: 'root:', os: 'linux' },
    { value: 'php://filter/convert.base64-encode/resource=index.php', indicator: 'PD9', os: 'php' },
  ];

  const parsed = URLParser.parse(url);
  if (!parsed) return findings;

  const paramsToTest = Object.keys(params).filter(p => lfiParams.some(lp => p.toLowerCase().includes(lp)));

  for (const param of paramsToTest) {
    for (const payload of payloads) {
      try {
        const testParams = { ...parsed.params, [param]: payload.value };
        const testUrl = URLParser.buildUrl(url.split('?')[0], testParams);
        const response = await httpGet(testUrl, { timeout: 10000 });
        const body = typeof response.data === 'string' ? response.data : '';

        if (body.includes(payload.indicator)) {
          findings.push({
            id: generateId('LFI'),
            type: 'local-file-inclusion',
            severity: 'critical',
            url,
            parameter: param,
            payload: payload.value,
            os: payload.os,
            evidence: `File content indicator "${payload.indicator}" found in response`,
            timestamp: new Date().toISOString(),
          });
          break;
        }
      } catch { /* skip */ }
    }
  }

  return findings;
}

export default handleHunt;
