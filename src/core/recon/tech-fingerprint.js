import { httpGet } from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * Technology Fingerprinter - Detect technologies used by target
 */
export class TechFingerprinter {
  constructor() {
    this.fingerprints = this._loadFingerprints();
  }

  /**
   * Full fingerprint scan
   */
  async fingerprint(url) {
    logger.info(`Fingerprinting: ${url}`);
    const results = [];

    try {
      const response = await httpGet(url, { timeout: 15000 });
      if (response.error) {
        logger.warn(`Cannot reach ${url}: ${response.error}`);
        return results;
      }

      const html = typeof response.data === 'string' ? response.data : '';
      const headers = response.headers || {};

      // Header-based detection
      results.push(...this._detectFromHeaders(headers));

      // HTML-based detection
      results.push(...this._detectFromHTML(html));

      // Cookie-based detection
      results.push(...this._detectFromCookies(headers['set-cookie']));

      // URL pattern detection
      results.push(...this._detectFromURL(url, html));

      // Meta tag detection
      results.push(...this._detectFromMeta(html));

      // JavaScript detection
      results.push(...this._detectFromScripts(html));

      // Deduplicate
      const seen = new Set();
      const unique = results.filter(r => {
        const key = `${r.name}:${r.version || ''}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

      logger.success(`Detected ${unique.length} technologies on ${url}`);
      return unique;
    } catch (error) {
      logger.error(`Fingerprint error: ${error.message}`);
      return results;
    }
  }

  /**
   * Detect from HTTP headers
   */
  _detectFromHeaders(headers) {
    const results = [];

    // Server header
    if (headers.server) {
      const serverMatch = headers.server.match(/^([^\/]+)(?:\/([0-9.]+))?/);
      if (serverMatch) {
        results.push({
          name: serverMatch[1].trim(),
          version: serverMatch[2] || null,
          category: 'web-server',
          confidence: 100,
          source: 'header:server',
        });
      }
    }

    // X-Powered-By
    if (headers['x-powered-by']) {
      const powered = headers['x-powered-by'];
      const match = powered.match(/^([^\/]+)(?:\/([0-9.]+))?/);
      if (match) {
        results.push({
          name: match[1].trim(),
          version: match[2] || null,
          category: 'framework',
          confidence: 100,
          source: 'header:x-powered-by',
        });
      }
    }

    // X-AspNet-Version
    if (headers['x-aspnet-version']) {
      results.push({
        name: 'ASP.NET',
        version: headers['x-aspnet-version'],
        category: 'framework',
        confidence: 100,
        source: 'header:x-aspnet-version',
      });
    }

    // X-Generator
    if (headers['x-generator']) {
      results.push({
        name: headers['x-generator'],
        version: null,
        category: 'cms',
        confidence: 90,
        source: 'header:x-generator',
      });
    }

    // CDN detection
    if (headers['cf-ray'] || headers['cf-cache-status']) {
      results.push({ name: 'Cloudflare', version: null, category: 'cdn', confidence: 100, source: 'header:cf-ray' });
    }
    if (headers['x-amz-cf-id'] || headers['x-amz-cf-pop']) {
      results.push({ name: 'Amazon CloudFront', version: null, category: 'cdn', confidence: 100, source: 'header:x-amz' });
    }
    if (headers['x-fastly-request-id']) {
      results.push({ name: 'Fastly', version: null, category: 'cdn', confidence: 100, source: 'header:fastly' });
    }
    if (headers['x-akamai-transformed']) {
      results.push({ name: 'Akamai', version: null, category: 'cdn', confidence: 100, source: 'header:akamai' });
    }

    return results;
  }

  /**
   * Detect from HTML content
   */
  _detectFromHTML(html) {
    const results = [];
    if (!html) return results;

    const patterns = [
      // CMS
      { regex: /wp-content|wp-includes|wordpress/i, name: 'WordPress', category: 'cms' },
      { regex: /\/joomla|com_content|Joomla!/i, name: 'Joomla', category: 'cms' },
      { regex: /\/sites\/default\/files|Drupal/i, name: 'Drupal', category: 'cms' },
      { regex: /\/skin\/frontend|Magento/i, name: 'Magento', category: 'cms' },
      { regex: /shopify\.com|Shopify/i, name: 'Shopify', category: 'cms' },

      // JS Frameworks
      { regex: /__next|_next\/static/i, name: 'Next.js', category: 'js-framework' },
      { regex: /ng-app|ng-controller|angular/i, name: 'Angular', category: 'js-framework' },
      { regex: /data-reactroot|__NEXT_DATA__|react/i, name: 'React', category: 'js-framework' },
      { regex: /data-v-[a-f0-9]|__vue|Vue\.js/i, name: 'Vue.js', category: 'js-framework' },
      { regex: /ember-view|ember\.js/i, name: 'Ember.js', category: 'js-framework' },

      // JS Libraries
      { regex: /jquery[.-]([0-9.]+)/i, name: 'jQuery', category: 'js-library', versionGroup: 1 },
      { regex: /bootstrap[.-]([0-9.]+)/i, name: 'Bootstrap', category: 'css-framework', versionGroup: 1 },
      { regex: /tailwindcss|tailwind/i, name: 'Tailwind CSS', category: 'css-framework' },

      // Analytics
      { regex: /google-analytics|gtag|ga\.js|analytics\.js/i, name: 'Google Analytics', category: 'analytics' },
      { regex: /hotjar\.com/i, name: 'Hotjar', category: 'analytics' },
      { regex: /matomo|piwik/i, name: 'Matomo', category: 'analytics' },

      // Security
      { regex: /recaptcha|grecaptcha/i, name: 'reCAPTCHA', category: 'security' },
      { regex: /hcaptcha/i, name: 'hCaptcha', category: 'security' },

      // Hosting
      { regex: /amazonaws\.com/i, name: 'AWS', category: 'hosting' },
      { regex: /googleusercontent\.com|googleapis\.com/i, name: 'Google Cloud', category: 'hosting' },
      { regex: /azurewebsites\.net|azure/i, name: 'Microsoft Azure', category: 'hosting' },
    ];

    for (const pattern of patterns) {
      const match = html.match(pattern.regex);
      if (match) {
        results.push({
          name: pattern.name,
          version: pattern.versionGroup ? match[pattern.versionGroup] : null,
          category: pattern.category,
          confidence: 80,
          source: 'html',
        });
      }
    }

    return results;
  }

  /**
   * Detect from cookies
   */
  _detectFromCookies(setCookie) {
    const results = [];
    if (!setCookie) return results;

    const cookies = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;

    const patterns = [
      { regex: /PHPSESSID/i, name: 'PHP', category: 'language' },
      { regex: /JSESSIONID/i, name: 'Java', category: 'language' },
      { regex: /ASP\.NET_SessionId/i, name: 'ASP.NET', category: 'framework' },
      { regex: /laravel_session/i, name: 'Laravel', category: 'framework' },
      { regex: /django/i, name: 'Django', category: 'framework' },
      { regex: /express\.sid|connect\.sid/i, name: 'Express.js', category: 'framework' },
      { regex: /wordpress_logged_in|wp-settings/i, name: 'WordPress', category: 'cms' },
      { regex: /__cfduid|__cf_bm/i, name: 'Cloudflare', category: 'cdn' },
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(cookies)) {
        results.push({
          name: pattern.name,
          version: null,
          category: pattern.category,
          confidence: 85,
          source: 'cookie',
        });
      }
    }

    return results;
  }

  /**
   * Detect from URL patterns
   */
  _detectFromURL(url, html) {
    const results = [];

    const patterns = [
      { regex: /\/wp-admin|\/wp-login|\/wp-json/i, name: 'WordPress', category: 'cms' },
      { regex: /\/administrator\/|\/components\/com_/i, name: 'Joomla', category: 'cms' },
      { regex: /\/user\/login|\/admin\/structure/i, name: 'Drupal', category: 'cms' },
      { regex: /\/admin\.php|\/index\.php\?route=/i, name: 'OpenCart', category: 'cms' },
      { regex: /\/graphql/i, name: 'GraphQL', category: 'api' },
      { regex: /\/api\/v[0-9]/i, name: 'REST API', category: 'api' },
      { regex: /\/swagger|\/api-docs/i, name: 'Swagger/OpenAPI', category: 'api' },
    ];

    const combined = url + ' ' + (html || '');
    for (const pattern of patterns) {
      if (pattern.regex.test(combined)) {
        results.push({
          name: pattern.name,
          version: null,
          category: pattern.category,
          confidence: 70,
          source: 'url-pattern',
        });
      }
    }

    return results;
  }

  /**
   * Detect from meta tags
   */
  _detectFromMeta(html) {
    const results = [];
    if (!html) return results;

    const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
    if (generatorMatch) {
      const parts = generatorMatch[1].match(/^([^0-9]+)\s*([0-9.]+)?/);
      if (parts) {
        results.push({
          name: parts[1].trim(),
          version: parts[2] || null,
          category: 'cms',
          confidence: 95,
          source: 'meta:generator',
        });
      }
    }

    return results;
  }

  /**
   * Detect from script sources
   */
  _detectFromScripts(html) {
    const results = [];
    if (!html) return results;

    const scriptSrcs = html.match(/src=["']([^"']+\.js[^"']*)["']/gi) || [];
    const allScripts = scriptSrcs.join(' ');

    const patterns = [
      { regex: /jquery[.-]([0-9.]+)/i, name: 'jQuery', category: 'js-library', versionGroup: 1 },
      { regex: /angular[.-]([0-9.]+)/i, name: 'Angular', category: 'js-framework', versionGroup: 1 },
      { regex: /react[.-]([0-9.]+)/i, name: 'React', category: 'js-framework', versionGroup: 1 },
      { regex: /vue[.-]([0-9.]+)/i, name: 'Vue.js', category: 'js-framework', versionGroup: 1 },
      { regex: /lodash/i, name: 'Lodash', category: 'js-library' },
      { regex: /moment[.-]([0-9.]+)?/i, name: 'Moment.js', category: 'js-library' },
      { regex: /axios/i, name: 'Axios', category: 'js-library' },
    ];

    for (const pattern of patterns) {
      const match = allScripts.match(pattern.regex);
      if (match) {
        results.push({
          name: pattern.name,
          version: pattern.versionGroup ? match[pattern.versionGroup] : null,
          category: pattern.category,
          confidence: 75,
          source: 'script-src',
        });
      }
    }

    return results;
  }

  _loadFingerprints() {
    // Extensible fingerprint database
    return {};
  }
}

export default TechFingerprinter;
