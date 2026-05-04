import { parse as tldParse } from 'tldts';

/**
 * URL Parser - Parse and normalize target URLs
 */
export class URLParser {
  /**
   * Parse URL and extract all components
   */
  static parse(input) {
    input = input.trim();

    // Add protocol if missing
    if (!input.match(/^https?:\/\//i) && !input.match(/^\*\./)) {
      input = `https://${input}`;
    }

    try {
      const url = new URL(input);
      const tld = tldParse(url.hostname);

      return {
        original: input,
        protocol: url.protocol.replace(':', ''),
        hostname: url.hostname,
        port: url.port ? parseInt(url.port) : (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        query: url.search,
        hash: url.hash,
        params: Object.fromEntries(url.searchParams),
        domain: tld.domain || url.hostname,
        subdomain: tld.subdomain || '',
        tld: tld.publicSuffix || '',
        isIP: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname),
        full: url.toString(),
      };
    } catch {
      // Handle wildcard domains and bare domains
      const wildcardMatch = input.match(/^\*\.(.+)$/);
      if (wildcardMatch) {
        return {
          original: input,
          protocol: 'https',
          hostname: wildcardMatch[1],
          port: 443,
          path: '/',
          query: '',
          hash: '',
          params: {},
          domain: wildcardMatch[1],
          subdomain: '*',
          tld: '',
          isIP: false,
          isWildcard: true,
          full: `https://${wildcardMatch[1]}`,
        };
      }
      return null;
    }
  }

  /**
   * Normalize URL for consistent comparison
   */
  static normalize(url) {
    const parsed = this.parse(url);
    if (!parsed) return url;

    let normalized = `${parsed.protocol}://${parsed.hostname.toLowerCase()}`;
    if (parsed.port !== 80 && parsed.port !== 443) {
      normalized += `:${parsed.port}`;
    }
    normalized += parsed.path === '/' ? '' : parsed.path.replace(/\/$/, '');
    if (parsed.query) normalized += parsed.query;
    return normalized;
  }

  /**
   * Extract all parameters from URL
   */
  static extractParams(url) {
    const parsed = this.parse(url);
    if (!parsed) return {};
    return parsed.params;
  }

  /**
   * Check if input is a valid URL/domain
   */
  static isValid(input) {
    input = input.trim();
    if (!input) return false;

    // Wildcard domain
    if (/^\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(input)) return true;

    // IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(input)) return true;

    // IP range (CIDR)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(input)) return true;

    // Domain or URL
    try {
      const url = input.match(/^https?:\/\//) ? input : `https://${input}`;
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Extract base URL (protocol + host + port)
   */
  static getBaseUrl(url) {
    const parsed = this.parse(url);
    if (!parsed) return url;
    let base = `${parsed.protocol}://${parsed.hostname}`;
    if (parsed.port !== 80 && parsed.port !== 443) {
      base += `:${parsed.port}`;
    }
    return base;
  }

  /**
   * Build URL with modified parameters
   */
  static buildUrl(baseUrl, params = {}) {
    const url = new URL(baseUrl.match(/^https?:\/\//) ? baseUrl : `https://${baseUrl}`);
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });
    return url.toString();
  }

  /**
   * Extract all URLs from HTML content
   */
  static extractUrls(html, baseUrl) {
    const urls = new Set();
    const patterns = [
      /href=["']([^"']+)["']/gi,
      /src=["']([^"']+)["']/gi,
      /action=["']([^"']+)["']/gi,
      /url\(["']?([^"')]+)["']?\)/gi,
      /https?:\/\/[^\s"'<>]+/gi,
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(html)) !== null) {
        let url = match[1] || match[0];
        try {
          if (url.startsWith('//')) url = `https:${url}`;
          else if (url.startsWith('/')) url = new URL(url, baseUrl).toString();
          else if (!url.startsWith('http')) url = new URL(url, baseUrl).toString();
          urls.add(url);
        } catch { /* skip invalid */ }
      }
    }
    return [...urls];
  }
}

export default URLParser;
