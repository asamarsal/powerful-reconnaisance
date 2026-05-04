import { URLParser } from './url-parser.js';

/**
 * Scope Validator - Validates targets against defined scope
 */
export class ScopeValidator {
  constructor(scopeConfig = {}) {
    this.include = scopeConfig.include || [];
    this.exclude = scopeConfig.exclude || [];
    this.allowedPorts = scopeConfig.allowedPorts || [80, 443, 8080, 8443];
    this.allowedProtocols = scopeConfig.allowedProtocols || ['http', 'https'];
    this.maxDepth = scopeConfig.maxDepth || 10;
  }

  /**
   * Check if URL is within scope
   */
  isInScope(url) {
    const parsed = URLParser.parse(url);
    if (!parsed) return false;

    // Check protocol
    if (!this.allowedProtocols.includes(parsed.protocol)) return false;

    // Check port
    if (this.allowedPorts.length > 0 && !this.allowedPorts.includes(parsed.port)) return false;

    // Check exclude first (takes priority)
    for (const pattern of this.exclude) {
      if (this._matchPattern(parsed, pattern)) return false;
    }

    // If no include rules, everything not excluded is in scope
    if (this.include.length === 0) return true;

    // Check include
    for (const pattern of this.include) {
      if (this._matchPattern(parsed, pattern)) return true;
    }

    return false;
  }

  /**
   * Match URL against a scope pattern
   */
  _matchPattern(parsed, pattern) {
    // Wildcard subdomain: *.example.com
    if (pattern.startsWith('*.')) {
      const domain = pattern.substring(2);
      return parsed.hostname === domain ||
             parsed.hostname.endsWith(`.${domain}`);
    }

    // Exact domain match
    if (!pattern.includes('/') && !pattern.includes(':')) {
      return parsed.hostname === pattern || parsed.domain === pattern;
    }

    // Path-based pattern
    if (pattern.includes('/')) {
      const patternParsed = URLParser.parse(pattern);
      if (patternParsed) {
        return parsed.hostname === patternParsed.hostname &&
               parsed.path.startsWith(patternParsed.path);
      }
    }

    // IP range (CIDR) - simplified check
    if (pattern.includes('/')) {
      return this._isInCIDR(parsed.hostname, pattern);
    }

    return parsed.hostname === pattern;
  }

  /**
   * Simple CIDR check
   */
  _isInCIDR(ip, cidr) {
    const [range, bits] = cidr.split('/');
    if (!bits || !ip.match(/^\d+\.\d+\.\d+\.\d+$/)) return false;

    const ipNum = this._ipToNum(ip);
    const rangeNum = this._ipToNum(range);
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);

    return (ipNum & mask) === (rangeNum & mask);
  }

  _ipToNum(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
  }

  /**
   * Validate batch of targets
   */
  validateBatch(urls) {
    return urls.map(url => ({
      url,
      inScope: this.isInScope(url),
    }));
  }

  /**
   * Filter only in-scope URLs
   */
  filterInScope(urls) {
    return urls.filter(url => this.isInScope(url));
  }

  /**
   * Add pattern to include list
   */
  addInclude(pattern) {
    if (!this.include.includes(pattern)) {
      this.include.push(pattern);
    }
  }

  /**
   * Add pattern to exclude list
   */
  addExclude(pattern) {
    if (!this.exclude.includes(pattern)) {
      this.exclude.push(pattern);
    }
  }

  /**
   * Export scope config
   */
  toJSON() {
    return {
      include: this.include,
      exclude: this.exclude,
      allowedPorts: this.allowedPorts,
      allowedProtocols: this.allowedProtocols,
      maxDepth: this.maxDepth,
    };
  }
}

export default ScopeValidator;
