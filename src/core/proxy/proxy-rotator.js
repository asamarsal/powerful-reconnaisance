import { ProxyScraper } from './proxy-scraper.js';
import { createHttpClient } from '../../utils/http-client.js';
import logger from '../../utils/logger.js';

/**
 * Proxy Rotator - Automatically rotate proxies for stealth scanning
 * Integrates with ProxyScrape for fresh proxy supply
 */
export class ProxyRotator {
  constructor(options = {}) {
    this.scraper = new ProxyScraper(options);
    this.failCount = new Map(); // Track failures per proxy
    this.maxFails = options.maxFails || 3;
    this.rotateAfter = options.rotateAfter || 10; // Rotate after N requests
    this.requestCount = 0;
    this.currentProxy = null;
    this.initialized = false;
  }

  /**
   * Initialize - fetch and validate proxies
   */
  async initialize(options = {}) {
    if (this.initialized && this.scraper.getCount().working > 0) return;

    logger.info('[ProxyRotator] Initializing proxy pool...');
    await this.scraper.fetchProxies(options);

    if (options.validate !== false) {
      await this.scraper.validateProxies({ concurrent: 100, timeout: 5000 });
    }

    const count = this.scraper.getCount();
    if (count.working === 0 && count.total > 0) {
      logger.warn('[ProxyRotator] No working proxies found, using unvalidated pool');
    } else if (count.total === 0) {
      logger.warn('[ProxyRotator] No proxies available, requests will go direct');
    }

    this.initialized = true;
    logger.success(`[ProxyRotator] Ready with ${count.working || count.total} proxies`);
  }

  /**
   * Make HTTP request through rotating proxy
   */
  async request(url, options = {}) {
    const proxy = this._getProxy();

    const requestOptions = {
      ...options,
      timeout: options.timeout || 15000,
    };

    if (proxy) {
      requestOptions.proxy = proxy.url;
    }

    try {
      const client = createHttpClient(requestOptions);
      const response = await client.get(url);

      // Success - reset fail count
      if (proxy) this.failCount.set(proxy.url, 0);
      this.requestCount++;

      return {
        status: response.status,
        headers: response.headers,
        data: response.data,
        proxy: proxy ? proxy.url : 'direct',
      };
    } catch (error) {
      // Track failure
      if (proxy) {
        const fails = (this.failCount.get(proxy.url) || 0) + 1;
        this.failCount.set(proxy.url, fails);

        if (fails >= this.maxFails) {
          this.scraper.removeBad(proxy);
          this.failCount.delete(proxy.url);
          logger.debug(`[ProxyRotator] Removed bad proxy: ${proxy.url}`);
        }
      }

      // Retry with different proxy
      if (options._retryCount < (options.maxRetries || 3)) {
        return this.request(url, { ...options, _retryCount: (options._retryCount || 0) + 1 });
      }

      return { status: 0, headers: {}, data: '', error: error.message, proxy: proxy?.url };
    }
  }

  /**
   * Get current proxy with rotation logic
   */
  _getProxy() {
    if (this.requestCount % this.rotateAfter === 0 || !this.currentProxy) {
      this.currentProxy = this.scraper.getRandom();
    }
    return this.currentProxy;
  }

  /**
   * Force rotate to next proxy
   */
  rotate() {
    this.currentProxy = this.scraper.getRandom();
    return this.currentProxy;
  }

  /**
   * Get proxy stats
   */
  getStats() {
    return {
      ...this.scraper.getCount(),
      requestsMade: this.requestCount,
      currentProxy: this.currentProxy?.url || 'none',
      failedProxies: this.failCount.size,
    };
  }
}

export default ProxyRotator;
