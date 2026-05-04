import axios from 'axios';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import net from 'net';
import logger from '../../utils/logger.js';
import config from '../../../config/default.js';

/**
 * Proxy Scraper - Fetch and manage proxies from ProxyScrape and other sources
 * Supports HTTP, HTTPS, SOCKS4, SOCKS5
 */
export class ProxyScraper {
  constructor(options = {}) {
    this.proxyFile = join(config.paths.data, 'proxies.json');
    this.proxies = [];
    this.workingProxies = [];
    this.currentIndex = 0;
    this.protocol = options.protocol || 'http'; // http, socks4, socks5
    this.timeout = options.timeout || 5000;
    this.country = options.country || 'all';
    this.anonymity = options.anonymity || 'all'; // elite, anonymous, transparent
    this.autoRotate = options.autoRotate !== false;
    this.maxRetries = options.maxRetries || 3;
    this._loadCached();
  }

  /**
   * Fetch fresh proxies from multiple sources
   */
  async fetchProxies(options = {}) {
    logger.info('[Proxy] Fetching fresh proxies from multiple sources...');
    const allProxies = new Set();

    const sources = [
      this._fetchFromProxyScrape(options),
      this._fetchFromProxyScrapeV3(options),
      this._fetchFromFreeProxyList(),
      this._fetchFromGeonode(),
      this._fetchFromProxyList(),
      this._fetchFromSpysOne(),
    ];

    const results = await Promise.allSettled(sources);

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        result.value.forEach(p => allProxies.add(p));
      }
    }

    this.proxies = [...allProxies].map(p => this._parseProxy(p)).filter(Boolean);
    logger.success(`[Proxy] Fetched ${this.proxies.length} proxies total`);

    // Save to cache
    this._saveCache();

    return this.proxies;
  }

  /**
   * Fetch from ProxyScrape.com API v2
   */
  async _fetchFromProxyScrape(options = {}) {
    const protocol = options.protocol || this.protocol;
    const country = options.country || this.country;
    const anonymity = options.anonymity || this.anonymity;

    const params = new URLSearchParams({
      request: 'displayproxies',
      protocol: protocol,
      timeout: '10000',
      country: country,
      ssl: 'all',
      anonymity: anonymity,
    });

    try {
      const url = `https://api.proxyscrape.com/v2/?${params.toString()}`;
      logger.debug(`[Proxy] Fetching from ProxyScrape v2: ${protocol}/${country}`);

      const response = await axios.get(url, { timeout: 15000 });
      if (response.status === 200 && response.data) {
        const proxies = response.data
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && line.includes(':'));

        logger.info(`[Proxy] ProxyScrape v2: ${proxies.length} ${protocol} proxies`);
        return proxies.map(p => `${protocol}://${p}`);
      }
    } catch (error) {
      logger.debug(`[Proxy] ProxyScrape v2 error: ${error.message}`);
    }
    return [];
  }

  /**
   * Fetch from ProxyScrape.com API v3 (newer endpoint)
   */
  async _fetchFromProxyScrapeV3(options = {}) {
    const protocol = options.protocol || this.protocol;

    try {
      const url = `https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_format=protocolipport&format=text&protocol=${protocol}`;
      logger.debug(`[Proxy] Fetching from ProxyScrape v3`);

      const response = await axios.get(url, { timeout: 15000 });
      if (response.status === 200 && response.data) {
        const proxies = response.data
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && (line.includes('://') || line.includes(':')));

        logger.info(`[Proxy] ProxyScrape v3: ${proxies.length} proxies`);
        return proxies.map(p => p.includes('://') ? p : `${protocol}://${p}`);
      }
    } catch (error) {
      logger.debug(`[Proxy] ProxyScrape v3 error: ${error.message}`);
    }
    return [];
  }

  /**
   * Fetch from free-proxy-list.net
   */
  async _fetchFromFreeProxyList() {
    try {
      const response = await axios.get('https://free-proxy-list.net/', { timeout: 10000 });
      if (response.status === 200) {
        const matches = response.data.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/g) || [];
        logger.info(`[Proxy] free-proxy-list.net: ${matches.length} proxies`);
        return matches.map(p => `http://${p}`);
      }
    } catch (error) {
      logger.debug(`[Proxy] free-proxy-list error: ${error.message}`);
    }
    return [];
  }

  /**
   * Fetch from geonode.com
   */
  async _fetchFromGeonode() {
    try {
      const url = 'https://proxylist.geonode.com/api/proxy-list?limit=200&page=1&sort_by=lastChecked&sort_type=desc';
      const response = await axios.get(url, { timeout: 10000 });
      if (response.status === 200 && response.data?.data) {
        const proxies = response.data.data.map(p => `${p.protocols[0]}://${p.ip}:${p.port}`);
        logger.info(`[Proxy] Geonode: ${proxies.length} proxies`);
        return proxies;
      }
    } catch (error) {
      logger.debug(`[Proxy] Geonode error: ${error.message}`);
    }
    return [];
  }

  /**
   * Fetch from proxy-list.download
   */
  async _fetchFromProxyList() {
    try {
      const types = ['http', 'https', 'socks4', 'socks5'];
      const allProxies = [];

      for (const type of types) {
        try {
          const url = `https://www.proxy-list.download/api/v1/get?type=${type}`;
          const response = await axios.get(url, { timeout: 10000 });
          if (response.status === 200 && response.data) {
            const proxies = response.data.split('\n').filter(l => l.trim()).map(p => `${type}://${p.trim()}`);
            allProxies.push(...proxies);
          }
        } catch { /* skip */ }
      }

      logger.info(`[Proxy] proxy-list.download: ${allProxies.length} proxies`);
      return allProxies;
    } catch (error) {
      logger.debug(`[Proxy] proxy-list error: ${error.message}`);
    }
    return [];
  }

  /**
   * Fetch from spys.one
   */
  async _fetchFromSpysOne() {
    try {
      const response = await axios.get('https://spys.me/proxy.txt', { timeout: 10000 });
      if (response.status === 200) {
        const matches = response.data.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/g) || [];
        logger.info(`[Proxy] spys.me: ${matches.length} proxies`);
        return matches.map(p => `http://${p}`);
      }
    } catch (error) {
      logger.debug(`[Proxy] spys.one error: ${error.message}`);
    }
    return [];
  }

  /**
   * Validate/test proxies for connectivity
   */
  async validateProxies(options = {}) {
    const testUrl = options.testUrl || 'http://httpbin.org/ip';
    const maxConcurrent = options.concurrent || 50;
    const timeout = options.timeout || this.timeout;

    logger.info(`[Proxy] Validating ${this.proxies.length} proxies...`);
    this.workingProxies = [];

    const batches = [];
    for (let i = 0; i < this.proxies.length; i += maxConcurrent) {
      batches.push(this.proxies.slice(i, i + maxConcurrent));
    }

    let tested = 0;
    for (const batch of batches) {
      const results = await Promise.allSettled(
        batch.map(proxy => this._testProxy(proxy, testUrl, timeout))
      );

      for (let i = 0; i < results.length; i++) {
        if (results[i].status === 'fulfilled' && results[i].value) {
          this.workingProxies.push({
            ...batch[i],
            responseTime: results[i].value.responseTime,
            testedAt: new Date().toISOString(),
          });
        }
      }

      tested += batch.length;
      logger.progress(tested, this.proxies.length, `Testing proxies (${this.workingProxies.length} working)`);
    }

    // Sort by response time
    this.workingProxies.sort((a, b) => a.responseTime - b.responseTime);

    logger.success(`[Proxy] ${this.workingProxies.length}/${this.proxies.length} proxies working`);
    this._saveCache();

    return this.workingProxies;
  }

  /**
   * Test a single proxy
   */
  async _testProxy(proxy, testUrl, timeout) {
    const start = Date.now();
    try {
      const proxyConfig = {
        host: proxy.host,
        port: proxy.port,
        protocol: proxy.protocol,
      };

      const response = await axios.get(testUrl, {
        proxy: proxyConfig,
        timeout,
        validateStatus: () => true,
      });

      if (response.status === 200) {
        return { working: true, responseTime: Date.now() - start };
      }
    } catch { /* not working */ }
    return null;
  }

  /**
   * Get next proxy (rotation)
   */
  getNext() {
    const pool = this.workingProxies.length > 0 ? this.workingProxies : this.proxies;
    if (pool.length === 0) return null;

    const proxy = pool[this.currentIndex % pool.length];
    this.currentIndex++;
    return proxy;
  }

  /**
   * Get random proxy
   */
  getRandom() {
    const pool = this.workingProxies.length > 0 ? this.workingProxies : this.proxies;
    if (pool.length === 0) return null;
    return pool[Math.floor(Math.random() * pool.length)];
  }

  /**
   * Get proxy formatted for axios
   */
  getAxiosProxy() {
    const proxy = this.getNext();
    if (!proxy) return null;
    return {
      host: proxy.host,
      port: proxy.port,
      protocol: proxy.protocol,
    };
  }

  /**
   * Get proxy as URL string
   */
  getProxyUrl() {
    const proxy = this.getNext();
    if (!proxy) return null;
    return `${proxy.protocol}://${proxy.host}:${proxy.port}`;
  }

  /**
   * Get all working proxies
   */
  getWorking() {
    return this.workingProxies;
  }

  /**
   * Get proxy count
   */
  getCount() {
    return {
      total: this.proxies.length,
      working: this.workingProxies.length,
    };
  }

  /**
   * Remove a bad proxy from the pool
   */
  removeBad(proxy) {
    this.workingProxies = this.workingProxies.filter(
      p => !(p.host === proxy.host && p.port === proxy.port)
    );
  }

  /**
   * Parse proxy string to object
   */
  _parseProxy(proxyStr) {
    try {
      // Format: protocol://host:port or host:port
      let protocol = 'http';
      let hostPort = proxyStr;

      if (proxyStr.includes('://')) {
        const parts = proxyStr.split('://');
        protocol = parts[0];
        hostPort = parts[1];
      }

      const [host, portStr] = hostPort.split(':');
      const port = parseInt(portStr);

      if (!host || !port || isNaN(port)) return null;

      return { protocol, host, port, url: `${protocol}://${host}:${port}` };
    } catch {
      return null;
    }
  }

  /**
   * Save proxies to cache file
   */
  _saveCache() {
    const data = {
      fetchedAt: new Date().toISOString(),
      proxies: this.proxies,
      workingProxies: this.workingProxies,
    };
    try {
      writeFileSync(this.proxyFile, JSON.stringify(data, null, 2));
    } catch { /* skip */ }
  }

  /**
   * Load cached proxies
   */
  _loadCached() {
    try {
      if (existsSync(this.proxyFile)) {
        const data = JSON.parse(readFileSync(this.proxyFile, 'utf-8'));
        const age = Date.now() - new Date(data.fetchedAt).getTime();

        // Use cache if less than 30 minutes old
        if (age < 30 * 60 * 1000) {
          this.proxies = data.proxies || [];
          this.workingProxies = data.workingProxies || [];
          logger.debug(`[Proxy] Loaded ${this.proxies.length} cached proxies`);
        }
      }
    } catch { /* skip */ }
  }

  /**
   * Fetch proxies by country for specific TLD targeting
   */
  async fetchByCountry(countryCode) {
    const countryMap = {
      'id': 'ID',   // Indonesia (.id)
      'gov': 'US',  // US Government (.gov)
      'my': 'MY',   // Malaysia (.my)
      'sg': 'SG',   // Singapore (.sg)
      'th': 'TH',   // Thailand (.th)
      'ph': 'PH',   // Philippines (.ph)
      'vn': 'VN',   // Vietnam (.vn)
      'in': 'IN',   // India (.in)
      'au': 'AU',   // Australia (.au)
      'jp': 'JP',   // Japan (.jp)
      'kr': 'KR',   // Korea (.kr)
      'uk': 'GB',   // United Kingdom (.uk)
      'de': 'DE',   // Germany (.de)
      'fr': 'FR',   // France (.fr)
      'br': 'BR',   // Brazil (.br)
    };

    const country = countryMap[countryCode.toLowerCase()] || countryCode.toUpperCase();
    return this.fetchProxies({ country, protocol: 'http' });
  }
}

export default ProxyScraper;
