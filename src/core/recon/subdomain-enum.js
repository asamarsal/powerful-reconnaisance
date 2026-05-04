import { httpGet } from '../../utils/http-client.js';
import { RateLimiter } from '../../utils/rate-limiter.js';
import { unique, sleep } from '../../utils/helpers.js';
import logger from '../../utils/logger.js';
import dns from 'dns';
import { promisify } from 'util';

const resolve4 = promisify(dns.resolve4);
const resolveCname = promisify(dns.resolveCname);

/**
 * Subdomain Enumerator - Passive & Active subdomain discovery
 */
export class SubdomainEnumerator {
  constructor(options = {}) {
    this.rateLimiter = new RateLimiter(options.rateLimit || 5, options.concurrent || 10);
    this.timeout = options.timeout || 10000;
    this.results = [];
  }

  /**
   * Full enumeration (passive + active)
   */
  async enumerate(domain, options = {}) {
    logger.info(`Starting subdomain enumeration for: ${domain}`);
    const subdomains = new Set();

    // Passive enumeration
    const passiveResults = await this.passiveEnum(domain);
    passiveResults.forEach(s => subdomains.add(s));
    logger.info(`Passive enumeration found: ${passiveResults.length} subdomains`);

    // Active enumeration (if enabled)
    if (options.active !== false) {
      const activeResults = await this.activeEnum(domain, options.wordlist);
      activeResults.forEach(s => subdomains.add(s));
      logger.info(`Active enumeration found: ${activeResults.length} subdomains`);
    }

    // Verify subdomains
    const verified = await this.verifySubdomains([...subdomains]);
    logger.success(`Total verified subdomains: ${verified.length}`);

    this.results = verified;
    return verified;
  }

  /**
   * Passive enumeration using public sources
   */
  async passiveEnum(domain) {
    const sources = [
      this._crtsh(domain),
      this._hackertarget(domain),
      this._urlscan(domain),
      this._webArchive(domain),
      this._rapiddns(domain),
    ];

    const results = await Promise.allSettled(sources);
    const subdomains = new Set();

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        result.value.forEach(s => subdomains.add(s.toLowerCase()));
      }
    }

    return [...subdomains].filter(s => s.endsWith(domain));
  }

  /**
   * Active enumeration using DNS bruteforce
   */
  async activeEnum(domain, wordlist = null) {
    const words = wordlist || this._getDefaultWordlist();
    const found = [];

    logger.info(`DNS bruteforce with ${words.length} words...`);

    const checkSubdomain = async (word) => {
      const subdomain = `${word}.${domain}`;
      try {
        const ips = await resolve4(subdomain);
        if (ips && ips.length > 0) {
          found.push(subdomain);
          logger.debug(`Found: ${subdomain} -> ${ips[0]}`);
        }
      } catch { /* not found */ }
    };

    // Process in batches
    const batchSize = 50;
    for (let i = 0; i < words.length; i += batchSize) {
      const batch = words.slice(i, i + batchSize);
      await Promise.allSettled(batch.map(w => this.rateLimiter.execute(() => checkSubdomain(w))));
      logger.progress(Math.min(i + batchSize, words.length), words.length, 'DNS bruteforce');
    }

    return found;
  }

  /**
   * Verify subdomains resolve to IP
   */
  async verifySubdomains(subdomains) {
    const verified = [];

    for (const subdomain of subdomains) {
      try {
        const ips = await resolve4(subdomain);
        if (ips && ips.length > 0) {
          verified.push({
            subdomain,
            ips,
            alive: true,
          });
        }
      } catch {
        // Try CNAME
        try {
          const cnames = await resolveCname(subdomain);
          if (cnames && cnames.length > 0) {
            verified.push({
              subdomain,
              cnames,
              alive: true,
              possibleTakeover: true,
            });
          }
        } catch { /* skip */ }
      }
    }

    return verified;
  }

  /**
   * Check for subdomain takeover
   */
  async checkTakeover(subdomain) {
    const takeoverFingerprints = [
      { service: 'GitHub Pages', cname: 'github.io', fingerprint: 'There isn\'t a GitHub Pages site here' },
      { service: 'Heroku', cname: 'herokuapp.com', fingerprint: 'No such app' },
      { service: 'AWS S3', cname: 's3.amazonaws.com', fingerprint: 'NoSuchBucket' },
      { service: 'Shopify', cname: 'myshopify.com', fingerprint: 'Sorry, this shop is currently unavailable' },
      { service: 'Tumblr', cname: 'tumblr.com', fingerprint: 'There\'s nothing here' },
      { service: 'Surge.sh', cname: 'surge.sh', fingerprint: 'project not found' },
      { service: 'Fastly', cname: 'fastly.net', fingerprint: 'Fastly error: unknown domain' },
    ];

    try {
      const response = await httpGet(`https://${subdomain}`, { timeout: 5000 });
      const body = typeof response.data === 'string' ? response.data : '';

      for (const fp of takeoverFingerprints) {
        if (body.includes(fp.fingerprint)) {
          return { vulnerable: true, service: fp.service, subdomain };
        }
      }
    } catch { /* skip */ }

    return { vulnerable: false, subdomain };
  }

  // === Private Source Methods ===

  async _crtsh(domain) {
    try {
      const resp = await httpGet(`https://crt.sh/?q=%.${domain}&output=json`, { timeout: 15000 });
      if (resp.status === 200 && Array.isArray(resp.data)) {
        return resp.data
          .map(entry => entry.name_value)
          .flatMap(name => name.split('\n'))
          .map(s => s.replace(/^\*\./, '').trim().toLowerCase())
          .filter(s => s.endsWith(domain));
      }
    } catch { /* skip */ }
    return [];
  }

  async _hackertarget(domain) {
    try {
      const resp = await httpGet(`https://api.hackertarget.com/hostsearch/?q=${domain}`, { timeout: 10000 });
      if (resp.status === 200 && typeof resp.data === 'string') {
        return resp.data.split('\n')
          .map(line => line.split(',')[0]?.trim())
          .filter(Boolean);
      }
    } catch { /* skip */ }
    return [];
  }

  async _urlscan(domain) {
    try {
      const resp = await httpGet(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100`, { timeout: 10000 });
      if (resp.status === 200 && resp.data?.results) {
        return resp.data.results
          .map(r => r.page?.domain)
          .filter(d => d && d.endsWith(domain));
      }
    } catch { /* skip */ }
    return [];
  }

  async _webArchive(domain) {
    try {
      const resp = await httpGet(
        `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original&collapse=urlkey&limit=500`,
        { timeout: 15000 }
      );
      if (resp.status === 200 && Array.isArray(resp.data)) {
        return resp.data.slice(1)
          .map(entry => {
            try { return new URL(entry[0]).hostname; } catch { return null; }
          })
          .filter(h => h && h.endsWith(domain));
      }
    } catch { /* skip */ }
    return [];
  }

  async _rapiddns(domain) {
    try {
      const resp = await httpGet(`https://rapiddns.io/subdomain/${domain}?full=1`, { timeout: 10000 });
      if (resp.status === 200 && typeof resp.data === 'string') {
        const matches = resp.data.match(/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
        return matches.filter(m => m.endsWith(domain));
      }
    } catch { /* skip */ }
    return [];
  }

  _getDefaultWordlist() {
    return [
      'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
      'admin', 'api', 'app', 'dev', 'staging', 'test', 'beta', 'demo', 'portal',
      'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'media', 'img', 'images',
      'docs', 'help', 'support', 'status', 'monitor', 'dashboard', 'panel',
      'login', 'auth', 'sso', 'oauth', 'accounts', 'register', 'signup',
      'vpn', 'remote', 'gateway', 'proxy', 'firewall', 'waf',
      'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
      'jenkins', 'gitlab', 'github', 'ci', 'cd', 'deploy', 'build',
      'internal', 'intranet', 'private', 'corp', 'office',
      'mobile', 'ios', 'android', 'm', 'wap',
      'v1', 'v2', 'v3', 'api-v1', 'api-v2', 'graphql', 'rest',
      'staging2', 'uat', 'qa', 'preprod', 'sandbox',
      'backup', 'bak', 'old', 'new', 'temp', 'tmp',
      'mx', 'mx1', 'mx2', 'email', 'imap', 'pop3',
      'cpanel', 'whm', 'plesk', 'webmin',
      'git', 'svn', 'repo', 'code', 'source',
      'ws', 'websocket', 'socket', 'realtime',
      'pay', 'payment', 'billing', 'invoice', 'checkout',
      'search', 'elastic', 'solr', 'kibana', 'grafana',
    ];
  }
}

export default SubdomainEnumerator;
