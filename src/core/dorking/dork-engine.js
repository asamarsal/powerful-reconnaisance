import { httpGet } from '../../utils/http-client.js';
import { ProxyRotator } from '../proxy/proxy-rotator.js';
import { RateLimiter } from '../../utils/rate-limiter.js';
import { generateId, sleep, saveResults, unique } from '../../utils/helpers.js';
import logger from '../../utils/logger.js';
import config from '../../../config/default.js';
import { join } from 'path';

/**
 * Google Dorking Engine - Automated Google Dork scanning for bug bounty
 * Supports multiple TLDs (.id, .gov, .edu, etc.) with proxy rotation
 */
export class DorkEngine {
  constructor(options = {}) {
    this.proxyRotator = new ProxyRotator(options.proxy || {});
    this.rateLimiter = new RateLimiter(options.rateLimit || 2, options.concurrent || 1);
    this.timeout = options.timeout || 15000;
    this.results = [];
    this.useProxy = options.useProxy !== false;
    this.searchEngines = options.engines || ['google', 'bing', 'duckduckgo'];
  }

  /**
   * Initialize with proxies
   */
  async initialize() {
    if (this.useProxy) {
      await this.proxyRotator.initialize({ protocol: 'http' });
    }
    logger.success('[Dork] Engine initialized');
  }

  /**
   * Run dorks against specific TLD/domain
   */
  async dorkTarget(target, options = {}) {
    logger.info(`[Dork] Starting dorking for: ${target}`);
    const findings = [];

    const dorkCategories = options.categories || [
      'sensitive_files', 'admin_panels', 'login_pages',
      'exposed_data', 'sql_errors', 'directory_listing',
      'config_files', 'backup_files', 'api_endpoints',
      'vulnerable_params', 'information_disclosure',
    ];

    for (const category of dorkCategories) {
      const dorks = this._getDorksForCategory(category, target);
      logger.info(`[Dork] Running ${dorks.length} dorks for category: ${category}`);

      for (const dork of dorks) {
        try {
          const results = await this._executeDork(dork, options);
          if (results.length > 0) {
            findings.push({
              id: generateId('DORK'),
              category,
              dork: dork.query,
              description: dork.description,
              results,
              severity: dork.severity || 'info',
              target,
              timestamp: new Date().toISOString(),
            });
            logger.vuln(dork.severity || 'info', `[Dork] Found ${results.length} results: ${dork.description}`);
          }

          // Rate limiting between dorks
          await sleep(2000 + Math.random() * 3000);
        } catch (error) {
          logger.debug(`[Dork] Error: ${error.message}`);
        }
      }
    }

    this.results.push(...findings);
    return findings;
  }

  /**
   * Run dorks for specific TLD (.id, .gov, .edu, etc.)
   */
  async dorkByTLD(tld, options = {}) {
    logger.info(`[Dork] Dorking TLD: .${tld}`);
    const target = `site:*.${tld}`;
    return this.dorkTarget(target, options);
  }

  /**
   * Run dorks for Indonesian domains (.id, .go.id, .ac.id, etc.)
   */
  async dorkIndonesia(options = {}) {
    const tlds = ['id', 'go.id', 'ac.id', 'co.id', 'or.id', 'web.id', 'sch.id'];
    const allFindings = [];

    for (const tld of tlds) {
      logger.info(`[Dork] Scanning Indonesian TLD: .${tld}`);
      const findings = await this.dorkByTLD(tld, options);
      allFindings.push(...findings);
      await sleep(5000); // Delay between TLDs
    }

    return allFindings;
  }

  /**
   * Run dorks for government domains
   */
  async dorkGovernment(options = {}) {
    const govTLDs = [
      'gov', 'gov.id', 'go.id', 'gov.my', 'gov.sg', 'gov.ph',
      'gov.au', 'gov.uk', 'gov.in', 'go.th', 'go.jp', 'go.kr',
      'gob.mx', 'gov.br', 'gouv.fr', 'gov.za',
    ];
    const allFindings = [];

    for (const tld of govTLDs) {
      logger.info(`[Dork] Scanning government TLD: .${tld}`);
      const findings = await this.dorkByTLD(tld, options);
      allFindings.push(...findings);
      await sleep(5000);
    }

    return allFindings;
  }

  /**
   * Run custom dork query
   */
  async customDork(query, options = {}) {
    logger.info(`[Dork] Custom dork: ${query}`);
    return this._executeDork({ query, description: 'Custom dork', severity: 'info' }, options);
  }

  /**
   * Execute a single dork query across search engines
   */
  async _executeDork(dork, options = {}) {
    const results = [];

    for (const engine of this.searchEngines) {
      try {
        const engineResults = await this._searchEngine(engine, dork.query, options);
        results.push(...engineResults);
      } catch (error) {
        logger.debug(`[Dork] ${engine} error: ${error.message}`);
      }
      await sleep(1000);
    }

    return unique(results, 'url');
  }

  /**
   * Search using specific engine
   */
  async _searchEngine(engine, query, options = {}) {
    switch (engine) {
      case 'google': return this._searchGoogle(query, options);
      case 'bing': return this._searchBing(query, options);
      case 'duckduckgo': return this._searchDuckDuckGo(query, options);
      default: return [];
    }
  }

  /**
   * Google search (via scraping with proxy)
   */
  async _searchGoogle(query, options = {}) {
    const results = [];
    const pages = options.pages || 3;

    for (let page = 0; page < pages; page++) {
      const start = page * 10;
      const url = `https://www.google.com/search?q=${encodeURIComponent(query)}&start=${start}&num=10`;

      try {
        let response;
        if (this.useProxy) {
          response = await this.proxyRotator.request(url, {
            timeout: this.timeout,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.5',
            },
          });
        } else {
          response = await httpGet(url, { timeout: this.timeout });
        }

        if (response.status === 200) {
          const extracted = this._extractGoogleResults(response.data);
          results.push(...extracted);
        } else if (response.status === 429) {
          logger.warn('[Dork] Google rate limited, rotating proxy...');
          this.proxyRotator.rotate();
          await sleep(10000);
        }
      } catch (error) {
        logger.debug(`[Dork] Google page ${page} error: ${error.message}`);
      }

      await sleep(2000 + Math.random() * 3000);
    }

    return results;
  }

  /**
   * Bing search
   */
  async _searchBing(query, options = {}) {
    const results = [];
    const url = `https://www.bing.com/search?q=${encodeURIComponent(query)}&count=50`;

    try {
      let response;
      if (this.useProxy) {
        response = await this.proxyRotator.request(url, { timeout: this.timeout });
      } else {
        response = await httpGet(url, { timeout: this.timeout });
      }

      if (response.status === 200) {
        const extracted = this._extractBingResults(response.data);
        results.push(...extracted);
      }
    } catch (error) {
      logger.debug(`[Dork] Bing error: ${error.message}`);
    }

    return results;
  }

  /**
   * DuckDuckGo search (more lenient with scraping)
   */
  async _searchDuckDuckGo(query, options = {}) {
    const results = [];
    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;

    try {
      let response;
      if (this.useProxy) {
        response = await this.proxyRotator.request(url, { timeout: this.timeout });
      } else {
        response = await httpGet(url, { timeout: this.timeout });
      }

      if (response.status === 200) {
        const extracted = this._extractDDGResults(response.data);
        results.push(...extracted);
      }
    } catch (error) {
      logger.debug(`[Dork] DuckDuckGo error: ${error.message}`);
    }

    return results;
  }

  /**
   * Extract results from Google HTML
   */
  _extractGoogleResults(html) {
    if (!html || typeof html !== 'string') return [];
    const results = [];

    // Extract URLs from Google results
    const urlPatterns = [
      /href="\/url\?q=([^&"]+)/g,
      /data-href="([^"]+)"/g,
      /<a href="(https?:\/\/[^"]+)"[^>]*class="[^"]*"/g,
    ];

    for (const pattern of urlPatterns) {
      let match;
      while ((match = pattern.exec(html)) !== null) {
        let url = decodeURIComponent(match[1]);
        if (url.startsWith('http') && !url.includes('google.com') && !url.includes('googleapis.com')) {
          results.push({ url, source: 'google' });
        }
      }
    }

    // Also extract from cite tags
    const citePattern = /<cite[^>]*>([^<]+)<\/cite>/g;
    let citeMatch;
    while ((citeMatch = citePattern.exec(html)) !== null) {
      const cite = citeMatch[1].replace(/<[^>]+>/g, '').trim();
      if (cite.startsWith('http')) {
        results.push({ url: cite, source: 'google' });
      }
    }

    return results;
  }

  /**
   * Extract results from Bing HTML
   */
  _extractBingResults(html) {
    if (!html || typeof html !== 'string') return [];
    const results = [];

    const pattern = /<a[^>]*href="(https?:\/\/[^"]+)"[^>]*>/g;
    let match;
    while ((match = pattern.exec(html)) !== null) {
      const url = match[1];
      if (!url.includes('bing.com') && !url.includes('microsoft.com') && !url.includes('msn.com')) {
        results.push({ url, source: 'bing' });
      }
    }

    return results;
  }

  /**
   * Extract results from DuckDuckGo HTML
   */
  _extractDDGResults(html) {
    if (!html || typeof html !== 'string') return [];
    const results = [];

    const pattern = /class="result__url"[^>]*href="([^"]+)"/g;
    let match;
    while ((match = pattern.exec(html)) !== null) {
      let url = match[1];
      if (!url.startsWith('http')) url = `https://${url}`;
      results.push({ url, source: 'duckduckgo' });
    }

    // Alternative pattern
    const altPattern = /class="result__a"[^>]*href="([^"]+)"/g;
    while ((match = altPattern.exec(html)) !== null) {
      let url = match[1];
      if (url.startsWith('//duckduckgo.com/l/?')) {
        const uddg = new URLSearchParams(url.split('?')[1]).get('uddg');
        if (uddg) url = decodeURIComponent(uddg);
      }
      if (url.startsWith('http')) {
        results.push({ url, source: 'duckduckgo' });
      }
    }

    return results;
  }

  /**
   * Get dorks for a specific category
   */
  _getDorksForCategory(category, target) {
    const siteFilter = target.startsWith('site:') ? target : `site:${target}`;

    const dorkDB = {
      sensitive_files: [
        { query: `${siteFilter} ext:env OR ext:yml OR ext:yaml "password"`, description: 'Environment/config files with passwords', severity: 'critical' },
        { query: `${siteFilter} ext:sql OR ext:db OR ext:sqlite`, description: 'Database files exposed', severity: 'critical' },
        { query: `${siteFilter} ext:log "error" OR "warning" OR "fatal"`, description: 'Log files with errors', severity: 'high' },
        { query: `${siteFilter} ext:bak OR ext:backup OR ext:old OR ext:temp`, description: 'Backup files', severity: 'high' },
        { query: `${siteFilter} ext:conf OR ext:cfg OR ext:ini`, description: 'Configuration files', severity: 'high' },
        { query: `${siteFilter} filetype:pdf "confidential" OR "internal" OR "restricted"`, description: 'Confidential documents', severity: 'medium' },
        { query: `${siteFilter} ext:key OR ext:pem OR ext:crt`, description: 'SSL/SSH keys exposed', severity: 'critical' },
        { query: `${siteFilter} ext:json "api_key" OR "apikey" OR "secret"`, description: 'JSON files with secrets', severity: 'critical' },
      ],
      admin_panels: [
        { query: `${siteFilter} inurl:admin OR inurl:administrator OR inurl:panel`, description: 'Admin panels', severity: 'medium' },
        { query: `${siteFilter} inurl:login OR inurl:signin OR inurl:auth`, description: 'Login pages', severity: 'low' },
        { query: `${siteFilter} intitle:"admin" OR intitle:"dashboard" OR intitle:"panel"`, description: 'Admin dashboards', severity: 'medium' },
        { query: `${siteFilter} inurl:cpanel OR inurl:whm OR inurl:webmail`, description: 'cPanel/WHM access', severity: 'high' },
        { query: `${siteFilter} inurl:phpmyadmin OR inurl:adminer OR inurl:dbadmin`, description: 'Database admin panels', severity: 'critical' },
        { query: `${siteFilter} inurl:wp-admin OR inurl:wp-login`, description: 'WordPress admin', severity: 'medium' },
        { query: `${siteFilter} inurl:manager OR inurl:console`, description: 'Management consoles', severity: 'medium' },
      ],
      login_pages: [
        { query: `${siteFilter} inurl:login intitle:"login"`, description: 'Login pages', severity: 'info' },
        { query: `${siteFilter} inurl:signup OR inurl:register`, description: 'Registration pages', severity: 'info' },
        { query: `${siteFilter} inurl:forgot OR inurl:reset "password"`, description: 'Password reset pages', severity: 'low' },
        { query: `${siteFilter} inurl:oauth OR inurl:sso`, description: 'OAuth/SSO endpoints', severity: 'medium' },
      ],
      exposed_data: [
        { query: `${siteFilter} "index of" OR "directory listing"`, description: 'Directory listings', severity: 'high' },
        { query: `${siteFilter} ext:xls OR ext:xlsx OR ext:csv "password" OR "username"`, description: 'Spreadsheets with credentials', severity: 'critical' },
        { query: `${siteFilter} "phpinfo()" OR "PHP Version"`, description: 'PHP info pages', severity: 'medium' },
        { query: `${siteFilter} inurl:".git" OR inurl:".svn"`, description: 'Version control exposed', severity: 'critical' },
        { query: `${siteFilter} "server at" "port" intitle:index.of`, description: 'Server info disclosure', severity: 'medium' },
        { query: `${siteFilter} "DB_PASSWORD" OR "DB_USERNAME" OR "MYSQL_ROOT_PASSWORD"`, description: 'Database credentials in source', severity: 'critical' },
        { query: `${siteFilter} "AWS_ACCESS_KEY" OR "AWS_SECRET" OR "AKIA"`, description: 'AWS credentials exposed', severity: 'critical' },
      ],
      sql_errors: [
        { query: `${siteFilter} "SQL syntax" OR "mysql_fetch" OR "mysql_num_rows"`, description: 'MySQL errors', severity: 'high' },
        { query: `${siteFilter} "PostgreSQL" "ERROR" OR "pg_query"`, description: 'PostgreSQL errors', severity: 'high' },
        { query: `${siteFilter} "ORA-" OR "Oracle error"`, description: 'Oracle errors', severity: 'high' },
        { query: `${siteFilter} "Microsoft OLE DB" OR "ODBC SQL Server"`, description: 'MSSQL errors', severity: 'high' },
        { query: `${siteFilter} "SQLite" "error" OR "sqlite3"`, description: 'SQLite errors', severity: 'high' },
        { query: `${siteFilter} "Warning:" "mysql_" OR "mysqli_"`, description: 'PHP MySQL warnings', severity: 'high' },
        { query: `${siteFilter} inurl:id= OR inurl:pid= OR inurl:uid=`, description: 'Potential SQLi parameters', severity: 'medium' },
      ],
      directory_listing: [
        { query: `${siteFilter} intitle:"index of" "parent directory"`, description: 'Apache directory listing', severity: 'high' },
        { query: `${siteFilter} intitle:"index of" "last modified"`, description: 'Directory listing with dates', severity: 'high' },
        { query: `${siteFilter} intitle:"index of" ext:php OR ext:asp OR ext:jsp`, description: 'Script files in directory listing', severity: 'high' },
        { query: `${siteFilter} intitle:"index of" "backup" OR "dump" OR "sql"`, description: 'Backup files in directory listing', severity: 'critical' },
      ],
      config_files: [
        { query: `${siteFilter} inurl:web.config OR inurl:.htaccess`, description: 'Web server config files', severity: 'high' },
        { query: `${siteFilter} inurl:wp-config.php OR inurl:configuration.php`, description: 'CMS config files', severity: 'critical' },
        { query: `${siteFilter} inurl:config.php OR inurl:settings.php OR inurl:database.php`, description: 'PHP config files', severity: 'critical' },
        { query: `${siteFilter} "define('DB_" OR "define('MYSQL_"`, description: 'Database constants in source', severity: 'critical' },
        { query: `${siteFilter} ext:xml "password" OR "passwd" OR "credentials"`, description: 'XML files with credentials', severity: 'high' },
      ],
      backup_files: [
        { query: `${siteFilter} ext:zip OR ext:tar OR ext:gz OR ext:rar "backup"`, description: 'Compressed backup files', severity: 'high' },
        { query: `${siteFilter} ext:sql "INSERT INTO" OR "CREATE TABLE"`, description: 'SQL dump files', severity: 'critical' },
        { query: `${siteFilter} inurl:backup OR inurl:bak OR inurl:old`, description: 'Backup directories', severity: 'high' },
        { query: `${siteFilter} ext:php.bak OR ext:php.old OR ext:php.save`, description: 'PHP backup files', severity: 'high' },
      ],
      api_endpoints: [
        { query: `${siteFilter} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:rest`, description: 'API endpoints', severity: 'medium' },
        { query: `${siteFilter} inurl:swagger OR inurl:api-docs OR inurl:openapi`, description: 'API documentation', severity: 'medium' },
        { query: `${siteFilter} inurl:graphql OR inurl:graphiql`, description: 'GraphQL endpoints', severity: 'medium' },
        { query: `${siteFilter} ext:json inurl:api "token" OR "key"`, description: 'API tokens in JSON', severity: 'high' },
        { query: `${siteFilter} inurl:wsdl OR inurl:asmx`, description: 'SOAP/Web service endpoints', severity: 'medium' },
      ],
      vulnerable_params: [
        { query: `${siteFilter} inurl:"id=" OR inurl:"page=" OR inurl:"file="`, description: 'Common injectable parameters', severity: 'medium' },
        { query: `${siteFilter} inurl:"redirect=" OR inurl:"url=" OR inurl:"next="`, description: 'Open redirect parameters', severity: 'medium' },
        { query: `${siteFilter} inurl:"search=" OR inurl:"query=" OR inurl:"q="`, description: 'Search parameters (XSS)', severity: 'medium' },
        { query: `${siteFilter} inurl:"file=" OR inurl:"path=" OR inurl:"include="`, description: 'File inclusion parameters', severity: 'high' },
        { query: `${siteFilter} inurl:"cmd=" OR inurl:"exec=" OR inurl:"command="`, description: 'Command injection parameters', severity: 'critical' },
        { query: `${siteFilter} inurl:"upload" OR inurl:"import" ext:php`, description: 'File upload endpoints', severity: 'high' },
        { query: `${siteFilter} inurl:"download" "file=" OR "path="`, description: 'File download (path traversal)', severity: 'high' },
      ],
      information_disclosure: [
        { query: `${siteFilter} "powered by" OR "running" OR "version"`, description: 'Version disclosure', severity: 'low' },
        { query: `${siteFilter} "error" "stack trace" OR "traceback"`, description: 'Stack traces', severity: 'medium' },
        { query: `${siteFilter} "debug" "true" OR "mode" "development"`, description: 'Debug mode enabled', severity: 'high' },
        { query: `${siteFilter} intitle:"phpMyAdmin" OR intitle:"Adminer"`, description: 'Database management tools', severity: 'critical' },
        { query: `${siteFilter} "not for distribution" OR "internal use only"`, description: 'Internal documents', severity: 'medium' },
        { query: `${siteFilter} inurl:server-status OR inurl:server-info`, description: 'Apache server status', severity: 'medium' },
        { query: `${siteFilter} inurl:elmah.axd OR inurl:trace.axd`, description: 'ASP.NET error logs', severity: 'high' },
      ],
    };

    return dorkDB[category] || [];
  }

  /**
   * Get all available dork categories
   */
  getCategories() {
    return [
      'sensitive_files', 'admin_panels', 'login_pages',
      'exposed_data', 'sql_errors', 'directory_listing',
      'config_files', 'backup_files', 'api_endpoints',
      'vulnerable_params', 'information_disclosure',
    ];
  }

  /**
   * Get all available TLDs for dorking
   */
  getAvailableTLDs() {
    return {
      indonesia: ['id', 'go.id', 'ac.id', 'co.id', 'or.id', 'web.id', 'sch.id'],
      government: ['gov', 'gov.id', 'go.id', 'gov.my', 'gov.sg', 'gov.ph', 'gov.au', 'gov.uk', 'gov.in'],
      education: ['edu', 'ac.id', 'edu.my', 'edu.sg', 'ac.uk', 'edu.au'],
      commercial: ['com', 'co.id', 'com.my', 'com.sg', 'co.uk', 'com.au'],
      organization: ['org', 'or.id', 'org.my', 'org.sg', 'org.uk'],
      military: ['mil', 'mil.id'],
      network: ['net', 'net.id'],
      asia: ['id', 'my', 'sg', 'th', 'ph', 'vn', 'in', 'jp', 'kr', 'cn', 'tw', 'hk'],
      europe: ['uk', 'de', 'fr', 'it', 'es', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk', 'fi'],
      americas: ['us', 'ca', 'mx', 'br', 'ar', 'co', 'cl', 'pe'],
    };
  }

  /**
   * Save results to file
   */
  saveResults(filename = null) {
    const file = filename || join(config.paths.output, `dork-results-${Date.now()}.json`);
    saveResults(file, {
      timestamp: new Date().toISOString(),
      totalFindings: this.results.length,
      findings: this.results,
    });
    logger.success(`[Dork] Results saved to: ${file}`);
    return file;
  }
}

export default DorkEngine;
