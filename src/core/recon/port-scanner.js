import net from 'net';
import { RateLimiter } from '../../utils/rate-limiter.js';
import logger from '../../utils/logger.js';

/**
 * Port Scanner - TCP port scanning with service detection
 */
export class PortScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 3000;
    this.rateLimiter = new RateLimiter(options.rateLimit || 100, options.concurrent || 50);
    this.results = [];
  }

  /**
   * Scan specific ports on a host
   */
  async scan(host, ports = null, options = {}) {
    const portsToScan = ports || this.getTopPorts();
    logger.info(`Scanning ${portsToScan.length} ports on ${host}...`);

    const results = [];
    const batchSize = 100;

    for (let i = 0; i < portsToScan.length; i += batchSize) {
      const batch = portsToScan.slice(i, i + batchSize);
      const batchResults = await Promise.allSettled(
        batch.map(port => this.rateLimiter.execute(() => this._scanPort(host, port)))
      );

      for (const result of batchResults) {
        if (result.status === 'fulfilled' && result.value.open) {
          results.push(result.value);
          logger.success(`${host}:${result.value.port} - OPEN (${result.value.service || 'unknown'})`);
        }
      }
      logger.progress(Math.min(i + batchSize, portsToScan.length), portsToScan.length, `Scanning ${host}`);
    }

    // Banner grabbing for open ports
    if (options.bannerGrab !== false) {
      for (const result of results) {
        const banner = await this._grabBanner(host, result.port);
        if (banner) {
          result.banner = banner;
          result.service = this._identifyService(result.port, banner);
          result.version = this._extractVersion(banner);
        }
      }
    }

    this.results = results;
    return results;
  }

  /**
   * Scan a single port
   */
  async _scanPort(host, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(this.timeout);

      socket.on('connect', () => {
        socket.destroy();
        resolve({
          host,
          port,
          open: true,
          service: this._getDefaultService(port),
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ host, port, open: false });
      });

      socket.on('error', () => {
        socket.destroy();
        resolve({ host, port, open: false });
      });

      socket.connect(port, host);
    });
  }

  /**
   * Grab banner from service
   */
  async _grabBanner(host, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(3000);
      let data = '';

      socket.on('connect', () => {
        // Send probe for HTTP services
        if ([80, 443, 8080, 8443, 8000, 3000, 5000].includes(port)) {
          socket.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
        } else {
          // Wait for banner
          setTimeout(() => {
            if (!data) socket.write('\r\n');
          }, 1000);
        }
      });

      socket.on('data', (chunk) => {
        data += chunk.toString();
        if (data.length > 1024) {
          socket.destroy();
          resolve(data.substring(0, 1024));
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(data || null);
      });

      socket.on('error', () => {
        socket.destroy();
        resolve(data || null);
      });

      socket.on('end', () => {
        resolve(data || null);
      });

      socket.connect(port, host);
    });
  }

  /**
   * Identify service from banner
   */
  _identifyService(port, banner) {
    if (!banner) return this._getDefaultService(port);

    const lower = banner.toLowerCase();
    if (lower.includes('ssh')) return 'ssh';
    if (lower.includes('ftp')) return 'ftp';
    if (lower.includes('smtp')) return 'smtp';
    if (lower.includes('http')) return port === 443 || port === 8443 ? 'https' : 'http';
    if (lower.includes('mysql')) return 'mysql';
    if (lower.includes('postgresql')) return 'postgresql';
    if (lower.includes('redis')) return 'redis';
    if (lower.includes('mongodb')) return 'mongodb';
    if (lower.includes('nginx')) return 'http/nginx';
    if (lower.includes('apache')) return 'http/apache';
    if (lower.includes('iis')) return 'http/iis';

    return this._getDefaultService(port);
  }

  /**
   * Extract version from banner
   */
  _extractVersion(banner) {
    if (!banner) return null;
    const patterns = [
      /(?:nginx|apache|iis)\/([0-9.]+)/i,
      /(?:ssh|openssh)[_-]([0-9.]+)/i,
      /(?:mysql|mariadb)\s*([0-9.]+)/i,
      /(?:redis)\s*v?=?([0-9.]+)/i,
      /server:\s*\S+\/([0-9.]+)/i,
    ];

    for (const pattern of patterns) {
      const match = banner.match(pattern);
      if (match) return match[1];
    }
    return null;
  }

  /**
   * Get default service name for common ports
   */
  _getDefaultService(port) {
    const services = {
      21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
      80: 'http', 110: 'pop3', 111: 'rpc', 135: 'msrpc', 139: 'netbios',
      143: 'imap', 443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
      1433: 'mssql', 1521: 'oracle', 2049: 'nfs', 3306: 'mysql',
      3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
      8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt',
      9090: 'http-mgmt', 27017: 'mongodb', 11211: 'memcached',
    };
    return services[port] || 'unknown';
  }

  /**
   * Get top ports for scanning
   */
  getTopPorts(count = 100) {
    const topPorts = [
      80, 443, 8080, 8443, 21, 22, 23, 25, 53, 110, 111, 135, 139, 143,
      445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
      8000, 8008, 8888, 9090, 9443, 27017, 11211, 2083, 2087, 2096,
      3000, 3001, 4443, 5000, 5001, 5601, 7001, 7002, 8001, 8081,
      8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
      8181, 8880, 8888, 9000, 9001, 9200, 9300, 9443, 10000, 10443,
      4848, 6080, 6443, 7443, 7070, 7071, 8880, 8983, 9043, 9060,
      49152, 49153, 49154, 49155, 49156, 49157, 1080, 1443, 2222,
      4000, 4001, 4040, 4443, 4444, 5555, 6000, 6001, 6666, 7000,
      7777, 8002, 8003, 8004, 8005, 8006, 8007, 8009, 8010, 8011,
    ];
    return topPorts.slice(0, count);
  }

  /**
   * Get web-specific ports
   */
  getWebPorts() {
    return [80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 5000, 5001,
            9090, 9443, 4443, 2083, 2087, 8880, 8008, 4848, 7001, 8181];
  }
}

export default PortScanner;
