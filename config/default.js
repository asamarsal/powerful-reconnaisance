import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { config as dotenvConfig } from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

dotenvConfig({ path: join(ROOT_DIR, '.env') });

export default {
  // Application
  appName: 'ReconTool',
  version: '1.0.0',
  rootDir: ROOT_DIR,

  // Network
  timeout: parseInt(process.env.TIMEOUT || '10000'),
  maxRetries: 3,
  maxConcurrent: parseInt(process.env.MAX_CONCURRENT_SCANS || '5'),
  maxRequestsPerSecond: parseInt(process.env.MAX_REQUESTS_PER_SECOND || '10'),

  // Proxy
  proxy: process.env.PROXY_URL || null,
  proxyListFile: process.env.PROXY_LIST_FILE || null,

  // API Keys
  keys: {
    nvd: process.env.NVD_API_KEY || '',
    shodan: process.env.SHODAN_API_KEY || '',
    github: process.env.GITHUB_TOKEN || '',
    securityTrails: process.env.SECURITYTRAILS_API_KEY || '',
    virusTotal: process.env.VIRUSTOTAL_API_KEY || '',
    hackerOne: {
      identifier: process.env.HACKERONE_API_IDENTIFIER || '',
      token: process.env.HACKERONE_API_TOKEN || '',
    },
  },

  // Server
  server: {
    port: parseInt(process.env.API_PORT || '3000'),
    host: process.env.API_HOST || '127.0.0.1',
  },

  // Paths
  paths: {
    data: join(ROOT_DIR, 'data'),
    output: join(ROOT_DIR, 'output'),
    wordlists: join(ROOT_DIR, 'config', 'wordlists'),
    payloads: join(ROOT_DIR, 'config', 'wordlists', 'payloads'),
  },

  // Scanning defaults
  scanning: {
    threads: 10,
    timeout: 10000,
    followRedirects: true,
    maxRedirects: 5,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    respectRobotsTxt: false,
    safeMode: false,
  },

  // Recon defaults
  recon: {
    subdomainWordlist: join(ROOT_DIR, 'config', 'wordlists', 'subdomains.txt'),
    dirWordlist: join(ROOT_DIR, 'config', 'wordlists', 'directories.txt'),
    topPorts: [80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 5000, 9090, 9443, 4443, 2083, 2087, 8880, 8008],
    dnsServers: ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'],
  },

  // CVE
  cve: {
    cacheTTL: 3600, // 1 hour in seconds
    maxResults: 100,
    monitorInterval: 900000, // 15 minutes
  },

  // Notifications
  notifications: {
    telegram: {
      botToken: process.env.TELEGRAM_BOT_TOKEN || '',
      chatId: process.env.TELEGRAM_CHAT_ID || '',
    },
    discord: {
      webhookUrl: process.env.DISCORD_WEBHOOK_URL || '',
    },
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
    },
  },
};
