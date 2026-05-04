#!/usr/bin/env node

import { Command } from 'commander';
import logger from '../utils/logger.js';
import config from '../../config/default.js';

const program = new Command();

program
  .name('recon-tool')
  .description('Powerful Bug Bounty Toolkit with Live CVE & Proxy Support')
  .version(config.version);

// ============================================
// SCAN Command - Full vulnerability scan
// ============================================
program
  .command('scan')
  .description('Full vulnerability scan on target(s)')
  .option('-t, --target <urls...>', 'Target URL(s) to scan')
  .option('-f, --file <path>', 'Import targets from file')
  .option('--stdin', 'Read targets from stdin')
  .option('--scope <path>', 'Scope configuration file')
  .option('--exclude <patterns...>', 'Exclude patterns')
  .option('--threads <number>', 'Concurrent threads', '10')
  .option('--timeout <ms>', 'Request timeout in ms', '10000')
  .option('--proxy', 'Use proxy rotation (auto-fetch from ProxyScrape)')
  .option('--proxy-file <path>', 'Custom proxy list file')
  .option('--safe', 'Safe mode - no destructive tests')
  .option('-o, --output <path>', 'Output file path')
  .option('--format <type>', 'Output format (json|csv|html|pdf)', 'json')
  .option('-v, --verbose', 'Verbose output')
  .action(async (options) => {
    const { handleScan } = await import('./commands/scan.js');
    await handleScan(options);
  });

// ============================================
// RECON Command - Reconnaissance
// ============================================
program
  .command('recon')
  .description('Reconnaissance on target (subdomain, ports, tech, etc.)')
  .option('-t, --target <domain>', 'Target domain')
  .option('--full', 'Full reconnaissance')
  .option('--quick', 'Quick recon (subdomain + tech only)')
  .option('--modules <list>', 'Specific modules: subdomain,ports,tech,dns,dirs,waf,crawl')
  .option('--active', 'Include active enumeration (DNS bruteforce)')
  .option('--proxy', 'Use proxy rotation')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handleRecon } = await import('./commands/recon.js');
    await handleRecon(options);
  });

// ============================================
// HUNT Command - Bug hunting
// ============================================
program
  .command('hunt')
  .description('Hunt for vulnerabilities (XSS, SQLi, SSRF, etc.)')
  .option('-t, --target <url>', 'Target URL')
  .option('--types <list>', 'Vulnerability types: xss,sqli,ssrf,redirect,cors,headers,auth,lfi,idor,ssti')
  .option('--full', 'Test all vulnerability types')
  .option('--deep', 'Deep scan with more payloads')
  .option('--safe', 'Safe mode')
  .option('--proxy', 'Use proxy rotation')
  .option('--engine <type>', 'Scan engine: node, python, both', 'node')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handleHunt } = await import('./commands/hunt.js');
    await handleHunt(options);
  });

// ============================================
// DORK Command - Google dorking
// ============================================
program
  .command('dork')
  .description('Google dorking for bug bounty targets')
  .option('-t, --target <domain>', 'Target domain or TLD')
  .option('--tld <tld>', 'Target TLD (id, gov, edu, etc.)')
  .option('--indonesia', 'Dork all Indonesian TLDs (.id, .go.id, .ac.id, etc.)')
  .option('--government', 'Dork all government TLDs')
  .option('--categories <list>', 'Dork categories: sensitive_files,admin_panels,sql_errors,etc.')
  .option('--custom <query>', 'Custom dork query')
  .option('--proxy', 'Use proxy rotation (recommended)')
  .option('--pages <number>', 'Number of search pages per dork', '3')
  .option('--engines <list>', 'Search engines: google,bing,duckduckgo', 'google,bing,duckduckgo')
  .option('--delay <ms>', 'Delay between requests in ms', '3000')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handleDork } = await import('./commands/dork.js');
    await handleDork(options);
  });

// ============================================
// CVE Command - Live CVE scanning
// ============================================
program
  .command('cve')
  .description('Live CVE scanning and matching')
  .option('-t, --target <url>', 'Target URL')
  .option('--id <cveId>', 'Search specific CVE ID')
  .option('--tech <technology>', 'Search CVEs for technology')
  .option('--recent', 'Get recent CVEs')
  .option('--severity <level>', 'Filter by severity: critical,high,medium,low')
  .option('--verify', 'Verify CVE exploitability')
  .option('--safe', 'Safe verification only')
  .option('--update', 'Update CVE database')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handleCVE } = await import('./commands/cve.js');
    await handleCVE(options);
  });

// ============================================
// PROXY Command - Proxy management
// ============================================
program
  .command('proxy')
  .description('Manage proxy pool')
  .option('--fetch', 'Fetch fresh proxies from ProxyScrape')
  .option('--validate', 'Validate/test proxies')
  .option('--list', 'List working proxies')
  .option('--count', 'Show proxy count')
  .option('--protocol <type>', 'Protocol: http, socks4, socks5', 'http')
  .option('--country <code>', 'Country code filter')
  .action(async (options) => {
    const { handleProxy } = await import('./commands/proxy.js');
    await handleProxy(options);
  });

// ============================================
// BYPASS Command - Bypass techniques
// ============================================
program
  .command('bypass')
  .description('Run bypass techniques (admin, 403, WAF, etc.)')
  .option('-t, --target <url>', 'Target URL')
  .option('--type <type>', 'Bypass type: admin, 403, waf, auth, rate-limit')
  .option('--proxy', 'Use proxy rotation')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handleBypass } = await import('./commands/bypass.js');
    await handleBypass(options);
  });

// ============================================
// POC Command - Proof of Concept generation
// ============================================
program
  .command('poc')
  .description('Generate Proof of Concept for findings')
  .option('--vuln-id <id>', 'Vulnerability ID')
  .option('--format <type>', 'PoC format: curl, python, node, nuclei, all', 'all')
  .option('--validate', 'Validate PoC still works')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handlePoC } = await import('./commands/poc.js');
    await handlePoC(options);
  });

// ============================================
// REPORT Command - Generate reports
// ============================================
program
  .command('report')
  .description('Generate vulnerability report')
  .option('--vuln-id <id>', 'Specific vulnerability ID')
  .option('--all', 'Report all findings')
  .option('--platform <name>', 'Platform format: hackerone, bugcrowd, intigriti')
  .option('--format <type>', 'Report format: md, html, pdf, json', 'md')
  .option('-o, --output <path>', 'Output file path')
  .action(async (options) => {
    const { handleReport } = await import('./commands/report.js');
    await handleReport(options);
  });

// ============================================
// AI Command - AI-assisted scanning
// ============================================
program
  .command('ai')
  .description('AI-assisted vulnerability scanning (DeepSeek/OpenAI/Claude/Groq/Gemini)')
  .option('-t, --target <url>', 'Target URL for AI scan')
  .option('--provider <name>', 'AI provider: deepseek, openai, claude, groq, gemini')
  .option('--analyze <file>', 'Analyze existing findings JSON file')
  .option('--suggest <url>', 'Suggest hidden attack surface')
  .option('--report <id>', 'Enhance report with AI')
  .option('--setup', 'Interactive AI setup (choose provider & enter key)')
  .action(async (options) => {
    if (options.setup) {
      const { interactiveSetup } = await import('../core/ai/ai-setup.js');
      await interactiveSetup();
      return;
    }
    const { handleAI } = await import('./commands/ai.js');
    await handleAI(options);
  });

// Show banner and parse
logger.banner();
program.parse(process.argv);

// Show help if no command
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
