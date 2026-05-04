import { WebScanner } from './hunter/web/web-scanner.js';
import { AdvancedScanner } from './hunter/web/advanced-scanner.js';
import { InfraScanner } from './hunter/infra/infra-scanner.js';
import { AuthScanner } from './hunter/auth/auth-scanner.js';
import { SubdomainEnumerator } from './recon/subdomain-enum.js';
import { PortScanner } from './recon/port-scanner.js';
import { TechFingerprinter } from './recon/tech-fingerprint.js';
import { ProxyRotator } from './proxy/proxy-rotator.js';
import { AIScanner } from './ai/ai-scanner.js';
import { PoCReport } from './poc/poc-report.js';
import { TargetManager } from './input/target-manager.js';
import { URLParser } from './input/url-parser.js';
import { httpGet } from '../utils/http-client.js';
import logger from '../utils/logger.js';
import { formatDuration, saveResults } from '../utils/helpers.js';
import { join } from 'path';
import config from '../../config/default.js';

/**
 * Master Orchestrator
 * Coordinates all scanning modules and produces final PoC report
 */
export class Orchestrator {
  constructor(options = {}) {
    this.options = options;
    this.targetManager = new TargetManager();
    this.pocReport = new PoCReport(options);
    this.proxyRotator = options.useProxy ? new ProxyRotator(options.proxy) : null;
    this.ai = new AIScanner({ provider: options.ai || process.env.AI_PROVIDER });
    this.findings = [];
    this.technologies = [];
  }

  /**
   * Full scan pipeline: Recon → Fingerprint → Hunt → PoC Report
   */
  async fullScan(targets, options = {}) {
    const startTime = Date.now();

    logger.banner();
    logger.info('Starting Full Vulnerability Scan...');
    logger.divider();

    // Parse targets
    const targetList = Array.isArray(targets) ? targets : [targets];
    for (const t of targetList) {
      this.targetManager.addTarget(t);
    }

    const allTargets = this.targetManager.getAll();
    logger.info(`Targets: ${allTargets.length}`);

    // Initialize proxy if needed
    if (this.proxyRotator) {
      logger.info('[Proxy] Initializing proxy pool...');
      await this.proxyRotator.initialize();
      logger.success(`[Proxy] Ready: ${this.proxyRotator.getStats().working} proxies`);
    }

    // Process each target
    for (const target of allTargets) {
      logger.divider();
      logger.info(`\n>>> SCANNING: ${target.url}\n`);
      this.targetManager.setStatus(target.id, 'scanning');

      try {
        // Phase 1: Reconnaissance
        if (options.recon !== false) {
          await this._runRecon(target, options);
        }

        // Phase 2: Technology Fingerprinting
        logger.info('[Phase 2] Technology Fingerprinting...');
        const fingerprinter = new TechFingerprinter();
        this.technologies = await fingerprinter.fingerprint(target.url);
        if (this.technologies.length > 0) {
          logger.success(`  Technologies: ${this.technologies.map(t => t.name + (t.version ? '/' + t.version : '')).join(', ')}`);
        }

        // Phase 2.5: AI Pre-Scan Analysis (if AI available)
        let aiAnalysis = null;
        if (this.ai.isAvailable()) {
          logger.info('[AI] Running pre-scan analysis...');
          try {
            const baseResp = await httpGet(target.url, { timeout: 8000 });
            aiAnalysis = await this.ai.preScanAnalysis(target.url, {
              server: baseResp.headers?.server,
              headers: baseResp.headers,
              technologies: this.technologies,
              status: baseResp.status,
              bodySnippet: typeof baseResp.data === 'string' ? baseResp.data.substring(0, 500) : '',
            });
            if (aiAnalysis?.attack_priority) {
              logger.success(`[AI] ${aiAnalysis.attack_priority.length} attack vectors identified`);
              aiAnalysis.attack_priority.slice(0, 3).forEach(a => {
                logger.info(`  [AI] [${a.likelihood}] ${a.vuln_type} - ${a.reason}`);
              });
            }
          } catch (e) {
            logger.debug(`[AI] Pre-scan error: ${e.message}`);
          }
        }

        // Phase 3: Vulnerability Scanning
        logger.info('[Phase 3] Vulnerability Scanning (All Categories)...');
        const webScanner = new WebScanner({
          timeout: options.timeout || 10000,
          safe: options.safe || false,
          deep: options.deep || false,
        });

        const webFindings = await webScanner.scan(target.url, options);
        this.findings.push(...webFindings);

        // Phase 4: Advanced Web Scanning (JWT, CSRF, Cache Poison, Smuggling, etc.)
        logger.info('[Phase 4] Advanced Vulnerability Scanning...');
        try {
          const advScanner = new AdvancedScanner({ timeout: options.timeout || 10000 });
          const advFindings = await advScanner.scanAll(target.url, options);
          this.findings.push(...advFindings);
          if (advFindings.length > 0) {
            logger.success(`  Advanced scan found ${advFindings.length} additional issues`);
          }
        } catch (e) {
          logger.debug(`  Advanced scan error: ${e.message}`);
        }

        // Phase 5: Infrastructure Scanning (exposed panels, files, services)
        logger.info('[Phase 5] Infrastructure Exposure Scanning...');
        try {
          const infraScanner = new InfraScanner({ timeout: options.timeout || 8000 });
          const infraFindings = await infraScanner.scanAll(target.url, options);
          this.findings.push(...infraFindings);
          if (infraFindings.length > 0) {
            logger.success(`  Infrastructure scan found ${infraFindings.length} exposures`);
          }
        } catch (e) {
          logger.debug(`  Infra scan error: ${e.message}`);
        }

        // Phase 6: Authentication & Authorization Scanning
        logger.info('[Phase 6] Auth & Access Control Scanning...');
        try {
          const authScanner = new AuthScanner({ timeout: options.timeout || 10000 });
          const authFindings = await authScanner.scanAll(target.url, options);
          this.findings.push(...authFindings);
          if (authFindings.length > 0) {
            logger.success(`  Auth scan found ${authFindings.length} issues`);
          }
        } catch (e) {
          logger.debug(`  Auth scan error: ${e.message}`);
        }

        // Update target
        this.targetManager.setStatus(target.id, 'completed');
        this.targetManager.updateTarget(target.id, {
          technologies: this.technologies,
          lastScannedAt: new Date().toISOString(),
        });

      } catch (error) {
        logger.error(`Error scanning ${target.url}: ${error.message}`);
        this.targetManager.setStatus(target.id, 'error');
      }
    }

    // Phase 7: AI Post-Scan Analysis (if AI available and findings exist)
    if (this.ai.isAvailable() && this.findings.length > 0) {
      logger.info('\n[AI] Post-scan analysis...');
      try {
        // Analyze top findings
        const criticalFindings = this.findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 5);
        for (const finding of criticalFindings) {
          const analysis = await this.ai.analyzeAndExploit(finding);
          if (analysis) {
            finding.aiAnalysis = analysis;
            if (analysis.bounty_estimate) finding.bountyEstimate = analysis.bounty_estimate;
            if (analysis.report_title) finding.title = analysis.report_title;
            if (analysis.real_impact) finding.aiImpact = analysis.real_impact;
          }
        }

        // Find vulnerability chains
        if (this.findings.length >= 2) {
          const chains = await this.ai.findChains(this.findings);
          if (chains?.chains?.length) {
            logger.success(`[AI] ${chains.chains.length} vulnerability chain(s) discovered!`);
            chains.chains.forEach(c => logger.vuln('critical', `  Chain: ${c.name} → ${c.combined_impact}`));
          }
        }
      } catch (e) {
        logger.debug(`[AI] Post-scan error: ${e.message}`);
      }
    }

    // Final Phase: Generate PoC Report
    const elapsed = Date.now() - startTime;
    logger.divider();
    logger.info(`\n[REPORT] Generating Proof of Concept Report...`);

    // Print PoC to console
    this.pocReport.printToConsole(this.findings, { url: targetList.join(', ') });

    // Save report files
    const reportResult = this.pocReport.generateReport(this.findings, {
      url: targetList.join(', '),
      technologies: this.technologies,
    });

    // Save JSON results
    const jsonFile = join(config.paths.output, `scan-results-${Date.now()}.json`);
    saveResults(jsonFile, {
      scanInfo: {
        timestamp: new Date().toISOString(),
        duration: formatDuration(elapsed),
        targets: targetList,
        options,
      },
      summary: {
        totalFindings: this.findings.length,
        critical: this.findings.filter(f => f.severity === 'critical').length,
        high: this.findings.filter(f => f.severity === 'high').length,
        medium: this.findings.filter(f => f.severity === 'medium').length,
        low: this.findings.filter(f => f.severity === 'low').length,
        info: this.findings.filter(f => f.severity === 'info').length,
      },
      technologies: this.technologies,
      findings: this.findings,
    });

    // Final summary
    logger.divider();
    logger.success(`\n  SCAN COMPLETE | Duration: ${formatDuration(elapsed)}`);
    logger.info(`  Total Findings: ${this.findings.length}`);
    if (reportResult) {
      logger.success(`  PoC Report: ${reportResult.filepath}`);
    }
    logger.success(`  JSON Results: ${jsonFile}`);
    logger.divider();

    this.targetManager.save();
    return { findings: this.findings, report: reportResult, jsonFile };
  }

  /**
   * Run reconnaissance phase
   */
  async _runRecon(target, options) {
    const parsed = URLParser.parse(target.url);
    if (!parsed) return;

    logger.info('[Phase 1] Reconnaissance...');

    // Subdomain enumeration (only for domains, not IPs)
    if (!parsed.isIP && options.subdomains !== false) {
      try {
        logger.info('  [Subdomains] Enumerating...');
        const subEnum = new SubdomainEnumerator({ rateLimit: 5 });
        const subs = await subEnum.passiveEnum(parsed.domain);
        if (subs.length > 0) {
          logger.success(`  [Subdomains] Found ${subs.length} subdomains`);
          // Add discovered subdomains as targets
          for (const sub of subs.slice(0, 20)) { // Limit to top 20
            this.targetManager.addTarget(`https://${sub}`);
          }
        }
      } catch (e) {
        logger.debug(`  [Subdomains] Error: ${e.message}`);
      }
    }

    // Port scanning
    if (options.ports !== false) {
      try {
        logger.info('  [Ports] Scanning web ports...');
        const portScanner = new PortScanner({ timeout: 2000 });
        const host = parsed.hostname;
        const openPorts = await portScanner.scan(host, portScanner.getWebPorts().slice(0, 10));
        if (openPorts.length > 0) {
          logger.success(`  [Ports] Open: ${openPorts.map(p => `${p.port}/${p.service}`).join(', ')}`);
        }
      } catch (e) {
        logger.debug(`  [Ports] Error: ${e.message}`);
      }
    }
  }
}

export default Orchestrator;
