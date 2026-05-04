import { DorkEngine } from '../../core/dorking/dork-engine.js';
import { DORK_TEMPLATES, getAvailableTypes } from '../../core/dorking/dork-templates.js';
import logger from '../../utils/logger.js';
import { saveResults } from '../../utils/helpers.js';
import { join } from 'path';
import config from '../../../config/default.js';

/**
 * Handle dork command
 */
export async function handleDork(options) {
  const engineOptions = {
    useProxy: options.proxy || false,
    proxy: { protocol: 'http' },
  };

  if (options.engines) {
    engineOptions.engines = options.engines.split(',').map(e => e.trim());
  }

  const engine = new DorkEngine(engineOptions);

  try {
    // Initialize (fetch proxies if needed)
    if (options.proxy) {
      logger.info('[Dork] Fetching proxies for stealth dorking...');
    }
    await engine.initialize();

    let findings = [];

    // Custom dork query
    if (options.custom) {
      logger.info(`[Dork] Running custom dork: ${options.custom}`);
      const results = await engine.customDork(options.custom, { pages: parseInt(options.pages) || 3 });
      findings.push({
        category: 'custom',
        dork: options.custom,
        results,
        timestamp: new Date().toISOString(),
      });
    }
    // Indonesian TLDs
    else if (options.indonesia) {
      logger.info('[Dork] Scanning all Indonesian TLDs...');
      findings = await engine.dorkIndonesia({
        pages: parseInt(options.pages) || 3,
        categories: options.categories ? options.categories.split(',') : undefined,
      });
    }
    // Government TLDs
    else if (options.government) {
      logger.info('[Dork] Scanning all Government TLDs...');
      findings = await engine.dorkGovernment({
        pages: parseInt(options.pages) || 3,
        categories: options.categories ? options.categories.split(',') : undefined,
      });
    }
    // Specific TLD
    else if (options.tld) {
      logger.info(`[Dork] Scanning TLD: .${options.tld}`);
      findings = await engine.dorkByTLD(options.tld, {
        pages: parseInt(options.pages) || 3,
        categories: options.categories ? options.categories.split(',') : undefined,
      });
    }
    // Specific target domain
    else if (options.target) {
      logger.info(`[Dork] Scanning target: ${options.target}`);
      findings = await engine.dorkTarget(options.target, {
        pages: parseInt(options.pages) || 3,
        categories: options.categories ? options.categories.split(',') : undefined,
      });
    }
    else {
      logger.error('Please specify a target (-t), TLD (--tld), --indonesia, or --government');
      logger.info('\nAvailable categories:');
      engine.getCategories().forEach(c => logger.info(`  - ${c}`));
      logger.info('\nAvailable TLDs:');
      const tlds = engine.getAvailableTLDs();
      Object.entries(tlds).forEach(([region, list]) => {
        logger.info(`  ${region}: ${list.join(', ')}`);
      });
      logger.info('\nDork types for --categories:');
      getAvailableTypes().forEach(t => logger.info(`  - ${t}`));
      return;
    }

    // Display results
    logger.divider();
    logger.success(`\nDorking complete! Found ${findings.length} findings\n`);

    // Summary by severity
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) {
      severityCounts[finding.severity || 'info']++;
    }

    logger.info('Severity Summary:');
    if (severityCounts.critical > 0) logger.vuln('critical', `  Critical: ${severityCounts.critical}`);
    if (severityCounts.high > 0) logger.vuln('high', `  High: ${severityCounts.high}`);
    if (severityCounts.medium > 0) logger.vuln('medium', `  Medium: ${severityCounts.medium}`);
    if (severityCounts.low > 0) logger.vuln('low', `  Low: ${severityCounts.low}`);
    if (severityCounts.info > 0) logger.info(`  Info: ${severityCounts.info}`);

    // Show top findings
    const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (criticalFindings.length > 0) {
      logger.divider();
      logger.info('\nTop Critical/High Findings:');
      for (const finding of criticalFindings.slice(0, 20)) {
        logger.vuln(finding.severity, `  [${finding.category}] ${finding.description || finding.dork}`);
        if (finding.results) {
          finding.results.slice(0, 3).forEach(r => logger.info(`    -> ${r.url}`));
        }
      }
    }

    // Save results
    if (options.output || findings.length > 0) {
      const outputFile = options.output || join(config.paths.output, `dork-${Date.now()}.json`);
      saveResults(outputFile, {
        timestamp: new Date().toISOString(),
        target: options.target || options.tld || 'multi-tld',
        totalFindings: findings.length,
        severitySummary: severityCounts,
        findings,
      });
      logger.success(`\nResults saved to: ${outputFile}`);
    }

  } catch (error) {
    logger.error(`Dork error: ${error.message}`);
    if (options.verbose) console.error(error);
  }
}

export default handleDork;
