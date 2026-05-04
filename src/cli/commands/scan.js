import { Orchestrator } from '../../core/orchestrator.js';
import logger from '../../utils/logger.js';

/**
 * Handle full scan command - runs ALL scanners and generates PoC
 */
export async function handleScan(options) {
  // Validate input
  if (!options.target && !options.file) {
    logger.error('Please specify target(s) with -t or -f');
    logger.info('  Example: recon-tool scan -t https://example.com');
    logger.info('  Example: recon-tool scan -t https://example.com/page?id=1');
    logger.info('  Example: recon-tool scan -f targets.txt');
    return;
  }

  // Build target list
  let targets = [];
  if (options.target) {
    targets = Array.isArray(options.target) ? options.target : [options.target];
  }

  if (options.file) {
    const { readFileSync } = await import('fs');
    try {
      const content = readFileSync(options.file, 'utf-8');
      const fileTargets = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      targets.push(...fileTargets);
    } catch (e) {
      logger.error(`Cannot read file: ${options.file} - ${e.message}`);
      return;
    }
  }

  if (targets.length === 0) {
    logger.error('No valid targets provided');
    return;
  }

  // Configure orchestrator
  const orchestrator = new Orchestrator({
    useProxy: options.proxy || false,
    outputDir: options.output ? require('path').dirname(options.output) : undefined,
  });

  // Run full scan
  const scanOptions = {
    timeout: parseInt(options.timeout) || 10000,
    safe: options.safe || false,
    deep: options.deep || false,
    recon: !options.noRecon,
    subdomains: !options.noSubdomains,
    ports: !options.noPorts,
  };

  try {
    const result = await orchestrator.fullScan(targets, scanOptions);

    if (result.findings.length === 0) {
      logger.info('\n  No vulnerabilities found. Target appears secure for tested vectors.');
      logger.info('  Consider: deeper scanning (--deep), different parameters, or authenticated testing.\n');
    }
  } catch (error) {
    logger.error(`Scan failed: ${error.message}`);
    if (options.verbose) console.error(error.stack);
  }
}

export default handleScan;
