import { AIScanner } from '../../core/ai/ai-scanner.js';
import { interactiveSetup, quickSetup } from '../../core/ai/ai-setup.js';
import { WebScanner } from '../../core/hunter/web/web-scanner.js';
import { TechFingerprinter } from '../../core/recon/tech-fingerprint.js';
import { httpGet } from '../../utils/http-client.js';
import { PoCReport } from '../../core/poc/poc-report.js';
import logger from '../../utils/logger.js';
import { saveResults, formatDuration } from '../../utils/helpers.js';
import { join } from 'path';
import config from '../../../config/default.js';

/**
 * Handle AI command - AI-assisted vulnerability scanning
 */
export async function handleAI(options) {
  // Step 1: Setup AI (interactive or from env)
  let aiConfig = quickSetup({ provider: options.provider });

  if (!aiConfig) {
    // Interactive setup if no config
    aiConfig = await interactiveSetup();
    if (!aiConfig) {
      logger.error('AI setup cancelled. Cannot proceed without AI configuration.');
      return;
    }
  }

  const ai = new AIScanner(aiConfig);
  logger.success(`[AI] Connected to ${aiConfig.provider} (${aiConfig.model})`);

  // Route to sub-command
  if (options.analyze) {
    await handleAnalyzeFindings(ai, options);
  } else if (options.suggest) {
    await handleSuggest(ai, options);
  } else if (options.report) {
    await handleEnhanceReport(ai, options);
  } else if (options.target) {
    await handleAIScan(ai, options);
  } else {
    logger.info('\nAI Commands:');
    logger.info('  --target <url>     AI-assisted full scan');
    logger.info('  --analyze <file>   Analyze existing findings');
    logger.info('  --suggest <url>    Suggest attack vectors');
    logger.info('  --report <id>      Enhance PoC report with AI');
  }
}

/**
 * AI-Assisted Full Scan
 */
async function handleAIScan(ai, options) {
  const target = options.target;
  const startTime = Date.now();

  logger.info(`\n[AI SCAN] Target: ${target}`);
  logger.divider();

  // Phase 1: Gather target info
  logger.info('[Phase 1] Gathering target information...');
  const response = await httpGet(target, { timeout: 10000 });
  const fingerprinter = new TechFingerprinter();
  const technologies = await fingerprinter.fingerprint(target);

  logger.info(`  Technologies: ${technologies.map(t => t.name).join(', ') || 'unknown'}`);

  // Phase 2: AI Pre-scan Analysis
  logger.info('[Phase 2] AI analyzing target...');
  const analysis = await ai.preScanAnalysis(target, {
    server: response.headers?.server,
    headers: response.headers,
    technologies,
    status: response.status,
    bodySnippet: typeof response.data === 'string' ? response.data.substring(0, 500) : '',
  });

  if (analysis) {
    logger.success('[AI] Attack plan generated:');
    if (analysis.attack_priority) {
      analysis.attack_priority.forEach((a, i) => {
        logger.info(`  ${i + 1}. [${a.likelihood}] ${a.vuln_type} - ${a.reason}`);
        if (a.payloads?.length) logger.debug(`     Payloads: ${a.payloads.slice(0, 2).join(', ')}`);
      });
    }
    if (analysis.waf_detected && analysis.waf_detected !== 'none') {
      logger.warn(`  WAF Detected: ${analysis.waf_detected}`);
      logger.info(`  Bypass Strategy: ${analysis.bypass_strategy}`);
    }
    if (analysis.hidden_endpoints?.length) {
      logger.info(`  Hidden endpoints to test: ${analysis.hidden_endpoints.join(', ')}`);
    }
  }

  // Phase 3: Standard vulnerability scan
  logger.info('\n[Phase 3] Running vulnerability scan...');
  const scanner = new WebScanner({ timeout: 10000 });
  const findings = await scanner.scan(target);

  // Phase 4: AI-enhanced payload generation for blocked params
  if (analysis?.waf_detected && analysis.waf_detected !== 'none') {
    logger.info('\n[Phase 4] AI generating WAF bypass payloads...');
    // Get smart payloads for each attack type
    for (const attack of (analysis.attack_priority || []).slice(0, 3)) {
      const smartPayloads = await ai.generateSmartPayloads({
        vulnType: attack.vuln_type,
        url: target,
        parameter: attack.test_params?.[0] || 'id',
        waf: analysis.waf_detected,
        technology: technologies[0]?.name,
        blockedPayloads: [],
      });
      if (smartPayloads.length > 0) {
        logger.info(`  [${attack.vuln_type}] Generated ${smartPayloads.length} bypass payloads`);
      }
    }
  }

  // Phase 5: AI analysis of findings
  if (findings.length > 0) {
    logger.info('\n[Phase 5] AI analyzing findings...');
    for (const finding of findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 5)) {
      const deepAnalysis = await ai.analyzeAndExploit(finding);
      if (deepAnalysis) {
        finding.aiAnalysis = deepAnalysis;
        finding.aiEnhancedImpact = deepAnalysis.real_impact;
        finding.aiBountyEstimate = deepAnalysis.bounty_estimate;
        if (deepAnalysis.report_title) finding.title = deepAnalysis.report_title;
      }
    }

    // Chain discovery
    if (findings.length >= 2) {
      const chains = await ai.findChains(findings);
      if (chains?.chains?.length) {
        logger.success(`\n[AI] Vulnerability chains discovered:`);
        chains.chains.forEach(c => {
          logger.vuln('critical', `  Chain: ${c.name} → ${c.combined_impact}`);
        });
      }
    }
  }

  // Phase 6: Generate PoC Report
  const elapsed = Date.now() - startTime;
  logger.divider();

  const poc = new PoCReport();
  poc.printToConsole(findings, { url: target });

  const reportResult = poc.generateReport(findings, { url: target, technologies });

  // AI-enhanced report for top finding
  if (findings.length > 0 && findings[0].severity !== 'info') {
    logger.info('\n[AI] Generating enhanced report for top finding...');
    const enhancedReport = await ai.enhanceReport(findings[0]);
    if (enhancedReport) {
      const aiReportFile = join(config.paths.output, `ai-report-${Date.now()}.md`);
      saveResults(aiReportFile, typeof enhancedReport === 'string' ? enhancedReport : JSON.stringify(enhancedReport, null, 2));
      logger.success(`[AI] Enhanced report: ${aiReportFile}`);
    }
  }

  // Summary
  logger.divider();
  logger.success(`\n  AI SCAN COMPLETE | Duration: ${formatDuration(elapsed)}`);
  logger.info(`  Provider: ${ai.getInfo().provider} (${ai.getInfo().model})`);
  logger.info(`  Findings: ${findings.length}`);
  if (reportResult) logger.success(`  Report: ${reportResult.filepath}`);
  logger.divider();
}

/**
 * Analyze existing findings with AI
 */
async function handleAnalyzeFindings(ai, options) {
  const { readFileSync } = await import('fs');
  try {
    const data = JSON.parse(readFileSync(options.analyze, 'utf-8'));
    const findings = data.findings || data;

    logger.info(`[AI] Analyzing ${findings.length} findings...`);

    for (const finding of findings.filter(f => f.severity === 'critical' || f.severity === 'high')) {
      const analysis = await ai.analyzeAndExploit(finding);
      if (analysis) {
        logger.vuln(finding.severity, `\n  ${finding.type} in ${finding.parameter}:`);
        logger.info(`    Impact: ${analysis.real_impact}`);
        logger.info(`    CVSS: ${analysis.cvss_score}`);
        logger.info(`    Bounty: ${analysis.bounty_estimate}`);
        if (analysis.chain_with?.length) {
          logger.info(`    Chain with: ${analysis.chain_with.join(', ')}`);
        }
      }
    }
  } catch (e) {
    logger.error(`Cannot read findings file: ${e.message}`);
  }
}

/**
 * AI suggest attack vectors for target
 */
async function handleSuggest(ai, options) {
  const target = options.suggest || options.target;
  if (!target) {
    logger.error('Please specify target with --suggest <url>');
    return;
  }

  logger.info(`[AI] Discovering hidden attack surface for: ${target}`);
  const fingerprinter = new TechFingerprinter();
  const technologies = await fingerprinter.fingerprint(target);

  const surface = await ai.discoverHiddenSurface(target, technologies);
  if (surface) {
    logger.success('\n[AI] Hidden Attack Surface:');
    if (surface.hidden_endpoints?.length) {
      logger.info('\n  Endpoints to test:');
      surface.hidden_endpoints.forEach(e => logger.info(`    ${e.method || 'GET'} ${e.path} → ${e.test_for}`));
    }
    if (surface.hidden_parameters?.length) {
      logger.info('\n  Hidden parameters:');
      surface.hidden_parameters.forEach(p => logger.info(`    ${p.name} (${p.where}) → ${p.test_for}`));
    }
    if (surface.business_logic_flaws?.length) {
      logger.info('\n  Business logic tests:');
      surface.business_logic_flaws.forEach(f => logger.info(`    • ${f}`));
    }
  }
}

/**
 * Enhance report with AI
 */
async function handleEnhanceReport(ai, options) {
  logger.info('[AI] Enhancing report...');
  // This would load a finding by ID and generate enhanced report
  logger.info('Use: node src/cli/index.js ai --target <url> for full AI scan');
}

export default handleAI;
