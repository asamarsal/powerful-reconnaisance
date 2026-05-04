import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { generateId } from '../../utils/helpers.js';
import logger from '../../utils/logger.js';
import config from '../../../config/default.js';

/**
 * PoC Report Generator
 * Generates clear, professional Proof of Concept reports
 * Ready to submit to bug bounty platforms (HackerOne, Bugcrowd, etc.)
 */
export class PoCReport {
  constructor(options = {}) {
    this.outputDir = options.outputDir || config.paths.output;
    this.format = options.format || 'markdown';
  }

  /**
   * Generate full PoC report from scan findings
   */
  generateReport(findings, targetInfo = {}) {
    if (!findings || findings.length === 0) {
      logger.info('[PoC] No findings to report');
      return null;
    }

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

    const report = this._buildMarkdownReport(findings, targetInfo);
    const filename = `poc-report-${Date.now()}.md`;
    const filepath = join(this.outputDir, filename);

    if (!existsSync(this.outputDir)) mkdirSync(this.outputDir, { recursive: true });
    writeFileSync(filepath, report, 'utf-8');

    // Also generate individual PoC files for each critical/high finding
    const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    for (const finding of criticalFindings) {
      const pocFile = join(this.outputDir, `poc-${finding.id}.md`);
      writeFileSync(pocFile, this._buildIndividualPoC(finding, targetInfo), 'utf-8');
    }

    return { filepath, filename, totalFindings: findings.length, criticalCount: criticalFindings.length };
  }

  /**
   * Print PoC to console (for immediate viewing)
   */
  printToConsole(findings, targetInfo = {}) {
    if (!findings || findings.length === 0) {
      console.log('\n  No vulnerabilities found.\n');
      return;
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5));

    console.log('\n');
    console.log('╔══════════════════════════════════════════════════════════════════╗');
    console.log('║              VULNERABILITY REPORT & PROOF OF CONCEPT            ║');
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log(`║  Target  : ${(targetInfo.url || 'N/A').padEnd(52)}║`);
    console.log(`║  Date    : ${new Date().toISOString().padEnd(52)}║`);
    console.log(`║  Findings: ${String(findings.length).padEnd(52)}║`);
    console.log('╚══════════════════════════════════════════════════════════════════╝');

    // Summary
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => counts[f.severity || 'info']++);

    console.log('\n┌─── SEVERITY SUMMARY ───────────────────────────────────────────┐');
    if (counts.critical) console.log(`│  🔴 CRITICAL : ${counts.critical}`);
    if (counts.high) console.log(`│  🟠 HIGH     : ${counts.high}`);
    if (counts.medium) console.log(`│  🟡 MEDIUM   : ${counts.medium}`);
    if (counts.low) console.log(`│  🔵 LOW      : ${counts.low}`);
    if (counts.info) console.log(`│  ⚪ INFO     : ${counts.info}`);
    console.log('└────────────────────────────────────────────────────────────────┘');

    // Individual findings with PoC
    let idx = 1;
    for (const finding of findings) {
      console.log(`\n${'═'.repeat(68)}`);
      console.log(`  FINDING #${idx} | ${this._severityBadge(finding.severity)} | ${finding.type.toUpperCase()}`);
      console.log(`${'═'.repeat(68)}`);
      console.log(`\n  Title       : ${finding.title}`);
      console.log(`  Severity    : ${finding.severity.toUpperCase()}`);
      console.log(`  URL         : ${finding.url}`);
      console.log(`  Parameter   : ${finding.parameter || 'N/A'}`);
      console.log(`  CWE         : ${finding.cwe || 'N/A'}`);
      console.log(`  OWASP       : ${finding.owasp || 'N/A'}`);

      console.log(`\n  ┌─── PROOF OF CONCEPT ──────────────────────────────────────┐`);
      console.log(`  │`);
      console.log(`  │  Payload:`);
      console.log(`  │    ${finding.payload || 'N/A'}`);
      console.log(`  │`);
      console.log(`  │  Evidence:`);
      console.log(`  │    ${finding.evidence || 'N/A'}`);
      console.log(`  │`);

      if (finding.request) {
        console.log(`  │  HTTP Request:`);
        finding.request.split('\n').forEach(l => console.log(`  │    ${l}`));
        console.log(`  │`);
      }

      if (finding.response) {
        console.log(`  │  HTTP Response:`);
        finding.response.split('\n').forEach(l => console.log(`  │    ${l}`));
        console.log(`  │`);
      }

      // Generate cURL command
      const curl = this._generateCurl(finding);
      if (curl) {
        console.log(`  │  cURL Reproduction:`);
        console.log(`  │    ${curl}`);
        console.log(`  │`);
      }

      console.log(`  │  Remediation:`);
      console.log(`  │    ${finding.remediation || 'N/A'}`);
      console.log(`  │`);
      console.log(`  └──────────────────────────────────────────────────────────┘`);

      idx++;
    }

    console.log(`\n${'═'.repeat(68)}`);
    console.log('  END OF REPORT');
    console.log(`${'═'.repeat(68)}\n`);
  }

  /**
   * Build full Markdown report
   */
  _buildMarkdownReport(findings, targetInfo) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => counts[f.severity || 'info']++);

    let md = `# Vulnerability Report & Proof of Concept\n\n`;
    md += `## Target Information\n\n`;
    md += `| Field | Value |\n|-------|-------|\n`;
    md += `| Target | ${targetInfo.url || 'N/A'} |\n`;
    md += `| Date | ${new Date().toISOString()} |\n`;
    md += `| Total Findings | ${findings.length} |\n`;
    md += `| Scanner | ReconTool v1.0.0 |\n\n`;

    md += `## Severity Summary\n\n`;
    md += `| Severity | Count |\n|----------|-------|\n`;
    md += `| 🔴 Critical | ${counts.critical} |\n`;
    md += `| 🟠 High | ${counts.high} |\n`;
    md += `| 🟡 Medium | ${counts.medium} |\n`;
    md += `| 🔵 Low | ${counts.low} |\n`;
    md += `| ⚪ Info | ${counts.info} |\n\n`;

    md += `---\n\n## Findings\n\n`;

    let idx = 1;
    for (const f of findings) {
      md += `### ${idx}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
      md += `| Field | Detail |\n|-------|--------|\n`;
      md += `| ID | ${f.id} |\n`;
      md += `| Type | ${f.type} |\n`;
      md += `| Severity | ${f.severity} |\n`;
      md += `| URL | \`${f.url}\` |\n`;
      md += `| Parameter | \`${f.parameter || 'N/A'}\` |\n`;
      md += `| CWE | ${f.cwe || 'N/A'} |\n`;
      md += `| OWASP | ${f.owasp || 'N/A'} |\n\n`;

      md += `#### Proof of Concept\n\n`;
      md += `**Payload:**\n\`\`\`\n${f.payload || 'N/A'}\n\`\`\`\n\n`;
      md += `**Evidence:**\n> ${f.evidence || 'N/A'}\n\n`;

      if (f.request) {
        md += `**HTTP Request:**\n\`\`\`http\n${f.request}\n\`\`\`\n\n`;
      }
      if (f.response) {
        md += `**HTTP Response:**\n\`\`\`\n${f.response}\n\`\`\`\n\n`;
      }

      const curl = this._generateCurl(f);
      if (curl) {
        md += `**cURL Command (Reproduce):**\n\`\`\`bash\n${curl}\n\`\`\`\n\n`;
      }

      md += `#### Remediation\n\n${f.remediation || 'N/A'}\n\n`;
      md += `---\n\n`;
      idx++;
    }

    md += `## Disclaimer\n\n`;
    md += `This report was generated for authorized security testing purposes only.\n`;
    md += `All findings should be reported responsibly to the asset owner.\n`;

    return md;
  }

  /**
   * Build individual PoC for a single finding (for submission)
   */
  _buildIndividualPoC(finding, targetInfo) {
    let md = `# ${finding.title}\n\n`;
    md += `## Summary\n\n`;
    md += `A ${finding.severity} severity ${finding.type} vulnerability was found `;
    md += `in the parameter \`${finding.parameter}\` at \`${finding.url}\`.\n\n`;

    md += `## Severity\n\n`;
    md += `- **CVSS Score**: ${this._estimateCVSS(finding)}\n`;
    md += `- **Severity**: ${finding.severity.toUpperCase()}\n`;
    md += `- **CWE**: ${finding.cwe || 'N/A'}\n`;
    md += `- **OWASP**: ${finding.owasp || 'N/A'}\n\n`;

    md += `## Affected Asset\n\n`;
    md += `- **URL**: ${finding.url}\n`;
    md += `- **Parameter**: ${finding.parameter}\n`;
    md += `- **Type**: ${finding.type}\n\n`;

    md += `## Steps to Reproduce\n\n`;
    md += `1. Navigate to: \`${finding.url}\`\n`;
    md += `2. Inject the following payload in the \`${finding.parameter}\` parameter:\n`;
    md += `   \`\`\`\n   ${finding.payload}\n   \`\`\`\n`;
    md += `3. Observe the response:\n`;
    md += `   > ${finding.evidence}\n\n`;

    md += `## Proof of Concept\n\n`;
    md += `### HTTP Request\n\`\`\`http\n${finding.request || 'N/A'}\n\`\`\`\n\n`;
    md += `### HTTP Response\n\`\`\`\n${finding.response || 'N/A'}\n\`\`\`\n\n`;

    const curl = this._generateCurl(finding);
    if (curl) {
      md += `### cURL Command\n\`\`\`bash\n${curl}\n\`\`\`\n\n`;
    }

    md += `## Impact\n\n${this._describeImpact(finding)}\n\n`;
    md += `## Remediation\n\n${finding.remediation || 'N/A'}\n\n`;
    md += `## References\n\n`;
    md += `- ${finding.cwe ? `https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html` : 'N/A'}\n`;
    md += `- https://owasp.org/Top10/\n`;

    return md;
  }

  /**
   * Generate cURL command for reproduction
   */
  _generateCurl(finding) {
    if (!finding.url) return null;

    if (finding.request && finding.request.startsWith('POST')) {
      const bodyMatch = finding.request.match(/\n\n(.+)$/s);
      const body = bodyMatch ? bodyMatch[1] : finding.payload;
      return `curl -X POST "${finding.url}" \\\n  -H "Content-Type: application/xml" \\\n  -d '${body}'`;
    }

    if (finding.parameter && finding.payload && finding.parameter !== 'N/A' &&
        !finding.parameter.startsWith('Host') && !finding.parameter.startsWith('Origin') &&
        !finding.parameter.startsWith('Path') && !finding.parameter.startsWith('Response') &&
        !finding.parameter.startsWith('Server') && !finding.parameter.startsWith('X-Frame')) {

      const baseUrl = finding.url.split('?')[0];
      const encodedPayload = encodeURIComponent(finding.payload);
      return `curl -s "${baseUrl}?${finding.parameter}=${encodedPayload}"`;
    }

    if (finding.parameter && finding.parameter.startsWith('Origin')) {
      return `curl -s "${finding.url}" -H "Origin: ${finding.payload}"`;
    }

    if (finding.parameter && (finding.parameter.includes('Host') || finding.parameter.includes('Forwarded'))) {
      return `curl -s "${finding.url}" -H "Host: evil.com" -H "X-Forwarded-Host: evil.com"`;
    }

    return `curl -s "${finding.url}"`;
  }

  /**
   * Estimate CVSS score based on vulnerability type
   */
  _estimateCVSS(finding) {
    const scores = {
      'sqli-error': '9.8 (Critical)', 'sqli-time-blind': '8.6 (High)',
      'cmdi': '9.8 (Critical)', 'xxe': '9.1 (Critical)',
      'ssrf': '8.6 (High)', 'ssti': '9.8 (Critical)',
      'lfi': '8.6 (High)', 'rce': '10.0 (Critical)',
      'xss': '6.1 (Medium)', 'nosqli': '9.8 (Critical)',
      'idor': '7.5 (High)', 'open-redirect': '4.7 (Medium)',
      'cors-misconfig': '5.3 (Medium)', 'crlf': '6.1 (Medium)',
      'host-header-injection': '6.1 (Medium)', 'clickjacking': '4.3 (Medium)',
      'missing-header': '3.7 (Low)', 'info-disclosure': '2.7 (Low)',
      'directory-listing': '5.3 (Medium)', 'exposed-file': '7.5 (High)',
      'secret-leakage': '9.1 (Critical)',
    };
    return scores[finding.type] || '5.0 (Medium)';
  }

  /**
   * Describe impact based on vulnerability type
   */
  _describeImpact(finding) {
    const impacts = {
      'sqli-error': 'An attacker can extract sensitive data from the database, including user credentials, personal information, and business data. In severe cases, this can lead to full database compromise, data modification, or deletion.',
      'sqli-time-blind': 'An attacker can extract data from the database character by character. While slower than error-based SQLi, this still allows full database enumeration and data theft.',
      'cmdi': 'An attacker can execute arbitrary operating system commands on the server. This leads to full server compromise, data theft, lateral movement, and potential ransomware deployment.',
      'xxe': 'An attacker can read arbitrary files from the server, perform SSRF attacks to internal services, and potentially achieve remote code execution.',
      'ssrf': 'An attacker can make the server perform requests to internal services, potentially accessing cloud metadata, internal APIs, and sensitive infrastructure.',
      'ssti': 'An attacker can execute arbitrary code on the server through template injection, leading to full server compromise.',
      'lfi': 'An attacker can read arbitrary files from the server, including configuration files with credentials, source code, and sensitive system files.',
      'xss': 'An attacker can execute JavaScript in the context of other users, stealing session cookies, performing actions on behalf of victims, and defacing the application.',
      'nosqli': 'An attacker can bypass authentication, extract data, or modify database records through NoSQL operator injection.',
      'idor': 'An attacker can access or modify resources belonging to other users by manipulating object identifiers.',
      'open-redirect': 'An attacker can redirect users to malicious websites, facilitating phishing attacks and credential theft.',
      'cors-misconfig': 'An attacker can read sensitive data from the API cross-origin, potentially stealing user data or performing unauthorized actions.',
      'secret-leakage': 'Exposed credentials or API keys can be used to access backend services, cloud infrastructure, or third-party APIs.',
    };
    return impacts[finding.type] || 'This vulnerability may allow an attacker to compromise the security of the application or its users.';
  }

  _severityBadge(severity) {
    const badges = { critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM', low: '🔵 LOW', info: '⚪ INFO' };
    return badges[severity] || '⚪ UNKNOWN';
  }
}

export default PoCReport;
