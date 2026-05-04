import axios from 'axios';
import logger from '../../utils/logger.js';
import { generateId } from '../../utils/helpers.js';

/**
 * AI-Assisted Vulnerability Scanner
 * Integrates with DeepSeek, OpenAI, Claude, Groq, Gemini
 * 
 * Capabilities:
 * - Analyze target & suggest attack vectors
 * - Generate smart WAF-bypass payloads
 * - Analyze findings & suggest exploitation chains
 * - Write professional PoC reports
 * - Identify business logic vulnerabilities
 * - Suggest hidden parameters & endpoints
 */
export class AIScanner {
  constructor(options = {}) {
    this.provider = options.provider || process.env.AI_PROVIDER || 'deepseek';
    this.apiKey = options.apiKey || process.env.AI_API_KEY || '';
    this.model = options.model || process.env.AI_MODEL || this._getDefaultModel();
    this.timeout = options.timeout || 60000;
    this.maxTokens = options.maxTokens || 4096;
    this.temperature = options.temperature || 0.2;
  }

  _getDefaultModel() {
    const models = {
      deepseek: 'deepseek-chat',
      openai: 'gpt-4o-mini',
      claude: 'claude-3-5-sonnet-20241022',
      groq: 'llama-3.1-70b-versatile',
      gemini: 'gemini-1.5-flash',
    };
    return models[this.provider] || 'deepseek-chat';
  }

  _getBaseUrl() {
    const urls = {
      deepseek: 'https://api.deepseek.com/v1',
      openai: 'https://api.openai.com/v1',
      claude: 'https://api.anthropic.com/v1',
      groq: 'https://api.groq.com/openai/v1',
      gemini: 'https://generativelanguage.googleapis.com/v1beta',
    };
    return urls[this.provider] || urls.deepseek;
  }

  /**
   * Check if AI is available
   */
  isAvailable() {
    return !!this.apiKey;
  }

  /**
   * PHASE 1: Pre-scan Analysis
   * Analyze target before scanning to prioritize attack vectors
   */
  async preScanAnalysis(url, responseData = {}) {
    if (!this.isAvailable()) return null;
    logger.info(`[AI/${this.provider}] Analyzing target: ${url}`);

    const prompt = `You are an elite bug bounty hunter. Analyze this web target and provide a prioritized attack plan.

TARGET: ${url}
SERVER: ${responseData.server || 'unknown'}
HEADERS: ${JSON.stringify(responseData.headers || {}, null, 2).substring(0, 1000)}
TECHNOLOGIES: ${JSON.stringify(responseData.technologies || [], null, 2)}
STATUS CODE: ${responseData.status || 'unknown'}
BODY SNIPPET: ${(responseData.bodySnippet || '').substring(0, 500)}

Analyze and return JSON:
{
  "attack_priority": [
    {"vuln_type": "sqli|xss|ssrf|lfi|idor|ssti|rce|auth_bypass|etc", "likelihood": "high|medium|low", "reason": "why this is likely", "test_params": ["param1","param2"], "payloads": ["payload1","payload2","payload3"]}
  ],
  "hidden_endpoints": ["/api/admin", "/debug", "etc"],
  "hidden_params": ["debug", "admin", "test", "etc"],
  "waf_detected": "cloudflare|aws|none|etc",
  "bypass_strategy": "description of bypass approach",
  "business_logic_tests": ["test1", "test2"],
  "technology_cves": [{"tech": "name", "cve": "CVE-xxx", "severity": "critical"}]
}`;

    const result = await this._chat(prompt);
    if (result) {
      logger.success(`[AI] Analysis complete - ${result.attack_priority?.length || 0} attack vectors identified`);
    }
    return result;
  }

  /**
   * PHASE 2: Smart Payload Generation
   * Generate context-aware payloads that bypass WAF
   */
  async generateSmartPayloads(context) {
    if (!this.isAvailable()) return [];
    logger.info(`[AI/${this.provider}] Generating smart payloads for ${context.vulnType}`);

    const prompt = `You are a WAF bypass expert. Generate 15 advanced ${context.vulnType} payloads.

CONTEXT:
- URL: ${context.url}
- Parameter: ${context.parameter}
- Injection point: ${context.injectionContext || 'unknown'} (html|attribute|javascript|url)
- WAF: ${context.waf || 'unknown'}
- Technology: ${context.technology || 'unknown'}
- What was blocked: ${JSON.stringify(context.blockedPayloads || [])}

REQUIREMENTS:
- Must bypass the WAF using encoding, obfuscation, or alternative syntax
- Each payload uses a DIFFERENT bypass technique
- Include: encoding bypass, case manipulation, comment injection, alternative tags/functions, unicode, null bytes, double encoding
- For XSS: use uncommon event handlers, SVG, MathML, mutation XSS
- For SQLi: use inline comments, scientific notation, hex encoding, alternative functions
- For SSTI: use alternative object chains, filter bypass
- For LFI: use wrappers, encoding, null bytes, path normalization tricks

Return ONLY a JSON array of payload strings. No explanation.`;

    const result = await this._chat(prompt);
    if (Array.isArray(result)) return result;
    try {
      if (typeof result === 'string') return JSON.parse(result);
    } catch {}
    return [];
  }

  /**
   * PHASE 3: Finding Analysis & Exploitation
   * Analyze confirmed findings for deeper exploitation
   */
  async analyzeAndExploit(finding) {
    if (!this.isAvailable()) return null;
    logger.info(`[AI/${this.provider}] Deep analysis: ${finding.type} in ${finding.parameter}`);

    const prompt = `You are an expert exploit developer. A vulnerability has been confirmed. Provide deep exploitation analysis.

CONFIRMED VULNERABILITY:
- Type: ${finding.type}
- URL: ${finding.url}
- Parameter: ${finding.parameter}
- Payload that worked: ${finding.payload}
- Evidence: ${finding.evidence}
- Technology: ${finding.technology || 'unknown'}

Provide JSON:
{
  "is_exploitable": true/false,
  "real_impact": "what an attacker can actually achieve",
  "exploitation_steps": ["step1", "step2", "step3"],
  "advanced_payloads": ["more dangerous payload 1", "payload 2"],
  "data_extraction": "how to extract sensitive data",
  "privilege_escalation": "how to escalate from this vuln",
  "chain_with": ["other vulns that can be chained"],
  "max_impact_poc": {
    "description": "most impactful PoC",
    "curl_command": "curl ...",
    "expected_result": "what happens"
  },
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/...",
  "bounty_estimate": "$500-$2000",
  "report_title": "Professional title for bug bounty report",
  "report_summary": "2-3 sentence summary for report"
}`;

    return this._chat(prompt);
  }

  /**
   * PHASE 4: Vulnerability Chain Discovery
   * Find ways to chain multiple vulnerabilities
   */
  async findChains(findings) {
    if (!this.isAvailable() || findings.length < 2) return null;

    const prompt = `You are a vulnerability chaining expert. Analyze these findings and identify exploitation chains.

FINDINGS:
${JSON.stringify(findings.map(f => ({ type: f.type, url: f.url, parameter: f.parameter, severity: f.severity })), null, 2)}

Identify:
1. Which vulnerabilities can be chained together?
2. What is the combined impact?
3. Step-by-step chain exploitation
4. How does chaining increase severity/bounty?

Return JSON:
{
  "chains": [
    {
      "name": "Chain name",
      "steps": ["vuln1 -> vuln2 -> impact"],
      "combined_severity": "critical",
      "combined_impact": "Full account takeover",
      "exploitation": ["step1", "step2", "step3"],
      "bounty_multiplier": "2-3x higher than individual"
    }
  ]
}`;

    return this._chat(prompt);
  }

  /**
   * PHASE 5: Report Enhancement
   * Generate professional bug bounty report
   */
  async enhanceReport(finding) {
    if (!this.isAvailable()) return null;

    const prompt = `You are a top bug bounty hunter who writes reports that always get maximum payouts. Write a professional vulnerability report.

FINDING:
- Type: ${finding.type}
- Severity: ${finding.severity}
- URL: ${finding.url}
- Parameter: ${finding.parameter}
- Payload: ${finding.payload}
- Evidence: ${finding.evidence}

Write a complete bug bounty report in Markdown format with:
1. Title (impactful, clear)
2. Summary (2-3 sentences, emphasize business impact)
3. Severity justification with CVSS
4. Detailed Steps to Reproduce (numbered, clear)
5. Proof of Concept (curl command, HTTP request/response)
6. Impact (real-world attack scenario, what data is at risk)
7. Remediation (specific, actionable)
8. References

Make it persuasive and professional. Emphasize BUSINESS IMPACT.`;

    const result = await this._chat(prompt);
    return typeof result === 'string' ? result : JSON.stringify(result, null, 2);
  }

  /**
   * PHASE 6: Suggest Hidden Attack Surface
   * Discover endpoints and params that scanners might miss
   */
  async discoverHiddenSurface(url, technologies = []) {
    if (!this.isAvailable()) return null;

    const prompt = `Based on the technology stack, suggest hidden attack surfaces that automated scanners typically miss.

TARGET: ${url}
TECHNOLOGIES: ${technologies.map(t => t.name).join(', ')}

Suggest JSON:
{
  "hidden_endpoints": [
    {"path": "/path", "method": "GET|POST", "reason": "why this might exist", "test_for": "vuln type"}
  ],
  "hidden_parameters": [
    {"name": "param", "where": "query|body|header|cookie", "test_for": "vuln type"}
  ],
  "api_patterns": ["/api/v1/users/{id}", "/api/internal/debug"],
  "common_misconfigs": ["description of likely misconfiguration"],
  "business_logic_flaws": ["potential business logic issue to test"]
}`;

    return this._chat(prompt);
  }

  /**
   * Core chat function - routes to correct provider
   */
  async _chat(prompt) {
    try {
      if (this.provider === 'claude') return this._chatClaude(prompt);
      if (this.provider === 'gemini') return this._chatGemini(prompt);
      return this._chatOpenAICompatible(prompt);
    } catch (error) {
      logger.debug(`[AI/${this.provider}] Error: ${error.message}`);
      return null;
    }
  }

  /**
   * OpenAI-compatible API (DeepSeek, OpenAI, Groq)
   */
  async _chatOpenAICompatible(prompt) {
    const response = await axios.post(
      `${this._getBaseUrl()}/chat/completions`,
      {
        model: this.model,
        messages: [
          {
            role: 'system',
            content: 'You are an elite penetration tester and bug bounty hunter with 10+ years experience. You specialize in finding critical vulnerabilities. Always respond with valid JSON when the user asks for JSON format. Be precise and technical.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: this.temperature,
        max_tokens: this.maxTokens,
      },
      {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: this.timeout,
      }
    );

    const content = response.data?.choices?.[0]?.message?.content;
    return this._parseResponse(content);
  }

  /**
   * Claude API
   */
  async _chatClaude(prompt) {
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: this.model,
        max_tokens: this.maxTokens,
        system: 'You are an elite penetration tester. Always respond with valid JSON when asked. Be precise.',
        messages: [{ role: 'user', content: prompt }],
      },
      {
        headers: {
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json',
        },
        timeout: this.timeout,
      }
    );

    const content = response.data?.content?.[0]?.text;
    return this._parseResponse(content);
  }

  /**
   * Gemini API
   */
  async _chatGemini(prompt) {
    const response = await axios.post(
      `${this._getBaseUrl()}/models/${this.model}:generateContent?key=${this.apiKey}`,
      {
        contents: [{ parts: [{ text: `You are an elite penetration tester. ${prompt}` }] }],
        generationConfig: { temperature: this.temperature, maxOutputTokens: this.maxTokens },
      },
      { timeout: this.timeout }
    );

    const content = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    return this._parseResponse(content);
  }

  /**
   * Parse AI response - extract JSON if present
   */
  _parseResponse(content) {
    if (!content) return null;

    // Try direct JSON parse
    try { return JSON.parse(content); } catch {}

    // Try extracting JSON from markdown code block
    const jsonBlock = content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/);
    if (jsonBlock) {
      try { return JSON.parse(jsonBlock[1]); } catch {}
    }

    // Try finding JSON object/array in text
    const jsonMatch = content.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
    if (jsonMatch) {
      try { return JSON.parse(jsonMatch[1]); } catch {}
    }

    // Return raw text
    return content;
  }

  /**
   * Get provider info
   */
  getInfo() {
    return {
      provider: this.provider,
      model: this.model,
      available: this.isAvailable(),
    };
  }
}

export default AIScanner;
