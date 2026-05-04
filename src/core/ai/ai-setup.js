import { createInterface } from 'readline';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import axios from 'axios';
import logger from '../../utils/logger.js';

/**
 * AI Setup - Interactive setup for AI-assisted scanning
 * Allows user to choose AI provider and enter API key at startup
 */

const PROVIDERS = {
  deepseek: {
    name: 'DeepSeek',
    description: 'DeepSeek AI - Powerful & affordable (RECOMMENDED)',
    baseUrl: 'https://api.deepseek.com/v1',
    models: ['deepseek-chat', 'deepseek-reasoner'],
    defaultModel: 'deepseek-chat',
    pricing: '$0.14/1M input, $0.28/1M output',
    getKeyUrl: 'https://platform.deepseek.com/api_keys',
  },
  openai: {
    name: 'OpenAI',
    description: 'OpenAI GPT-4 - Most capable',
    baseUrl: 'https://api.openai.com/v1',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'],
    defaultModel: 'gpt-4o-mini',
    pricing: '$0.15-$5/1M tokens',
    getKeyUrl: 'https://platform.openai.com/api-keys',
  },
  claude: {
    name: 'Claude (Anthropic)',
    description: 'Claude 3.5 - Excellent reasoning',
    baseUrl: 'https://api.anthropic.com/v1',
    models: ['claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307'],
    defaultModel: 'claude-3-5-sonnet-20241022',
    pricing: '$3-$15/1M tokens',
    getKeyUrl: 'https://console.anthropic.com/settings/keys',
  },
  groq: {
    name: 'Groq',
    description: 'Groq - Ultra fast inference (FREE tier available)',
    baseUrl: 'https://api.groq.com/openai/v1',
    models: ['llama-3.1-70b-versatile', 'mixtral-8x7b-32768', 'llama-3.1-8b-instant'],
    defaultModel: 'llama-3.1-70b-versatile',
    pricing: 'FREE tier: 30 req/min',
    getKeyUrl: 'https://console.groq.com/keys',
  },
  gemini: {
    name: 'Google Gemini',
    description: 'Gemini 1.5 - Google AI',
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta',
    models: ['gemini-1.5-pro', 'gemini-1.5-flash'],
    defaultModel: 'gemini-1.5-flash',
    pricing: 'FREE tier available',
    getKeyUrl: 'https://aistudio.google.com/app/apikey',
  },
};

/**
 * Interactive AI provider selection
 */
export async function interactiveSetup() {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║          AI-ASSISTED VULNERABILITY SCANNING             ║');
  console.log('║                                                          ║');
  console.log('║  AI akan membantu:                                       ║');
  console.log('║  • Menganalisis target & suggest attack vectors          ║');
  console.log('║  • Generate smart payloads bypass WAF                    ║');
  console.log('║  • Analisis findings & suggest exploitation chain        ║');
  console.log('║  • Menulis PoC report yang lebih baik                    ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('  Pilih AI Provider:\n');

  const providerKeys = Object.keys(PROVIDERS);
  providerKeys.forEach((key, i) => {
    const p = PROVIDERS[key];
    console.log(`  [${i + 1}] ${p.name}`);
    console.log(`      ${p.description}`);
    console.log(`      Pricing: ${p.pricing}`);
    console.log(`      Get key: ${p.getKeyUrl}`);
    console.log('');
  });

  console.log(`  [0] Skip - Scan tanpa AI\n`);

  const choice = await ask('  Pilih (0-5): ');
  const choiceNum = parseInt(choice);

  if (choiceNum === 0 || isNaN(choiceNum) || choiceNum > providerKeys.length) {
    rl.close();
    console.log('\n  Scanning tanpa AI. Anda bisa setup nanti di .env\n');
    return null;
  }

  const providerKey = providerKeys[choiceNum - 1];
  const provider = PROVIDERS[providerKey];

  console.log(`\n  Provider: ${provider.name}`);
  console.log(`  Get API key di: ${provider.getKeyUrl}\n`);

  const apiKey = await ask('  Masukkan API Key: ');

  if (!apiKey || apiKey.trim().length < 10) {
    rl.close();
    console.log('\n  API key tidak valid. Scanning tanpa AI.\n');
    return null;
  }

  // Select model
  console.log(`\n  Pilih Model:`);
  provider.models.forEach((m, i) => {
    const isDefault = m === provider.defaultModel ? ' (recommended)' : '';
    console.log(`  [${i + 1}] ${m}${isDefault}`);
  });

  const modelChoice = await ask(`\n  Pilih (default: 1): `);
  const modelIdx = parseInt(modelChoice) - 1;
  const model = provider.models[modelIdx >= 0 && modelIdx < provider.models.length ? modelIdx : 0];

  rl.close();

  // Validate API key
  console.log('\n  Memvalidasi API key...');
  const valid = await validateApiKey(providerKey, apiKey.trim(), model);

  if (valid) {
    console.log('  ✅ API key valid! AI scanning aktif.\n');

    // Save to .env
    saveToEnv(providerKey, apiKey.trim(), model);

    return {
      provider: providerKey,
      apiKey: apiKey.trim(),
      model,
      baseUrl: provider.baseUrl,
    };
  } else {
    console.log('  ❌ API key tidak valid atau tidak bisa connect.');
    console.log('  Scanning akan berjalan tanpa AI.\n');
    return null;
  }
}

/**
 * Quick setup (non-interactive) - from env or args
 */
export function quickSetup(options = {}) {
  const provider = options.provider || process.env.AI_PROVIDER;
  const apiKey = options.apiKey || process.env.AI_API_KEY;
  const model = options.model || process.env.AI_MODEL;

  if (!provider || !apiKey) return null;

  const providerConfig = PROVIDERS[provider];
  if (!providerConfig) return null;

  return {
    provider,
    apiKey,
    model: model || providerConfig.defaultModel,
    baseUrl: providerConfig.baseUrl,
  };
}

/**
 * Validate API key by making a test request
 */
async function validateApiKey(provider, apiKey, model) {
  try {
    const providerConfig = PROVIDERS[provider];

    if (provider === 'claude') {
      const resp = await axios.post(
        'https://api.anthropic.com/v1/messages',
        { model, max_tokens: 10, messages: [{ role: 'user', content: 'hi' }] },
        { headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' }, timeout: 10000 }
      );
      return resp.status === 200;
    }

    if (provider === 'gemini') {
      const resp = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        { contents: [{ parts: [{ text: 'hi' }] }] },
        { timeout: 10000 }
      );
      return resp.status === 200;
    }

    // OpenAI-compatible (deepseek, openai, groq)
    const resp = await axios.post(
      `${providerConfig.baseUrl}/chat/completions`,
      { model, messages: [{ role: 'user', content: 'hi' }], max_tokens: 5 },
      { headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }, timeout: 10000 }
    );
    return resp.status === 200;
  } catch (error) {
    if (error.response?.status === 401 || error.response?.status === 403) return false;
    // Network error but key format might be valid
    return error.response?.status >= 400 && error.response?.status < 500 ? false : true;
  }
}

/**
 * Save AI config to .env file
 */
function saveToEnv(provider, apiKey, model) {
  const envPath = join(process.cwd(), '.env');
  let content = '';

  if (existsSync(envPath)) {
    content = readFileSync(envPath, 'utf-8');
    // Update existing values
    content = content.replace(/^AI_PROVIDER=.*/m, `AI_PROVIDER=${provider}`);
    content = content.replace(/^AI_API_KEY=.*/m, `AI_API_KEY=${apiKey}`);
    content = content.replace(/^AI_MODEL=.*/m, `AI_MODEL=${model}`);

    // Add if not exists
    if (!content.includes('AI_PROVIDER=')) content += `\nAI_PROVIDER=${provider}`;
    if (!content.includes('AI_API_KEY=')) content += `\nAI_API_KEY=${apiKey}`;
    if (!content.includes('AI_MODEL=')) content += `\nAI_MODEL=${model}`;
  } else {
    content = `AI_PROVIDER=${provider}\nAI_API_KEY=${apiKey}\nAI_MODEL=${model}\n`;
  }

  writeFileSync(envPath, content, 'utf-8');
  logger.debug('[AI] Config saved to .env');
}

/**
 * Get available providers info
 */
export function getProviders() {
  return PROVIDERS;
}

export default { interactiveSetup, quickSetup, getProviders };
