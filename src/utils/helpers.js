import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 */
export async function retry(fn, maxRetries = 3, delay = 1000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await sleep(delay * Math.pow(2, i));
    }
  }
}

/**
 * Chunk array into smaller arrays
 */
export function chunk(array, size) {
  const chunks = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Remove duplicates from array
 */
export function unique(array, key) {
  if (key) {
    const seen = new Set();
    return array.filter(item => {
      const k = typeof key === 'function' ? key(item) : item[key];
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  return [...new Set(array)];
}

/**
 * Safe JSON parse
 */
export function safeJsonParse(str, fallback = null) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

/**
 * Save results to file
 */
export function saveResults(filePath, data) {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const content = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  writeFileSync(filePath, content, 'utf-8');
}

/**
 * Load file lines (for wordlists)
 */
export function loadLines(filePath) {
  if (!existsSync(filePath)) return [];
  return readFileSync(filePath, 'utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

/**
 * Format bytes to human readable
 */
export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format duration
 */
export function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

/**
 * Generate unique ID
 */
export function generateId(prefix = 'VULN') {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 6);
  return `${prefix}-${ts}-${rand}`.toUpperCase();
}

/**
 * Encode/decode for safe payloads
 */
export function urlEncode(str) {
  return encodeURIComponent(str);
}

export function htmlEncode(str) {
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[m]);
}

export function base64Encode(str) {
  return Buffer.from(str).toString('base64');
}

export function base64Decode(str) {
  return Buffer.from(str, 'base64').toString('utf-8');
}
