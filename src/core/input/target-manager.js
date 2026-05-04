import { URLParser } from './url-parser.js';
import { ScopeValidator } from './scope-validator.js';
import { generateId, saveResults, loadLines } from '../../utils/helpers.js';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import config from '../../../config/default.js';

/**
 * Target Manager - Manages all scan targets
 */
export class TargetManager {
  constructor(options = {}) {
    this.targets = new Map();
    this.scope = new ScopeValidator(options.scope || {});
    this.dataFile = join(config.paths.data, 'targets.json');
    this._loadSaved();
  }

  /**
   * Add a single target
   */
  addTarget(input, metadata = {}) {
    if (!URLParser.isValid(input)) {
      return { success: false, error: `Invalid target: ${input}` };
    }

    const parsed = URLParser.parse(input);
    if (!parsed) return { success: false, error: `Cannot parse: ${input}` };

    const id = generateId('TGT');
    const target = {
      id,
      url: parsed.full,
      hostname: parsed.hostname,
      domain: parsed.domain,
      subdomain: parsed.subdomain,
      port: parsed.port,
      protocol: parsed.protocol,
      path: parsed.path,
      params: parsed.params,
      isIP: parsed.isIP,
      isWildcard: parsed.isWildcard || false,
      status: 'pending',
      technologies: [],
      headers: {},
      responseCode: null,
      vulnerabilities: [],
      tags: metadata.tags || [],
      notes: metadata.notes || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastScannedAt: null,
    };

    this.targets.set(id, target);
    return { success: true, target };
  }

  /**
   * Add multiple targets from various sources
   */
  addTargets(inputs) {
    const results = { added: [], failed: [] };
    const list = Array.isArray(inputs) ? inputs : inputs.split(',').map(s => s.trim());

    for (const input of list) {
      if (!input) continue;
      const result = this.addTarget(input);
      if (result.success) {
        results.added.push(result.target);
      } else {
        results.failed.push({ input, error: result.error });
      }
    }
    return results;
  }

  /**
   * Import targets from file
   */
  importFromFile(filePath) {
    if (!existsSync(filePath)) {
      return { success: false, error: `File not found: ${filePath}` };
    }

    const ext = filePath.toLowerCase().split('.').pop();
    let targets = [];

    if (ext === 'json') {
      try {
        const data = JSON.parse(readFileSync(filePath, 'utf-8'));
        targets = Array.isArray(data) ? data : [data];
        targets = targets.map(t => typeof t === 'string' ? t : (t.url || t.target || t.host));
      } catch (e) {
        return { success: false, error: `JSON parse error: ${e.message}` };
      }
    } else {
      // TXT, CSV (first column), or any line-based format
      targets = loadLines(filePath);
      if (ext === 'csv') {
        targets = targets.map(line => line.split(',')[0].trim());
      }
    }

    return this.addTargets(targets.filter(Boolean));
  }

  /**
   * Import from stdin data
   */
  importFromStdin(data) {
    const lines = data.split('\n').map(l => l.trim()).filter(Boolean);
    return this.addTargets(lines);
  }

  /**
   * Get all targets
   */
  getAll(filter = {}) {
    let targets = [...this.targets.values()];

    if (filter.status) targets = targets.filter(t => t.status === filter.status);
    if (filter.domain) targets = targets.filter(t => t.domain === filter.domain);
    if (filter.tag) targets = targets.filter(t => t.tags.includes(filter.tag));

    return targets;
  }

  /**
   * Get target by ID
   */
  getById(id) {
    return this.targets.get(id) || null;
  }

  /**
   * Update target
   */
  updateTarget(id, updates) {
    const target = this.targets.get(id);
    if (!target) return null;

    Object.assign(target, updates, { updatedAt: new Date().toISOString() });
    this.targets.set(id, target);
    return target;
  }

  /**
   * Update target status
   */
  setStatus(id, status) {
    return this.updateTarget(id, { status });
  }

  /**
   * Add vulnerability to target
   */
  addVulnerability(targetId, vulnerability) {
    const target = this.targets.get(targetId);
    if (!target) return null;
    target.vulnerabilities.push(vulnerability);
    target.updatedAt = new Date().toISOString();
    return target;
  }

  /**
   * Get targets grouped by domain
   */
  groupByDomain() {
    const groups = {};
    for (const target of this.targets.values()) {
      if (!groups[target.domain]) groups[target.domain] = [];
      groups[target.domain].push(target);
    }
    return groups;
  }

  /**
   * Get statistics
   */
  getStats() {
    const targets = [...this.targets.values()];
    return {
      total: targets.length,
      pending: targets.filter(t => t.status === 'pending').length,
      scanning: targets.filter(t => t.status === 'scanning').length,
      completed: targets.filter(t => t.status === 'completed').length,
      error: targets.filter(t => t.status === 'error').length,
      domains: new Set(targets.map(t => t.domain)).size,
      vulnerabilities: targets.reduce((sum, t) => sum + t.vulnerabilities.length, 0),
    };
  }

  /**
   * Save targets to file
   */
  save() {
    const data = [...this.targets.values()];
    saveResults(this.dataFile, data);
  }

  /**
   * Load saved targets
   */
  _loadSaved() {
    if (existsSync(this.dataFile)) {
      try {
        const data = JSON.parse(readFileSync(this.dataFile, 'utf-8'));
        for (const target of data) {
          this.targets.set(target.id, target);
        }
      } catch { /* ignore */ }
    }
  }

  /**
   * Clear all targets
   */
  clear() {
    this.targets.clear();
  }

  /**
   * Remove target
   */
  remove(id) {
    return this.targets.delete(id);
  }

  /**
   * Get pending targets for scanning
   */
  getPending(limit = 10) {
    return [...this.targets.values()]
      .filter(t => t.status === 'pending')
      .slice(0, limit);
  }
}

export default TargetManager;
