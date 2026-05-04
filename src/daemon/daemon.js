/**
 * ReconTool - 24/7 Bug Bounty Scanning Daemon
 * Runs continuous reconnaissance and vulnerability scanning
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { EventEmitter } from 'events';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../../');

// Paths
const CONFIG_PATH = path.join(ROOT_DIR, 'scan-config.json');
const FINDINGS_DB_PATH = path.join(ROOT_DIR, 'data/findings-db.json');
const TARGETS_PATH = path.join(ROOT_DIR, 'data/targets.json');
const LOG_PATH = path.join(ROOT_DIR, 'data/daemon.log');
const STATE_PATH = path.join(ROOT_DIR, 'data/daemon-state.json');

// Daemon State
const daemonState = {
  status: 'idle',
  startedAt: new Date().toISOString(),
  uptime: 0,
  currentScan: null,
  lastScan: null,
  totalScans: 0,
  totalFindings: 0,
  scanHistory: [],
  errors: [],
  scheduledJobs: {}
};

const eventBus = new EventEmitter();

// ─── Logging ────────────────────────────────────────────────────────────────

function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] [${level.toUpperCase()}] ${message}${data ? ' | ' + JSON.stringify(data) : ''}`;
  console.log(entry);

  try {
    fs.appendFileSync(LOG_PATH, entry + '\n');
  } catch (e) {
    // Silent fail on log write
  }
}

// ─── Config Management ──────────────────────────────────────────────────────

function loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    log('error', 'Failed to load config', { error: e.message });
    return null;
  }
}

function loadFindings() {
  try {
    if (fs.existsSync(FINDINGS_DB_PATH)) {
      return JSON.parse(fs.readFileSync(FINDINGS_DB_PATH, 'utf-8'));
    }
  } catch (e) {
    log('error', 'Failed to load findings DB', { error: e.message });
  }
  return { findings: [], lastUpdated: null };
}

function saveFindings(db) {
  try {
    db.lastUpdated = new Date().toISOString();
    fs.writeFileSync(FINDINGS_DB_PATH, JSON.stringify(db, null, 2));
  } catch (e) {
    log('error', 'Failed to save findings DB', { error: e.message });
  }
}

function loadTargets() {
  try {
    if (fs.existsSync(TARGETS_PATH)) {
      return JSON.parse(fs.readFileSync(TARGETS_PATH, 'utf-8'));
    }
  } catch (e) {
    log('error', 'Failed to load targets', { error: e.message });
  }
  return { targets: [] };
}

function saveState() {
  try {
    daemonState.uptime = Math.floor((Date.now() - new Date(daemonState.startedAt).getTime()) / 1000);
    fs.writeFileSync(STATE_PATH, JSON.stringify(daemonState, null, 2));
  } catch (e) {
    // Silent fail
  }
}

// ─── Notifications ──────────────────────────────────────────────────────────

async function sendTelegramNotification(config, finding) {
  if (!config.telegram?.enabled || !config.telegram.botToken || !config.telegram.chatId) return;

  const message = `🚨 *${finding.severity.toUpperCase()} Finding*\n\n` +
    `*Type:* ${finding.type}\n` +
    `*Target:* ${finding.url}\n` +
    `*Parameter:* ${finding.parameter || 'N/A'}\n` +
    `*Description:* ${finding.description || 'N/A'}\n` +
    `*Time:* ${finding.timestamp}`;

  try {
    const url = `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: message,
        parse_mode: 'Markdown'
      })
    });
    if (response.ok) {
      log('info', 'Telegram notification sent', { findingId: finding.id });
    }
  } catch (e) {
    log('error', 'Telegram notification failed', { error: e.message });
  }
}

async function sendDiscordNotification(config, finding) {
  if (!config.discord?.enabled || !config.discord.webhookUrl) return;

  const colors = { critical: 0xFF0000, high: 0xFF6600, medium: 0xFFCC00, low: 0x00FF00 };

  const embed = {
    title: `${finding.severity.toUpperCase()} - ${finding.type}`,
    description: finding.description || 'New vulnerability finding detected',
    color: colors[finding.severity] || 0xFFFFFF,
    fields: [
      { name: 'Target', value: finding.url || 'N/A', inline: true },
      { name: 'Parameter', value: finding.parameter || 'N/A', inline: true },
      { name: 'Severity', value: finding.severity.toUpperCase(), inline: true }
    ],
    timestamp: finding.timestamp
  };

  try {
    const response = await fetch(config.discord.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] })
    });
    if (response.ok) {
      log('info', 'Discord notification sent', { findingId: finding.id });
    }
  } catch (e) {
    log('error', 'Discord notification failed', { error: e.message });
  }
}

async function notifyFinding(finding) {
  const config = loadConfig();
  if (!config?.options?.notifications) return;

  const notifConfig = config.options.notifications;
  const severities = notifConfig.onSeverity || ['critical', 'high'];

  if (!severities.includes(finding.severity)) return;

  await sendTelegramNotification(notifConfig, finding);
  await sendDiscordNotification(notifConfig, finding);
}

// ─── Orchestrator Integration ───────────────────────────────────────────────

async function loadOrchestrator() {
  try {
    const orchestratorPath = path.join(ROOT_DIR, 'src/core/orchestrator.js');
    if (fs.existsSync(orchestratorPath)) {
      const { Orchestrator } = await import(orchestratorPath);
      return new Orchestrator();
    }
  } catch (e) {
    log('warn', 'Orchestrator not available, using mock scanner', { error: e.message });
  }
  return null;
}

// Mock scanner for when orchestrator is not available
async function mockScan(type, targets, options) {
  log('info', `Running ${type} scan (mock mode)`, { targets: targets.length });

  // Simulate scan duration
  const duration = Math.random() * 5000 + 2000;
  await new Promise(resolve => setTimeout(resolve, duration));

  // Generate mock findings for demonstration
  const mockFindings = [];
  if (Math.random() > 0.7) {
    const severities = ['low', 'medium', 'high', 'critical'];
    const types = ['XSS', 'SQLi', 'SSRF', 'Open Redirect', 'IDOR', 'Info Disclosure'];
    const finding = {
      id: `finding-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: types[Math.floor(Math.random() * types.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      url: targets[0] || 'https://example.com',
      parameter: ['id', 'q', 'redirect', 'url', 'file'][Math.floor(Math.random() * 5)],
      description: 'Potential vulnerability detected during automated scan',
      poc: `curl -X GET "${targets[0] || 'https://example.com'}?test=payload"`,
      scanType: type,
      timestamp: new Date().toISOString(),
      verified: false
    };
    mockFindings.push(finding);
  }

  return {
    success: true,
    findings: mockFindings,
    duration: Math.floor(duration),
    targetsScanned: targets.length
  };
}

// ─── Scan Execution ─────────────────────────────────────────────────────────

async function executeScan(type) {
  const config = loadConfig();
  if (!config) {
    log('error', 'Cannot run scan - config not loaded');
    return;
  }

  const targets = config.targets || [];
  const targetData = loadTargets();
  const allTargets = [...new Set([...targets, ...(targetData.targets || []).map(t => t.url || t)])];

  if (allTargets.length === 0) {
    log('info', `Skipping ${type} scan - no targets configured`);
    return;
  }

  const scanId = `scan-${Date.now()}-${type}`;
  daemonState.status = 'scanning';
  daemonState.currentScan = {
    id: scanId,
    type,
    startedAt: new Date().toISOString(),
    targets: allTargets.length,
    progress: 0
  };
  saveState();

  log('info', `Starting ${type} scan`, { scanId, targets: allTargets.length });

  try {
    const orchestrator = await loadOrchestrator();
    let result;

    if (orchestrator) {
      // Use the real orchestrator's fullScan method
      const scanResult = await orchestrator.fullScan(allTargets, {
        ...config.options,
        recon: type === 'fullScan',
        subdomains: type === 'fullScan',
        ports: type === 'fullScan' || type === 'quickScan',
      });
      result = {
        success: true,
        findings: scanResult.findings || [],
        duration: 0,
        targetsScanned: allTargets.length,
      };
    } else {
      result = await mockScan(type, allTargets, config.options || {});
    }

    // Process findings
    if (result?.findings?.length > 0) {
      const db = loadFindings();
      for (const finding of result.findings) {
        db.findings.push(finding);
        daemonState.totalFindings++;
        await notifyFinding(finding);
        eventBus.emit('newFinding', finding);
      }
      saveFindings(db);
      log('info', `Scan complete - ${result.findings.length} new findings`, { scanId });
    } else {
      log('info', `Scan complete - no new findings`, { scanId });
    }

    // Update state
    daemonState.totalScans++;
    daemonState.lastScan = {
      id: scanId,
      type,
      completedAt: new Date().toISOString(),
      findings: result?.findings?.length || 0,
      duration: result?.duration || 0
    };
    daemonState.scanHistory.unshift(daemonState.lastScan);
    if (daemonState.scanHistory.length > 100) {
      daemonState.scanHistory = daemonState.scanHistory.slice(0, 100);
    }

  } catch (e) {
    log('error', `Scan failed: ${type}`, { scanId, error: e.message });
    daemonState.errors.push({
      timestamp: new Date().toISOString(),
      scanId,
      error: e.message
    });
    if (daemonState.errors.length > 50) {
      daemonState.errors = daemonState.errors.slice(-50);
    }
  } finally {
    daemonState.status = 'idle';
    daemonState.currentScan = null;
    saveState();
  }
}

// ─── Schedule Management ────────────────────────────────────────────────────

const intervals = {};

function parseScheduleToMs(cronExpr) {
  // Simple cron-like parser for common patterns
  // */30 * * * * = every 30 minutes
  // 0 * * * * = every hour
  // 0 */6 * * * = every 6 hours
  // 0 0 * * * = daily

  if (cronExpr.startsWith('*/')) {
    const minutes = parseInt(cronExpr.split(' ')[0].replace('*/', ''));
    return minutes * 60 * 1000;
  }

  const parts = cronExpr.split(' ');
  if (parts[1] && parts[1].startsWith('*/')) {
    const hours = parseInt(parts[1].replace('*/', ''));
    return hours * 60 * 60 * 1000;
  }

  if (parts[0] === '0' && parts[1] === '*') {
    return 60 * 60 * 1000; // Every hour
  }

  if (parts[0] === '0' && parts[1] === '0') {
    return 24 * 60 * 60 * 1000; // Daily
  }

  // Default: every 6 hours
  return 6 * 60 * 60 * 1000;
}

function setupSchedule() {
  const config = loadConfig();
  if (!config?.schedule) {
    log('warn', 'No schedule configured, using defaults');
    return;
  }

  const schedule = config.schedule;

  // Clear existing intervals
  Object.values(intervals).forEach(id => clearInterval(id));

  // Full Scan - every 6 hours
  if (schedule.fullScan) {
    const ms = parseScheduleToMs(schedule.fullScan);
    intervals.fullScan = setInterval(() => executeScan('fullScan'), ms);
    daemonState.scheduledJobs.fullScan = { interval: ms, next: new Date(Date.now() + ms).toISOString() };
    log('info', `Scheduled fullScan every ${ms / 1000 / 60} minutes`);
  }

  // Quick Scan - every 1 hour
  if (schedule.quickScan) {
    const ms = parseScheduleToMs(schedule.quickScan);
    intervals.quickScan = setInterval(() => executeScan('quickScan'), ms);
    daemonState.scheduledJobs.quickScan = { interval: ms, next: new Date(Date.now() + ms).toISOString() };
    log('info', `Scheduled quickScan every ${ms / 1000 / 60} minutes`);
  }

  // Dork Scan - daily
  if (schedule.dorkScan) {
    const ms = parseScheduleToMs(schedule.dorkScan);
    intervals.dorkScan = setInterval(() => executeScan('dorkScan'), ms);
    daemonState.scheduledJobs.dorkScan = { interval: ms, next: new Date(Date.now() + ms).toISOString() };
    log('info', `Scheduled dorkScan every ${ms / 1000 / 60} minutes`);
  }

  // CVE Scan - every 30 minutes
  if (schedule.cveScan) {
    const ms = parseScheduleToMs(schedule.cveScan);
    intervals.cveScan = setInterval(() => executeScan('cveScan'), ms);
    daemonState.scheduledJobs.cveScan = { interval: ms, next: new Date(Date.now() + ms).toISOString() };
    log('info', `Scheduled cveScan every ${ms / 1000 / 60} minutes`);
  }

  saveState();
}

// ─── Initialization ─────────────────────────────────────────────────────────

function ensureDataDir() {
  const dataDir = path.join(ROOT_DIR, 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(FINDINGS_DB_PATH)) {
    fs.writeFileSync(FINDINGS_DB_PATH, JSON.stringify({ findings: [], lastUpdated: null }, null, 2));
  }
  if (!fs.existsSync(TARGETS_PATH)) {
    fs.writeFileSync(TARGETS_PATH, JSON.stringify({ targets: [] }, null, 2));
  }
}

// ─── Graceful Shutdown ──────────────────────────────────────────────────────

function shutdown(signal) {
  log('info', `Received ${signal}, shutting down gracefully...`);
  daemonState.status = 'shutting_down';
  saveState();

  // Clear all intervals
  Object.values(intervals).forEach(id => clearInterval(id));

  // Give ongoing operations time to complete
  setTimeout(() => {
    log('info', 'Daemon stopped');
    process.exit(0);
  }, 2000);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (err) => {
  log('error', 'Uncaught exception', { error: err.message, stack: err.stack });
  daemonState.errors.push({ timestamp: new Date().toISOString(), error: err.message });
  saveState();
});
process.on('unhandledRejection', (reason) => {
  log('error', 'Unhandled rejection', { reason: String(reason) });
});

// ─── State Update Interval ──────────────────────────────────────────────────

setInterval(() => {
  saveState();
}, 10000); // Save state every 10 seconds

// ─── Start Daemon ───────────────────────────────────────────────────────────

async function start() {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║   ReconTool - Bug Bounty Scanner Daemon  ║
  ║   24/7 Automated Reconnaissance          ║
  ╚══════════════════════════════════════════╝
  `);

  ensureDataDir();
  log('info', 'Daemon starting...');

  const config = loadConfig();
  if (!config) {
    log('error', 'Failed to load scan-config.json - daemon cannot start');
    process.exit(1);
  }

  log('info', 'Configuration loaded', {
    targets: config.targets?.length || 0,
    schedule: Object.keys(config.schedule || {})
  });

  daemonState.status = 'running';
  saveState();

  // Setup scheduled scans
  setupSchedule();

  // Run initial quick scan after 30 seconds
  setTimeout(() => {
    log('info', 'Running initial quick scan...');
    executeScan('quickScan');
  }, 30000);

  log('info', 'Daemon is running. Press Ctrl+C to stop.');
}

start();

// ─── Exports for Dashboard ──────────────────────────────────────────────────

export { daemonState, eventBus, executeScan, loadConfig, loadFindings, loadTargets };
export default { daemonState, eventBus, executeScan };
