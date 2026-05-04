/**
 * ReconTool - Web Dashboard Server
 * Real-time monitoring and control interface
 */

import express from 'express';
import { createServer } from 'http';
import { Server as SocketIO } from 'socket.io';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '../../');

// Paths
const FINDINGS_DB_PATH = path.join(ROOT_DIR, 'data/findings-db.json');
const TARGETS_PATH = path.join(ROOT_DIR, 'data/targets.json');
const STATE_PATH = path.join(ROOT_DIR, 'data/daemon-state.json');
const CONFIG_PATH = path.join(ROOT_DIR, 'scan-config.json');
const SCAN_HISTORY_PATH = path.join(ROOT_DIR, 'data/scan-history.json');

const PORT = process.env.PORT || 4500;

// ─── Express App Setup ──────────────────────────────────────────────────────

const app = express();
const httpServer = createServer(app);
const io = new SocketIO(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Helper Functions ───────────────────────────────────────────────────────

function readJSON(filePath, defaultValue = null) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    }
  } catch (e) {
    console.error(`Error reading ${filePath}:`, e.message);
  }
  return defaultValue;
}

function writeJSON(filePath, data) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (e) {
    console.error(`Error writing ${filePath}:`, e.message);
    return false;
  }
}

function getDaemonState() {
  return readJSON(STATE_PATH, {
    status: 'unknown',
    startedAt: null,
    uptime: 0,
    currentScan: null,
    lastScan: null,
    totalScans: 0,
    totalFindings: 0,
    scanHistory: [],
    errors: []
  });
}

// ─── API Routes ─────────────────────────────────────────────────────────────

// GET /api/stats - Scan statistics
app.get('/api/stats', (req, res) => {
  const state = getDaemonState();
  const findings = readJSON(FINDINGS_DB_PATH, { findings: [] });
  const targets = readJSON(TARGETS_PATH, { targets: [] });

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (findings.findings || []).forEach(f => {
    if (severityCounts.hasOwnProperty(f.severity)) {
      severityCounts[f.severity]++;
    }
  });

  res.json({
    status: state.status,
    uptime: state.uptime,
    startedAt: state.startedAt,
    totalScans: state.totalScans,
    totalFindings: (findings.findings || []).length,
    totalTargets: (targets.targets || []).length,
    severity: severityCounts,
    lastScan: state.lastScan,
    currentScan: state.currentScan,
    scheduledJobs: state.scheduledJobs || {}
  });
});

// GET /api/findings - All findings with pagination and filtering
app.get('/api/findings', (req, res) => {
  const { page = 1, limit = 50, severity, type, search } = req.query;
  const db = readJSON(FINDINGS_DB_PATH, { findings: [] });
  let findings = db.findings || [];

  // Filter by severity
  if (severity) {
    const severities = severity.split(',');
    findings = findings.filter(f => severities.includes(f.severity));
  }

  // Filter by type
  if (type) {
    findings = findings.filter(f => f.type?.toLowerCase().includes(type.toLowerCase()));
  }

  // Search
  if (search) {
    const s = search.toLowerCase();
    findings = findings.filter(f =>
      f.url?.toLowerCase().includes(s) ||
      f.type?.toLowerCase().includes(s) ||
      f.description?.toLowerCase().includes(s) ||
      f.parameter?.toLowerCase().includes(s)
    );
  }

  // Sort by timestamp descending
  findings.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Pagination
  const total = findings.length;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const paginated = findings.slice(offset, offset + parseInt(limit));

  res.json({
    findings: paginated,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / parseInt(limit))
    }
  });
});

// GET /api/findings/:id - Single finding detail
app.get('/api/findings/:id', (req, res) => {
  const db = readJSON(FINDINGS_DB_PATH, { findings: [] });
  const finding = (db.findings || []).find(f => f.id === req.params.id);

  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  res.json(finding);
});

// GET /api/targets - All targets
app.get('/api/targets', (req, res) => {
  const data = readJSON(TARGETS_PATH, { targets: [] });
  res.json(data);
});

// POST /api/targets - Add new target
app.post('/api/targets', (req, res) => {
  const { url, name, scope, notes } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  const data = readJSON(TARGETS_PATH, { targets: [] });
  const newTarget = {
    id: randomUUID(),
    url,
    name: name || url,
    scope: scope || 'full',
    notes: notes || '',
    addedAt: new Date().toISOString(),
    lastScanned: null,
    findingsCount: 0
  };

  data.targets.push(newTarget);
  writeJSON(TARGETS_PATH, data);

  io.emit('targetAdded', newTarget);
  res.status(201).json(newTarget);
});

// DELETE /api/targets/:id - Remove target
app.delete('/api/targets/:id', (req, res) => {
  const data = readJSON(TARGETS_PATH, { targets: [] });
  const index = data.targets.findIndex(t => t.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ error: 'Target not found' });
  }

  const removed = data.targets.splice(index, 1)[0];
  writeJSON(TARGETS_PATH, data);

  io.emit('targetRemoved', { id: req.params.id });
  res.json({ message: 'Target removed', target: removed });
});

// POST /api/scan/start - Start a scan
app.post('/api/scan/start', (req, res) => {
  const { type = 'quickScan', targets } = req.body;
  const state = getDaemonState();

  if (state.status === 'scanning') {
    return res.status(409).json({ error: 'A scan is already in progress' });
  }

  // Write a trigger file for the daemon to pick up
  const triggerPath = path.join(ROOT_DIR, 'data/scan-trigger.json');
  writeJSON(triggerPath, {
    type,
    targets: targets || [],
    triggeredAt: new Date().toISOString(),
    triggeredBy: 'dashboard'
  });

  io.emit('scanStarted', { type, triggeredAt: new Date().toISOString() });
  res.json({ message: `${type} scan triggered`, type });
});

// GET /api/scan/status - Current scan status
app.get('/api/scan/status', (req, res) => {
  const state = getDaemonState();
  res.json({
    status: state.status,
    currentScan: state.currentScan,
    lastScan: state.lastScan
  });
});

// GET /api/scans/history - Scan history
app.get('/api/scans/history', (req, res) => {
  const state = getDaemonState();
  const { limit = 50 } = req.query;
  const history = (state.scanHistory || []).slice(0, parseInt(limit));
  res.json({ history, total: (state.scanHistory || []).length });
});

// GET /api/proxy/status - Proxy pool status
app.get('/api/proxy/status', (req, res) => {
  const proxyPath = path.join(ROOT_DIR, 'data/proxy-pool.json');
  const proxyData = readJSON(proxyPath, { proxies: [], lastRefreshed: null });

  res.json({
    total: proxyData.proxies?.length || 0,
    active: proxyData.proxies?.filter(p => p.active)?.length || 0,
    lastRefreshed: proxyData.lastRefreshed,
    proxies: (proxyData.proxies || []).slice(0, 20)
  });
});

// POST /api/proxy/refresh - Refresh proxies
app.post('/api/proxy/refresh', (req, res) => {
  const triggerPath = path.join(ROOT_DIR, 'data/proxy-refresh-trigger.json');
  writeJSON(triggerPath, { triggeredAt: new Date().toISOString() });
  res.json({ message: 'Proxy refresh triggered' });
});

// GET /api/config - Get current config
app.get('/api/config', (req, res) => {
  const config = readJSON(CONFIG_PATH, {});
  // Mask sensitive data
  if (config.options?.notifications?.telegram?.botToken) {
    config.options.notifications.telegram.botToken = '***masked***';
  }
  if (config.options?.notifications?.discord?.webhookUrl) {
    const url = config.options.notifications.discord.webhookUrl;
    config.options.notifications.discord.webhookUrl = url ? '***masked***' : '';
  }
  res.json(config);
});

// POST /api/config - Update config
app.post('/api/config', (req, res) => {
  const currentConfig = readJSON(CONFIG_PATH, {});
  const updates = req.body;

  // Merge updates (shallow merge for top-level keys)
  const newConfig = { ...currentConfig };
  for (const [key, value] of Object.entries(updates)) {
    if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
      newConfig[key] = { ...(currentConfig[key] || {}), ...value };
    } else {
      newConfig[key] = value;
    }
  }

  if (writeJSON(CONFIG_PATH, newConfig)) {
    io.emit('configUpdated', { updatedAt: new Date().toISOString() });
    res.json({ message: 'Config updated', config: newConfig });
  } else {
    res.status(500).json({ error: 'Failed to save config' });
  }
});

// Serve dashboard at /dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Redirect root to dashboard
app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

// ─── Socket.IO ──────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log(`[Dashboard] Client connected: ${socket.id}`);

  // Send initial state
  socket.emit('state', getDaemonState());

  socket.on('requestState', () => {
    socket.emit('state', getDaemonState());
  });

  socket.on('disconnect', () => {
    console.log(`[Dashboard] Client disconnected: ${socket.id}`);
  });
});

// Watch findings file for changes and emit events
let lastFindingsSize = 0;
setInterval(() => {
  try {
    if (fs.existsSync(FINDINGS_DB_PATH)) {
      const stat = fs.statSync(FINDINGS_DB_PATH);
      if (stat.size !== lastFindingsSize) {
        lastFindingsSize = stat.size;
        const db = readJSON(FINDINGS_DB_PATH, { findings: [] });
        io.emit('findingsUpdated', {
          total: db.findings.length,
          latest: db.findings.slice(-5)
        });
      }
    }
  } catch (e) {
    // Silent
  }
}, 5000);

// Emit daemon state periodically
setInterval(() => {
  io.emit('state', getDaemonState());
}, 10000);

// ─── Start Server ───────────────────────────────────────────────────────────

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║   ReconTool Dashboard                    ║
  ║   Running on http://0.0.0.0:${PORT}        ║
  ║   Dashboard: http://localhost:${PORT}/dashboard ║
  ╚══════════════════════════════════════════╝
  `);
});

export { app, io, httpServer };
