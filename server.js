require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { runFullScan } = require('./engines/aggregator');

const app = express();
const PORT = process.env.PORT || 3700;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Active SSE connections for progress streaming
const activeScans = new Map();

// Track which emails are currently being scanned (for polling fallback)
const scanningEmails = new Set();

// In-memory result cache — don't re-scan same email within 5 minutes
const scanCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

// Rate limiting — max 3 concurrent scans
let activeScanCount = 0;
const MAX_CONCURRENT = 3;

function isValidEmail(email) {
  // Stricter: alphanumeric + dots/hyphens/underscores/plus in local, valid domain chars
  return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email) && email.length <= 254;
}

function getCached(email) {
  const cached = scanCache.get(email);
  if (cached && (Date.now() - cached.time) < CACHE_TTL) {
    return cached.report;
  }
  scanCache.delete(email);
  return null;
}

function setCache(email, report) {
  scanCache.set(email, { report, time: Date.now() });
  // Evict old entries
  if (scanCache.size > 50) {
    const oldest = [...scanCache.entries()].sort((a, b) => a[1].time - b[1].time)[0];
    scanCache.delete(oldest[0]);
  }
}

// SSE endpoint for scan progress
app.get('/api/scan/progress/:scanId', (req, res) => {
  const { scanId } = req.params;

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  // Send initial heartbeat
  res.write(`data: ${JSON.stringify({ status: 'connected' })}\n\n`);

  activeScans.set(scanId, res);

  // Keepalive ping every 15s
  const keepalive = setInterval(() => {
    try { res.write(`:keepalive\n\n`); } catch (e) {}
  }, 15000);

  req.on('close', () => {
    clearInterval(keepalive);
    activeScans.delete(scanId);
  });
});

// Main scan endpoint
app.post('/api/scan', async (req, res) => {
  const { email } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // Check cache
  const cached = getCached(normalizedEmail);
  if (cached) {
    const scanId = 'cached_' + Date.now().toString(36);
    res.json({ scanId, status: 'started', cached: true });

    // Immediately send cached result via SSE
    setTimeout(() => {
      const sseConn = activeScans.get(scanId);
      if (sseConn) {
        sseConn.write(`data: ${JSON.stringify({ status: 'complete', report: cached })}\n\n`);
        sseConn.end();
        activeScans.delete(scanId);
      }
    }, 500);
    return;
  }

  // Rate limit
  if (activeScanCount >= MAX_CONCURRENT) {
    return res.status(429).json({ error: 'Too many concurrent scans. Try again in a moment.' });
  }

  const scanId = Date.now().toString(36) + Math.random().toString(36).slice(2);
  res.json({ scanId, status: 'started' });

  activeScanCount++;
  scanningEmails.add(normalizedEmail);

  try {
    const report = await runFullScan(normalizedEmail, (progress) => {
      const sseConn = activeScans.get(scanId);
      if (sseConn) {
        try {
          sseConn.write(`data: ${JSON.stringify(progress)}\n\n`);
        } catch (e) {}
      }
    });

    setCache(normalizedEmail, report);
    scanningEmails.delete(normalizedEmail);

    const sseConn = activeScans.get(scanId);
    if (sseConn) {
      try {
        sseConn.write(`data: ${JSON.stringify({ status: 'complete', report })}\n\n`);
        sseConn.end();
      } catch (e) {}
    }
    activeScans.delete(scanId);
  } catch (err) {
    scanningEmails.delete(normalizedEmail);
    const sseConn = activeScans.get(scanId);
    if (sseConn) {
      try {
        sseConn.write(`data: ${JSON.stringify({ status: 'error', error: err.message })}\n\n`);
        sseConn.end();
      } catch (e) {}
    }
    activeScans.delete(scanId);
  } finally {
    activeScanCount--;
  }
});

// Polling status endpoint — used by frontend when SSE drops mid-scan
// Returns: { status: 'complete', report } | { status: 'scanning' } | { status: 'idle' }
app.get('/api/scan/status/:email', (req, res) => {
  const email = decodeURIComponent(req.params.email).trim().toLowerCase();
  const cached = getCached(email);
  if (cached) return res.json({ status: 'complete', report: cached });
  if (scanningEmails.has(email)) return res.json({ status: 'scanning' });
  return res.json({ status: 'idle' });
});

// Quick lookup endpoint
app.get('/api/quick/:email', async (req, res) => {
  const { email } = req.params;
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  const cached = getCached(normalizedEmail);
  if (cached) return res.json(cached);

  if (activeScanCount >= MAX_CONCURRENT) {
    return res.status(429).json({ error: 'Too many concurrent scans' });
  }

  activeScanCount++;
  try {
    const report = await runFullScan(normalizedEmail);
    setCache(normalizedEmail, report);
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    activeScanCount--;
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    version: '2.1',
    activeScans: activeScanCount,
    cacheSize: scanCache.size,
    uptime: process.uptime(),
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler — don't crash the server
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT]', err.message);
});

process.on('unhandledRejection', (err) => {
  console.error('[UNHANDLED]', err?.message || err);
});

app.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║          FINDER_IO v2.1 — LIVE           ║`);
  console.log(`  ║  http://localhost:${PORT}                  ║`);
  console.log(`  ║  OSINT Email Intelligence Engine         ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
