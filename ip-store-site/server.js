// server.js
// Node 18+ (ESM). Lightweight IP logging backend with GeoIP enrichment,
// pseudonymization via HMAC, admin view and retention job.

import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import basicAuth from 'express-basic-auth';
import sqlite3 from 'sqlite3';
const db = new sqlite3.Database('./ip_store.db');
import crypto from 'crypto';
import cron from 'node-cron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Configuration (override via environment) ----------
const PORT = process.env.PORT || 10000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'secretpassword';
const IP_HMAC_KEY = process.env.IP_HMAC_KEY || 'replace_this_with_a_strong_secret';
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || '30', 10); // delete logs older than this
const GEOAPI_TIMEOUT_MS = 2500; // geo lookup timeout

// ---------- App & middleware ----------
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cookieParser());
app.set('trust proxy', true); // IMPORTANT when behind proxies

// Basic rate limit
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
}));

// Serve public static (admin and optional assets)
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Database init ----------
const dbPromise = open({
  filename: path.join(__dirname, 'ip_store.db'),
  driver: sqlite3.Database
});

(async function initDb() {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      ip_masked TEXT NOT NULL,
      ip_pseudonym TEXT NOT NULL,
      country TEXT,
      region TEXT,
      city TEXT,
      path TEXT,
      user_agent TEXT,
      source TEXT DEFAULT 'frontend'
    );
  `);
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(timestamp)`);
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_pseudonym ON logs(ip_pseudonym)`);
  console.log('✅ Database initialized');
})();

// ---------- Utility functions ----------
function maskIp(ipRaw) {
  if (!ipRaw) return 'unknown';
  // Remove IPv4-mapped IPv6 prefix if present
  let ip = ipRaw.replace(/^::ffff:/, '');
  // IPv4 mask
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) return `${m[1]}.${m[2]}.x.x`;
  // IPv6 truncation - keep first 3 groups
  const parts = ip.split(':').filter(Boolean);
  if (parts.length >= 3) return parts.slice(0,3).join(':') + ':xxxx:xxxx';
  return 'masked';
}

function pseudonymizeIp(ipRaw) {
  // deterministic HMAC-SHA256 using server-side secret
  const h = crypto.createHmac('sha256', IP_HMAC_KEY);
  h.update(ipRaw || '');
  return h.digest('hex');
}

async function geoLookup(ip) {
  // Uses ipapi.co public endpoint. For production, prefer local MaxMind DB.
  if (!ip || ip === 'unknown') return null;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), GEOAPI_TIMEOUT_MS);
  try {
    // Node 18+ has global fetch
    const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { signal: controller.signal });
    clearTimeout(id);
    if (!res.ok) return null;
    const j = await res.json();
    return {
      country: j.country_name || null,
      region: j.region || null,
      city: j.city || null
    };
  } catch (e) {
    clearTimeout(id);
    // network/timeouts -> ignore geo info
    return null;
  }
}

// Get client IP safely (respect X-Forwarded-For)
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  if (req.socket && req.socket.remoteAddress) return req.socket.remoteAddress;
  if (req.ip) return req.ip;
  return 'unknown';
}

// ---------- API: /api/log ----------
app.post('/api/log', async (req, res) => {
  try {
    const db = await dbPromise;
    const rawIp = getClientIp(req).replace(/^::ffff:/, '');
    const ipMasked = maskIp(rawIp);
    const ipPseudo = pseudonymizeIp(rawIp);
    const pathField = req.body?.path || req.originalUrl || '/';
    const ua = req.get('User-Agent') || null;

    // Geo enrich but do not block logging on failure
    let geo = null;
    try { geo = await geoLookup(rawIp); } catch (e) { geo = null; }

    await db.run(
      `INSERT INTO logs (timestamp, ip_masked, ip_pseudonym, country, region, city, path, user_agent, source)
       VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)`,
      [ipMasked, ipPseudo, geo?.country || null, geo?.region || null, geo?.city || null, pathField, ua, 'frontend']
    );

    console.log(`Logged: ${ipMasked} (${ipPseudo.slice(0,8)}...) ${geo ? `${geo.city || ''} ${geo.region || ''} ${geo.country || ''}` : ''} ${pathField}`);

    res.status(200).json({ success: true, ip_masked: ipMasked });
  } catch (err) {
    console.error('Error in /api/log:', err);
    res.status(500).json({ success: false });
  }
});

// ---------- Admin endpoints (protected) ----------
app.use('/admin', basicAuth({
  users: { [ADMIN_USER]: ADMIN_PASS },
  challenge: true,
  unauthorizedResponse: () => 'Unauthorized'
}));

// JSON API for logs (supports pagination)
app.get('/admin/logs', async (req, res) => {
  try {
    const db = await dbPromise;
    const limit = Math.min(parseInt(req.query.limit || '100', 10), 1000);
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
    const rows = await db.all('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ? OFFSET ?', [limit, offset]);
    const totalRow = await db.get('SELECT COUNT(*) as cnt FROM logs');
    res.json({ total: totalRow.cnt || 0, limit, offset, logs: rows });
  } catch (e) {
    console.error('admin/logs error', e);
    res.status(500).json({ error: 'internal' });
  }
});

// Admin UI (serves static admin.html from /public)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ---------- Retention job (daily) ----------
function retentionDeleteOldLogs() {
  (async () => {
    try {
      const db = await dbPromise;
      const cutoffDate = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);
      const cutoffIso = cutoffDate.toISOString().replace('T', ' ').split('.')[0];
      // SQLite datetime comparing using timestamps stored by datetime('now') format - use >= date('now','-X days')
      await db.run(`DELETE FROM logs WHERE timestamp <= datetime('now','-${RETENTION_DAYS} days')`);
      console.log(`Retention: deleted logs older than ${RETENTION_DAYS} days`);
    } catch (e) {
      console.error('Retention job failed:', e);
    }
  })();
}
// Run retention job daily at 02:05 (server local time)
cron.schedule('5 2 * * *', () => retentionDeleteOldLogs(), { timezone: 'UTC' });
// Also run once at startup to enforce retention
retentionDeleteOldLogs();

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`🚀 ip-store-site listening on port ${PORT} (ADMIN_USER=${ADMIN_USER})`);
  if (!process.env.IP_HMAC_KEY) {
    console.warn('⚠️ Warning: IP_HMAC_KEY not set in environment. Using default insecure key. Set IP_HMAC_KEY to a strong secret.');
  }
});
