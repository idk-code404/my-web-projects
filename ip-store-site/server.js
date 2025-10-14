// server.js
// A simple Express app that logs visitor IPs into SQLite (masked), with admin viewer.

const express = require('express');
const path = require('path');
const Helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const basicAuth = require('express-basic-auth');

const app = express();
const PORT = process.env.PORT || 3001;

// -- Security middleware
app.use(Helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Simple rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // limit each IP to 120 requests per windowMs
});
app.use(limiter);

// -- Static files
app.use(express.static(path.join(__dirname, 'public')));

// -- Database init
const db = new Database(path.join(__dirname, 'ip_store.db'));
db.pragma('journal_mode = WAL');

// Create table if not exists
db.prepare(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip_masked TEXT NOT NULL,
    ip_raw TEXT,             -- only present if visitor consented explicitly (nullable)
    user_agent TEXT,
    path TEXT,
    consent_flag INTEGER NOT NULL DEFAULT 0
  );
`).run();

// Prepared statements
const insertLog = db.prepare(`
  INSERT INTO logs (timestamp, ip_masked, ip_raw, user_agent, path, consent_flag)
  VALUES (?, ?, ?, ?, ?, ?)
`);
const getLogs = db.prepare(`SELECT id, timestamp, ip_masked, ip_raw, user_agent, path, consent_flag FROM logs ORDER BY id DESC LIMIT ? OFFSET ?`);
const countLogs = db.prepare(`SELECT COUNT(*) AS cnt FROM logs`);

// -- Helpers
function maskIp(ip) {
  if (!ip) return 'unknown';
  // Some frameworks give IPv6 mapped IPv4 like ::ffff:127.0.0.1
  if (ip.includes('::ffff:')) ip = ip.split('::ffff:')[1];

  // IPv4
  const ipv4Match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    return `${ipv4Match[1]}.${ipv4Match[2]}.x.x`;
  }

  // IPv6 - mask last 5 groups (retain first 3 groups)
  const ipv6Parts = ip.split(':').filter(Boolean);
  if (ipv6Parts.length >= 3) {
    const keep = ipv6Parts.slice(0, 3);
    return keep.join(':') + ':xxxx:xxxx:xxxx:xxxx';
  }

  return 'masked';
}

function getClientIp(req) {
  // Respect X-Forwarded-For if behind proxy (first item)
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    return xff.split(',')[0].trim();
  }
  // fallback
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : req.ip;
}

// -- Logging middleware
app.use((req, res, next) => {
  try {
    const ipRaw = getClientIp(req);
    const ipMasked = maskIp(ipRaw);
    const ua = req.get('User-Agent') || null;
    const pathReq = req.originalUrl || req.path || '/';
    // Consent cookie: client sets consent=true when they agree
    const consentCookie = req.cookies && req.cookies.consent === 'true' ? 1 : 0;

    // Only store raw IP when consentCookie === 1; otherwise store null
    const ipRawToStore = consentCookie ? ipRaw : null;

    insertLog.run(new Date().toISOString(), ipMasked, ipRawToStore, ua, pathReq, consentCookie);
  } catch (err) {
    console.error('Logging error:', err);
  }
  next();
});

// -- API endpoint to explicitly log+return current stored masked ip (optional)
app.get('/api/my-ip', (req, res) => {
  const ip = getClientIp(req);
  const masked = maskIp(ip);
  res.json({ ip_masked: masked });
});

// -- Endpoint to set consent cookie (called from front-end when user agrees)
app.post('/api/consent', (req, res) => {
  // Set cookie for 365 days
  res.cookie('consent', 'true', { maxAge: 365 * 24 * 60 * 60 * 1000, httpOnly: false, sameSite: 'lax' });
  res.json({ success: true });
});

// -- Admin viewer (protected with basic auth)
// Credentials via environment variables: ADMIN_USER, ADMIN_PASS (fallback to default demo/demo)
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'demo';

// Basic auth
app.use('/admin', basicAuth({
  users: { [ADMIN_USER]: ADMIN_PASS },
  challenge: true,
  unauthorizedResponse: (req) => req.auth ? 'Credentials rejected' : 'No credentials provided'
}));

// Admin page: static HTML served from /public/admin.html or generate here
app.get('/admin/logs', (req, res) => {
  // Accept query params for pagination
  const limit = Math.min(parseInt(req.query.limit) || 50, 500);
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const offset = (page - 1) * limit;
  const rows = getLogs.all(limit, offset);
  const total = countLogs.get().cnt;
  res.json({ total, page, per_page: limit, logs: rows });
});

// Admin simple viewer file
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`IP Store site running at http://localhost:${PORT}`);
  console.log(`Admin user: ${ADMIN_USER} (set ADMIN_USER / ADMIN_PASS to override)`);
});
