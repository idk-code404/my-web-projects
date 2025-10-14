// server.js
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import basicAuth from 'express-basic-auth';
import sqlite3 from 'sqlite3';
import fetch from 'node-fetch';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60 * 1000, max: 100 }));

// Tell Express it's behind a proxy (Render, Nginx, etc.)
app.set('trust proxy', true);

// Serve static files from 'public' folder
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite
const db = new sqlite3.Database('./ip_store.db', (err) => {
  if (err) {
    console.error('Could not connect to SQLite database', err);
  } else {
    console.log('✅ Connected to SQLite database');

    // Create logs table if it doesn't exist
    db.run(
      `CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        country TEXT,
        region TEXT,
        city TEXT,
        path TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      (err) => {
        if (err) console.error('Failed to create logs table', err);
      }
    );
  }
});

// 🧾 Log endpoint (called by frontend)
app.post('/api/log', async (req, res) => {
  try {
    // Detect visitor IP
    const forwarded = req.headers['x-forwarded-for'];
    const ip = (forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress)?.replace('::ffff:', '') || 'Unknown';
    const pathLogged = req.body.path || '/';

    // 🌍 GeoIP Lookup (using ipapi.co)
    let country = 'Unknown', region = 'Unknown', city = 'Unknown';
    try {
      const geoRes = await fetch(`https://ipapi.co/${ip}/json/`);
      if (geoRes.ok) {
        const geo = await geoRes.json();
        country = geo.country_name || 'Unknown';
        region = geo.region || 'Unknown';
        city = geo.city || 'Unknown';
      }
    } catch (geoErr) {
      console.warn('GeoIP lookup failed:', geoErr.message);
    }

    // Insert log into database
    db.run(
      'INSERT INTO logs (ip, country, region, city, path) VALUES (?, ?, ?, ?, ?)',
      [ip, country, region, city, pathLogged],
      function (err) {
        if (err) {
          console.error('Logging failed:', err);
          res.status(500).json({ success: false });
        } else {
          console.log(`✅ Logged: ${ip} | ${city}, ${region}, ${country} | ${pathLogged}`);
          res.status(200).json({ success: true });
        }
      }
    );
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ success: false });
  }
});

// 🔐 Admin view (only if ADMIN_USER and ADMIN_PASS are set)
const adminUser = process.env.ADMIN_USER;
const adminPass = process.env.ADMIN_PASS;

if (adminUser && adminPass) {
  app.use(
    '/admin',
    basicAuth({
      users: { [adminUser]: adminPass },
      challenge: true,
    })
  );

  app.get('/admin', (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100', [], (err, logs) => {
      if (err) {
        console.error('Failed to fetch logs:', err);
        return res.status(500).send('Error fetching logs');
      }

      res.send(`
        <html>
          <head>
            <title>IP Logs Dashboard</title>
            <style>
              body { font-family: Arial, sans-serif; background:#fafafa; padding:20px; }
              table { border-collapse: collapse; width:100%; }
              th, td { border:1px solid #ccc; padding:8px; text-align:left; }
              th { background:#333; color:white; }
            </style>
          </head>
          <body>
            <h1>🌍 Visitor Logs</h1>
            <table>
              <tr>
                <th>ID</th><th>IP</th><th>Country</th><th>Region</th><th>City</th><th>Path</th><th>Timestamp</th>
              </tr>
              ${logs
                .map(
                  (log) => `
                <tr>
                  <td>${log.id}</td>
                  <td>${log.ip}</td>
                  <td>${log.country}</td>
                  <td>${log.region}</td>
                  <td>${log.city}</td>
                  <td>${log.path}</td>
                  <td>${log.timestamp}</td>
                </tr>`
                )
                .join('')}
            </table>
          </body>
        </html>
      `);
    });
  });
} else {
  console.warn('⚠️ Admin credentials not set. /admin route is disabled.');
}

// Optional: SPA fallback for client-side routing (if needed)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/admin')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(process.env.PORT || 10000, () =>
  console.log(`🚀 Server running on port ${process.env.PORT || 10000}`)
);
