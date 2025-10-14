// server.js
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import basicAuth from 'express-basic-auth';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fetch from 'node-fetch';

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60 * 1000, max: 100 }));

// Tell Express it's behind a proxy (Render, Nginx, etc.)
app.set('trust proxy', true);

// Initialize SQLite
const dbPromise = open({
  filename: './ip_store.db',
  driver: sqlite3.Database,
});

// Create logs table if not exists
(async () => {
  const db = await dbPromise;
  await db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      country TEXT,
      region TEXT,
      city TEXT,
      path TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
})();

// 🧾 Log endpoint (called by frontend)
app.post('/api/log', async (req, res) => {
  try {
    const db = await dbPromise;

    // Detect visitor IP
    const forwarded = req.headers['x-forwarded-for'];
    const ip = (forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress)?.replace('::ffff:', '') || 'Unknown';
    const path = req.body.path || '/';

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

    await db.run(
      'INSERT INTO logs (ip, country, region, city, path) VALUES (?, ?, ?, ?, ?)',
      [ip, country, region, city, path]
    );

    console.log(`✅ Logged: ${ip} | ${city}, ${region}, ${country} | ${path}`);

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Logging failed:', err);
    res.status(500).json({ success: false });
  }
});

// 🔐 Admin view
app.use(
  '/admin',
  basicAuth({
    users: { [process.env.ADMIN_USER]: process.env.ADMIN_PASS },
    challenge: true,
  })
);

app.get('/admin', async (req, res) => {
  const db = await dbPromise;
  const logs = await db.all('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100');
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

app.listen(process.env.PORT || 10000, () =>
  console.log(`🚀 Server running on port ${process.env.PORT || 10000}`)
);
