// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Simple IP logging middleware
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
    const maskedIp = ip.replace(/(\d+\.\d+)\.\d+\.\d+/, '$1.x.x'); // mask IPv4 partials

    const logEntry = `[${new Date().toISOString()}] IP: ${maskedIp}\n`;
    fs.appendFile(path.join(__dirname, 'ip-log.txt'), logEntry, (err) => {
        if (err) console.error('Error logging IP:', err);
    });
    next();
});

// Default route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
