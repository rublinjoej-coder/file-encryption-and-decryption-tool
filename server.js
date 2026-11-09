/**
 * VaultLite - Zero-Dependency Local Static Server
 * Runs out of the box using built-in Node.js modules (http, fs, path).
 * No npm install or third-party packages needed.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const BASE_DIR = path.join(__dirname, 'VaultLite');

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.sfe': 'application/octet-stream'
};

const server = http.createServer((req, res) => {
    // Parse URL and clean path
    let reqUrl = req.url.split('?')[0];
    if (reqUrl === '/' || reqUrl === '') {
        reqUrl = '/index.html';
    }

    // Support requests prefixed with /VaultLite/
    if (reqUrl.startsWith('/VaultLite/')) {
        reqUrl = reqUrl.replace('/VaultLite', '');
    }

    const safePath = path.normalize(reqUrl).replace(/^(\.\.[\/\\])+/, '');
    let filePath = path.join(BASE_DIR, safePath);

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('404 Not Found');
            return;
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });

        const stream = fs.createReadStream(filePath);
        stream.pipe(res);
    });
});

server.listen(PORT, () => {
    console.log('====================================================');
    console.log('🛡️  VaultLite Local Server Running');
    console.log(`🚀 Access URL: http://localhost:${PORT}`);
    console.log('====================================================');
    console.log('Press Ctrl + C to stop the server.\n');
});
