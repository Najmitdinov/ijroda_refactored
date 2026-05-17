import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';

const root = resolve(process.argv[2] || process.cwd());
const port = Number(process.argv[3] || 5177);
const host = process.argv[4] || '127.0.0.1';

const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
};

function resolveRequestPath(url = '/') {
  const cleanUrl = decodeURIComponent(url.split('?')[0] || '/');
  const requested = cleanUrl === '/' ? '/index.html' : cleanUrl;
  const fullPath = normalize(join(root, requested));
  if (!fullPath.startsWith(root)) return null;
  if (!existsSync(fullPath)) return null;
  const stats = statSync(fullPath);
  if (stats.isDirectory()) return join(fullPath, 'index.html');
  return fullPath;
}

createServer((req, res) => {
  const filePath = resolveRequestPath(req.url);
  if (!filePath || !existsSync(filePath)) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }

  res.writeHead(200, {
    'content-type': types[extname(filePath).toLowerCase()] || 'application/octet-stream',
    'cache-control': 'no-store'
  });
  createReadStream(filePath).pipe(res);
}).listen(port, host, () => {
  console.log(`Ijroda static server: http://${host}:${port}/`);
});
