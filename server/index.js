const http = require('http');
const fs = require('fs');
const path = require('path');
const { runScan, normalizeTarget } = require('./engine');
const { demoHandler } = require('./demo');

const PORT = Number(process.env.PORT ?? 4000);
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const DATA_DIR = path.join(__dirname, '..', '.data', 'scans');

function ensureDataDir() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
}

// 把完成的扫描存下来，方便以后回看 / 做趋势对比
function saveScan(id, target, summary, findings) {
  ensureDataDir();
  const record = { id, target, summary, findings, finishedAt: new Date().toISOString() };
  try { fs.writeFileSync(path.join(DATA_DIR, `${id}.json`), JSON.stringify(record)); } catch {}
}
function listScans() {
  ensureDataDir();
  let files = [];
  try { files = fs.readdirSync(DATA_DIR).filter((f) => f.endsWith('.json')); } catch { return []; }
  return files
    .map((f) => {
      try {
        const r = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f), 'utf8'));
        const s = r.summary || {};
        return {
          id: r.id, target: r.target, finishedAt: r.finishedAt,
          riskScore: s.riskScore ?? 0, total: s.total ?? (r.findings ? r.findings.length : 0),
          bySeverity: s.bySeverity || {},
        };
      } catch { return null; }
    })
    .filter(Boolean)
    .sort((a, b) => (a.finishedAt < b.finishedAt ? 1 : -1));
}
function readScan(id) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, `${id}.json`), 'utf8')); } catch { return null; }
}
function deleteScan(id) {
  try { fs.unlinkSync(path.join(DATA_DIR, `${id}.json`)); return true; } catch { return false; }
}

// 一次扫描的 SSE 事件会分发给（可能多个）客户端
class Scan {
  constructor() { this.subs = []; this.buffer = []; this.ended = false; }
  subscribe(res) {
    this.subs.push(res);
    this.buffer.forEach((e) => this.write(res, e));
    if (this.ended) res.end();
  }
  publish(e) {
    this.buffer.push(e);
    this.subs.forEach((r) => this.write(r, e));
    if (e.type === 'done' || e.type === 'error') {
      this.ended = true;
      this.subs.forEach((r) => r.end());
    }
  }
  write(res, e) { res.write(`data: ${JSON.stringify(e)}\n\n`); }
}

const scans = new Map();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

function sendJson(res, obj, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function serveStatic(reqUrl, res) {
  let rel = decodeURIComponent(reqUrl.pathname);
  if (rel === '/' || rel === '') rel = '/index.html';
  const filePath = path.join(PUBLIC_DIR, rel);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // 不做 SPA fallback：未知路径返回 404，端点发现的"暴露"判定才是真的
      // （否则 fallback 一律 200 会造出一堆假阳性的"暴露路径"）
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] ?? 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);

  if (reqUrl.pathname === '/api/health') return sendJson(res, { ok: true, name: 'Sentinel', version: '1.4.0' });

  if (reqUrl.pathname === '/api/scan' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      let parsed = {};
      try { parsed = JSON.parse(body || '{}'); } catch {}
      const raw = String(parsed.target ?? '').trim();
      if (!raw) return sendJson(res, { error: 'target is required' }, 400);
      let target;
      try {
        target = normalizeTarget(raw);
        const u = new URL(target);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return sendJson(res, { error: 'Only http(s) targets are supported' }, 400);
      } catch { return sendJson(res, { error: 'Invalid URL' }, 400); }

      const options = {};
      if (parsed.cookie) options.cookie = String(parsed.cookie).trim();
      if (parsed.auth && typeof parsed.auth === 'object' && parsed.auth.loginUrl) {
        options.auth = {
          loginUrl: String(parsed.auth.loginUrl),
          usernameField: parsed.auth.usernameField,
          passwordField: parsed.auth.passwordField,
          username: parsed.auth.username,
          password: parsed.auth.password,
        };
      }

      const id = `scan_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
      const scan = new Scan();
      scans.set(id, scan);
      sendJson(res, { id, target, authenticated: !!options.cookie || !!options.auth });

      const collected = [];
      runScan(target, (e) => {
        if (e.type === 'finding') collected.push(e.finding);
        if (e.type === 'done') saveScan(id, target, e.summary, collected);
        scan.publish(e);
      }, options).catch((err) =>
        scan.publish({ type: 'error', message: err?.message ?? String(err) })
      );
      setTimeout(() => scans.delete(id), 60_000);
    });
    return;
  }

  if (/^\/api\/scan\/[^/]+\/events$/.test(reqUrl.pathname) && req.method === 'GET') {
    const id = reqUrl.pathname.split('/')[3];
    const scan = scans.get(id);
    if (!scan) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Unknown scan id' })); return; }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write('retry: 3000\n\n');
    scan.subscribe(res);
    req.on('close', () => {
      const i = scan.subs.indexOf(res);
      if (i >= 0) scan.subs.splice(i, 1);
    });
    return;
  }

  if (reqUrl.pathname === '/api/scans' && req.method === 'GET') {
    return sendJson(res, { scans: listScans() });
  }
  const histMatch = /^\/api\/scans\/([^/]+)$/.exec(reqUrl.pathname);
  if (histMatch) {
    const id = histMatch[1];
    if (req.method === 'GET') {
      const rec = readScan(id);
      if (!rec) return sendJson(res, { error: 'Unknown scan id' }, 404);
      return sendJson(res, rec);
    }
    if (req.method === 'DELETE') {
      if (!deleteScan(id)) return sendJson(res, { error: 'Unknown scan id' }, 404);
      return sendJson(res, { ok: true });
    }
    return sendJson(res, { error: 'Method not allowed' }, 405);
  }

  if (demoHandler(req, reqUrl, res)) return;

  serveStatic(reqUrl, res);
});

server.listen(PORT, () => {
  console.log(`\n  Sentinel scanner listening on http://localhost:${PORT}`);
  console.log(`  Scan the built-in demo:  POST /api/scan  {"target":"http://localhost:${PORT}/demo"}\n`);
});
// do not fall back to index.html for unknown routes
