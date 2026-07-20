
function sendHtml(res, html, status = 200, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...extra });
  res.end(html);
}
function sendText(res, text, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(text);
}
function sendJson(res, obj, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

const DEMO_JWT = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.';

const fs = require('fs');
const { request } = require('./http');

// 演示登录用的内存会话表（这样"认证态扫描"才有真实要打的受保护页面）
const SESSIONS = new Map();

function demoHandler(req, reqUrl, res) {
  const pathname = reqUrl.pathname;
  const q = reqUrl.searchParams;

  if (pathname === '/demo') {
    // 故意的开放重定向：?next=https://evil.example 就跳走了
    const next = q.get('next');
    if (next && /^(https?:\/\/|\/\/)/i.test(next)) {
      res.writeHead(302, { Location: next });
      res.end();
      return true;
    }

    res.setHeader('Set-Cookie', 'session=tok-demo-123; Path=/');

    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    const name = q.get('name') ?? 'Guest';
    sendHtml(res, `<!doctype html><html><head><title>Vulnerable Demo</title></head><body>
      <!-- TODO: 上线前把管理员密码改了，见 /demo/profile -->
      <h1>Welcome, ${name}</h1>

      <form action="/demo" method="get">
        <input name="name" type="text" placeholder="your name" />
        <input type="submit" value="Greet" />
      </form>

      <form action="/demo/search" method="get">
        <input name="q" type="text" placeholder="search the catalogue" />
        <input type="submit" value="Search" />
      </form>

      <form action="/demo/login" method="post">
        <input name="username" type="text" placeholder="username" />
        <input name="password" type="password" placeholder="password" />
        <input type="submit" value="Log in" />
      </form>

      <form action="/demo/subscribe" method="post">
        <input name="email" type="email" placeholder="you@example.com" />
        <input type="submit" value="Subscribe" />
      </form>

      <!-- 一次重构时把 apiKey 落在前端 bundle 里了，先这么着 -->
      <script>
        var cfg = { apiKey: "AKIAIOSFODNN7EXAMPLE", region: "us-east-1", jwt: "${DEMO_JWT}" };
        window.__token = cfg.jwt;
      </script>
    </body></html>`);
    return true;
  }

  if (pathname === '/demo/search') {
    const query = q.get('q') ?? '';
    if (query.includes("'")) {
      sendHtml(res, `<html><body><h1>Server Error</h1><p>SQLite3:: near "${query}": syntax error</p></body></html>`, 500);
      return true;
    }
    const isTrue = query.includes("1'='1");
    const rows = isTrue ? 'row '.repeat(8) : 'no results';
    sendHtml(res, `<html><body><h1>Catalogue</h1><p>You searched for: ${query}</p><div>${rows}</div></body></html>`);
    return true;
  }

  if (pathname === '/demo/login') {
    const handleLogin = (username, password) => {
      if (String(password ?? '').includes("'")) {
        sendHtml(res, `<html><body><h1>Server Error</h1><p>You have an error in your SQL syntax near '${username ?? ''}'</p></body></html>`, 500);
        return;
      }
      const sid = 'sess_' + Math.random().toString(36).slice(2, 12);
      SESSIONS.set(sid, { user: username || 'guest' });
      res.setHeader('Set-Cookie', `session=${sid}; Path=/; HttpOnly`);
      res.setHeader('X-Session', sid); // 浏览器拿不到 Set-Cookie，演示的"登录靶机"用这个取会话
      sendHtml(res, `<html><body><h1>Logged in (demo)</h1><p>Welcome, ${username || 'guest'}.</p></body></html>`);
    };
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const params = new URLSearchParams(body);
        handleLogin(params.get('username') ?? q.get('username'), params.get('password') ?? q.get('password'));
      });
      return true;
    }
    handleLogin(q.get('username'), q.get('password'));
    return true;
  }

  if (pathname === '/demo/account') {
    const ck = req.headers.cookie || '';
    const sid = (/(?:^|;\s*)session=([^;]+)/.exec(ck) || [])[1];
    if (!sid || !SESSIONS.has(sid)) {
      sendJson(res, { error: 'unauthorized', message: 'authentication required' }, 401);
      return true;
    }
    const note = q.get('note') ?? '';
    sendHtml(res, `<!doctype html><html><body>
      <h1>Account · ${SESSIONS.get(sid).user}</h1>
      <p>Your note: ${note}</p>
      <p>SSN: 123-45-6789 · Card: 4111 1111 1111 1111</p>
      <form action="/demo/account" method="get"><input name="note" placeholder="note" /><input type="submit" value="Save" /></form>
    </body></html>`);
    return true;
  }

  if (pathname === '/demo/subscribe') {
    const email = q.get('email') ?? '';
    sendHtml(res, `<html><body><h1>Subscribed</h1><p>Thanks, ${email}</p></body></html>`);
    return true;
  }

  if (pathname === '/demo/profile') {
    sendHtml(res, `<!doctype html><html><body>
      <h1>Admin Profile</h1>
      <p>Logged in as admin. DB password is still rootpass (fixme).</p>
      <pre>${DEMO_JWT}</pre>
    </body></html>`);
    return true;
  }

  if (pathname === '/demo/download' || pathname === '/download') {
    const file = q.get('file') ?? '';
    const isTraversal = /(\.\.\/|\.\.\\|%2e%2e|%252e|\.\.%2f)/i.test(file);
    if (isTraversal) {
      sendText(res,
`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
# leaked via /download?file=${file}`);
      return true;
    }
    sendText(res, `Contents of "${file || 'index.txt'}": (demo file viewer)`);
    return true;
  }

  if (pathname === '/fetch' || pathname === '/demo/fetch') {
    const furl = q.get('url') || q.get('u');
    if (!furl) { sendText(res, 'missing url parameter', 400); return true; }
    request(furl, { method: 'GET', timeout: 6000, redirect: 'follow' })
      .then((r) => sendText(res, `Fetched ${furl}:\n\n${(r.body || '').slice(0, 2000)}`, 200))
      .catch((e) => sendText(res, `fetch error: ${e?.message ?? e}`, 502));
    return true;
  }

  if (pathname === '/api/xml' || pathname === '/xml') {
    if (req.method !== 'POST') { sendText(res, 'POST an XML body', 405); return true; }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const m = body.match(/<!ENTITY\s+\w+\s+SYSTEM\s+["']([^"']+)["']\s*>/i);
      let out = 'ok';
      if (m) {
        const fm = /^file:\/\/(.+)$/i.exec(m[1]);
        if (fm) {
          let fp = fm[1];
          if (/^\/[A-Za-z]:/.test(fp)) fp = fp.replace(/^\//, ''); // /C:/… → C:/…
          try { out = fs.readFileSync(fp, 'utf8').slice(0, 400); }
          catch { out = `cannot read ${fp}`; }
        }
      }
      sendText(res, `<result>${out}</result>`, 200, { 'Content-Type': 'application/xml' });
    });
    return true;
  }

  if (pathname === '/internal/admin-data') {
    sendJson(res, { flag: 'INTERNAL_SECRET_9f3c', note: 'intentionally exposed only to internal network / SSRF' }, 200);
    return true;
  }

  if (pathname === '/login') { res.setHeader('Set-Cookie', 'session=tok-demo-123; Path=/'); sendHtml(res, '<html><body><h1>Logged in (demo)</h1></body></html>'); return true; }
  if (pathname === '/admin') { sendHtml(res, '<html><body><h1>Admin Panel</h1><p>Internal only.</p></body></html>'); return true; }
  if (pathname === '/config') { sendHtml(res, '<html><body><h1>Config</h1></body></html>'); return true; }
  if (pathname === '/dashboard') { sendHtml(res, '<html><body><h1>Dashboard</h1></body></html>'); return true; }
  if (pathname === '/console') { sendHtml(res, '<html><body><h1>Dev Console</h1></body></html>'); return true; }
  if (pathname === '/debug') { sendHtml(res, '<html><body><h1>Debug</h1><p>DEBUG=true, verbose logging on.</p></body></html>'); return true; }
  if (pathname === '/status') { sendHtml(res, '<html><body><h1>System Status</h1><p>All systems nominal.</p></body></html>'); return true; }
  if (pathname === '/uploads') { sendHtml(res, '<html><body><h1>Uploads</h1></body></html>'); return true; }
  if (pathname === '/static') { sendHtml(res, '<html><body><h1>Static Assets</h1></body></html>'); return true; }
  if (pathname === '/api/keys') {
    sendJson(res, { aws_key: 'AKIAIOSFODNN7EXAMPLE', password: 'supersecret123', stripe: 'sk_live_DEMO_PLACEHOLDER_NOT_REAL', note: 'do not ship this' });
    return true;
  }
  if (pathname === '/.env') {
    sendText(res, 'DB_PASSWORD=rootpass\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET_KEY=demo-secret\n');
    return true;
  }
  if (pathname === '/backup') { sendText(res, 'database dump placeholder'); return true; }
  if (pathname === '/robots.txt') { sendText(res, 'User-agent: *\nDisallow: /admin\nDisallow: /api/'); return true; }
  if (pathname === '/server-status') { sendHtml(res, '<html><body><h1>403 Forbidden</h1></body></html>', 403); return true; }

  return false;
}

module.exports = { demoHandler };
// /demo/account requires the session cookie
