const tls = require('tls');
const { request, mapLimit } = require('./http');
const {
  makeId, parseQueryParams, extractFormFields, resolveUrl, buildFinding,
  COMMON_PATHS, SECRET_PATTERNS, SQL_ERROR_SIGNATURES,
  LFI_SIGNATURES, FILE_PARAMS,
} = require('./util');

function sameOrigin(url, ctx) {
  try { return new URL(url).host === ctx.host; } catch { return false; }
}

// 把 value 打到某个参数上，GET 走 query，POST 走 form
async function sendParam(point, value) {
  if (point.method === 'GET') {
    const u = new URL(point.url);
    u.searchParams.set(point.field, value);
    return request(u.toString(), { method: 'GET' });
  }
  const body = `${encodeURIComponent(point.field)}=${encodeURIComponent(value)}`;
  return request(point.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
}

// 安全头
const HEADER_CHECKS = [
  { header: 'strict-transport-security', severity: 'medium', title: 'Missing Strict-Transport-Security (HSTS)',
    remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to force HTTPS and prevent downgrade (SSL-stripping) attacks.',
    owasp: 'A02:2021', cwe: 'CWE-319' },
  { header: 'content-security-policy', severity: 'medium', title: 'Missing Content-Security-Policy (CSP)',
    remediation: 'Define a CSP to mitigate XSS and data injection. Start strict, then whitelist only required origins.',
    owasp: 'A05:2021', cwe: 'CWE-1021' },
  { header: 'x-content-type-options', severity: 'low', title: 'Missing X-Content-Type-Options',
    remediation: 'Set "X-Content-Type-Options: nosniff" to stop MIME sniffing that can lead to script execution in legacy browsers.',
    owasp: 'A05:2021', cwe: 'CWE-693' },
  { header: 'x-frame-options', severity: 'low', title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
    remediation: 'Set "X-Frame-Options: DENY" or CSP "frame-ancestors \'none\'" to prevent the page being embedded in a malicious iframe.',
    owasp: 'A05:2021', cwe: 'CWE-1021' },
  { header: 'referrer-policy', severity: 'low', title: 'Missing Referrer-Policy',
    remediation: 'Set "Referrer-Policy: no-referrer" or "strict-origin-when-cross-origin" to limit what URL data leaks to third parties.',
    owasp: 'A05:2021', cwe: 'CWE-200' },
  { header: 'permissions-policy', severity: 'info', title: 'Missing Permissions-Policy',
    remediation: 'Add a Permissions-Policy to disable unused powerful browser features (camera, microphone, geolocation, usb).',
    owasp: 'A05:2021', cwe: 'CWE-693' },
];

async function checkHeaders(ctx) {
  const res = await request(ctx.target, { method: 'GET' });
  if (res.error || res.status === 0) {
    ctx.emitProgress('Security Headers', `Could not reach target: ${res.error ?? res.statusText}`);
    return;
  }
  ctx.emitProgress('Security Headers', `Audited ${res.status} response headers`);
  const isHttps = ctx.protocol === 'https:';
  for (const h of HEADER_CHECKS) {
    if (h.header === 'strict-transport-security' && !isHttps) continue;
    if (h.header === 'x-frame-options' && res.headers['content-security-policy']?.includes('frame-ancestors')) continue;
    if (!res.headers[h.header]) {
      ctx.emitFinding(buildFinding({
        severity: h.severity, category: 'Security Headers', title: h.title,
        owasp: h.owasp, cwe: h.cwe,
        description: `The response did not include the "${h.header}" response header.`,
        evidence: `Header "${h.header}" absent on ${res.url}`,
        remediation: h.remediation, url: res.url,
      }));
    }
  }

  // 顺手看看 CSP 是不是又放了 unsafe-inline
  const csp = res.headers['content-security-policy'];
  if (csp) {
    if (/script-src[^;]*unsafe-inline/.test(csp) || /default-src[^;]*unsafe-inline/.test(csp)) {
      ctx.emitFinding(buildFinding({
        severity: 'medium', category: 'Security Headers',
        title: 'CSP Allows unsafe-inline Scripts',
        owasp: 'A05:2021', cwe: 'CWE-1021',
        description: 'The Content-Security-Policy permits "unsafe-inline" in script-src, which negates most of the XSS protection CSP provides.',
        evidence: `script-src / default-src contains "unsafe-inline": ${csp.slice(0, 120)}${csp.length > 120 ? '…' : ''}`,
        remediation: 'Remove unsafe-inline and deliver scripts with nonces or hashes so only trusted code can execute.',
        url: res.url,
      }));
    }
  }

  const server = res.headers['server'];
  const powered = res.headers['x-powered-by'];
  if (server || powered) {
    const detail = [server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`].filter(Boolean).join('; ');
    ctx.emitFinding(buildFinding({
      severity: 'low', category: 'Information Disclosure',
      title: 'Server Banner Information Disclosure',
      owasp: 'A05:2021', cwe: 'CWE-200',
      description: 'The server exposes technology/version banners that help attackers fingerprint the stack and pick exploits.',
      evidence: detail,
      remediation: 'Strip or genericise Server and X-Powered-By headers (via reverse proxy or framework config).',
      url: res.url,
    }));
  }
}

// cookie
async function checkCookies(ctx) {
  const res = await request(ctx.target, { method: 'GET' });
  if (res.error || res.status === 0) return;
  ctx.emitProgress('Cookie Security', `Inspecting ${res.cookies.length} Set-Cookie header(s)`);
  if (res.cookies.length === 0) {
    ctx.emitProgress('Cookie Security', 'No cookies set by the landing page');
    return;
  }
  const isHttps = ctx.protocol === 'https:';
  res.cookies.forEach((c, i) => {
    const lower = c.toLowerCase();
    const name = lower.split('=')[0]?.trim() ?? `cookie#${i}`;
    if (!lower.includes('secure') && isHttps) {
      ctx.emitFinding(buildFinding({ severity: 'medium', category: 'Cookie Security',
        title: `Cookie "${name}" missing Secure flag`, owasp: 'A05:2021', cwe: 'CWE-614',
        description: 'A session cookie without Secure can be transmitted over plaintext HTTP and intercepted on hostile networks.',
        evidence: c, remediation: 'Set the Secure attribute on all cookies so they are only sent over HTTPS.', url: res.url }));
    }
    if (!lower.includes('httponly')) {
      ctx.emitFinding(buildFinding({ severity: 'medium', category: 'Cookie Security',
        title: `Cookie "${name}" missing HttpOnly flag`, owasp: 'A05:2021', cwe: 'CWE-1004',
        description: 'Without HttpOnly, the cookie is readable by JavaScript and therefore stealable through XSS.',
        evidence: c, remediation: 'Add the HttpOnly attribute to session cookies to block client-side access.', url: res.url }));
    }
    if (!lower.includes('samesite')) {
      ctx.emitFinding(buildFinding({ severity: 'low', category: 'Cookie Security',
        title: `Cookie "${name}" missing SameSite attribute`, owasp: 'A01:2021', cwe: 'CWE-352',
        description: 'Without SameSite, the cookie may be attached to cross-site requests, enabling cross-site request forgery.',
        evidence: c, remediation: 'Set SameSite=Lax (or Strict) to mitigate CSRF, in addition to anti-CSRF tokens.', url: res.url }));
    }
  });
}

// TLS/证书
async function checkSsl(ctx) {
  if (ctx.protocol !== 'https:') {
    ctx.emitProgress('TLS / Certificate', 'Target is not HTTPS, skipping certificate analysis');
    return;
  }
  const portMatch = /:(\d+)/.exec(ctx.host);
  const port = portMatch ? Number(portMatch[1]) : 443;
  const host = ctx.host.replace(/:\d+$/, '');
  ctx.emitProgress('TLS / Certificate', `Probing TLS on ${host}:${port}`);
  const result = await new Promise((resolve) => {
    const socket = tls.connect({ host, port, rejectUnauthorized: false, servername: host, timeout: 12000 }, () => {
      const cert = socket.getPeerCertificate(true);
      resolve({ cert, protocol: socket.getProtocol?.(), authorized: socket.authorized, error: socket.authorizationError });
    });
    socket.on('error', (e) => resolve({ authorized: false, error: e.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ authorized: false, error: 'TLS handshake timeout' }); });
    socket.setTimeout(12000);
  });
  if (result.error || !result.cert || Object.keys(result.cert).length === 0) {
    ctx.emitFinding(buildFinding({ severity: 'high', category: 'TLS / Certificate',
      title: 'TLS Handshake Failed', owasp: 'A02:2021', cwe: 'CWE-295',
      description: 'Could not establish a trusted TLS connection to the target.',
      evidence: result.error ?? 'No certificate returned',
      remediation: 'Ensure a valid certificate is installed and the service is reachable over TLS.', url: ctx.target }));
    return;
  }
  const cert = result.cert;
  const now = Date.now();
  const validFrom = cert.valid_from ? new Date(cert.valid_from).getTime() : 0;
  const validTo = cert.valid_to ? new Date(cert.valid_to).getTime() : 0;
  if (validTo && now > validTo) {
    ctx.emitFinding(buildFinding({ severity: 'high', category: 'TLS / Certificate',
      title: 'Expired TLS Certificate', owasp: 'A02:2021', cwe: 'CWE-324',
      description: 'The server certificate has expired, exposing clients to interception and impersonation.',
      evidence: `Valid until ${cert.valid_to}`,
      remediation: 'Renew the certificate before expiry (use ACME / Let’s Encrypt automation).', url: ctx.target }));
  } else if (validFrom && now < validFrom) {
    ctx.emitFinding(buildFinding({ severity: 'medium', category: 'TLS / Certificate',
      title: 'Certificate Not Yet Valid', owasp: 'A02:2021', cwe: 'CWE-295',
      description: 'The certificate validity period has not started.',
      evidence: `Valid from ${cert.valid_from}`,
      remediation: 'Verify the server clock and certificate issuance time.', url: ctx.target }));
  }
  if (!result.authorized && /self[- ]?signed/i.test(String(result.error))) {
    ctx.emitFinding(buildFinding({ severity: 'medium', category: 'TLS / Certificate',
      title: 'Self-Signed Certificate', owasp: 'A02:2021', cwe: 'CWE-295',
      description: 'The certificate is self-signed and not trusted by clients, undermining authenticity guarantees.',
      evidence: String(result.error),
      remediation: 'Replace with a certificate issued by a trusted CA.', url: ctx.target }));
  }
  const proto = (result.protocol ?? '').toUpperCase();
  if (proto && !/TLSv?1\.[23]/.test(proto)) {
    ctx.emitFinding(buildFinding({ severity: 'medium', category: 'TLS / Certificate',
      title: 'Weak TLS Protocol', owasp: 'A02:2021', cwe: 'CWE-326',
      description: `The server negotiated ${proto}, which is deprecated and vulnerable to known downgrade/crypto attacks.`,
      evidence: `Negotiated: ${proto}`,
      remediation: 'Disable TLS 1.0/1.1 and require TLS 1.2 or 1.3.', url: ctx.target }));
  }
  ctx.emitProgress('TLS / Certificate', `Certificate issuer: ${cert.issuer?.O ?? cert.issuer?.CN ?? 'unknown'}`);
}

// XSS
const PROBE = 'SENTINEL_PROBE_8821';
const XSS_PAYLOAD = `"><img src=x onerror=alert('SENTINEL_XSS')>`;

async function checkXss(ctx) {
  const pages = [ctx.target, ...ctx.discovered.filter((u) => sameOrigin(u, ctx))];
  const points = [];
  for (const p of pages) {
    for (const field of Object.keys(parseQueryParams(p))) points.push({ method: 'GET', url: p, field });
  }
  ctx.emitProgress('Reflected XSS', `Crawling ${pages.length} page(s) for injection points`);
  await mapLimit(pages, 3, async (p) => {
    const page = await request(p, { method: 'GET' });
    if (page.error) return;
    for (const form of extractFormFields(page.body)) {
      const action = resolveUrl(p, form.action || p);
      if (!sameOrigin(action, ctx)) continue;
      for (const field of form.fields) points.push({ method: form.method, url: action, field });
    }
  });
  ctx.emitProgress('Reflected XSS', `Found ${points.length} injection point(s)`);
  const seen = new Set();
  await mapLimit(points, 3, async (point) => {
    const key = `${point.method}:${point.url}:${point.field}`;
    if (seen.has(key)) return;
    seen.add(key);
    const probe = await sendParam(point, PROBE);
    if (probe.error || !probe.body.includes(PROBE)) return;
    const attack = await sendParam(point, XSS_PAYLOAD);
    if (attack.error) return;
    const reflected = attack.body.toLowerCase().includes(`onerror=alert('sentinel_xss')`) || attack.body.includes(XSS_PAYLOAD);
    if (reflected && !attack.body.includes('&lt;img')) {
      ctx.emitFinding(buildFinding({
        severity: 'high', category: 'Injection',
        title: 'Reflected Cross-Site Scripting (XSS)', owasp: 'A03:2021', cwe: 'CWE-79',
        description: `User input in parameter "${point.field}" is reflected into the HTML response without output encoding, allowing arbitrary script execution in the victim’s browser.`,
        evidence: `Parameter "${point.field}" reflected payload: ${XSS_PAYLOAD}`,
        remediation: 'Contextually encode all output (HTML/attribute/JS context) and deploy a strict Content-Security-Policy. Validate input server-side.',
        url: point.url, param: point.field,
      }));
    }
  });
}

// SQLi
const ERROR_PAYLOAD = `'`;
const TRUE_PAYLOAD = `' OR '1'='1`;
const FALSE_PAYLOAD = `' OR '1'='2`;

async function checkSqli(ctx) {
  const pages = [ctx.target, ...ctx.discovered.filter((u) => sameOrigin(u, ctx))];
  const points = [];
  for (const p of pages) {
    for (const field of Object.keys(parseQueryParams(p))) points.push({ method: 'GET', url: p, field });
  }
  ctx.emitProgress('SQL Injection', `Crawling ${pages.length} page(s) for injection points`);
  await mapLimit(pages, 3, async (p) => {
    const page = await request(p, { method: 'GET' });
    if (page.error) return;
    for (const form of extractFormFields(page.body)) {
      const action = resolveUrl(p, form.action || p);
      if (!sameOrigin(action, ctx)) continue;
      for (const field of form.fields) points.push({ method: form.method, url: action, field });
    }
  });
  ctx.emitProgress('SQL Injection', `Testing ${points.length} injection point(s)`);
  const seen = new Set();
  await mapLimit(points, 3, async (point) => {
    const key = `${point.method}:${point.url}:${point.field}`;
    if (seen.has(key)) return;
    seen.add(key);
    const errRes = await sendParam(point, ERROR_PAYLOAD);
    if (!errRes.error && errRes.status !== 0) {
      for (const sig of SQL_ERROR_SIGNATURES) {
        if (sig.re.test(errRes.body)) {
          ctx.emitFinding(buildFinding({
            severity: 'high', category: 'Injection',
            title: 'SQL Injection (Error-Based)', owasp: 'A03:2021', cwe: 'CWE-89',
            description: `Injecting a single quote into "${point.field}" produced a database error, indicating unsanitised SQL string concatenation.`,
            evidence: `Matched ${sig.db} error signature after payload: ${ERROR_PAYLOAD}`,
            remediation: 'Use parameterised queries / prepared statements and ORM bindings. Never concatenate user input into SQL.',
            url: point.url, param: point.field,
          }));
          return;
        }
      }
    }
    const [t, f] = await Promise.all([sendParam(point, TRUE_PAYLOAD), sendParam(point, FALSE_PAYLOAD)]);
    if (t.error || f.error) return;
    const diff = Math.abs(t.body.length - f.body.length);
    if (diff > 40 && t.status === 200) {
      ctx.emitFinding(buildFinding({
        severity: 'medium', category: 'Injection',
        title: 'Potential SQL Injection (Boolean-Blind)', owasp: 'A03:2021', cwe: 'CWE-89',
        description: `Responses to TRUE ("${TRUE_PAYLOAD}") and FALSE ("${FALSE_PAYLOAD}") payloads differ materially (${diff} bytes), suggesting a conditionally evaluated query.`,
        evidence: `TRUE length=${t.body.length}, FALSE length=${f.body.length}`,
        remediation: 'Switch to parameterised queries and validate input types server-side; confirm with manual testing.',
        url: point.url, param: point.field,
      }));
    }
  });
}

// 敏感信息泄露
async function scanSecretsAt(ctx, url) {
  const res = await request(url, { method: 'GET' });
  if (res.error || res.status === 0) return;
  for (const p of SECRET_PATTERNS) {
    const matches = res.body.match(p.re);
    if (matches && matches.length > 0) {
      const sample = matches[0].slice(0, 64);
      ctx.emitFinding(buildFinding({
        severity: p.severity, category: 'Sensitive Data Exposure',
        title: `Possible ${p.name} Exposed`, owasp: 'A02:2021', cwe: 'CWE-798',
        description: `The response body contains a pattern resembling a ${p.name}. Secrets reachable from the client can be harvested and abused immediately.`,
        evidence: `Matched: ${sample}${sample.length >= 64 ? '…' : ''}`,
        remediation: 'Never embed secrets in frontend code or responses. Rotate any exposed credential and load secrets from a backend vault / env at runtime.',
        url: res.url,
      }));
    }
  }
  const commentRe = /<!--([\s\S]*?)-->/g;
  const leakWords = /password|secret|token|api[_-]?key|private|admin/i;
  let cm, count = 0;
  while ((cm = commentRe.exec(res.body)) && count < 5) {
    if (leakWords.test(cm[1])) {
      count += 1;
      ctx.emitFinding(buildFinding({
        severity: 'low', category: 'Sensitive Data Exposure',
        title: 'Sensitive Keyword in HTML Comment', owasp: 'A05:2021', cwe: 'CWE-200',
        description: 'An HTML comment contains security-sensitive keywords and is visible to anyone viewing the source.',
        evidence: `Comment: ${cm[1].trim().slice(0, 80)}`,
        remediation: 'Remove comments that reveal implementation details, credentials, or internal paths before deployment.',
        url: res.url,
      }));
    }
  }
}

async function checkSecrets(ctx) {
  // 扫描着陆页 + 登录后才出现的页面，后者往往比公开页漏更多 PII
  const pages = [ctx.target, ...ctx.discovered.filter((u) => sameOrigin(u, ctx))];
  const uniq = [...new Set(pages)];
  ctx.emitProgress('Sensitive Data Exposure', `Scanning ${uniq.length} page(s) for leaked secrets / PII`);
  await mapLimit(uniq, 4, (url) => scanSecretsAt(ctx, url));
}

// 端点发现
async function checkEndpoints(ctx) {
  const targets = COMMON_PATHS.map((p) => resolveUrl(ctx.baseUrl, p));
  ctx.emitProgress('Endpoint Discovery', `Probing ${targets.length} common paths`);
  await mapLimit(targets, 5, async (url) => {
    const res = await request(url, { method: 'GET', redirect: 'manual' });
    const found = [200, 201, 301, 302, 307, 308, 401, 403, 405, 500].includes(res.status);
    if (!found) return;
    ctx.discovered.push(url);
    const severity = res.status === 500 ? 'medium'
      : (res.status === 401 || res.status === 403) ? 'low' : 'info';
    const note = res.status === 401 ? 'Requires authentication (may be admin/protected area)'
      : res.status === 403 ? 'Forbidden but exists (interesting for further testing)'
      : res.status >= 300 && res.status < 400 ? 'Redirects (may reveal internal routes)'
      : 'Accessible resource';
    ctx.emitFinding(buildFinding({
      severity, category: 'Information Disclosure',
      title: `Exposed Path: ${url.replace(ctx.baseUrl, '') || '/'}`, owasp: 'A05:2021', cwe: 'CWE-538',
      description: `${note}. Discoverable endpoints widen the attack surface and often hide unauthenticated functionality.`,
      evidence: `GET ${url} → HTTP ${res.status}`,
      remediation: 'Remove unused endpoints, enforce auth on sensitive ones, and avoid revealing internal structure.', url,
    }));
  });
}

// CSRF
const CSRF_TOKEN_RE = /(csrf|_token|token|authenticity|xsrf|anticsrf)/i;

async function checkCsrf(ctx) {
  const res = await request(ctx.target, { method: 'GET' });
  if (res.error || res.status === 0) return;
  ctx.emitProgress('Cross-Site Request Forgery', 'Inspecting state-changing forms');
  const hasSameSite = res.cookies.some((c) => /samesite=/i.test(c));
  if (hasSameSite) {
    ctx.emitProgress('Cross-Site Request Forgery', 'SameSite cookies present — CSRF risk mitigated');
    return;
  }
  const forms = extractFormFields(res.body).filter((f) => f.method === 'POST' && sameOrigin(resolveUrl(ctx.target, f.action || ctx.target), ctx));
  ctx.emitProgress('Cross-Site Request Forgery', `Found ${forms.length} POST form(s)`);
  forms.forEach((form) => {
    const hasToken = form.fields.some((field) => CSRF_TOKEN_RE.test(field));
    if (!hasToken) {
      const action = resolveUrl(ctx.target, form.action || ctx.target);
      ctx.emitFinding(buildFinding({
        severity: 'medium', category: 'Cross-Site Request Forgery',
        title: 'State-Changing Form Without CSRF Token', owasp: 'A01:2021', cwe: 'CWE-352',
        description: `A POST form submitting to "${action}" has no anti-CSRF token field and no SameSite cookie was observed, allowing an attacker to forge cross-site requests on behalf of an authenticated user.`,
        evidence: `Form fields: ${form.fields.join(', ') || '(none)'} — no CSRF token detected`,
        remediation: 'Add a server-validated, unpredictable anti-CSRF token to every state-changing form (paired with SameSite=Lax cookies).',
        url: action,
      }));
    }
  });
}

// 开放重定向
const REDIRECT_PARAMS = ['next', 'url', 'redirect', 'return', 'r', 'to', 'target'];
const OFF_ORIGIN = 'https://oast.sentinel.example';

async function checkOpenRedirect(ctx) {
  ctx.emitProgress('Open Redirect', `Probing ${REDIRECT_PARAMS.length} redirect parameters`);
  let flagged = false;
  await mapLimit(REDIRECT_PARAMS, 3, async (param) => {
    if (flagged) return;
    const u = new URL(ctx.target);
    u.searchParams.set(param, OFF_ORIGIN);
    const res = await request(u.toString(), { method: 'GET', redirect: 'manual' });
    const loc = res.headers['location'];
    if (!loc) return;
    let target;
    try { target = new URL(loc, ctx.target); } catch { target = null; }
    if (target && target.host !== ctx.host) {
      flagged = true;
      ctx.emitFinding(buildFinding({
        severity: 'medium', category: 'Open Redirect',
        title: 'Unvalidated Redirect (Open Redirect)', owasp: 'A01:2021', cwe: 'CWE-601',
        description: `Parameter "${param}" is reflected into a redirect Location header pointing off-origin (${target.host}), enabling phishing by abusing the site’s trusted domain.`,
        evidence: `GET ${u.pathname}?${param}=${OFF_ORIGIN} → 3xx Location: ${loc}`,
        remediation: 'Allow-list redirect destinations or require same-origin relative paths; never pass user input straight into a redirect.',
        url: u.toString(), param,
      }));
    }
  });
}

// CORS
const PROBE_ORIGIN = 'https://oast.sentinel.example';

async function checkCors(ctx) {
  ctx.emitProgress('CORS Misconfiguration', 'Sending cross-origin preflight probe');
  const res = await request(ctx.target, { method: 'GET', headers: { Origin: PROBE_ORIGIN } });
  if (res.error || res.status === 0) return;
  const acao = res.headers['access-control-allow-origin'];
  const acac = res.headers['access-control-allow-credentials'];
  if (!acao) {
    ctx.emitProgress('CORS Misconfiguration', 'No CORS headers present — nothing to flag');
    return;
  }
  const reflects = acao === PROBE_ORIGIN || acao === 'null' || acao === '*';
  if (!reflects) {
    ctx.emitProgress('CORS Misconfiguration', `ACAO fixed to ${acao} — not exploitable`);
    return;
  }
  const withCreds = acac === 'true';
  if ((acao === PROBE_ORIGIN || acao === 'null') && withCreds) {
    ctx.emitFinding(buildFinding({
      severity: 'high', category: 'CORS Misconfiguration',
      title: 'CORS Allows Arbitrary Origin With Credentials',
      owasp: 'A05:2021', cwe: 'CWE-942',
      description: 'The server reflects the caller’s Origin into Access-Control-Allow-Origin and sends Access-Control-Allow-Credentials: true. Any website can read authenticated, same-origin responses (PII, CSRF tokens, API data) on behalf of a logged-in victim.',
      evidence: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
      remediation: 'Never echo arbitrary origins together with credentials. Restrict ACAO to an explicit allow-list and drop ACA-Credentials unless strictly required.',
      url: ctx.target,
    }));
  } else if (acao === '*' && withCreds) {
    ctx.emitFinding(buildFinding({
      severity: 'medium', category: 'CORS Misconfiguration',
      title: 'Wildcard ACAO Combined With Credentials',
      owasp: 'A05:2021', cwe: 'CWE-942',
      description: 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is ignored by browsers, but the configuration signals a misunderstanding of CORS and may become exploitable if later narrowed to a dynamic origin.',
      evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: ${acac}`,
      remediation: 'Remove the credentials flag or pin ACAO to known origins; do not combine wildcard ACAO with credentials.',
      url: ctx.target,
    }));
  } else {
    ctx.emitFinding(buildFinding({
      severity: 'medium', category: 'CORS Misconfiguration',
      title: 'CORS Reflects Arbitrary Origin',
      owasp: 'A05:2021', cwe: 'CWE-942',
      description: 'Access-Control-Allow-Origin reflects the caller’s Origin, so any site can read cross-origin responses that the endpoint exposes. Exploitable when the endpoint returns sensitive data without requiring credentials.',
      evidence: `Access-Control-Allow-Origin: ${acao}`,
      remediation: 'Replace dynamic origin reflection with a static allow-list of trusted domains.',
      url: ctx.target,
    }));
  }
}

// 路径遍历 / LFI
const TRAVERSAL_PAYLOADS = [
  { raw: '../../../../../../etc/passwd', label: '../../../../../../etc/passwd' },
  { raw: '....//....//....//....//etc/passwd', label: '....// nested' },
  { raw: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd', label: 'URL-encoded ..%2f' },
  { raw: '..%252f..%252f..%252fetc/passwd', label: 'double-encoded ..%252f' },
];

async function checkTraversal(ctx) {
  const candidates = [];
  const qp = parseQueryParams(ctx.target);
  if (Object.keys(qp).some((k) => FILE_PARAMS.includes(k.toLowerCase()))) candidates.push(ctx.target);
  for (const ep of ['download', 'file', 'files', 'read', 'get', 'view', 'attachment', 'doc', 'load', 'fetch']) {
    candidates.push(resolveUrl(ctx.baseUrl, ep));
  }
  ctx.emitProgress('Path Traversal', `Identifying file-read endpoints (${candidates.length} candidates)`);

  await mapLimit(candidates, 4, async (base) => {
    // 先用一个良性 file 参数探一下，确认这端点确实消费文件参数，免得对着 404 乱发载荷
    const probeUrl = base.includes('?') ? `${base}&file=sentinel-probe.txt` : `${base}?file=sentinel-probe.txt`;
    const probe = await request(probeUrl, { method: 'GET', redirect: 'manual' });
    if (probe.error || [404, 405, 410].includes(probe.status)) return;
    for (const p of TRAVERSAL_PAYLOADS) {
      const u = base.includes('?') ? `${base}&file=${p.raw}` : `${base}?file=${encodeURIComponent(p.raw)}`;
      const res = await request(u, { method: 'GET', redirect: 'manual' });
      if (res.error) continue;
      for (const sig of LFI_SIGNATURES) {
        if (sig.re.test(res.body)) {
          ctx.emitFinding(buildFinding({
            severity: 'high', category: 'Path Traversal',
            title: 'Local File Inclusion / Path Traversal', owasp: 'A01:2021', cwe: 'CWE-22',
            description: `A file-read parameter on this endpoint fails to sanitise "../" sequences, allowing the server to be coerced into returning ${sig.os} system files. Payload "${p.label}" produced OS file content in the response.`,
            evidence: `GET ${u}\n→ matched ${sig.os} signature (${sig.re.source.slice(0, 24)}…)`,
            remediation: 'Canonicalise and validate the resolved path against an allow-listed base directory; reject ".." and null bytes; serve files via an indirection map rather than user-supplied paths.',
            url: base, param: 'file',
          }));
          return;
        }
      }
    }
  });
}

// JWT
function b64urlDecode(s) {
  let t = s.replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  try { return Buffer.from(t, 'base64').toString('utf8'); } catch { return ''; }
}

async function checkJwt(ctx) {
  ctx.emitProgress('JWT Security', 'Extracting and decoding JWTs from the landing response');
  const res = await request(ctx.target, { method: 'GET' });
  if (res.error || res.status === 0) return;
  const tokens = res.body.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g) || [];
  const seen = new Set();
  for (const token of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);
    const parts = token.split('.');
    let header = {};
    try { header = JSON.parse(b64urlDecode(parts[0])); } catch {}
    const alg = String(header.alg ?? '').toLowerCase();

    if (alg === 'none' || (alg === '' && parts[2] === '')) {
      ctx.emitFinding(buildFinding({
        severity: 'critical', category: 'JWT Security',
        title: 'JWT Signed With "none" Algorithm', owasp: 'A02:2021', cwe: 'CWE-347',
        description: 'The token’s header declares alg "none", meaning the server is (or can be tricked into) accepting unsigned tokens. An attacker can forge any Claims (e.g. {"role":"admin"}) and strip the signature.',
        evidence: `header: ${parts[0]}. (alg=none)`,
        remediation: 'Reject alg:none server-side; enforce an explicit allow-list of signing algorithms (e.g. RS256) and verify the signature against a pinned key before trusting any claim.',
        url: ctx.target,
      }));
      continue;
    }
    if (/^hs(256|384|512)$/.test(alg) && typeof header.kid === 'string') {
      const kid = header.kid;
      if (/\.\./.test(kid) || /[\0'"]/.test(kid)) {
        ctx.emitFinding(buildFinding({
          severity: 'medium', category: 'JWT Security',
          title: 'JWT "kid" Header May Enable Key Injection', owasp: 'A08:2021', cwe: 'CWE-502',
          description: 'The JWT "kid" (key ID) header contains path or metacharacters, a known vector for path traversal / SQL injection in the key-lookup step of symmetric verification.',
          evidence: `header.kid = "${kid}"`,
          remediation: 'Treat "kid" as untrusted: validate it against a strict allow-list and never interpolate it directly into file paths or SQL. Prefer asymmetric (RS/ES) algorithms.',
          url: ctx.target,
        }));
      }
    }
    if (typeof header.jku === 'string' && /^https?:/i.test(header.jku)) {
      ctx.emitFinding(buildFinding({
        severity: 'medium', category: 'JWT Security',
        title: 'JWT "jku" Points to Attacker-Controllable Key URL', owasp: 'A08:2021', cwe: 'CWE-346',
        description: 'The "jku" (JWK Set URL) header tells the verifier to fetch the signing key from a URL. If not strictly allow-listed, an attacker can host a key they control and forge tokens.',
        evidence: `header.jku = "${header.jku}"`,
        remediation: 'Ignore client-supplied "jku"/"x5u" entirely; resolve keys only from a trusted, server-side configuration.',
        url: ctx.target,
      }));
    }
  }
  if (tokens.length > 0) {
    ctx.emitProgress('JWT Security', `Decoded ${tokens.length} JWT token(s)`);
  }
}

// SSRF
const SSRF_PARAMS = ['url', 'uri', 'dest', 'redirect_uri', 'image', 'img', 'avatar', 'remote', 'site', 'page', 'load', 'proxy', 'r', 'u', 'file', 'path', 'to', 'target'];
const SSRF_ENDPOINTS = ['fetch', 'proxy', 'load', 'api/fetch', 'api/proxy', 'demo/fetch', 'demo/proxy', 'read'];
const SSRF_INTERNAL = '/internal/admin-data'; // 只有 SSRF 才够得着的隐藏端点
const SSRF_MARKERS = ['INTERNAL_SECRET', 'only reachable from internal'];

async function checkSsrf(ctx) {
  ctx.emitProgress('Server-Side Request Forgery', 'Probing server-side fetch endpoints');
  const internal = `http://${ctx.host}${SSRF_INTERNAL}`;
  const pages = [ctx.target, ...ctx.discovered.filter((u) => sameOrigin(u, ctx))];
  const candidates = SSRF_ENDPOINTS.map((ep) => resolveUrl(ctx.baseUrl, ep));
  const paramPages = new Set();
  for (const p of pages) {
    paramPages.add(p);
    for (const k of Object.keys(parseQueryParams(p))) if (SSRF_PARAMS.includes(k.toLowerCase())) paramPages.add(p);
  }
  let found = false;
  await mapLimit([...candidates, ...paramPages], 4, async (target) => {
    if (found) return;
    const u = new URL(target);
    const known = Object.keys(parseQueryParams(target)).find((k) => SSRF_PARAMS.includes(k.toLowerCase()));
    const paramName = known || 'url';
    u.searchParams.set(paramName, internal);
    const res = await request(u.toString(), { method: 'GET', redirect: 'manual', timeout: 6000 });
    if (res.error) return;
    if (SSRF_MARKERS.some((m) => res.body.includes(m))) {
      found = true;
      ctx.emitFinding(buildFinding({
        severity: 'high', category: 'Server-Side Request Forgery',
        title: 'Server-Side Request Forgery (SSRF)', owasp: 'A10:2021', cwe: 'CWE-918',
        description: `A server-side fetch endpoint forwards attacker-controlled URLs and returns the response body. The scanner supplied an internal-only URL (${internal}) and the server fetched it and disclosed the result, proving the app can be coerced into reaching internal network resources (metadata services, admin endpoints, cloud credential stores).`,
        evidence: `GET ${u.pathname}?${paramName}=${internal}\n→ response contained internal marker (${SSRF_MARKERS.join(' / ').slice(0, 36)}…)`,
        remediation: 'Never fetch user-supplied URLs server-side. Allow-list schemes/hosts, block link-local & metadata ranges (169.254.169.254, 127.0.0.0/8, ::1), disable follow-redirects, and add DNS-rebinding protection.',
        url: target, param: paramName,
      }));
    }
  });
}

// XXE
const XXE_ENDPOINTS = ['api/xml', 'xml', 'soap', 'upload', 'demo/xml', 'parse', 'import'];
const XXE_PAYLOADS = [
  { os: 'Windows', xml: `<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]><r>&xxe;</r>` },
  { os: 'Linux', xml: `<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><r>&xxe;</r>` },
];

async function checkXxe(ctx) {
  ctx.emitProgress('XML External Entity (XXE)', 'Probing XML-parsing endpoints');
  const candidates = XXE_ENDPOINTS.map((ep) => resolveUrl(ctx.baseUrl, ep));
  let found = false;
  await mapLimit(candidates, 3, async (ep) => {
    if (found) return;
    const benign = await request(ep, {
      method: 'POST', headers: { 'Content-Type': 'application/xml' },
      body: '<?xml version="1.0"?><r>ok</r>', redirect: 'manual',
    });
    if (benign.error || [404, 405, 410, 400].includes(benign.status)) return;
    for (const p of XXE_PAYLOADS) {
      const res = await request(ep, {
        method: 'POST', headers: { 'Content-Type': 'application/xml' },
        body: p.xml, redirect: 'manual',
      });
      if (res.error) continue;
      const disclosed =
        /root:x:\d+:\d+/i.test(res.body) ||          // /etc/passwd
        /\[extensions\]/i.test(res.body) ||          // windows win.ini
        /for 16-bit app support/i.test(res.body);
      if (disclosed) {
        found = true;
        ctx.emitFinding(buildFinding({
          severity: 'high', category: 'XML External Entity (XXE)',
          title: 'XML External Entity (XXE) Injection', owasp: 'A05:2021', cwe: 'CWE-611',
          description: 'The endpoint parses attacker-supplied XML with external-entity resolution enabled. Injecting an external ENTITY referencing a local file caused the server to read and return its contents — a local file was disclosed in the response.',
          evidence: `POST ${ep}\nContent-Type: application/xml\n<!ENTITY xxe SYSTEM "file:///…">\n→ response disclosed local file content (${p.os})`,
          remediation: 'Disable DTD / external-entity processing in the XML parser (e.g. XMLConstants.ACCESS_EXTERNAL_DTD & ACCESS_EXTERNAL_ENTITY → "all"/disallow), use a hardened parser config, and validate against a strict schema.',
          url: ep,
        }));
        return;
      }
    }
  });
}

// 顺序：先做被动检查 + 端点发现，再做主动注入；端点发现提前跑，
// 让它挖到的页面能喂给后面的蜘蛛式检测（XSS/SQLi/密钥）
const CHECKS = [
  { name: 'Security Headers', run: checkHeaders },
  { name: 'Endpoint Discovery', run: checkEndpoints },
  { name: 'Cookie Security', run: checkCookies },
  { name: 'TLS / Certificate', run: checkSsl },
  { name: 'Sensitive Data Exposure', run: checkSecrets },
  { name: 'Cross-Site Request Forgery', run: checkCsrf },
  { name: 'Open Redirect', run: checkOpenRedirect },
  { name: 'CORS Misconfiguration', run: checkCors },
  { name: 'Path Traversal', run: checkTraversal },
  { name: 'JWT Security', run: checkJwt },
  { name: 'Server-Side Request Forgery', run: checkSsrf },
  { name: 'XML External Entity (XXE)', run: checkXxe },
  { name: 'Reflected XSS', run: checkXss },
  { name: 'SQL Injection', run: checkSqli },
];

module.exports = { CHECKS };
// spider runs after endpoint discovery
