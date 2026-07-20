
const DEFAULT_TIMEOUT = 12000;

// 认证扫描时存一下抓到的会话 cookie，只挂到同源请求上
// 不然把 cookie 带给 SSRF/CORS 那些离站探测目标就泄了
let _authCookie = '';
let _authHost = '';
function setAuth(cookie, host) { _authCookie = cookie || ''; _authHost = host || ''; }

async function request(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeout ?? DEFAULT_TIMEOUT);
  const start = Date.now();

  const headers = {
    'User-Agent': 'Sentinel-Scanner/1.0 (+https://github.com/sentinel-scanner)',
    'Accept': 'text/html,application/xhtml+xml,application/xml,application/json,*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    ...(opts.headers ?? {}),
  };

  if (_authCookie) {
    try {
      const uh = new URL(url);
      if (uh.host === _authHost) headers['Cookie'] = _authCookie;
    } catch {}
  }

  try {
    const res = await fetch(url, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body,
      redirect: opts.redirect ?? 'follow',
      signal: controller.signal,
    });
    const buf = await res.arrayBuffer();
    const body = Buffer.from(buf).toString('utf8');
    const normHeaders = {};
    res.headers.forEach((v, k) => { normHeaders[k.toLowerCase()] = v; });

    let cookies = [];
    const anyRes = res;
    if (typeof anyRes.getSetCookie === 'function') cookies = anyRes.getSetCookie();
    else if (normHeaders['set-cookie']) cookies = normHeaders['set-cookie'].split(',');

    return {
      ok: res.ok, status: res.status, statusText: res.statusText,
      url: res.url, headers: normHeaders, cookies, body, durationMs: Date.now() - start,
    };
  } catch (err) {
    return {
      ok: false, status: 0, statusText: 'ERROR', url,
      headers: {}, cookies: [], body: '',
      durationMs: Date.now() - start, error: err?.message ?? String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

// 限制并发数的小工具，避免一次性把目标打爆
async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return results;
}

module.exports = { request, mapLimit, setAuth };
// setAuth only attaches cookie on same-origin requests
