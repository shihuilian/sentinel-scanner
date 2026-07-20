'use strict';


const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const SEV_LABEL_EN = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
const RAIL_LABEL = {
  'Security Headers': 'Headers', 'Cookie Security': 'Cookies', 'TLS / Certificate': 'TLS',
  'Sensitive Data Exposure': 'Secrets', 'Endpoint Discovery': 'Endpoints',
  'Cross-Site Request Forgery': 'CSRF', 'Open Redirect': 'Open Redirect',
  'CORS Misconfiguration': 'CORS', 'Path Traversal': 'LFI', 'JWT Security': 'JWT',
  'Server-Side Request Forgery': 'SSRF', 'XML External Entity (XXE)': 'XXE',
  'Reflected XSS': 'XSS', 'SQL Injection': 'SQLi',
};

const $ = (id) => document.getElementById(id);

function applyTheme(theme) {
  const root = document.documentElement;
  root.dataset.theme = theme === 'system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : theme;
  localStorage.setItem('sentinel-theme', theme);
  document.querySelectorAll('.theme-switch button').forEach((b) =>
    b.classList.toggle('is-active', b.dataset.themeSet === theme));
  if (window.__refreshCanvas) window.__refreshCanvas();
}
let theme = localStorage.getItem('sentinel-theme') || 'system';
applyTheme(theme);
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (theme === 'system') applyTheme('system'); });
document.querySelectorAll('.theme-switch button').forEach((b) =>
  b.addEventListener('click', () => { theme = b.dataset.themeSet; applyTheme(theme); }));

(function threatField() {
  const canvas = $('threatfield');
  const ctx = canvas.getContext('2d');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let w = 0, h = 0, dpr = 1, nodes = [], mouse = { x: -9999, y: -9999 }, raf = null;
  let colNode = '150,160,180', colLine = '232,176,75';

  function readColors() {
    const cs = getComputedStyle(document.documentElement);
    const accent = cs.getPropertyValue('--accent').trim();
    colLine = hexToRgb(accent) || '232,176,75';
    const faint = cs.getPropertyValue('--text-faint').trim();
    colNode = hexToRgb(faint) || '150,160,180';
  }
  window.__refreshCanvas = readColors;

  function hexToRgb(str) {
    if (!str) return null;
    str = str.replace('#', '');
    if (str.length === 3) str = str.split('').map((c) => c + c).join('');
    const n = parseInt(str, 16);
    if (Number.isNaN(n)) return null;
    return `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}`;
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.min(90, Math.floor((w * h) / 18000));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.22, vy: (Math.random() - 0.5) * 0.22,
    }));
  }

  function frame() {
    ctx.clearRect(0, 0, w, h);
    const D = 132, R = 190;
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > w) n.vx *= -1;
      if (n.y < 0 || n.y > h) n.vy *= -1;
    }
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.hypot(dx, dy);
        if (dist < D) {
          const alpha = (1 - dist / D) * 0.16;
          ctx.strokeStyle = `rgba(${colNode},${alpha})`;
          ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
      const mdx = a.x - mouse.x, mdy = a.y - mouse.y;
      const mdist = Math.hypot(mdx, mdy);
      if (mdist < R) {
        const alpha = (1 - mdist / R) * 0.5;
        ctx.strokeStyle = `rgba(${colLine},${alpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
      }
      ctx.fillStyle = `rgba(${colNode},0.55)`;
      ctx.beginPath(); ctx.arc(a.x, a.y, 1.6, 0, Math.PI * 2); ctx.fill();
    }
    raf = requestAnimationFrame(frame);
  }

  function start() { if (!raf && !reduce) frame(); else if (reduce) { frame(); cancelAnimationFrame(raf); raf = null; } }
  function stop() { if (raf) cancelAnimationFrame(raf); raf = null; }

  readColors(); resize();
  if (reduce) { frame(); stop(); } else { start(); }
  window.addEventListener('resize', () => { resize(); if (reduce) { frame(); stop(); } });
  window.addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY; });
  window.addEventListener('mouseleave', () => { mouse.x = -9999; mouse.y = -9999; });
  document.addEventListener('visibilitychange', () => { document.hidden ? stop() : start(); });
})();

const targetInput = $('target');
const startBtn = $('startBtn');
const scanView = $('scanView');
const rail = $('rail');
const progressFill = $('progressFill');
const scanPct = $('scanPct');
const logEl = $('log');
const errorBox = $('errorBox');
const errorMsg = $('errorMsg');
const results = $('results');
const statusPill = $('statusPill');
const statusText = $('statusText');

targetInput.value = `${window.location.origin}/demo`;

let es = null, findings = [], summary = null, filter = 'all', status = 'idle';
const railNodes = {};

function ts() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}
function logLine(text, cls = 'l-sys') {
  const span = document.createElement('div');
  span.className = cls;
  span.textContent = `${ts()}  ${text}`;
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}
function setStatus(state, text) {
  statusPill.classList.toggle('is-live', state === 'live');
  statusPill.classList.toggle('is-error', state === 'error');
  statusText.textContent = text;
}

function startScan() {
  const target = targetInput.value.trim();
  if (!target || status === 'scanning') return;
  if (es) es.close();

  status = 'scanning'; findings = []; summary = null; filter = 'all';
  rail.innerHTML = ''; logEl.innerHTML = ''; railNodes.__idx = 0;
  Object.keys(railNodes).forEach((k) => delete railNodes[k]);
  errorBox.hidden = true; results.hidden = true; scanView.hidden = false;
  progressFill.style.width = '0%'; scanPct.textContent = '0%';
  startBtn.disabled = true;
  startBtn.querySelector('.btn-scan__label').textContent = '扫描中…';
  setStatus('live', '侦察中');

  const cookie = $('cookie').value.trim();
  const payload = { target };
  if (cookie) payload.cookie = cookie;

  fetch('/api/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then((r) => (r.ok ? r.json() : r.json().then((e) => Promise.reject(new Error(e.error || `HTTP ${r.status}`)))))
    .then(({ id }) => {
      es = new EventSource(`/api/scan/${id}/events`);
      es.onmessage = (ev) => handleEvent(JSON.parse(ev.data));
      es.onerror = () => { if (status === 'scanning') finishError('与扫描流连接中断'); if (es) es.close(); };
    })
    .catch((e) => finishError(e.message));
}

function handleEvent(e) {
  if (e.type === 'start') {
    logLine(`▶ SCAN ${e.target} · ${e.checks.length} checks queued`, 'l-sys');
    e.checks.forEach((name, i) => {
      const el = document.createElement('div');
      el.className = 'node';
      el.innerHTML = `<span class="node__dot"></span>${RAIL_LABEL[name] || name}`;
      rail.appendChild(el);
      railNodes[i] = el;
    });
  } else if (e.type === 'check-start') {
    const el = railNodes[e.index - 1];
    if (el) el.className = 'node is-running';
  } else if (e.type === 'check-done') {
    const el = railNodes[e.index - 1];
    if (el) el.className = 'node is-done';
    const pct = e.total ? Math.round((e.index / e.total) * 100) : 0;
    progressFill.style.width = pct + '%'; scanPct.textContent = pct + '%';
  } else if (e.type === 'progress') {
    logLine(`[${String(e.index).padStart(2, '0')}/${e.total}] ${e.check} — ${e.message}`);
  } else if (e.type === 'finding') {
    findings.push(e.finding);
    logLine(`⚠ ${SEV_LABEL_EN[e.finding.severity]}  ${e.finding.title}`, 'l-find');
  } else if (e.type === 'done') {
    summary = e.summary;
    status = 'done';
    logLine(`✓ COMPLETE · ${e.summary.total} findings · ${e.summary.riskScore}/100 risk · ${(e.summary.durationMs / 1000).toFixed(2)}s`, 'l-ok');
    if (es) es.close();
    setStatus('idle', '完成');
    renderResults();
  } else if (e.type === 'error') {
    finishError(e.message);
  }
}

function finishError(msg) {
  status = 'error';
  scanView.hidden = true; errorBox.hidden = false; errorMsg.textContent = msg;
  startBtn.disabled = false;
  startBtn.querySelector('.btn-scan__label').textContent = '开始扫描';
  setStatus('error', '中止');
  logLine(`✕ ERROR ${msg}`, 'l-err');
}

const GAUGE_LEN = Math.PI * 88;

function renderResults() {
  scanView.hidden = true; results.hidden = false;
  startBtn.disabled = false;
  startBtn.querySelector('.btn-scan__label').textContent = '开始扫描';

  $('reportTarget').textContent = summary.target;
  $('factDuration').textContent = (summary.durationMs / 1000).toFixed(2) + 's';
  $('factTotal').textContent = String(summary.total);
  $('factTime').textContent = new Date().toLocaleTimeString();

  const gv = $('gaugeValue');
  gv.style.strokeDasharray = GAUGE_LEN;
  gv.style.strokeDashoffset = GAUGE_LEN;
  requestAnimationFrame(() => { gv.style.strokeDashoffset = GAUGE_LEN * (1 - summary.riskScore / 100); });
  countUp($('gaugeNum'), summary.riskScore);
  const band = $('gaugeBand');
  const [bandText, bandColor] = riskBand(summary.riskScore);
  band.textContent = bandText;
  band.style.color = bandColor; band.style.borderColor = bandColor;

  const sb = $('severityBar');
  sb.innerHTML = '';
  const total = Math.max(1, summary.total);
  SEVERITY_ORDER.forEach((s) => {
    const c = summary.bySeverity[s];
    if (!c) return;
    const span = document.createElement('span');
    span.className = `sev-${s}`;
    span.style.width = (c / total) * 100 + '%';
    span.title = `${SEV_LABEL[s]}: ${c}`;
    sb.appendChild(span);
  });

  const fb = $('filterBar');
  fb.innerHTML = '';
  const mk = (key, label) => {
    const b = document.createElement('button');
    b.className = 'filter' + (filter === key ? ' is-active' : '');
    b.textContent = label;
    b.onclick = () => { filter = key; renderFindings(); };
    return b;
  };
  fb.appendChild(mk('all', '全部'));
  SEVERITY_ORDER.forEach((s) => {
    if (summary.bySeverity[s]) fb.appendChild(mk(s, `${SEV_LABEL[s]} ${summary.bySeverity[s]}`));
  });

  renderFindings();
}

function countUp(el, target) {
  const dur = 1100, t0 = performance.now();
  function step(now) {
    const p = Math.min(1, (now - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(eased * target);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function riskBand(score) {
  if (score >= 71) return ['严重 CRITICAL', 'var(--sev-critical)'];
  if (score >= 46) return ['高 HIGH', 'var(--sev-high)'];
  if (score >= 21) return ['中 MEDIUM', 'var(--sev-medium)'];
  if (score > 0) return ['低 LOW', 'var(--sev-low)'];
  return ['无 NONE', 'var(--text-faint)'];
}

function renderFindings() {
  const list = (filter === 'all' ? findings : findings.filter((f) => f.severity === filter))
    .slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  [...$('filterBar').children].forEach((b, i) => {
    const key = i === 0 ? 'all' : SEVERITY_ORDER[i - 1];
    b.classList.toggle('is-active', key === filter);
  });

  const wrap = $('findings');
  wrap.innerHTML = '';
  if (!list.length) {
    wrap.innerHTML = '<div class="card" style="padding:26px;text-align:center;color:var(--text-faint)">无符合当前筛选的发现。</div>';
    return;
  }
  list.forEach((f, i) => wrap.appendChild(buildCard(f, i === 0)));
}

function buildCard(f, open) {
  const card = document.createElement('article');
  card.className = `card sev-${f.severity}` + (open ? ' is-open' : '');

  const tags = [f.category, f.owasp, f.cwe].filter(Boolean)
    .map((t) => `<span class="tag">${esc(t)}</span>`).join('');
  const paramTag = f.param ? `<span class="tag tag--param">参数 · ${esc(f.param)}</span>` : '';

  card.innerHTML = `
    <div class="card__head">
      <span class="badge sev-${f.severity}">${SEV_LABEL[f.severity]}</span>
      <span class="card__title">${esc(f.title)}</span>
      <svg class="card__chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </div>
    <div class="card__tags">${tags}${paramTag}</div>
    <div class="card__body"><div class="card__inner">
      <p class="card__desc">${esc(f.description)}</p>
      ${f.evidence ? `
      <div class="evidence">
        <div class="evidence__bar"><span class="evidence__label">证据 · Evidence</span><button class="copy-btn" data-copy="${esc(f.evidence)}">复制</button></div>
        <pre>${esc(f.evidence)}</pre>
      </div>` : ''}
      <div><div class="field-label">修复建议 · Remediation</div><p class="field-text">${esc(f.remediation)}</p></div>
      ${f.url ? `<a class="card__url" href="${esc(f.url)}" target="_blank" rel="noreferrer">${esc(f.url)} ↗</a>` : ''}
    </div></div>`;

  card.querySelector('.card__head').addEventListener('click', () => card.classList.toggle('is-open'));
  const copyBtn = card.querySelector('.copy-btn');
  if (copyBtn) copyBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(f.evidence).then(() => {
      copyBtn.textContent = '已复制';
      setTimeout(() => (copyBtn.textContent = '复制'), 1400);
    });
  });
  return card;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const METHOD = [
  ['安全头审计', '被动检查 HSTS / CSP / X-Content-Type-Options / X-Frame-Options / Referrer-Policy / Permissions-Policy 是否缺失，并评估 CSP 是否允许 unsafe-inline。'],
  ['Cookie 安全', '解析 Set-Cookie，核查 Secure / HttpOnly / SameSite 标志，识别可被中间人窃取或 XSS 读取的会话凭证。'],
  ['TLS / 证书', '对 HTTPS 目标建立 TLS 握手，检查证书有效期、颁发者可信度、是否自签名，以及协商协议版本（拒绝 TLS 1.0/1.1）。'],
  ['敏感信息泄露', '在着陆页响应中正则匹配密钥模式（AWS / 私钥 / JWT / 内部 IP 等），并扫描 HTML 注释中的敏感关键词。'],
  ['端点探测', '以受限并发探测常见路径（admin / .env / 备份 / 调试接口等），依据状态码评估暴露面。'],
  ['CSRF', '提取同源 POST 表单，检查是否存在服务端校验的反 CSRF Token 字段，或是否依赖 SameSite Cookie 缓解。'],
  ['开放重定向', '对预定义的重定向参数注入离站地址，以 manual 重定向模式读取 Location，若跳转到非同源域名则判定为开放重定向。'],
  ['CORS 配置错误', '携带 Origin 头探测，读取 Access-Control-Allow-Origin 与 Access-Control-Allow-Credentials；若反射任意源且允许凭据，则可被任意站点读取同源认证响应。'],
  ['路径遍历', '对待测的文件读取端点先以良性参数确认其消费 file 参数，再注入 ../、嵌套、URL 编码与双重编码等载荷，依据响应是否泄露系统文件特征判定 LFI。'],
  ['JWT 安全', '从着陆页响应中提取 JWT，Base64URL 解码头部：alg=none 视为签名绕过（严重）；kid 含路径/元字符、jku 指向外部 URL 视为密钥注入/伪造风险。'],
  ['服务端请求伪造 (SSRF)', '针对服务端 fetch / 代理类端点，注入内网地址（含仅供内部访问的隐藏端点），依据响应是否回显内部资源内容判定 SSRF，可借此触达元数据服务与云凭证存储。'],
  ['XML 外部实体 (XXE)', '向 XML 解析端点投递含外部实体的载荷（file:// 引用本地文件），依据响应是否回显本地文件内容判定 XXE 注入。'],
  ['反射型 XSS', '先探针确认参数被原样反射，再注入带事件处理器的 payload，依据是否未编码回显判定漏洞。'],
  ['SQL 注入', '报错型：注入单引号观察数据库错误特征；布尔盲注：对比 TRUE/FALSE payload 的响应长度差。'],
  ['认证态扫描', '支持携带会话 Cookie（或自动登录内置靶机）重跑全部检测，对登录后的受保护页面（如含 PII 的账户页）进行被动与主动审计，模拟攻击者在已认证上下文下的攻击面。'],
];
(function fillMethod() {
  const mb = $('methodBody');
  mb.innerHTML = METHOD.map(([t, d]) => `<div class="method__item"><h4>${t}</h4><p>${d}</p></div>`).join('');
})();

const scanPane = $('scanPane');
const historyPane = $('historyPane');
const navScan = $('navScan');
const navHistory = $('navHistory');

function showView(v) {
  const h = v === 'history';
  scanPane.hidden = h;
  historyPane.hidden = !h;
  navScan.classList.toggle('is-active', !h);
  navHistory.classList.toggle('is-active', h);
  if (h) loadHistory();
}
navScan.addEventListener('click', () => showView('scan'));
navHistory.addEventListener('click', () => showView('history'));

function scoreSeverity(score) {
  if (score >= 71) return 'critical';
  if (score >= 46) return 'high';
  if (score >= 21) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function renderTrend(scans) {
  const el = $('trend');
  if (!scans || scans.length < 2) {
    el.innerHTML = '<span class="trend__note">至少完成两次扫描后，这里会显示风险评分随时间的趋势。</span>';
    return;
  }
  const w = 720, h = 64, pad = 10;
  const vals = scans.slice().reverse().map((s) => s.riskScore); // 从旧到新
  const stepX = (w - pad * 2) / (vals.length - 1);
  const y = (v) => (h - pad - (v / 100) * (h - pad * 2)).toFixed(1);
  const x = (i) => (pad + i * stepX).toFixed(1);
  const pts = vals.map((v, i) => `${x(i)},${y(v)}`).join(' ');
  const dots = vals.map((v, i) => `<circle cx="${x(i)}" cy="${y(v)}" r="2.6" fill="var(--accent)"/>`).join('');
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" class="trend__svg" preserveAspectRatio="none">
    <line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" stroke="var(--border-strong)" stroke-width="1"/>
    <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${dots}
  </svg>`;
}

async function loadHistory() {
  const list = $('historyList');
  const empty = $('historyEmpty');
  list.innerHTML = '<div class="hrow hrow--loading">读取历史记录…</div>';
  let scans = [];
  try {
    const r = await fetch('/api/scans');
    if (r.ok) scans = (await r.json()).scans || [];
  } catch {}
  renderTrend(scans);
  if (!scans.length) {
    list.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  list.innerHTML = '';
  scans.forEach((s) => {
    const sev = scoreSeverity(s.riskScore);
    const [band] = riskBand(s.riskScore);
    const row = document.createElement('div');
    row.className = 'hrow';
    row.innerHTML = `
      <span class="hrow__score sev-${sev}">${s.riskScore}</span>
      <div class="hrow__main">
        <div class="hrow__target">${esc(s.target)}</div>
        <div class="hrow__meta">${new Date(s.finishedAt).toLocaleString()} · ${s.total} 项发现</div>
      </div>
      <span class="hrow__band">${band}</span>
      <button class="hrow__view" data-id="${esc(s.id)}">查看</button>
      <button class="hrow__del" data-id="${esc(s.id)}" title="删除" aria-label="删除">✕</button>`;
    list.appendChild(row);
  });
}

$('historyList').addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.classList.contains('hrow__view')) viewHistory(id);
  else if (btn.classList.contains('hrow__del')) deleteHistory(id);
});

async function viewHistory(id) {
  let rec = null;
  try {
    const r = await fetch(`/api/scans/${encodeURIComponent(id)}`);
    if (r.ok) rec = await r.json();
  } catch {}
  if (!rec) { alert('无法加载该扫描记录'); return; }
  findings = rec.findings || [];
  summary = rec.summary || { target: rec.target, total: (rec.findings || []).length, bySeverity: {}, riskScore: 0, durationMs: 0 };
  showView('scan');
  scanView.hidden = true; results.hidden = false;
  startBtn.disabled = false;
  startBtn.querySelector('.btn-scan__label').textContent = '开始扫描';
  renderResults();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function deleteHistory(id) {
  try { await fetch(`/api/scans/${encodeURIComponent(id)}`, { method: 'DELETE' }); } catch {}
  loadHistory();
}

$('refreshHistory').addEventListener('click', loadHistory);

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

$('exportJson').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify({ generatedAt: new Date().toISOString(), summary, findings }, null, 2)], { type: 'application/json' });
  download(blob, 'sentinel-report.json');
});

function reportHtml() {
  const now = new Date();
  const score = summary.riskScore;
  const [band] = riskBand(score);
  const rows = findings.slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .map((f, i) => `
      <div class="r-item sev-${f.severity}">
        <div class="r-item__h"><span class="r-badge sev-${f.severity}">${SEV_LABEL[f.severity]}</span>
          <h3>${esc(f.title)}</h3><span class="r-score">${f.score.toFixed(1)}</span></div>
        <div class="r-meta">${[f.category, f.owasp, f.cwe].filter(Boolean).map((t) => `<code>${esc(t)}</code>`).join('')}${f.param ? ` · 参数 <code>${esc(f.param)}</code>` : ''}</div>
        <p class="r-desc">${esc(f.description)}</p>
        ${f.evidence ? `<div class="r-ev"><span>证据</span><pre>${esc(f.evidence)}</pre></div>` : ''}
        <div class="r-fix"><span>修复建议</span><p>${esc(f.remediation)}</p></div>
        ${f.url ? `<a href="${esc(f.url)}">${esc(f.url)}</a>` : ''}
      </div>`).join('');

  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>Sentinel 安全扫描报告 — ${esc(summary.target)}</title>
<style>
  :root{--critical:#ff4d6d;--high:#ff9f45;--medium:#f5c451;--low:#5fb8ff;--info:#8b97a8;--ink:#15181d;--paper:#f6f4ee;--line:rgba(20,24,33,.12)}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:var(--paper);color:var(--ink);line-height:1.65;padding:0}
  .page{max-width:820px;margin:0 auto;padding:54px 40px 80px}
  .cover{border-bottom:3px solid var(--ink);padding-bottom:26px;margin-bottom:34px}
  .cover .kicker{font:600 11px/1 ui-monospace,monospace;letter-spacing:3px;text-transform:uppercase;color:#b9801f}
  .cover h1{font:600 34px/1.1 Georgia,serif;margin:12px 0 6px}
  .cover .sub{color:#5b6470;font-size:14px}
  .facts{display:flex;gap:30px;flex-wrap:wrap;margin-top:22px}
  .facts div{display:flex;flex-direction:column}
  .facts i{font-style:normal;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#98a0ab}
  .facts b{font:600 20px/1 ui-monospace,monospace}
  .gauge{display:flex;align-items:center;gap:18px;margin:30px 0;padding:20px;background:#fff;border:1px solid var(--line);border-radius:12px}
  .gauge .num{font:600 52px/1 Georgia,serif}
  .gauge .band{font:600 12px/1 ui-monospace,monospace;letter-spacing:1px;padding:5px 12px;border:1px solid var(--line);border-radius:999px}
  .gauge .meta{font-size:13px;color:#5b6470}
  h2.sec{font:600 16px/1 ui-monospace,monospace;letter-spacing:1px;text-transform:uppercase;margin:38px 0 16px;border-bottom:1px solid var(--line);padding-bottom:8px}
  .summary-grid{display:flex;gap:12px;flex-wrap:wrap}
  .summary-grid .s{flex:1;min-width:90px;text-align:center;padding:14px;border:1px solid var(--line);border-radius:10px;background:#fff}
  .summary-grid .s b{display:block;font:700 26px/1 ui-monospace,monospace}
  .summary-grid .s span{font-size:11px;color:#5b6470}
  .r-item{border:1px solid var(--line);border-left:4px solid #ccc;border-radius:10px;padding:18px;margin-bottom:14px;background:#fff;break-inside:avoid}
  .r-item.sev-critical{border-left-color:var(--critical)} .r-item.sev-high{border-left-color:var(--high)}
  .r-item.sev-medium{border-left-color:var(--medium)} .r-item.sev-low{border-left-color:var(--low)} .r-item.sev-info{border-left-color:var(--info)}
  .r-item__h{display:flex;align-items:center;gap:12px} .r-item__h h3{font-size:16px;flex:1}
  .r-badge{padding:3px 9px;border-radius:6px;font:700 11px/1 ui-monospace,monospace;color:#15181d}
  .r-badge.sev-critical{background:var(--critical)} .r-badge.sev-high{background:var(--high)} .r-badge.sev-medium{background:var(--medium)}
  .r-badge.sev-low{background:var(--low)} .r-badge.sev-info{background:var(--info)}
  .r-score{font:600 14px ui-monospace,monospace;color:#b9801f}
  .r-meta{margin:8px 0;font-size:12px;color:#5b6470} .r-meta code{font:12px ui-monospace,monospace;background:#f0ece2;padding:1px 6px;border-radius:4px;margin-right:6px}
  .r-desc{font-size:13.5px;color:#15181d} .r-ev{margin-top:10px} .r-ev span,.r-fix span{display:block;font:700 10px/1 ui-monospace,monospace;letter-spacing:1.5px;text-transform:uppercase;color:#98a0ab;margin-bottom:5px}
  .r-ev pre{background:#15181d;color:#9fe6a0;padding:12px;border-radius:8px;font:12px ui-monospace,monospace;white-space:pre-wrap;word-break:break-all}
  .r-fix{margin-top:12px;font-size:13px} .r-item a{display:inline-block;margin-top:10px;font:12px ui-monospace,monospace;color:#b9801f;word-break:break-all}
  .method{margin-top:10px;font-size:13px;color:#5b6470} .method b{color:#15181d}
  .disclaimer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);font-size:11.5px;color:#98a0ab}
  @media print{body{background:#fff}.page{padding:0} .r-item{break-inside:avoid}}
</style></head><body><div class="page">
  <div class="cover">
    <div class="kicker">SENTINEL · WEB SECURITY ASSESSMENT</div>
    <h1>Web 应用安全扫描报告</h1>
    <div class="sub">目标：${esc(summary.target)}</div>
    <div class="facts">
      <div><i>生成时间</i><b>${now.toLocaleString()}</b></div>
      <div><i>耗时</i><b>${(summary.durationMs / 1000).toFixed(2)}s</b></div>
      <div><i>发现总数</i><b>${summary.total}</b></div>
      <div><i>扫描引擎</i><b>v1.4.0</b></div>
    </div>
  </div>

  <div class="gauge">
    <div class="num">${score}<span style="font-size:18px;color:#98a0ab">/100</span></div>
    <div><div class="band">${band}</div><div class="meta" style="margin-top:8px">综合风险评分（依据 OWASP 严重度加权）</div></div>
  </div>

  <h2 class="sec">执行摘要</h2>
  <div class="summary-grid">
    ${SEVERITY_ORDER.map((s) => `<div class="s"><b style="color:var(--${s})">${summary.bySeverity[s]}</b><span>${SEV_LABEL[s]}</span></div>`).join('')}
  </div>

  <h2 class="sec">发现明细（${summary.total}）</h2>
  ${rows || '<p style="color:#5b6470">未检测到问题。</p>'}

  <h2 class="sec">检测方法学</h2>
  <div class="method">${METHOD.map(([t, d]) => `<p><b>${t}</b> — ${d}</p>`).join('')}</div>

  <div class="disclaimer">
    本报告由 Sentinel 自动生成，仅用于目标所有者授权范围内的安全评估与教学。所有检测均为非破坏性、被动或受控的探测；结果须由具备资质的安全人员复核后方可用于正式处置。扫描内置 /demo 靶机所产生的全部“漏洞”均为故意构造，用于演示目的。
  </div>
</div></body></html>`;
}

$('exportHtml').addEventListener('click', () => {
  download(new Blob([reportHtml()], { type: 'text/html' }), 'sentinel-report.html');
});

$('printReport').addEventListener('click', () => {
  const w = window.open('', '_blank');
  if (!w) return;
  w.document.write(reportHtml());
  w.document.close();
  w.focus();
  setTimeout(() => w.print(), 350);
});

startBtn.addEventListener('click', startScan);
targetInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') startScan(); });
document.querySelectorAll('.preset').forEach((b) =>
  b.addEventListener('click', () => { targetInput.value = `${window.location.origin}${b.dataset.preset}`; startScan(); }));

startBtn.addEventListener('mousemove', (e) => {
  const r = startBtn.getBoundingClientRect();
  const x = e.clientX - r.left - r.width / 2;
  const y = e.clientY - r.top - r.height / 2;
  startBtn.style.transform = `translate(${x * 0.18}px, ${y * 0.28}px)`;
});
startBtn.addEventListener('mouseleave', () => { startBtn.style.transform = 'translate(0,0)'; });

// "登录靶机"：POST 演示登录，从 X-Session 头里把会话取出来填进"会话"框
// （浏览器读不到 Set-Cookie，所以服务端单独用 X-Session 镜像了一份）
const authBtn = $('authBtn');
const cookieInput = $('cookie');
authBtn.addEventListener('click', async () => {
  const demoLogin = `${window.location.origin}/demo/login`;
  authBtn.disabled = true;
  const prev = authBtn.textContent;
  authBtn.textContent = '登录中…';
  try {
    const r = await fetch(demoLogin, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=admin&password=demo',
    });
    const sid = r.headers.get('X-Session');
    if (sid) {
      cookieInput.value = `session=${sid}`;
      logLine('已为内置靶机获取会话 Cookie，已填入"会话"框 —— 现在可以跑一次登录态扫描', 'l-ok');
    } else {
      logLine('靶机登录未返回会话 Cookie（X-Session 缺失），请手动填入', 'l-err');
    }
  } catch (e) {
    logLine('靶机登录失败：' + e.message, 'l-err');
  } finally {
    authBtn.disabled = false;
    authBtn.textContent = prev;
  }
});
