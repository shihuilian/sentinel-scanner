const { CHECKS } = require('./checks');
const { SEVERITY_ORDER, SEV_SCORE } = require('./util');
const { request, setAuth } = require('./http');

function normalizeTarget(input) {
  let t = input.trim();
  if (!/^https?:\/\//i.test(t)) t = `http://${t}`;
  return t;
}

async function doLogin(auth) {
  const userField = auth.usernameField || 'username';
  const passField = auth.passwordField || 'password';
  const body = new URLSearchParams({
    [userField]: auth.username || '',
    [passField]: auth.password || '',
  }).toString();
  const res = await request(auth.loginUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'manual',
  });
  const raw = res.cookies && res.cookies[0];
  if (!raw) return '';
  return raw.split(';')[0];
}

// 风险评分用饱和曲线：几个高危就能把分拉满，但不会线性叠加到离谱
// raw 是每个 finding 的严重度权重之和，再 1 - e^(-raw/k) 压到 0..100
function computeRiskScore(findings) {
  const raw = findings.reduce((acc, f) => acc + (SEV_SCORE[f.severity] ?? 5), 0);
  return Math.min(100, Math.round(100 * (1 - Math.exp(-raw / 18))));
}

async function runScan(target, onEvent, options = {}) {
  const start = Date.now();
  const url = new URL(target);
  const baseUrl = `${url.protocol}//${url.host}`;
  const findings = [];

  let authCookie = options.cookie || '';
  if (options.auth && options.auth.loginUrl) {
    onEvent({ type: 'progress', check: 'Authentication', index: 0, total: CHECKS.length, message: `Logging in via ${options.auth.loginUrl}…` });
    try { authCookie = await doLogin(options.auth); } catch (e) { authCookie = ''; }
    if (authCookie) onEvent({ type: 'progress', check: 'Authentication', index: 0, total: CHECKS.length, message: 'Session captured — scanning authenticated surface' });
    else onEvent({ type: 'progress', check: 'Authentication', index: 0, total: CHECKS.length, message: 'Login failed — continuing unauthenticated' });
  }
  if (authCookie) setAuth(authCookie, url.host);

  const ctx = {
    target, baseUrl, host: url.host, protocol: url.protocol,
    discovered: [],
    emitFinding: (f) => { findings.push(f); onEvent({ type: 'finding', finding: f }); },
    emitProgress: (check, message) => onEvent({ type: 'progress', check, index: 0, total: CHECKS.length, message }),
  };

  onEvent({ type: 'start', target, checks: CHECKS.map((c) => c.name) });

  for (let i = 0; i < CHECKS.length; i++) {
    const check = CHECKS[i];
    ctx.emitProgress = (c, message) => onEvent({ type: 'progress', check: c, index: i + 1, total: CHECKS.length, message });
    onEvent({ type: 'check-start', name: check.name, index: i + 1, total: CHECKS.length });
    ctx.emitProgress(check.name, `Running ${check.name}…`);
    try {
      await check.run(ctx);
    } catch (e) {
      onEvent({ type: 'progress', check: check.name, index: i + 1, total: CHECKS.length, message: `Check errored: ${e?.message ?? e}` });
    }
    onEvent({ type: 'check-done', name: check.name, index: i + 1, total: CHECKS.length });
  }

  const bySeverity = {};
  SEVERITY_ORDER.forEach((s) => { bySeverity[s] = 0; });
  findings.forEach((f) => { bySeverity[f.severity] += 1; });

  const summary = {
    target, total: findings.length, bySeverity,
    riskScore: computeRiskScore(findings),
    durationMs: Date.now() - start, checkedUrls: 1,
  };
  onEvent({ type: 'done', summary, findings });
  return summary;
}

module.exports = { normalizeTarget, runScan };
// discovered pages feed back into xss/sqli/secrets checks
