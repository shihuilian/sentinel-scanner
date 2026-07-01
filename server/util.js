// 杂七杂八的公共小工具，被各个检测模块共用

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function severityRank(s) {
  return SEVERITY_ORDER.indexOf(s);
}

// 用来生成不重复的 finding id，带上时间戳免得撞车
let counter = 0;
function makeId(prefix) {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}`;
}

// 严重度 -> 类 CVSS 基础分，风险仪表和报告都靠它
const SEV_SCORE = { critical: 9.4, high: 8.1, medium: 5.3, low: 3.2, info: 1.1 };

// 让每条 finding 的 id 前缀能看出是哪类问题，方便看日志
const CATEGORY_PREFIX = {
  'Security Headers': 'hdr',
  'Cookie Security': 'ck',
  'TLS / Certificate': 'tls',
  'Injection': 'inj',
  'Sensitive Data Exposure': 'sec',
  'Information Disclosure': 'disc',
  'Cross-Site Request Forgery': 'csrf',
  'Open Redirect': 'redir',
  'CORS Misconfiguration': 'cors',
  'Path Traversal': 'lfi',
  'JWT Security': 'jwt',
  'Server-Side Request Forgery': 'ssrf',
  'XML External Entity (XXE)': 'xxe',
};

// 所有发现统一成同一种结构，前端和报告就不用到处判空
function buildFinding(f) {
  const sev = f.severity;
  return {
    id: makeId(CATEGORY_PREFIX[f.category] || 'f'),
    severity: sev,
    score: typeof f.score === 'number' ? f.score : (SEV_SCORE[sev] ?? 5),
    title: f.title,
    category: f.category,
    owasp: f.owasp || '',
    cwe: f.cwe || '',
    description: f.description || '',
    evidence: f.evidence || '',
    remediation: f.remediation || '',
    url: f.url || '',
    param: f.param || '',
  };
}

function parseQueryParams(url) {
  const out = {};
  try {
    const u = new URL(url);
    u.searchParams.forEach((v, k) => { out[k] = v; });
  } catch {}
  return out;
}

// 从 HTML 里扒出 form 和字段名，后面 XSS/SQLi/CSRF 都要用
function extractFormFields(html) {
  const forms = [];
  const formRe = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = formRe.exec(html))) {
    const formTag = m[0];
    const action = /action=["']([^"']*)["']/i.exec(formTag)?.[1] ?? '';
    const method = (/method=["']([^"']*)["']/i.exec(formTag)?.[1] ?? 'get').toUpperCase();
    const fields = [];
    const inputRe = /<input\b[^>]*\bname=["']([^"']*)["']/gi;
    let im;
    while ((im = inputRe.exec(m[1]))) { if (im[1]) fields.push(im[1]); }
    const taRe = /<textarea\b[^>]*\bname=["']([^"']*)["']/gi;
    while ((im = taRe.exec(m[1]))) { if (im[1]) fields.push(im[1]); }
    forms.push({ action, method, fields });
  }
  return forms;
}

function resolveUrl(base, path) {
  try { return new URL(path, base).toString(); } catch { return base; }
}

// 端点探测用的常见路径词表
const COMMON_PATHS = [
  'admin', 'login', 'wp-admin', 'phpmyadmin', 'dashboard', 'config',
  '.env', 'backup', 'api', 'api/keys', 'robots.txt', 'sitemap.xml',
  'admin.php', 'console', 'debug', 'status', 'health', 'actuator',
  '.git/HEAD', 'uploads', 'static', 'server-status', 'info.php',
  'demo/account',
];

// 敏感信息/密钥的正则。邮箱和 IP 也放进来是因为它们常出现在泄露事件里
const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'high' },
  { name: 'AWS Secret Access Key', re: /\baws_secret_access_key\s*=\s*['"]?[A-Za-z0-9/+=]{40}/gi, severity: 'high' },
  { name: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: 'high' },
  { name: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z\-]{10,}/g, severity: 'high' },
  { name: 'Hardcoded Password / Secret Assignment', re: /(password|passwd|secret|token|private_?key)\s*[:=]\s*['"][^'"]{4,}['"]/gi, severity: 'medium' },
  { name: 'Internal IP Address', re: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g, severity: 'low' },
  { name: 'Email Address', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, severity: 'info' },
  { name: 'US Social Security Number (PII)', re: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'medium' },
];

// 各数据库报错特征，SQLi 报错型检测用
const SQL_ERROR_SIGNATURES = [
  { db: 'MySQL', re: /(You have an error in your SQL syntax|mysql_fetch_array|MySQLSyntaxError|unknown column|where clause)/i },
  { db: 'PostgreSQL', re: /(PostgreSQL.*ERROR|pg_query|pg_exec|syntax error at or near)/i },
  { db: 'SQLite', re: /(SQLite3::|sqlite3\.|near ".*": syntax error|unrecognized token)/i },
  { db: 'SQL Server', re: /(Microsoft SQL Server|Unclosed quotation mark after the character string|Procedure '.*' requires)/i },
  { db: 'Oracle', re: /(ORA-\d{4,5}|quoted string not properly terminated)/i },
];

// 命中这些基本就能认定读到了系统文件（LFI）
const LFI_SIGNATURES = [
  { os: 'Linux', re: /root:x:\d+:\d+:/ },
  { os: 'Linux', re: /(nobody|xrph|daemon):x:\d+:/ },
  { os: 'Linux', re: /\[boot\]/i },
  { os: 'Linux', re: /\/bin\/(ba)?sh/ },
  { os: 'Windows', re: /\[fonts\]/i },
  { os: 'Windows', re: /\[services\]/i },
  { os: 'Windows', re: /;\s*for\s+%i\s+in/i },
  { os: 'Generic', re: /FORWARD\s*=\s*\(/i },
];

// 常见的"文件读取"参数名，路径遍历检测会优先看这些
const FILE_PARAMS = ['file', 'path', 'filepath', 'page', 'doc', 'document', 'name', 'src', 'f', 'p', 'read', 'download'];

module.exports = {
  SEVERITY_ORDER, severityRank, makeId, buildFinding, SEV_SCORE,
  parseQueryParams, extractFormFields, resolveUrl,
  COMMON_PATHS, SECRET_PATTERNS, SQL_ERROR_SIGNATURES,
  LFI_SIGNATURES, FILE_PARAMS,
};
// SECRET_PATTERNS must stay in sync with checks.js
