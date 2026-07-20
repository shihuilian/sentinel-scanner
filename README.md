# Sentinel

平时挖漏洞/做审计的时候随手写的一个扫描器，跑在浏览器里，Node 起个后端就行。

能扫的东西：

- 不用登录就能看的：安全头缺没缺、Cookie 标志、TLS 证书过没过期、页面里有没有泄露 key/密码/手机号、常见路径（admin、.env 之类）能不能访问、CSRF token 有没有、会不会被开放重定向坑、CORS 配置对不对、路径遍历、JWT 有没有弱签名
- 需要发 payload 的：XSS、SQL 注入（报错+盲注）、SSRF、XXE
- 登录之后也能扫：带上 Cookie 把认证后的页面一起检查

`/demo` 是个故意留了洞的靶机，本地 `node server/index.js` 起来之后默认就扫它，拿来试手用。

## 检测模块

| 模块 | 检测能力 | OWASP / CWE | 等级 |
| --- | --- | --- | --- |
| 安全头审计 | HSTS / CSP / X-Content-Type-Options / X-Frame-Options / Referrer-Policy / Permissions-Policy 缺失；CSP `unsafe-inline` 宽松度；Server 指纹泄露 | A05 / CWE-693,1021,200 | Low – Medium |
| Cookie 安全 | Secure / HttpOnly / SameSite 标志缺失 | A05 / CWE-614,1004 · A01 / CWE-352 | Low – Medium |
| TLS / 证书 | 证书过期、未生效、自签名、弱协议（TLS 1.0/1.1） | A02 / CWE-295,324,326 | Medium – High |
| 敏感信息泄露 | AWS / Google / Slack Key、私钥块、JWT、硬编码口令、内部 IP、邮箱、SSN(PII)、可疑 HTML 注释 | A02 / CWE-798 · A05 / CWE-200 | Info – Critical |
| 端点探测 | 常见路径 / 后台 / 备份 / 配置文件暴露（admin、.env、api/keys…），按状态码定级 | A05 / CWE-538,200 | Info – Medium |
| CSRF | 同源 POST 表单缺少反 CSRF Token 且无常驻 SameSite Cookie | A01 / CWE-352 | Medium |
| 开放重定向 | 重定向参数注入离站地址并以 `manual` 重定向读取 Location 判定 | A01 / CWE-601 | Medium |
| CORS 配置错误 | 反射任意 Origin + 允许凭据（高）；通配 + 凭据；动态反射 | A05 / CWE-942 | Medium – High |
| 路径遍历 / LFI | 对文件读取端点注入 `../`、嵌套、URL 编码、双重编码载荷，依据系统文件特征判定 | A01 / CWE-22 | High |
| JWT 安全 | `alg:none` 签名绕过（严重）；`kid` 路径/元字符注入；`jku` 指向外部 URL | A02 / CWE-347 · A08 / CWE-502,346 | Medium – Critical |
| 服务端请求伪造 (SSRF) | 对服务端 fetch/代理端点注入内网地址，依据响应是否回显内部资源（含仅供内网访问的隐藏端点）判定 | A10 / CWE-918 | High |
| XML 外部实体 (XXE) | 向 XML 端点投递含外部实体的载荷（`file://` 引用本地文件），依据响应是否回显本地文件内容判定 | A05 / CWE-611 | High |
| 反射型 XSS | 探针确认参数反射 → 注入带事件处理器 payload → 依据未编码回显判定 | A03 / CWE-79 | High |
| SQL 注入 | 报错型（数据库错误签名匹配）+ 布尔盲注（TRUE/FALSE 响应长度差） | A03 / CWE-89 | Medium – High |

## 运行

```bash
node server/index.js
# 浏览器打开 http://localhost:4000
```

默认目标是 `/demo`。换端口：`PORT=8080 node server/index.js`。

## 结构

```
sentinel-scanner/
├─ server/
│  ├─ index.js       # http 服务：API + SSE + 静态托管 + 历史 + 靶机
│  ├─ engine.js      # 扫描编排：顺序执行、事件、风险评分
│  ├─ checks.js      # 14 个检测模块，统一产出带 OWASP/CWE 的发现
│  ├─ http.js        # 简单 HTTP 客户端：超时、Set-Cookie 解析、并发上限、redirect
│  ├─ util.js        # 解析/词表/正则/严重度加权/发现构造器
│  └─ demo.js        # 故意留洞的多页面靶机
├─ public/
│  ├─ index.html
│  ├─ styles.css
│  └─ app.js
├─ .github/workflows/ci.yml
├─ .gitignore
├─ LICENSE
└─ CONTRIBUTING.md
```

数据流：`POST /api/scan` 创建扫描 → 引擎逐检查发事件 → `GET /api/scan/:id/events` 用 SSE 推流 → 前端实时渲染 → 完成落盘 `.data/scans/<id>.json`。

REST API：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/scan` | 启动扫描，返回 `{ id, target }` |
| GET | `/api/scan/:id/events` | SSE 事件流 |
| GET | `/api/scans` | 历史列表（按时间倒序） |
| GET | `/api/scans/:id` | 单次扫描完整记录 |
| DELETE | `/api/scans/:id` | 删除一条历史记录 |

风险评分：`raw = Σ 严重度权重`；`riskScore = 100·(1 − e^(−raw/18))`，少量高危即判严重，但不会无限线性膨胀。

## 检测方法

- **XSS**：先确认参数被原样反射，再注入带事件处理器的 payload，响应里未做 HTML 编码就判漏洞（区分"被反射"和"可执行"）。
- **SQLi**：报错型单引号 + 错误特征匹配；布尔盲注对比 `' OR '1'='1` 与 `' OR '1'='2` 的响应长度差（阈值 40 字节）。
- **CSRF**：提取同源 POST 表单，无反 CSRF token 且没看到 SameSite Cookie 就判。
- **开放重定向**：对 `next/url/redirect` 参数注入离站地址，用 `manual` 重定向读 Location 判断是否跳走。
- **CORS**：带 Origin 探，读 `Access-Control-Allow-Origin` 与 `Access-Control-Allow-Credentials`；反射任意源且允许凭据就判高危。
- **路径遍历 / LFI**：先确认端点吃文件参数（避免对 404 滥发），再打 `../`、嵌套、URL/双重编码，看是否泄露系统文件。
- **JWT**：取响应里的 JWT 解头部——`alg=none` 视为签名绕过；`kid` 含路径/元字符、`jku` 指外站视为伪造风险。
- **SSRF**：对服务端 `fetch` / 代理端点注入内网地址（含隐藏端点 `/internal/admin-data`），响应回显内部内容就判。
- **XXE**：向 `/api/xml` 投外部实体载荷（`<!ENTITY xxe SYSTEM "file:///etc/passwd">`），响应回显本地文件内容就判。
- **认证态扫描**：捕获的 Cookie 只附加到同源请求；端点探测先于注入类，把发现页加入蜘蛛集合，让 XSS/SQLi/敏感信息检测也能打到登录后的页面。
- **端点探测**：限 5 路并发，只对 2xx/3xx/401/403/405/500 计分，未知路径返回 404 不算暴露（避免误报）。

别拿来扫没授权的站点，就扫自己东西或者本地 demo 就行。
