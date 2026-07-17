# Contributing to Sentinel

Thanks for taking the time to contribute. Sentinel does not use any third-party
runtime dependencies — `node server/index.js` should work on a clean machine.
Please keep it that way in your changes.

## Ground rules

1. **Never introduce runtime dependencies.** The whole point is that
   `node server/index.js` works on a clean machine. If you need a third-party
   library, open a discussion first.
2. **Only scan what you are authorised to scan.** The built-in `/demo`
   target exists for testing. Do not add checks that perform destructive or
   denial-of-service behaviour. All detection must be passive or tightly rate
   limited (see `mapLimit` in `server/http.js`).
3. **Every finding must carry OWASP + CWE + a remediation.** This is what
   makes the output defensible. Use `buildFinding()` in `server/util.js`.

## Adding a new detection module

1. Create `async function checkXxx(ctx)` in `server/checks.js` that calls
   `ctx.emitFinding(...)` / `ctx.emitProgress(...)`.
2. Register it in the `CHECKS` array. Passive checks go first, active
   injection checks last.
3. Add a matching entry to `RAIL_LABEL` and `METHOD` in `public/app.js`
   so the UI labels and the methodology appendix stay in sync.
4. If you add a new risk category, add a prefix in `CATEGORY_PREFIX`
   (`server/util.js`) so finding IDs stay unique.

## Local development

```bash
node server/index.js          # serves UI on http://localhost:4000
# open http://localhost:4000  → click "开始扫描" to scan /demo
node --check server/checks.js # syntax check before committing
```

## Pull requests

- Keep commits focused and messages descriptive.
- Ensure `node --check` passes on every changed file.
- CI runs a self-scan against `/demo` and fails if zero findings are produced
  (that would mean the engine regressed).
