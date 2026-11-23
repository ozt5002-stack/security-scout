# Security report: fitbalance-ad-agents

Date: 2026-11-23 · Scope: code only · Facts from scanners: 3

## Summary
1. Slow down wrong-password attempts on `/api/*` and log them. Today anyone with the URL can guess `APP_PASSWORD` as fast as they like, and nothing records it.
2. Add the two missing security headers, HSTS and Permissions-Policy, to `SECURITY_HEADERS` in `src/server.mjs`.
3. Upgrade `yaml` to 2.9.1 and pin the two GitHub Actions to commit SHAs.

The scanner fact `publish.no-header-config` (no header config for `public/`) is only partly right. `public/` is served by `src/server.mjs`, and that code already sends CSP, X-Frame-Options, nosniff and Referrer-Policy. Only HSTS and Permissions-Policy are missing (F-02).

## Findings

### F-01 · MEDIUM · A07 Authentication Failures
**What can happen:** Anyone who finds the site's address can try passwords against the API as fast as they want. Nothing slows them down and nothing is logged. Once they guess it, they can read every draft and spend your Anthropic and OpenAI/Gemini credit, up to the daily cap.
**Where:** `src/server.mjs:40`, `src/server.mjs:75`, `src/env.mjs:49`
**Evidence:** `if (!authorized(req.headers.authorization)) return send(res, 401, { error: 'Wrong or missing password.' });` has no counter, delay or log line. The length check in `src/env.mjs` only warns: `else if (config.appPassword.length < 12) warnings.push('APP_PASSWORD is shorter than 12 characters. Use a longer one.');`
**Fix:** In `route()`, keep an in-memory map of failed attempts per IP (`req.socket.remoteAddress`, or the first `x-forwarded-for` entry behind Railway or Caddy). After about 10 failures in 15 minutes, answer `429` for that IP. Also call `warn(\`failed login from ${ip}\`)` on every 401. In `checkConfig()`, move the "shorter than 12 characters" case from `warnings` to `fatal`, so the server will not start with a short password.
**Verify:** Send 15 requests in a row with a wrong password: `curl -u x:wrong https://<app>/api/info`. The later ones should get `429`, and the server log should show a `failed login` line for each. Start the server with an 8-character `APP_PASSWORD`: it should exit.

### F-02 · LOW · A02 Security Misconfiguration
**What can happen:** Without HSTS, a browser on hostile Wi-Fi can be pushed to the plain-HTTP version of the site the first time it connects, and the password can be read there. Without Permissions-Policy, the page does not switch off browser features it never uses, such as camera, microphone and location.
**Where:** `src/server.mjs:29`, `deploy/Caddyfile:2`
**Evidence:** `const SECURITY_HEADERS = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', 'content-security-policy': ... }`. There is no `strict-transport-security` or `permissions-policy`, and the Caddyfile has no `header` block.
**Fix:** Add two entries to `SECURITY_HEADERS`: `'strict-transport-security': 'max-age=31536000; includeSubDomains'` and `'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()'`. The Node server sits behind HTTPS on Railway and behind Caddy on the droplet, so sending HSTS from Node works on every host.
**Verify:** Run `curl -sI https://<app>/` and check that both headers are in the response.

### F-03 · LOW · A03 Software Supply Chain Failures
**What can happen:** The `yaml` version you use has a known bug: a deeply nested YAML file can crash the parser. Here it only parses your own `agents/*.md` and `environments/*.yaml` on your computer (it is a dev dependency and is not shipped to the server), so the real risk is small.
**Where:** `package.json:31`, `package-lock.json`, `scripts/agents-files.mjs:4`
**Evidence:** `"yaml": "2.6.1"`. Scanner: "yaml 2.0.0 - 2.8.2: yaml is vulnerable to Stack Overflow via deeply nested YAML collections (GHSA-48c2-rrv3-qjmp); fix: yaml 2.9.1".
**Fix:** Run `npm install --save-dev yaml@2.9.1` and commit `package.json` and `package-lock.json`.
**Verify:** `npm audit` no longer lists `yaml`, and `npm test` and `npm run agents:plan` still pass.

### F-04 · LOW · A08 Software or Data Integrity Failures
**What can happen:** The CI workflow pins its actions to tags. A tag can be moved to different code, and your CI would then run that code without you changing anything. The workflow's token is read-only and it holds no secrets, so the damage is limited.
**Where:** `.github/workflows/test.yml:25`, `.github/workflows/test.yml:26`
**Evidence:** `- uses: actions/checkout@v4` and `- uses: actions/setup-node@v4`
**Fix:** Replace each tag with the full commit SHA of that release and keep the tag as a comment, for example `actions/checkout@<40-char-sha> # v4`. Turn on Dependabot for `github-actions` so the SHAs get updated.
**Verify:** Every `uses:` line in the workflow ends in a 40-character SHA, and CI is still green.

### F-05 · LOW · A07 Authentication Failures
**What can happen:** The page saves the actual app password in the browser's `sessionStorage`. If someone ever manages to run their own JavaScript on the page (an XSS bug), it can read the password. The project's protections (a strict CSP and `textContent` everywhere) make that unlikely today.
**Where:** `public/app.js:13`, `public/app.js:74`, `public/app.js:250`
**Evidence:** `set(v) { try { sessionStorage.setItem(KEY, v); } ...` and `store.set(password);`
**Fix:** Keep the password only in the `password` variable in memory and remove the `store.set`/`store.get` calls. The cost is that a page reload asks for the password again. For a stronger fix, add `POST /api/login`, which checks the password once and sets an `HttpOnly; Secure; SameSite=Strict` session cookie.
**Verify:** Log in, then run `sessionStorage.getItem('ad-agents-password')` in DevTools: it should return `null`.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Owner's requests and revision messages (free text, up to 2,000 characters) | `data/ads/<id>.json` (`request`, `replies`), with the first 100 characters in the server log (`src/ads.mjs:136`, `src/ads.mjs:157`), and in the Anthropic session | Making the post | Usually no. Whatever the owner types is kept with no end date |
| Owner's name (Yahav Sror) and her own product reviews | `prompts/facts.md`, `prompts/brand-sheet.md`, `agents/ad-researcher.md` (committed to git) | The brand voice in posts | No (a public business identity) |
| Generated drafts, pictures, agent text and sources | `data/ads/` (Railway volume or droplet disk) | Showing and downloading drafts | No. Kept with no end date: should old drafts be deleted after a while? |
| App password | `.env` / platform variables; the browser's `sessionStorage` | Logging in | Yes (see F-05) |
| Client IPs and request paths | Caddy `/var/log/caddy/access.log` (droplet only) | Access log | Low. Kept with no stated end date |

## Accepted risks

- The agent's environment has unrestricted network access, because its job is open web research, it holds no keys, and only `web_search` and `web_fetch` are on (`environments/ad-research.yaml:4`).
- The container runs as root, because Railway mounts volumes owned by root (`Dockerfile:9`).

## Not checked

- Whether the live `APP_PASSWORD` is long and random, and who it has been shared with. It lives only in platform variables.
- Railway / DigitalOcean settings: variable encryption, who has access to the project, 2FA on those accounts and on GitHub, Anthropic, OpenAI and Google.
- The Anthropic workspace spend limit and any monthly limits at OpenAI or Google. `docs/06-audit.md` says these were set in the Console but cannot be seen from code.
- Backups of the Railway volume or the droplet's `data/` folder.
- Droplet hardening: SSH access as `root`, SSH key-only login, and the systemd unit's real user at runtime.
- The live site. No URL was given, so the headers and the 401 behaviour were not tested against a running deploy.
- Git history for secrets. Only the working tree was read; the scanners reported no secret findings.
- The planned Make/WhatsApp integration (`docs/05-whatsapp-make.md`: signed image URLs, `MAKE_PASSWORD`) is design only and not in the code yet. Review it when it is built.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
