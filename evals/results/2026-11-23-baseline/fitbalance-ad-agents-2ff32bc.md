# Security report: fitbalance-ad-agents

Date: 2026-11-23 · Scope: code only · Facts from scanners: 3

## Summary
1. Limit wrong-password attempts on the API, log them, and make a short `APP_PASSWORD` stop the server instead of only warning (F-01).
2. Send the two missing security headers, HSTS and Permissions-Policy, from `src/server.mjs` (F-02).
3. Save the daily run counter to disk so a restart does not reset the spending cap (F-03). Then pin the CI actions to commit SHAs (F-05).

The scanner facts file (`facts.json`, 3 facts) could not be opened during this run because reading it was refused. So the scanner facts were not confirmed one by one. Everything below comes from reading the code directly (see "Not checked").

## Findings

### F-01 · MEDIUM · A07 Authentication Failures
**What can happen:** Anyone who finds the URL can keep guessing the single shared password as fast as the server answers, with no slowdown, lockout or alert. A short password is accepted with only a warning. Once they guess it, they can spend your Anthropic and OpenAI credit and read every draft.
**Where:** `src/server.mjs:75`, `src/server.mjs:40`, `src/env.mjs:49`
**Evidence:** `if (!authorized(req.headers.authorization)) return send(res, 401, { error: 'Wrong or missing password.' });` has no counter or delay. `else if (config.appPassword.length < 12) warnings.push('APP_PASSWORD is shorter than 12 characters. Use a longer one.');` only warns, and the server still starts.
**Fix:** In `route()`, keep an in-memory map of failed attempts per client IP (on Railway, read the first address in `x-forwarded-for`). After about 10 failures in 15 minutes, answer `429` for that IP until the window ends, and log each block. In `checkConfig()`, move the `< 12` check (better: `< 16`) from `warnings` to `fatal`, so the server refuses to start with a short password.
**Verify:** Run `curl -u any:wrong https://<app>/api/info` 11 times in a row. The 11th call should return `429`, and the server log should show the block. Start the server with `APP_PASSWORD=short`: it should exit with a `[config]` error.

### F-02 · LOW · A02 Security Misconfiguration
**What can happen:** Without HSTS, a browser on a hostile network (for example public Wi-Fi) can be pushed onto plain HTTP for the first request, where the password header could be read. Without Permissions-Policy, the page does not switch off browser features it never uses.
**Where:** `src/server.mjs:29`, `deploy/Caddyfile:2`
**Evidence:** `SECURITY_HEADERS` sets `x-content-type-options`, `referrer-policy`, `x-frame-options` and `content-security-policy`, but no `strict-transport-security` and no `permissions-policy`. The Caddyfile only has `encode` and `reverse_proxy`, with no `header` block.
**Fix:** Add these two lines to `SECURITY_HEADERS` in `src/server.mjs`: `'strict-transport-security': 'max-age=31536000; includeSubDomains'` and `'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()'`. Since every response goes through `send()`, this covers Railway, App Platform and the droplet.
**Verify:** `curl -sI https://<app>/health` shows both headers. securityheaders.com should no longer list them as missing.

### F-03 · LOW · A06 Insecure Design
**What can happen:** The "30 runs a day" spending cap is kept only in memory. Every crash, redeploy or restart sets it back to zero, so on a day with several restarts more paid runs can go through than you set.
**Where:** `src/ads.mjs:110`, `src/ads.mjs:116`
**Evidence:** `const runTimes = [];         // start times of runs in the last 24 hours (resets on restart)`
**Fix:** Save `runTimes` to a small file under `config.dataDir` (for example `data/usage.json`) each time `admit()` adds a run, and load it when the module starts. The Railway volume at `/app/data` then keeps it across deploys. Keep the monthly limits in the Anthropic and OpenAI consoles as the final backstop.
**Verify:** Create two ads, restart the server, then open `/api/info`. `usage.runs` should still be 2.

### F-04 · LOW · A09 Security Logging & Alerting Failures
**What can happen:** If someone starts guessing the password, nothing in the server log shows it, so you would only find out from the bill.
**Where:** `src/server.mjs:75`
**Evidence:** The 401 path calls `send(res, 401, …)` with no `warn(...)`. The only things logged are ad events in `src/ads.mjs` and 500 errors.
**Fix:** Before returning the 401, call `warn(`auth failed: ${req.method} ${path} from ${req.headers['x-forwarded-for'] ?? req.socket.remoteAddress}`)`. Never log the header itself. Log the 429 blocks from F-01 the same way.
**Verify:** Send one request with a wrong password. The Railway log (or `logs/server.log` on the droplet) should show one `auth failed` line, and the password should not appear in it.

### F-05 · LOW · A03 Software Supply Chain Failures
**What can happen:** The CI workflow uses GitHub actions by a movable tag. If the tag were moved to bad code, that code would run in your CI with access to your repository checkout.
**Where:** `.github/workflows/test.yml:25`, `.github/workflows/test.yml:26`
**Evidence:** `- uses: actions/checkout@v4` and `- uses: actions/setup-node@v4`
**Fix:** Pin each action to a full commit SHA and keep the tag as a comment, for example `actions/checkout@<40-char-sha> # v4`. Add Dependabot for `github-actions` to keep the SHAs up to date. The `permissions: contents: read` setting is already right; keep it.
**Verify:** `grep "uses:" .github/workflows/test.yml` shows only 40-character SHAs, and CI still passes.

### F-06 · LOW · A07 Authentication Failures
**What can happen:** The app password is kept in the browser's `sessionStorage`, in plain text. Any script that ever ran on the page could read it and send it out. The strict CSP and the `textContent`-only rendering make this unlikely today.
**Where:** `public/app.js:13`, `public/app.js:14`, `public/app.js:74`
**Evidence:** `set(v) { try { sessionStorage.setItem(KEY, v); } …` and `store.set(password);`
**Fix:** Keep this low risk by keeping the CSP strict, with no `unsafe-inline` for scripts. If you add the Make/WhatsApp integration from `docs/05-whatsapp-make.md`, give it its own revocable password, as planned. Longer term, change login to exchange the password once for a random session id held in an `HttpOnly; Secure; SameSite=Strict` cookie.
**Verify:** After logging in, in DevTools → Application → Session Storage, no entry contains the password (with the cookie change), or the CSP header still has no `unsafe-inline` in `script-src`/`default-src` (without it).

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Owner's name (Yahav Sror), business details, prices, her own product reviews | `prompts/brand-sheet.md`, `prompts/facts.md` (in git, sent to Anthropic in every session) | Writing the posts in her voice | No (public business info) |
| Ad requests and revision texts typed by the owner | `data/ads/<id>.json`; first 100 characters in the server log (`src/ads.mjs:136`, `src/ads.mjs:157`); Anthropic session history | Making and revising drafts | No, unless she types personal details about clients |
| Generated drafts, pictures, image prompts, agent notes, web sources | `data/ads/` (Railway volume or droplet disk) | Showing drafts to the owner | No |
| `APP_PASSWORD` | `.env` / platform variables; browser `sessionStorage` | Access to the API | Yes (credential) |
| Anthropic, OpenAI and Gemini API keys | `.env` / platform variables only | Paid model calls | Yes (credential) |
| Caller IP addresses and request lines | `/var/log/caddy/access.log` (droplet only) | Access logging | Low (personal data under privacy law) |

Questions for the owner: how long should drafts in `data/ads/` and the Caddy access log be kept? Nothing in the code deletes them. Also ask Yahav never to put client names or health details in a request, because requests are sent to Anthropic and kept on disk.

## Accepted risks

- The container runs as root (`Dockerfile:9`: "The process runs as root on purpose: Railway mounts volumes owned by root, and a non-root user could not write to it."). On the droplet, the service runs as the unprivileged `adagents` user with systemd hardening (`deploy/ad-agents.service`).

## Not checked

- **The 3 scanner facts in `facts.json`.** The file could not be read in this run (access was refused), so none of them were confirmed or rejected. Re-run with the facts file readable.
- **The live site.** No URL was given, so the headers actually served and HTTPS settings on Railway were not seen.
- **Git history.** I could not inspect it with these tools. `docs/06-audit.md` says a key-pattern search over the full history found nothing; that claim was not re-checked.
- **Dependency versions.** `package-lock.json` was not checked against vulnerability databases. Run `npm audit`.
- **Hosting settings.** Who can access the Railway project and its variables, volume backups, and 2FA on GitHub, Railway, Anthropic, OpenAI and Google accounts.
- **Spend limits set in the provider consoles.** These are the Anthropic workspace limit (the audit notes it "cannot be verified with a regular API key") and the OpenAI and Gemini limits.
- **The Make/WhatsApp/Instagram integration** in `docs/05-whatsapp-make.md`. It is a design only, with no code yet. Review it again once it is built, especially the signed image URLs and `MAKE_PASSWORD`.
- **What the agent does on Anthropic's side.** I did not review its web searches and fetched pages. The code limits the agent to web search, web fetch and one checked submit tool, and the page shows all agent output with `textContent`.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
