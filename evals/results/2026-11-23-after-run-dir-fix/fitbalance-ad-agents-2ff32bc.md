# Security report: fitbalance-ad-agents

Date: 2026-11-23 · Scope: code only · Facts from scanners: 3

## Summary
1. Limit wrong-password attempts on `/api/*` and log them. Today anyone with the URL can guess `APP_PASSWORD` as fast as they like, and the guesses leave no trace.
2. Add the two missing security headers (HSTS and Permissions-Policy) to the `SECURITY_HEADERS` list in `src/server.mjs`.
3. Upgrade the dev dependency `yaml` to 2.9.1 and pin the GitHub Actions to commit SHAs.

Checked and partly not real: the scanner's `publish.no-header-config` fact says `public/` has no header config. In fact `src/server.mjs` serves that folder and sends CSP, X-Frame-Options, nosniff and Referrer-Policy. Only HSTS and Permissions-Policy are missing (F-02). The `yaml` advisory is real, but `yaml` is a devDependency used only by the local `agents:apply` script on the project's own files, and the Docker image leaves it out (`npm ci --omit=dev`). So it is ranked LOW, not MEDIUM.

## Findings

### F-01 · MEDIUM · A07 Authentication Failures
**What can happen:** Anyone who finds the site's address can try passwords automatically without limit. Once they guess `APP_PASSWORD`, they can create ads that spend the Anthropic and OpenAI/Gemini credit, and read every draft. The owner gets no log line showing it is happening.
**Where:** `src/server.mjs:75`, `src/env.mjs:49`
**Evidence:** `if (!authorized(req.headers.authorization)) return send(res, 401, { error: 'Wrong or missing password.' });`: there is no counter, delay or block per IP, and no log call on the 401. A short password only gives a warning: `else if (config.appPassword.length < 12) warnings.push(...)`.
**Fix:** In `route()`, before the `authorized` check, keep an in-memory `Map` of failed attempts per IP (read from `x-forwarded-for` behind Railway or Caddy). After, say, 10 failures in 15 minutes, return `429` and refuse until the window ends. On every failure call `warn(\`auth failed from ${ip} ${req.method} ${path}\`)`, without the password. In `checkConfig()`, make a password shorter than 12 characters a `fatal` error, not a warning. Keep using a long random password (for example 24+ characters from a password manager).
**Verify:** Send 15 requests in a row with `curl -u x:wrong https://<app>/api/info`. The later ones must return 429, and the server log must show one `auth failed` line per attempt. Starting the server with `APP_PASSWORD=short` must exit with an error.

### F-02 · LOW · A02 Security Misconfiguration
**What can happen:** Without HSTS, a browser on a hostile network (public Wi-Fi) can be pushed to plain HTTP the first time it opens the site, where the password sent with every API call can be read. Without Permissions-Policy, the page does not switch off browser features it never uses.
**Where:** `src/server.mjs:29`, `deploy/Caddyfile:2`
**Evidence:** `const SECURITY_HEADERS = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', 'content-security-policy': ... }`: there is no `strict-transport-security` and no `permissions-policy`. The Caddyfile has only `encode` and `reverse_proxy`, with no `header` directive.
**Fix:** Add `'strict-transport-security': 'max-age=31536000; includeSubDomains'` and `'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()'` to `SECURITY_HEADERS` in `src/server.mjs`. The droplet uses the same Node server, so it gets them too.
**Verify:** `curl -sI https://<app>/` shows both new headers next to the existing four.

### F-03 · LOW · A07 Authentication Failures
**What can happen:** If any script ever runs inside the page, it can read the real app password itself, not just a session token that expires. The password is the key to the API credit.
**Where:** `public/app.js:13`, `public/app.js:74`
**Evidence:** `store.set(password)` → `sessionStorage.setItem(KEY, v)` with `KEY = 'ad-agents-password'`. The risk is limited today: all agent and web text is set with `textContent`, and the CSP is `default-src 'self'`.
**Fix:** Have `POST /api/login` check the password once and set an `HttpOnly; Secure; SameSite=Strict` cookie holding a random session token (kept in a server-side `Map` with an expiry). Then remove the `sessionStorage` code. If that is too much for now, keep the password only in the `password` variable, so a page reload asks again.
**Verify:** After logging in, run `sessionStorage.getItem('ad-agents-password')` in the browser console. It must return `null`, and the API calls must still work.

### F-04 · LOW · A03 Software Supply Chain Failures
**What can happen:** A YAML file with very deeply nested lists can crash the `agents:apply` script. This is limited to the developer's machine, and the files it parses are the project's own.
**Where:** `package.json:31`, `package-lock.json:91`, `scripts/agents-files.mjs:4`
**Evidence:** `"yaml": "2.6.1"` (devDependency); advisory GHSA-48c2-rrv3-qjmp affects 2.0.0–2.8.2, fixed in 2.9.1. Used only in `import { parse } from 'yaml';` in `scripts/agents-files.mjs`.
**Fix:** `npm install --save-dev yaml@2.9.1`, then commit `package.json` and `package-lock.json`.
**Verify:** `npm audit` reports no `yaml` advisory, and `npm run agents:plan` still works.

### F-05 · LOW · A08 Software or Data Integrity Failures
**What can happen:** If someone moves the `v4` tag of a third-party action, the CI run would execute different code. The impact is small because the workflow has only `contents: read` and no secrets.
**Where:** `.github/workflows/test.yml:25`, `.github/workflows/test.yml:26`
**Evidence:** `- uses: actions/checkout@v4`, `- uses: actions/setup-node@v4`
**Fix:** Pin each action to the full commit SHA of the release, with the tag as a comment, for example `actions/checkout@<40-char-sha> # v4.x.y`. Let Dependabot (`.github/dependabot.yml`, `package-ecosystem: github-actions`) keep the SHAs up to date.
**Verify:** `grep -n "uses:" .github/workflows/test.yml` shows only 40-character SHAs, and CI still passes.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Yahav's post requests and revision replies (free text) | `data/ads/<id>.json` (`request`, `replies`); first 100 chars in the server log (`src/ads.mjs:136`, `:157`); Anthropic Managed Agents sessions | Making and revising post drafts | No, unless she types personal details into a request |
| Generated drafts, agent text, reviewer notes, web source URLs | `data/ads/<id>.json` | Showing the draft | No |
| Generated pictures | `data/ads/<id>_<n>.jpg` | Post picture | No |
| Business owner's name, brand voice, her own product reviews | `prompts/brand-sheet.md`, `prompts/facts.md` (in git) | Prompt context | No (business info she publishes) |
| App password | Server env `APP_PASSWORD`; browser `sessionStorage` | API access | Yes (credential), see F-01, F-03 |
| API keys (Anthropic, OpenAI/Gemini) | Server env / `.env` (git-ignored, docker-ignored) | Paid model calls | Yes (credential) |

Question for the owner: drafts in `data/ads/` have no end date. Do you want old drafts deleted after a set time?

## Accepted risks

- The container runs as root, because Railway mounts volumes owned by root and a non-root user could not write to them (`Dockerfile:9`). The droplet setup runs as the `adagents` user.

## Not checked

- The live site: no URL was given, so the headers actually sent and the TLS setup on Railway were not seen.
- Railway / DigitalOcean variables, who has access to those accounts, and whether they use 2FA.
- The spend limits in the Anthropic workspace and the OpenAI/Gemini consoles. `docs/06-audit.md` says the owner set the workspace limit, but this cannot be seen from code.
- Whether a Railway volume is attached, and any backups of `data/`.
- Who can read the platform logs and `/var/log/caddy/access.log` on a droplet. They contain request snippets.
- What Anthropic keeps from the agent sessions, and for how long.
- The WhatsApp/Make/Instagram flow in `docs/05-whatsapp-make.md` is only a design. No code for it was found, so it was not reviewed.
- Git history beyond the current tree. No scanner fact reported a committed secret.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
