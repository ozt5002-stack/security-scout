# Security report: fitbalance-ad-agents

Date: 2026-11-23 · Scope: code only · Facts from scanners: 1

## Summary
1. Store the `MAX_RUNS_PER_DAY` run count on disk under `data/` so a restart or a redeploy does not reset it.
2. Check how Railway fills in `X-Forwarded-For` before you rely on the 10-wrong-passwords block (see "Not checked").
3. Set a monthly spend limit in the Anthropic and OpenAI consoles, and decide how long drafts and logs are kept.

The scanner's one fact (`publish.no-header-config`, no security headers for `public/`) is not a finding. `src/server.mjs:30-38` sends all six headers (CSP with `frame-ancestors 'none'`, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy) on every response through `send()`. No other real problem turned up. Passwords are compared in constant time, and there is a wrong-password block, a CSRF check, JSON-only writes and textContent-only rendering. Source links must start with `http(s)`, CI actions are pinned to commits with read-only permissions, the reviewer agent has no web tools, and no keys appear in the files.

## Findings

### F-01 · LOW · A06 Insecure Design
**What can happen:** The "30 agent runs a day" spending cap starts from zero every time the service restarts. Every `git push` on Railway restarts it, and so does `Restart=always` on the droplet. So in a busy day, or if the password leaks, more runs can be paid for than the README promises. Only the $3 cap per session still holds.
**Where:** `src/ads.mjs:110`, `src/ads.mjs:112-119`
**Evidence:** `const runTimes = [];         // start times of runs in the last 24 hours (resets on restart)`
**Fix:** Keep `runTimes` in a small JSON file under `config.dataDir`, for example `data/usage.json`. Read it when the server starts, and write it in `admit()` after `runTimes.push(now)`. Do this the same way `saveJob` writes job files. Also set the monthly spend limit in the Anthropic and OpenAI consoles that README section 6 recommends, so a hard cap exists outside the app.
**Verify:** Start the server with `MAX_RUNS_PER_DAY=1` and the fake driver (`AD_AGENT_DRIVER=fake`, `IMAGE_PROVIDER=mock`). Create one ad, restart the server and try a second one. It must answer `429` with "daily limit".

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| App password (`APP_PASSWORD`) | `.env` / cloud variables; the owner's browser `sessionStorage` (`public/app.js:13-15`) | Login to the page and the API | Yes (credential) |
| API keys (Anthropic, OpenAI, Gemini) | `.env` / cloud variables only | Agent sessions and pictures | Yes (credential) |
| Post requests and replies typed by the owner | `data/ads/<id>.json` (`src/ads.mjs:52-53`); first 100 characters in the server log (`src/ads.mjs:136`, `:157`); sent to Anthropic | Writing the post | Normally no |
| Drafts, agent text, reviews, source URLs, pictures | `data/ads/` (job JSON and `.jpg`) | Showing and downloading drafts | No |
| Owner's business facts and quoted reviews, public Instagram handle | `prompts/facts.md`, `prompts/brand-sheet.md` (in git); sent to Anthropic in every kickoff | Facts a post may state | No (public business info) |
| Client IP addresses | Server log on wrong passwords (`src/server.mjs:68-69`); Caddy access log `/var/log/caddy/access.log` on the droplet | Spotting password guessing | Low (personal data under privacy law) |

Questions for the owner (not legal rulings): how long should `data/ads/`, `logs/server.log` and the Caddy access log be kept? Nothing in the code deletes them. Also make sure no customer details (names, phones, health details) are ever typed into a request, because those would be stored and sent to Anthropic.

## Accepted risks

- The container runs as root because Railway mounts the volume as root (`Dockerfile:9`, `docs/07-security-review.md` "סיכונים שהשארתי בכוונה").
- The research agent has unrestricted network access for open web research. It holds no keys and has no private data, and its output is checked by `validateBrief`, the reviewer and the owner (`environments/ad-research.yaml:4-6`, `docs/07-security-review.md`).
- The password is kept in `sessionStorage`. CSP allows only same-site scripts, and the planned next step is an `HttpOnly` session cookie (`docs/07-security-review.md`).
- `deploy.sh` connects as root, and `setup-droplet.sh` runs NodeSource's `curl | bash` once during setup (`deploy/setup-droplet.sh:14`, `docs/07-security-review.md`).

## Not checked

- **Railway / DigitalOcean proxy behaviour:** `clientAddress()` (`src/server.mjs:51-54`) trusts the last `X-Forwarded-For` entry. That is safe only if the platform's proxy always adds the real client address as the last entry. If the app is ever reached without such a proxy, an attacker can send a different fake address on every request, which avoids the wrong-password block and can also block other people. On the droplet, Caddy fronts the app and the firewall closes port 3000. Railway's and App Platform's behaviour cannot be seen from the code.
- Hosting settings on Railway or DigitalOcean: who has access to the account and its variables, 2FA, volume backups.
- Who can read the server logs and the Caddy access log, and how long they are kept.
- Spend limits actually set in the Anthropic, OpenAI and Google consoles.
- Git history and the current `npm audit` result: I can only read files, not run commands. The project's own review (`docs/07-security-review.md`) reports both as clean on 2026-11-18.
- The live site: no URL was given, so the headers and the 401/429 behaviour were checked only in the code.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
