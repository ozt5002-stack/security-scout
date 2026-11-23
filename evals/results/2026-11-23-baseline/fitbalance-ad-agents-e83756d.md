# Security report: fitbalance-ad-agents

Date: 2026-11-23 · Scope: code only · Facts from scanners: 1

## Summary
1. Make the wrong-password lockout trust `X-Forwarded-For` only when the app runs behind a known proxy. Also add a server-wide cap on wrong passwords, so changing a header cannot bypass the lockout.
2. Save the daily run counter (`MAX_RUNS_PER_DAY`) to the data folder, so a restart or redeploy does not reset the spending limit.
3. Decide how long drafts, pictures and logs (which hold IP addresses) are kept, and delete them on a schedule.

I could not read the scanners' facts file (permission was refused), so its one fact was not confirmed. All findings below come from reading the code. Overall the project is in good shape:
- All six security headers are sent from `src/server.mjs`.
- Agent output is shown with `textContent` only, and source links must start with `http(s)`.
- Ad ids and picture file names are checked against fixed patterns.
- The password is compared in constant time and must be at least 12 characters.
- POST requests must be JSON, and an `Origin` header must match the site.
- CI actions are pinned to a commit, and CI can only read the repository.
- No keys were found in the files.
- The research agent has only web search and web fetch, and its output is checked by code before anything is drawn.

## Findings

### F-01 · LOW · A07 Authentication Failures
**What can happen:** The block after 10 wrong passwords is keyed on an address the caller can choose. If the app is reached without a proxy that overwrites `X-Forwarded-For` (for example `npm start` on an open port, or a host that passes the client's header through), an attacker can send a new fake address with each guess and is never blocked.
**Where:** `src/server.mjs:51`, `src/server.mjs:52`, `src/server.mjs:53`, `src/server.mjs:129`
**Evidence:** `const fwd = String(req.headers['x-forwarded-for'] ?? '').split(',')...; return fwd.at(-1) || req.socket?.remoteAddress` (the last entry is trusted without checking that a proxy wrote it). Failures are also counted only per address (`failures.get(addr)`), with no limit across all addresses.
**Fix:**
- Add a setting such as `TRUST_PROXY=1`. Read `X-Forwarded-For` only when it is set, and use `req.socket.remoteAddress` otherwise.
- Set `TRUST_PROXY=1` only on Railway, App Platform and the Caddy droplet, after checking that each platform overwrites or appends the header.
- Also keep a global counter, for example more than 100 wrong passwords in 15 minutes across all addresses: log a warning and answer 429 to everyone for that window.

The required 12+ character password makes guessing very slow anyway, which is why this is LOW.
**Verify:**
- Without `TRUST_PROXY`, send 11 wrong passwords, each with a different `X-Forwarded-For` header. The 11th must return 429.
- Add a test for this next to the existing lockout test in `test/server.mjs`.

### F-02 · LOW · A06 Insecure Design
**What can happen:** The 30-runs-per-day spending limit is kept only in memory, so it starts again at zero after every restart, crash or deploy. Anyone who has the password, or a stuck script, can spend more than the owner planned. Picture costs are not covered by the per-session agent budget.
**Where:** `src/ads.mjs:110`, `src/ads.mjs:116`, `src/ads.mjs:117`, `railway.json:10`
**Evidence:** `const runTimes = [];         // start times of runs in the last 24 hours (resets on restart)`; `"restartPolicyType": "ON_FAILURE"`
**Fix:**
- In `admit()`, save `runTimes` to a small file under `config.dataDir` (for example `data/usage.json`) after each `push`, and load it when the module starts.
- Keep the monthly spend limits in the Anthropic and OpenAI consoles as the final backstop, as the README already advises.
**Verify:** Create two ads, restart the server, then open `/api/info`. `usage.runs` must still show 2.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Ad requests, replies, drafts, agent notes, web source links | `data/ads/<id>.json` (server disk or Railway volume) | Making and revising posts | No (business content) |
| Generated pictures | `data/ads/<id>_<n>.jpg` | Post images | No |
| Brand sheet and facts (owner's name, business, prices, owner's own reviews) | `prompts/brand-sheet.md`, `prompts/facts.md` (in git); sent to Anthropic in every kickoff | Agent context | No (public business info) |
| App password | `.env` / cloud variables; browser `sessionStorage` (`ad-agents-password`) | Logging in to the API | Yes (credential) |
| Caller IP addresses | In memory (`failures` map); server log lines `[auth] wrong password from <addr>`; Caddy `/var/log/caddy/access.log` | Wrong-password lockout, access logs | Personal data (IP address) |
| Request text (first 100 characters) | Server log (`info(`${id}: new ad: ...`)`) | Debugging | No |
| API keys (Anthropic, OpenAI, Gemini) | `.env` / cloud variables only | Calling the model providers | Yes (secret) |

Questions for the owner:
- How long should drafts, pictures and logs be kept? No deletion or expiry exists in the code.
- If customer details are ever added to `prompts/facts.md` or to requests, they will be sent to Anthropic and OpenAI and stored with no end date.

## Accepted risks

- The container runs as root, because Railway mounts its volume as root (`Dockerfile:9`, `docs/07-security-review.md`).
- The research agent has unrestricted network access for open web research. It holds no keys, its output is checked by `validateBrief` and the reviewer, and it cannot post, send or pay (`environments/ad-research.yaml:4`, `docs/07-security-review.md`).
- The password is kept in `sessionStorage`, where a script running in the page could read it. This is reduced by a CSP that allows only scripts from the site itself, and no third-party scripts are loaded (`public/app.js:3`, `docs/07-security-review.md`).
- `deploy.sh` connects as root, and `setup-droplet.sh` runs NodeSource's `curl | bash` (`deploy/deploy.sh:12`, `deploy/setup-droplet.sh:14`, `docs/07-security-review.md`).

## Not checked

- **The scanners' facts file** (`facts.json`, 1 fact): reading it was refused by a permission prompt, so that fact was neither confirmed nor rejected.
- **The live site:** no URL was given. I could not check headers on real responses, the HTTPS setup, or whether Railway / App Platform overwrite or append `X-Forwarded-For` (which decides how serious F-01 is in production).
- **Hosting settings:** who can see the Railway / DigitalOcean variables and logs, volume backups, and 2FA on the Railway, DigitalOcean, GitHub, Anthropic and OpenAI accounts.
- **Git history:** I cannot run git with my tools. The project's own review says the history was searched for keys and found clean; I did not verify that.
- **Known-vulnerable packages:** I cannot run `npm audit`. `package-lock.json` exists and `npm ci` uses it, and the project's own review reports 0 vulnerabilities.
- **Spend limits in the provider consoles** (Anthropic workspace limit, OpenAI monthly limit): these live outside the code.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
