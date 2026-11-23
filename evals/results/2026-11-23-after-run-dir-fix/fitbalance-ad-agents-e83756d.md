# Security report: fitbalance-ad-agents

Date: 2026-11-23 · Scope: code only · Facts from scanners: 1

## Summary
1. Put a daily limit in dollars on the service. Today it limits runs, and one run can open up to four paid agent sessions, each with its own $3 cap (F-01).
2. On every host you use (Railway, App Platform, droplet), check that the proxy adds the caller's real address as the last `X-Forwarded-For` entry. The wrong-password lockout trusts that entry.
3. Keep the "next step" from `docs/07-security-review.md`: replace Basic auth plus `sessionStorage` with an `HttpOnly` session cookie.

The scanner's one fact (`publish.no-header-config`, no header config for `public/`) was not confirmed. `src/server.mjs:30-38` sends all six security headers on every response through `send()` (line 105), so it is left out. The rest of the code holds up well: the page only shows text (`textContent`), links are allowed only when they start with `http(s)`, and the password check is constant-time. Wrong passwords are limited and logged, POSTs must be JSON from the same site, and secrets are kept out of git and out of the image.

## Findings

### F-01 · LOW · A06 Insecure Design
**What can happen:** Someone who has the password, or a stuck loop of revisions, can spend several times more than the "$3 per session × 30 runs a day" the README promises. The run counter also starts again at zero after every restart or redeploy.
**Where:** `src/ads.mjs:110`, `src/ads.mjs:112-119`, `src/ads.mjs:215-216`, `src/ads.mjs:238-246`, `src/env.mjs:31-37`
**Evidence:** `const runTimes = []; // start times of runs in the last 24 hours (resets on restart)`. And: "Each review is a new reviewer session with the same spend cap, inside the job's one admitted run". With `MAX_REVIEW_ROUNDS` 2, one admitted run can open one researcher session and up to 3 reviewer sessions, each with `AD_SESSION_BUDGET_CENTS` (300). That is about $12 per run, so roughly $360 a day in the worst case. Pictures come on top of that.
**Fix:** In `admit()`, also add up the day's cost (`job.usage.listCostCents + job.reviewCostCents`, which `agentTurn`/`reviewLoop` already record), and refuse new runs above a `MAX_DOLLARS_PER_DAY` setting. Keep `runTimes` (or the day's total) in a small file under `config.dataDir`, so a restart does not reset it. In the README, change "$3 per session" to the real worst case per run. Also set the monthly limit in the Anthropic and OpenAI consoles, which the README already recommends.
**Verify:** In `test/server.mjs`, use the fake driver with a fixed cost per session. Start runs until the dollar limit is reached and check that the next `POST /api/ads` returns 429. Then restart the app on the same `DATA_DIR` and check that it still returns 429.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Owner's post requests and revision texts | `data/ads/<id>.json`; first 100 characters also in the server log (`src/ads.mjs:136`, `src/ads.mjs:157`); sent to Anthropic | Making the post | No (marketing requests). Question for the owner: how long should the logs and job files be kept? There is no deletion. |
| Agent drafts, sources, review notes, generated pictures | `data/ads/` (volume or droplet disk) | Showing drafts to the owner | No |
| Brand sheet and facts, including the owner's name and her own product reviews | `prompts/brand-sheet.md`, `prompts/facts.md` (in git); sent to Anthropic in every kickoff | Writing posts in her voice | No (published business info), but it is personal text in the repo. Question for the owner: is the repository private? |
| `APP_PASSWORD` | `.env` / platform variables; in the browser tab's `sessionStorage` | Access to the API | Yes (secret) |
| API keys (Anthropic `sk-ant-…`, OpenAI `sk-…`, Gemini `AIza…`) | `.env` / platform variables only (none found in code) | Paid model calls | Yes (secret) |
| Caller IP addresses | Server log on wrong passwords (`src/server.mjs:68-69`); Caddy access log on the droplet | Spotting password guessing | Low. Question for the owner: how long are the logs kept? |

## Accepted risks

- The container runs as root, because Railway mounts volumes as root (`Dockerfile:9`, `docs/07-security-review.md`).
- The research agent has unrestricted web access, because open web research is its job, and it holds no keys and no private data (`environments/ad-research.yaml:4-6`, `docs/07-security-review.md`).
- The password is kept in `sessionStorage`. This is limited by a strict CSP and no third-party scripts, and an `HttpOnly` cookie is planned (`public/app.js:3`, `docs/07-security-review.md`).
- `deploy/deploy.sh` connects as root, and `deploy/setup-droplet.sh:14` runs NodeSource's `curl | bash` once (`docs/07-security-review.md`).

## Not checked

- Whether Railway, App Platform or Caddy really add the client address as the **last** `X-Forwarded-For` entry (`src/server.mjs:51-54`). If a host reaches the app directly, a caller can send a new fake address with every guess and get around the 10-guess lockout. If a host puts its own internal address last, all callers share one counter, and a stranger could lock the owner out.
- The scanner fact `publish.no-header-config`. It was not reported because `src/server.mjs` sends CSP, HSTS, X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy and Permissions-Policy. Whether a host or CDN strips them can only be seen on the live site, which was not given.
- Hosting settings: who has access to the Railway / DigitalOcean / GitHub accounts, 2FA on those accounts and on the Anthropic/OpenAI/Google consoles, and whether variables are marked encrypted.
- The monthly spend limits in the provider consoles, which the README relies on as the fourth cap.
- Who can read the server logs and the Caddy access log, how long they are kept, and backups of the `data/` volume.
- Git history and `npm audit` were not run here (no tools to run them). The project's own review says both were clean on 2026-11-18. `@anthropic-ai/sdk` is pinned with a caret range (`^0.124.0`), so the exact installed version depends on `package-lock.json`.
- How the Managed Agents platform enforces the agents' tool lists and budgets on Anthropic's side.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
