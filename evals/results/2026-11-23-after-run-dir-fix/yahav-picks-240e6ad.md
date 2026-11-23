I've finished reading the code and the one scanner fact, and I'm writing the report now.

# Security report: yahav-picks

Date: 2026-11-23 · Scope: code only · Facts from scanners: 1

## Summary
1. Before `hub/links/index.html` goes live on the main site, add a Content Security Policy (CSP) to it. Either put it in that site's header config or add a CSP meta tag, as this site already does in `build/templates.mjs:36`.
2. Make the local preview server `build/serve.mjs` listen on `127.0.0.1` only, and tighten its path check so it can't serve folders next to `dist/`.
3. Decide whether customers agree to have their names published (the "customer" field). Also check the hosting items under "Not checked": headers GitHub Pages sends, who can see Actions logs, and 2FA.

Overall this project is in good shape. It's a static site with no forms, logins or cookies. Text from Airtable is escaped (`esc()`), and link fields only accept `https` addresses on approved hosts (`safeUrl`). The pages ship a strict CSP meta tag. The CI workflow pins actions to commits and starts with `permissions: {}`. The one scanner fact (no header config for `hub/links/`) is real and is F-01 below. The main site's pages are not affected, because they carry a CSP meta tag.

## Findings

### F-01 · LOW · A02 Security Misconfiguration
**What can happen:** The Instagram bio page has no Content Security Policy and loads Google Fonts from Google's servers. If anything is ever injected into it, or a third-party file is changed, the browser has no rules limiting what runs, and every visitor's IP address goes to Google.
**Where:** `hub/links/index.html:4`, `hub/links/index.html:18`
**Evidence:** The `<head>` has no `Content-Security-Policy` meta tag. Line 18 loads `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Assistant...">`, and line 19 has an inline `<style>` block.
**Fix:** This page is meant to live in the main site repo (`fit-balance/fit-balance-site/links/index.html`, per the README). There, add the six security headers in that host's config (for example a `[[headers]]` block for `/links/*` in `netlify.toml`). The other option is a meta tag such as `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'">`. Better still, host the fonts yourself as this site does (`src/fonts/`): then you can drop Google and the `'unsafe-inline'` by moving the CSS into a file.
**Verify:** Open the live `/links/` page, then go to DevTools → Network → the document → Response Headers. Check that the CSP is there (or that the meta tag is in the page source) and that the Console shows no CSP errors.

### F-02 · LOW · A01 Broken Access Control
**What can happen:** While you run the local preview, anyone on the same network (café or office Wi-Fi) can open it. The path check also lets them read files from other folders next to `dist/` whose names start with `dist`, such as `dist-old/`.
**Where:** `build/serve.mjs:17`, `build/serve.mjs:26`
**Evidence:** `if (!file.startsWith(ROOT)) { res.writeHead(403).end(); return; }` and `.listen(PORT, () => ...)` (no host given, so Node listens on all network interfaces).
**Fix:** Use `.listen(PORT, '127.0.0.1', ...)`. Change the check to `if (file !== ROOT && !file.startsWith(ROOT + path.sep))`.
**Verify:** Run `node build/serve.mjs`. From another device on the same Wi-Fi, open `http://<your-PC-IP>:4173`: it should fail to connect. Locally, `curl --path-as-is http://localhost:4173/../dist-x/a` should return 403.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Customer name on a customer's recommendation (`customer` field) | Airtable; published on product pages (`build/templates.mjs:119`) | Credits the person who recommended the product | No, but it's a real person's name made public. Do customers agree? |
| Yahav's WhatsApp number | `build/config.mjs:16-17`; published on every page | Contact link | No (a business contact made public on purpose) |
| Builder's WhatsApp number | `build/config.mjs:18`; published in the footer | Credit link | No (made public on purpose) |
| Yahav's portrait photo | `src/img/yahav-src.jpg`; published | Hero image | No |
| Airtable access token | GitHub Actions secret `AIRTABLE_TOKEN` (`.github/workflows/site.yml:57`) | Reading product rows at build time | Yes (credential; not in the code) |
| Visitor IP addresses | GitHub Pages logs (and Google Fonts, for the links page) | Hosting | Personal data held by third parties |

## Accepted risks

- The site can be shown inside another site's frame (clickjacking), because GitHub Pages can't send a `frame-ancestors` header and a meta tag can't set it. The code says so: `build/templates.mjs:35`, "(frame-ancestors only works as a header, so framing is not blocked here.)" The risk is low: the site has no forms, logins or actions to trick anyone into.

## Not checked

- **Response headers GitHub Pages actually sends** (HSTS, nosniff, Referrer-Policy, Permissions-Policy) on `ozt5002-stack.github.io/yahav-picks` and `picks.fit-balance.co.il`: I wasn't given a live URL. GitHub Pages also can't be configured to add headers, so headers other than the CSP meta tag depend on the host.
- **The main site repo** where `hub/links/index.html` will live (its `netlify.toml` or `_headers`, and its `/privacy` page): it isn't in this folder.
- **Airtable**: whether the token really has only `data.records:read` on this one base (the README says it does), and who has access to or share links for the base.
- **GitHub account and repo**: 2FA, who has write access, branch protection on `main`, and whether the repo and its Actions logs are public. The logs print product names, including skipped ones.
- **Dependency vulnerabilities**: `sharp 0.35.5` and the lockfile weren't checked against an advisory database, because no scanner fact covers them and I can't run `npm audit`.
- **DNS** for `picks.fit-balance.co.il` (Netlify DNS) and whether "Enforce HTTPS" is turned on.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
