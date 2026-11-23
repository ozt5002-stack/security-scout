I've read every file in the project, but I couldn't open the scanner facts file, so I'm writing the report from the code alone.

# Security report: yahav-picks

Date: 2026-11-23 · Scope: code only · Facts from scanners: 4

## Summary
1. Only allow `https:` links for the "buy" and "video" fields from Airtable before they go into `href`. A `javascript:` value typed into Airtable would run on the live site.
2. Give the GitHub Actions jobs only the permissions they need. Right now the job that runs `npm ci` and holds the Airtable token can also push to the repo.
3. Add a Content-Security-Policy meta tag to every page, and pin the CI actions to commit SHAs instead of `@v4`/`@v3` tags.

Note: the facts file (4 facts) could not be opened in this run because access was denied. The findings below come only from reading the code, so none of the 4 facts was confirmed or ruled out (see "Not checked").

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone who can edit the Airtable table (a collaborator, or someone who takes over that account) can put `javascript:…` in the product link or video field. Every visitor who taps "לקנייה" or the video link on the live site would then run that script.
**Where:** `build/templates.mjs:104`, `build/templates.mjs:221`, `build/airtable.mjs:44`, `build/airtable.mjs:54`
**Evidence:** `href="${esc(p.link)}"` and `href="${esc(p.reel)}"`. `esc()` only escapes `& < > "`, and `link: text(f[F.link])` / `reel: text(f[F.reel])` are never checked for their URL scheme.
**Fix:** In `toProduct` (build/airtable.mjs), add a helper like `const safeUrl = (v) => { try { const u = new URL(text(v)); return u.protocol === 'https:' ? u.href : ''; } catch { return ''; } };` and use `link: safeUrl(f[F.link])`, `reel: safeUrl(f[F.reel])`. You can also add an allow-list of hosts (`s.click.aliexpress.com`, `www.instagram.com`, `www.tiktok.com`). A product with a rejected link then counts as "missing link" and is skipped by `missingFields`.
**Verify:** Add a fixture row with `"fldXxwbp2jzFw7MFJ": "javascript:alert(1)"` and run `npm run preview`. The card should show "חסר קישור" and no `javascript:` should appear anywhere in `dist/`.

### F-02 · MEDIUM · A08 Software or Data Integrity Failures
**What can happen:** If any npm package (for example `sharp` or one of its install steps) is compromised, it runs in the build job. That job holds both the Airtable token and a GitHub token that can push code and deploy Pages, so the package could change the site or the repo.
**Where:** `.github/workflows/site.yml:20`, `.github/workflows/site.yml:43`, `.github/workflows/site.yml:55`
**Evidence:** Workflow-wide `permissions: contents: write / pages: write / id-token: write`. The `build` job then runs `npm ci` and `npm run build` with `AIRTABLE_TOKEN: ${{ secrets.AIRTABLE_TOKEN }}`.
**Fix:** Set the top-level permissions to `permissions: contents: read`. Give the `build` job only `contents: read`. Give the `deploy` job `contents: write`, `pages: write` and `id-token: write`. Also run `npm ci --ignore-scripts` if `sharp` still works that way (it ships prebuilt binaries via optional dependencies); otherwise keep scripts but leave the token read-only.
**Verify:** Open a run in the Actions tab. Under "Set up job" → "GITHUB_TOKEN Permissions", the build job should list only `Contents: read`.

### F-03 · LOW · A03 Software Supply Chain Failures
**What can happen:** If the owner of a third-party action moves a tag like `@v4` to new code, that code runs in your workflow automatically, with your secrets and write permissions.
**Where:** `.github/workflows/site.yml:36`, `.github/workflows/site.yml:38`, `.github/workflows/site.yml:46`, `.github/workflows/site.yml:79`, `.github/workflows/site.yml:92`, `.github/workflows/site.yml:96`
**Evidence:** `uses: actions/checkout@v4`, `actions/setup-node@v4`, `actions/cache@v4`, `actions/upload-pages-artifact@v3`, `actions/deploy-pages@v4`
**Fix:** Replace each tag with the full commit SHA of that release, keeping the tag as a comment, for example `uses: actions/checkout@<40-char-sha> # v4.2.2`. Turn on Dependabot for `github-actions` so the SHAs are kept up to date.
**Verify:** `grep -n "uses:" .github/workflows/site.yml` should show only 40-character SHAs.

### F-04 · LOW · A02 Security Misconfiguration
**What can happen:** The pages have no Content-Security-Policy. If something unwanted ever ends up in a page (see F-01), the browser has no second line of defense. Other sites can also frame the pages.
**Where:** `build/templates.mjs:37`, `hub/links/index.html:4`
**Evidence:** The `<head>` built in `page()` holds only charset, viewport, SEO/OG meta, icon, font preload and stylesheet. There is no `<meta http-equiv="Content-Security-Policy">`, and GitHub Pages cannot send custom headers (no `_headers` or similar file exists).
**Fix:** In `page()` right after `<meta charset="utf-8">`, add `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; script-src 'self'; base-uri 'self'; form-action 'none'; object-src 'none'">` and `<meta name="referrer" content="strict-origin-when-cross-origin">`. The site has no inline scripts or styles, so this should not break anything. Do the same for `hub/links/index.html` when it moves to the main site, allowing `fonts.googleapis.com`/`fonts.gstatic.com` and `'unsafe-inline'` for its inline `<style>`, or move that CSS to a file. HSTS, frame-ancestors and nosniff can only be set by the host (see Not checked).
**Verify:** Open a product page, then DevTools → Console. There should be no CSP errors, and `document.querySelector('meta[http-equiv]')` should return the tag.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Customer name shown on a recommendation ("המלצה של …") | Airtable field `customer` → published in static HTML (`build/templates.mjs:113`) | Crediting a customer's recommendation | No, but it is a real person's name made public. Question for owner: is the customer's consent recorded, and is there a way to remove it on request? |
| Yahav's portrait photo | `src/img/yahav-src.jpg` in the repo → `dist/img/` | Site header and share image | No (public on purpose) |
| Business WhatsApp number | `build/config.mjs:16-17`, `hub/links/index.html:57` | Contact links | No (public on purpose) |
| Builder's WhatsApp number | `build/config.mjs:18` | Footer credit link | No (public on purpose); question for owner: is the builder OK with it being public? |
| Visitor IP / browser (by host) | GitHub Pages logs (outside the code) | Hosting | Personal data, held by GitHub as the privacy page says |
| Visitor IP (by Google Fonts) | Google, via `hub/links/index.html:16-18` | Fonts on the links page | Personal data. Question for owner: the main site's privacy policy should mention Google Fonts, or the fonts should be self-hosted as on the picks site |

## Accepted risks

None.

## Not checked

- The scanner facts file (`facts.json`, 4 facts): it could not be read in this run because access was denied, so none of its facts was confirmed or ruled out.
- The live site: no URL was given. I could not see the actual response headers from GitHub Pages (HSTS, X-Frame-Options, nosniff, Permissions-Policy) or whether "Enforce HTTPS" is on.
- Airtable: who has edit access to the base, whether the token really has only `data.records:read` on this one base, and whether accounts use 2FA.
- GitHub repo settings: who can push to `main`, branch protection, whether the `github-pages` environment limits deployments, and which token the "outside pinger" uses to call `workflow_dispatch` (its scope and where it is stored).
- Git history: earlier commits were not available to Read/Grep, so I could not check them for secrets.
- Package vulnerabilities in `package-lock.json` (for example `sharp` 0.33.5 and its libvips binaries): known-CVE lookup needs a scanner or network access.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
