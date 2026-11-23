# Security report: yahav-picks

Date: 2026-11-23 · Scope: code only · Facts from scanners: 4

## Summary
1. Update `sharp` from 0.33.5 to 0.35.5 or later. It processes every product photo during the build, and the build job can write to the repo.
2. Move the write permissions in `.github/workflows/site.yml` off the top level, so that only the `deploy` job has them.
3. Allow only `https://` links for the AliExpress link and the video link before they go into the page. Then add a Content-Security-Policy meta tag to the page template and to the links page.

## Findings

### F-01 · HIGH · A03 Software Supply Chain Failures
**What can happen:** A crafted image placed in Airtable can exploit known bugs in the image library during the hourly build. That build holds the Airtable token and has write access to your repo and your Pages site.
**Where:** `package.json:11`, `package-lock.json:490`, `build/images.mjs:3`
**Evidence:** `"sharp": "0.33.5"`. The npm audit report says: "sharp <=0.35.5-rc.1: … Vulnerability in librsvg dependency CVE-2026-96889; sharp inherited vulnerabilities in libvips … libheif … fix: sharp 0.35.5". In `build/images.mjs` the build downloads each Airtable photo with `fetch(photo.url)` and passes it to `sharp(src)`.
**Fix:** In `package.json` set `"sharp": "0.35.5"` (or newer), run `npm install` and commit the new `package-lock.json`. In `build/airtable.mjs:37`, also accept only `image/jpeg`, `image/png` and `image/webp` attachments, rather than anything that starts with `image/` (this also excludes SVG and HEIC).
**Verify:** Run `npm audit` and confirm it no longer lists sharp. Run `npm run preview` and confirm the photos still build.

### F-02 · MEDIUM · A01 Broken Access Control
**What can happen:** Every job gets write access to the repo and the right to deploy Pages. This includes the `build` job, which installs npm packages and processes downloaded images. So a bad package or image could push code or publish a changed site.
**Where:** `.github/workflows/site.yml:20`, `.github/workflows/site.yml:21`, `.github/workflows/site.yml:22`, `.github/workflows/site.yml:23`
**Evidence:** `permissions:` / `contents: write` / `pages: write` / `id-token: write` are set at the top level of the workflow.
**Fix:** Set the top level to `permissions: { contents: read }`. Under `deploy:` add `permissions: { contents: write, pages: write, id-token: write }`. The `build` job then keeps only `contents: read`, which is enough for `upload-pages-artifact`.
**Verify:** Run the workflow from the Actions tab. Open the `build` job log, expand "GITHUB_TOKEN Permissions" and check that it lists only `Contents: read`. The deploy should still succeed and still commit `data/last-hash.txt`.

### F-03 · LOW · A05 Injection
**What can happen:** If someone with edit access to the Airtable base enters a link such as `javascript:…` in the buy-link or video field, it is published as a clickable link that runs script on your site. Escaping the HTML does not stop this.
**Where:** `build/templates.mjs:104`, `build/templates.mjs:221`, `build/airtable.mjs:44`, `build/airtable.mjs:54`
**Evidence:** `href="${esc(p.link)}"` and `href="${esc(p.reel)}"`. `esc` only replaces `& < > "`. In `airtable.mjs` the values are only trimmed: `link: text(f[F.link])`, `reel: text(f[F.reel])`.
**Fix:** In `build/airtable.mjs`, add a helper `const safeUrl = (s) => { try { const u = new URL(s); return u.protocol === 'https:' ? u.href : ''; } catch { return ''; } };`. Use it with `link: safeUrl(text(f[F.link]))` and `reel: safeUrl(text(f[F.reel]))`. A bad link then counts as missing, and `missingFields` already holds back products with no link.
**Verify:** Add a row to `data/fixture.json` with link `javascript:alert(1)`. Run `npm run preview` and check that the card shows "חסר קישור" and that no `javascript:` appears anywhere in `dist/`.

### F-04 · LOW · A02 Security Misconfiguration
**What can happen:** Neither site sends any security headers or a Content-Security-Policy. If a script ever gets into a page, nothing limits what it can do. The pages can also be framed by other sites.
**Where:** `build/templates.mjs:38`, `hub/links/index.html:4`
**Evidence:** The `<head>` built in `page()` contains only charset, viewport, SEO and font/style tags, with no `http-equiv="Content-Security-Policy"`. `hub/links/index.html` has the same gap, and the scanner found no `_headers` file or `netlify.toml` headers for `hub/links/`. GitHub Pages cannot send custom headers, so a meta tag is the only option there.
**Fix:** In `page()`, after `<meta charset="utf-8">`, add `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'">` and `<meta name="referrer" content="strict-origin-when-cross-origin">`. In the links page, also allow `fonts.googleapis.com`/`fonts.gstatic.com` and `'unsafe-inline'` for its inline `<style>`. When it moves to the main Netlify site, add a `_headers` file there with CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` and `Permissions-Policy`.
**Verify:** Open the built site with the browser dev tools Console open, and check that there are no CSP errors and that search and filters still work. Run `curl -I` against the Netlify links page after deploy and check that the headers are there.

### F-05 · LOW · A08 Software or Data Integrity Failures
**What can happen:** The workflow uses actions by version tag. A tag can be moved to different code, and that code would then run with your Airtable token and Pages deploy rights.
**Where:** `.github/workflows/site.yml:36`, `.github/workflows/site.yml:38`, `.github/workflows/site.yml:46`, `.github/workflows/site.yml:79`, `.github/workflows/site.yml:92`, `.github/workflows/site.yml:96`
**Evidence:** `actions/checkout@v4`, `actions/setup-node@v4`, `actions/cache@v4`, `actions/upload-pages-artifact@v3`, `actions/deploy-pages@v4`
**Fix:** Replace each tag with the full commit SHA of that release and keep the tag as a comment, for example `actions/checkout@<40-char-sha> # v4`. Turn on Dependabot for `github-actions` so the SHAs stay up to date.
**Verify:** Run `grep -n "uses:" .github/workflows/site.yml` and check that every line ends in a 40-character SHA, then run the workflow once.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Customer name on customer recommendations (`customer` field) | Airtable, published in the built pages | "המלצה של …" byline on product pages | No, but it is a real person's name made public: do you have each customer's consent, and a way to remove it on request? |
| Yahav's portrait photo | `src/img/yahav-src.jpg`, published | Site hero and share image | No |
| Yahav's business WhatsApp number | `build/config.mjs:16`, published | Contact links | No (intentionally public) |
| Builder's personal WhatsApp number | `build/config.mjs:18`, published | Footer credit link | Low: is this personal number meant to be public on every page? |
| Visitor data | Not collected by the site, which has no forms, cookies or analytics | n/a | n/a |
| Visitor IP / browser on the links page | Google Fonts (`hub/links/index.html:18`) | Loading fonts | Question: the picks privacy page says fonts load "from the site itself". That is true for the picks site, but not for the links page, which needs its own privacy statement. |

## Accepted risks

None.

## Not checked

- Who has access to the Airtable base, and whether the token really has only the `data.records:read` scope for this one base. The README says so, but the token settings cannot be seen from the code.
- GitHub repo settings: branch protection on `main`, who can push or run `workflow_dispatch`, 2FA on the GitHub, Airtable and Netlify accounts, and the "Enforce HTTPS" setting on Pages.
- The live sites (`picks.fit-balance.co.il`, `fit-balance.co.il/links/`): no URL was given, so the headers and HTTPS actually served were not tested.
- Netlify DNS and the main `fit-balance-site` repo where `hub/links/index.html` is meant to live.
- Git history was not available to these tools. The scanners reported no secrets in it.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
