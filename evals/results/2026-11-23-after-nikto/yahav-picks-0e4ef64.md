# Security report: yahav-picks

Date: 2026-11-23 · Scope: code only · Facts from scanners: 4

## Summary
1. Upgrade `sharp` from 0.33.5 to 0.35.5 or later and commit the new `package-lock.json`. The build runs every photo from Airtable through it, and it has known security holes.
2. In `.github/workflows/site.yml`, give write permissions only to the `deploy` job. The `build` job runs third-party code and image parsing, so it should only be able to read.
3. Accept only `https://` links for the buy link and the video link, and add a Content-Security-Policy meta tag to the generated pages.

## Findings

### F-01 · HIGH · A03 Software Supply Chain Failures
**What can happen:** A specially made image file in Airtable could exploit known holes in the image library (libvips, librsvg, libheif inside `sharp`) during the hourly build. That build holds your Airtable token and a GitHub token that can write to the repo and publish the site.
**Where:** `package.json:11`, `package-lock.json:491`, `build/images.mjs:34`, `build/images.mjs:52`, `build/images.mjs:58`
**Evidence:** `"sharp": "0.33.5"`. The npm advisories list several CVEs/GHSAs for `sharp <=0.35.5-rc.1`, with the fix in 0.35.5. `build/images.mjs` calls `sharp(src)` on files downloaded from Airtable attachment URLs (`await fetch(photo.url)`).
**Fix:** Set `"sharp": "0.35.5"` (or later) in `package.json` and run `npm install` so the lock file updates. Commit both files. Also look at `toProduct` in `build/airtable.mjs`: it already keeps only attachments whose type starts with `image/`. Narrow that to `image/jpeg`, `image/png` and `image/webp` so SVG and HEIC files never reach the parser.
**Verify:** Run `npm ls sharp`. It should show 0.35.5 or later, and `npm audit` should report no sharp advisory. Then run `npm run preview` and check that the photos still build.

### F-02 · MEDIUM · A01 Broken Access Control
**What can happen:** The `build` job installs npm packages and parses downloaded images. If anything in that job is compromised, it has a GitHub token that can push code to the repo, publish to Pages and mint deploy credentials.
**Where:** `.github/workflows/site.yml:20`
**Evidence:** Top-level `permissions: contents: write, pages: write, id-token: write` applies to both jobs. Only `deploy` publishes to Pages and pushes `data/last-hash.txt`.
**Fix:** Change the top-level block to `permissions: contents: read`. Then add a block to the `deploy` job only: `permissions: { contents: write, pages: write, id-token: write }`. `build` keeps read-only access, which is enough for checkout, `npm ci` and `upload-pages-artifact`.
**Verify:** Open a run in the Actions tab and expand "Set up job" → "GITHUB_TOKEN Permissions" for each job. `build` should show only `Contents: read`. The site should still deploy, and the hash commit should still be pushed.

### F-03 · LOW · A05 Injection
**What can happen:** If a link in Airtable starts with `javascript:` (from a mistake, a shared Airtable form, or someone else with edit access), clicking "לקנייה" or the video button on the public site runs that script.
**Where:** `build/templates.mjs:104`, `build/templates.mjs:221`
**Evidence:** `href="${esc(p.link)}"` and `href="${esc(p.reel)}"`. `esc` escapes HTML characters but does not check the link scheme, so `javascript:` links get through.
**Fix:** In `build/airtable.mjs` `toProduct`, keep a link only if `new URL(value).protocol === 'https:'` (wrap it in try/catch) and otherwise set it to `''`. You could also allow only the hosts you expect: `s.click.aliexpress.com` for `link`, and Instagram or TikTok for `reel`. An empty `link` already marks the product as missing (`missingFields`), so it will not go live.
**Verify:** In a copy of `data/fixture.json`, set one link field to `javascript:alert(1)` and run `npm run preview`. That product should show "חסר קישור" (missing link), with no clickable link.

### F-04 · LOW · A02 Security Misconfiguration
**What can happen:** The pages have no Content-Security-Policy and no anti-framing rule. If anything ever gets injected (see F-03), the browser has no second line of defence, and other sites can show your pages inside a frame.
**Where:** `build/templates.mjs:38`, `hub/links/index.html:4`
**Evidence:** The `<head>` in `page()` contains `<meta charset>`, viewport, OG tags and stylesheet links, but no `http-equiv="Content-Security-Policy"`. The same is true of `hub/links/index.html`. GitHub Pages cannot send custom headers, and there is no `_headers` or `netlify.toml`.
**Fix:** In `page()` in `build/templates.mjs`, add after `<meta charset="utf-8">`:
`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'">` and `<meta name="referrer" content="strict-origin-when-cross-origin">`.
Notes:
- The inline `style="position:absolute"` on the icon SVG at line 23 would be blocked by `style-src 'self'`. Move it into `styles.css`.
- For `hub/links/index.html` (which belongs to the main site repo), the policy needs `'unsafe-inline'` for its `<style>` block and the Google Fonts hosts.
- `frame-ancestors` and HSTS cannot be set with a meta tag. On GitHub Pages they need a CDN in front (for example Netlify or Cloudflare) if you want them.
**Verify:** Build the site, open a product page, and check the browser console for CSP errors. Fonts, photos, search and the "new" badge should all still work. Then run the live URL through securityheaders.com.

### F-05 · LOW · A08 Software or Data Integrity Failures
**What can happen:** The workflow uses GitHub Actions by a version tag. If someone moves that tag to malicious code, your workflow runs it automatically with your secrets.
**Where:** `.github/workflows/site.yml:36`, `.github/workflows/site.yml:38`, `.github/workflows/site.yml:46`, `.github/workflows/site.yml:79`, `.github/workflows/site.yml:92`, `.github/workflows/site.yml:96`
**Evidence:** `uses: actions/checkout@v4`, `actions/setup-node@v4`, `actions/cache@v4`, `actions/upload-pages-artifact@v3`, `actions/deploy-pages@v4`
**Fix:** Replace each tag with the full commit SHA of that release, and keep the tag as a comment, for example `uses: actions/checkout@<40-char-sha> # v4`. Turn on Dependabot for `github-actions` so the pinned SHAs stay up to date.
**Verify:** `grep "uses:" .github/workflows/site.yml` should show a 40-character SHA on every line, and a manual "Run workflow" should still succeed.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Customer name on a recommendation (`customer` field) | Airtable, published on product pages (`build/templates.mjs:113`) | Crediting customer reviews ("המלצה של …") | No, but personal. Question for the owner: does each customer agree to having her name published, and how is it removed if she asks? |
| Customer and owner reviews, pros/cons, size tips | Airtable, published | Product pages | No. Watch that customers do not include health details. |
| Yahav's WhatsApp number | `build/config.mjs:16-17`, published | Contact links | No (public business contact, on purpose) |
| Site builder's WhatsApp number | `build/config.mjs:18`, published | Credit link in the footer | No (public, on purpose) |
| Yahav's portrait | `src/img/yahav-src.jpg`, published resized | Hero image | No |
| Visitor IP addresses | GitHub Pages logs; for `hub/links/index.html`, also Google Fonts | Hosting | No. Question for the owner: the links page loads Google Fonts (`hub/links/index.html:18`), so visitors' IPs go to Google. Does the main site's privacy page say so? |
| Airtable token | GitHub Actions secret `AIRTABLE_TOKEN` | Reading the product table | Secret (not found in the code) |

## Accepted risks

None.

## Not checked

- **GitHub account and repo settings:** who has write access, whether 2FA is on, branch protection on `main`, and the `github-pages` environment protection rules.
- **Airtable access:** whether the token really has only the `data.records:read` scope on this one base (README says so, but it cannot be seen from code), who can edit the base, and whether any Airtable form lets outsiders add records or attachments. That decides how exploitable F-01 and F-03 really are.
- **The "outside pinger":** the workflow comment mentions one calling `workflow_dispatch`. Where its GitHub token is stored and what scope it has is outside this repo.
- **The live site:** headers that GitHub Pages actually sends (including HSTS on the custom domain) and the HTTPS setting. No live URL was given.
- **The main site:** `hub/links/index.html` belongs to the main site repo per the README. That site's headers, and the `/privacy` and `/accessibility` pages it links to, were not reviewed.
- **Git history:** no secret was reported by the scanners. Only the current files were read.
- **`build/serve.mjs`:** it is a local preview server only and is not deployed. It listens on all network interfaces, but it only serves `dist/`, which is public anyway, so it is not listed as a finding.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
