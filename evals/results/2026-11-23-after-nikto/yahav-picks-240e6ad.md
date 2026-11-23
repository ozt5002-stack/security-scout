# Security report: yahav-picks

Date: 2026-11-23 · Scope: code only · Facts from scanners: 1

## Summary
1. Add a Content Security Policy and a referrer policy to the Instagram bio page `hub/links/index.html`. The simplest way is to host its fonts on the site itself instead of loading them from Google, as the picks site already does.
2. Accept the Airtable product number only if it is a positive whole number. Today it goes straight into the HTML and into the output file path without escaping.
3. Add `<meta name="referrer">` to the generated pages. Then look at the "Not checked" list, especially who can edit the Airtable base and how GitHub Pages and the `github-pages` environment are set up.

The scanner's one fact (no header config for `hub/links/`) is real and is reported as F-01. The main picks site already sends a CSP meta tag (`build/templates.mjs:36`). Other things I checked and found sound: links from Airtable are limited to https and to listed hosts (`safeUrl`, `build/airtable.mjs:37`), text is escaped, CI actions are pinned to commits, `permissions: {}` is set at the top of the workflow, and the build job can only read the repo. I found no AI or agent code and no secrets in the code.

## Findings

### F-01 · LOW · A02 Security Misconfiguration
**What can happen:** The bio page has no Content Security Policy or referrer policy. If anyone ever adds a script or third-party content to it, nothing in the browser will limit what that content can do. Today every visitor's IP address is also sent to Google Fonts.
**Where:** `hub/links/index.html:4`, `hub/links/index.html:18`, `build/templates.mjs:44`
**Evidence:** `hub/links/index.html` has no `Content-Security-Policy` meta tag and loads `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Assistant...">` plus an inline `<style>` block. The generated picks pages have a CSP (`build/templates.mjs:36`) but no `<meta name="referrer" ...>`.
**Fix:** In `hub/links/index.html`, which belongs in the main site repo (`fit-balance-site/links/index.html`):
- Host the Assistant and Bellefair fonts on the site itself, as `src/fonts/` does here.
- Move the `<style>` block into a `.css` file.
- Add `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; upgrade-insecure-requests">` and `<meta name="referrer" content="strict-origin-when-cross-origin">`.

In `build/templates.mjs`, add the same referrer meta right after the CSP meta on line 45.
**Verify:** Open both pages, then open DevTools → Console and Network. There should be no CSP errors and no requests to `fonts.googleapis.com` or `fonts.gstatic.com`. View the page source and confirm both meta tags are there.

### F-02 · LOW · A05 Injection
**What can happen:** If the "number" field in Airtable ever holds text instead of a number, for example after a field-type change or a mistake by someone with edit access, that text goes into the page as raw HTML (a script) and into the output file path (so files could be written outside `dist/`).
**Where:** `build/airtable.mjs:58`, `build/templates.mjs:17`, `build/templates.mjs:132`, `build/templates.mjs:136`, `build/templates.mjs:139`, `build/templates.mjs:219`, `build/templates.mjs:221`, `build/build.mjs:75`
**Evidence:** `code: f[F.code],` is taken without a check. It is then used unescaped in `<span class="num">${p.code}</span>` and in `export const productPath = (p) => \`${p.code}/\`;`, which feeds `write(productPath(p) + 'index.html', ...)`.
**Fix:** In `toProduct` (`build/airtable.mjs:58`), use `code: Number.isInteger(f[F.code]) && f[F.code] > 0 ? f[F.code] : null,`. The existing filter `p.name && p.code` in `build/build.mjs:41` then drops any bad row.
**Verify:** Copy `data/fixture.json`, set one record's `fldyLtURMuIeDAkWU` to `"<b>x</b>"` and another's to `"../../x"`, and run `node build/build.mjs --fixture <copy> --drafts`. Neither product should appear, and nothing should be written outside `dist/`.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Customer name on customer recommendations (`customer` field) | Airtable, then published on product pages (`build/templates.mjs:119`) | Credit for the review ("המלצה של …") | No, but it identifies a real person publicly |
| Yahav's name, portrait, WhatsApp number | `build/config.mjs:16-17`, `src/img/yahav-src.jpg`, every page | Public business contact | No (public on purpose) |
| Site builder's WhatsApp number | `build/config.mjs:18`, footer of every page (`build/templates.mjs:89`) | Builder credit link | No, but it is a personal phone number published on every page |
| Airtable access token | GitHub Actions secret `AIRTABLE_TOKEN` (`.github/workflows/site.yml:57`) | Reading products at build time | Yes (a credential) |
| Visitor IP and browser | GitHub Pages logs, and Google for `hub/links/` (fonts) | Hosting, font delivery | Personal data held by third parties |

Questions for the owner:
- Do customers agree, in writing, that their name will appear next to their review?
- Is the builder happy to have a personal phone number on every page?
- Does the main site's privacy policy mention Google Fonts on the bio page?

## Accepted risks

- Pages can be shown inside another site's frame: no `frame-ancestors` or `X-Frame-Options`, and also no HSTS, nosniff or Permissions-Policy, because GitHub Pages cannot send custom response headers. The project states this on purpose at `build/templates.mjs:33-35` ("frame-ancestors only works as a header, so framing is not blocked here"). The site has no forms or logins, so the impact is small. If you ever want these headers, put a CDN such as Cloudflare or Netlify in front of the site.

## Not checked

- **Airtable:** who can edit the base, and whether the token really has only `data.records:read` on this one base. Anyone with edit access decides what gets published.
- **GitHub settings:** branch protection on `main`, protection rules on the `github-pages` environment, 2FA on the GitHub accounts, and default workflow token settings. These cannot be seen from the code.
- **The outside "pinger"** that calls `workflow_dispatch` (`.github/workflows/site.yml:4`): where its GitHub token is stored and what scope it has.
- **DNS and the custom domain:** the Netlify DNS account (2FA), the `picks` CNAME, and whether "Enforce HTTPS" is on. There was no live URL to check.
- **The live response headers** of the deployed site and of `fit-balance.co.il/links/`: scope was code only.
- **Known vulnerabilities in `sharp` 0.35.5 and its dependencies:** no audit was run. Run `npm audit` and turn on Dependabot.
- **Git history:** the scanners reported no secrets, and I could not read the history with my tools.
- **The main site repo** where `hub/links/index.html` actually lives: not in this folder.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
