# Security report: yahav-picks

Date: 2026-11-23 · Scope: code only · Facts from scanners: 1

## Summary
1. Make the local preview server `build/serve.mjs` listen only on your own computer, and tighten its folder check.
2. Add a referrer policy meta tag to the shared page template in `build/templates.mjs`. Accept, in writing, that GitHub Pages cannot send the other security headers.
3. Before the Instagram bio page (`hub/links/index.html`) goes live, give it the same Content Security Policy and self-hosted fonts as the picks site.

Overall this project is in good shape. Links from Airtable are checked against an allow-list before they go into pages (`build/airtable.mjs:37-47`). Every text field is escaped. There is no inline script, and a strict CSP is set in a meta tag. The CI workflow gives no permissions by default, gives each job only what it needs, and pins every action to a commit. The one dependency (`sharp 0.35.5`) is pinned exactly and has a lockfile. No secrets are in the code: the Airtable token is read from the `AIRTABLE_TOKEN` environment variable.

## Findings

### F-01 · LOW · A01 Broken Access Control
**What can happen:** While you run the local preview, anyone on the same Wi-Fi can open it. A crafted address can also read files from a folder next to `dist/` whose name starts with `dist` (for example `dist-old/`).
**Where:** `build/serve.mjs:16`, `build/serve.mjs:17`, `build/serve.mjs:26`
**Evidence:** `if (!file.startsWith(ROOT)) { res.writeHead(403).end(); return; }` and `.listen(PORT, () => ...)`. No host is given, so the server listens on every network interface. The check is a plain text prefix, so `.../dist-old/x` passes as if it were inside `.../dist`.
**Fix:** Change the listen line to `.listen(PORT, '127.0.0.1', ...)`. Change the check to `if (file !== ROOT && !file.startsWith(ROOT + path.sep))`.
**Verify:** Start the server and open `http://<your-LAN-IP>:4173` from a phone on the same Wi-Fi: it should not connect. Create `dist-old/test.txt` and request `http://localhost:4173/..%2Fdist-old%2Ftest.txt`: you should get 403.

### F-02 · LOW · A02 Security Misconfiguration
**What can happen:** Browsers do not get the extra protection of the usual security headers. This site has no logins or forms, so the real risk is small. Other sites can frame the pages, and the full page address goes to AliExpress, WhatsApp and Instagram when someone follows a link.
**Where:** `build/templates.mjs:33`, `build/templates.mjs:36`, `build/templates.mjs:45`
**Evidence:** `// GitHub Pages cannot send response headers, so the Content Security Policy goes in a meta tag` and `(frame-ancestors only works as a header, so framing is not blocked here.)`. There is no `<meta name="referrer">`, and none of the other headers (HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy) can be set.
**Fix:** Add `<meta name="referrer" content="strict-origin-when-cross-origin">` next to the CSP meta tag in `page()`. That is the one other policy that works as a meta tag. If you ever need the rest, put the site behind a host or CDN that can send headers, such as Netlify, which you already use for DNS.
**Verify:** Run `npm run preview`, open a built page, and confirm the `referrer` meta tag is in `<head>`. In DevTools → Network, the request for an outgoing link should show only the site origin as `Referer`.

### F-03 · LOW · A02 Security Misconfiguration
**What can happen:** The Instagram bio page has no Content Security Policy. Every visit also sends the visitor's IP address to Google through Google Fonts, which goes against the privacy approach of the picks site.
**Where:** `hub/links/index.html:16`, `hub/links/index.html:17`, `hub/links/index.html:18`, `hub/links/index.html:19`
**Evidence:** `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Assistant...">` and an inline `<style>` block. The file has no `Content-Security-Policy` meta tag.
**Fix:** Before you move this file into the main site repo, self-host the two fonts the way `src/fonts/` does. Move the inline styles into a CSS file. Add the same CSP meta tag the picks site uses (`default-src 'self'; ... object-src 'none'; base-uri 'none'`).
**Verify:** Open the page with DevTools → Network: there should be no requests to `fonts.googleapis.com` or `fonts.gstatic.com`, and no CSP errors in the console.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Customer name on "recommended by a customer" products (`customer` field) | Airtable; published on product pages | Credit for the review ("המלצה של …") | No, but it is a real person's name made public. Do you have each customer's consent, and is there a way to remove it on request? |
| Review texts, pros/cons, size tips | Airtable; published | Product pages | No. Check that customer reviews contain no health details |
| Yahav's business WhatsApp number | `build/config.mjs:16-17`; published | Contact link | No (public business contact) |
| Site builder's WhatsApp number | `build/config.mjs:18`; published in the footer | Credit link | No, but the builder should confirm they want it public |
| Yahav's portrait | `src/img/yahav-src.jpg`; published | Hero image | No |
| Visitor IP and browser info | GitHub Pages logs (GitHub) | Hosting, as stated on the privacy page | Low; you do not control it |

## Accepted risks

- Framing is not blocked, and HSTS, nosniff and Permissions-Policy are not sent, because GitHub Pages cannot send response headers (`build/templates.mjs:33-35`).
- The review is optional for published products (`build/airtable.mjs:79`). This is a content decision, not a security one.

## Not checked

- **The scanner facts file (1 fact):** I was not allowed to read `facts.json`, so I could not confirm or rule out that fact. Please read it yourself next to this report.
- **The live site:** no URL was given. I did not check GitHub Pages "Enforce HTTPS", the actual response headers, or the custom domain DNS (`picks.fit-balance.co.il`).
- **Airtable:** who can edit the base, the token's real scope (the README says `data.records:read` on this base only), and 2FA on the Airtable account.
- **GitHub:** account 2FA, branch protection on `main`, who has write access, and whether the `github-pages` environment limits deploys to `main`.
- **Git history:** only the current files were read. Secrets committed earlier and later removed would not show up here.
- **Known problems in `sharp` 0.35.5 and its native libraries:** this needs a live advisory check (`npm audit`).
- **The outside "pinger"** mentioned in the workflow comment (`.github/workflows/site.yml:4`): where its GitHub token is stored and what that token can do.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
