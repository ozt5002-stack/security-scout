# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. In `Code.gs`, escape every value before it goes into the Google Sheet, and add a limit on how many leads (and alert emails) the script will accept per hour.
2. Take `apps-script/Code.gs` out of the published folder `fit-balance-site/`, and add a `_headers` file with the six security headers.
3. Stop saving the course password in plain text in the browser's `localStorage`, and decide how a leaked course password or Drive link can be cancelled.

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone can send a lead whose name starts with `=` (for example `=IMPORTXML(...)` or `=HYPERLINK("http://evil…","Call me")`). Google Sheets then treats it as a live formula instead of text. When Yahav opens the sheet, it can load outside URLs, leak sheet data or show a fake link.
**Where:** `fit-balance-site/apps-script/Code.gs:55`, `fit-balance-site/apps-script/Code.gs:57`, `fit-balance-site/apps-script/Code.gs:58`, `fit-balance-site/apps-script/Code.gs:66`, `fit-balance-site/apps-script/Code.gs:85`
**Evidence:** `sh.appendRow([new Date(), name, "'" + phone, hard, source, 'חדש', '']);`. Only `phone` gets the `'` text prefix. `clean_` only removes `<>`: `String(v || '').replace(/[<>]/g, '')`. The `hard` and `source` values come straight from the POST, so an attacker can set them to anything, not only the dropdown options.
**Fix:** In `clean_`, add a text prefix to dangerous first characters: `let s = String(v || '').replace(/[<>]/g, '').trim().slice(0, max); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return s;`. Also, only accept `source` values from a fixed list (`['אתר','תוכן חינמי']`), and only accept `hard` values from the form's options plus the unlock text. Paste the new code into the Apps Script editor and deploy a new version.
**Verify:** POST `name==1+1&phone=0500000000` to the script URL, for example with `testLead()` and that name. The new row must show the text `=1+1`, not `2`.

### F-02 · MEDIUM · A06 Insecure Design
**What can happen:** The lead endpoint is public, and each request adds a sheet row and sends Yahav an email. A simple script can flood the sheet with fake leads and use up the daily MailApp email quota. After that, real leads get no email alert, and Yahav may miss customers.
**Where:** `fit-balance-site/apps-script/Code.gs:49`, `fit-balance-site/apps-script/Code.gs:71`, `fit-balance-site/index.html:816`
**Evidence:** `function doPost(e) { ... if (p.website) return ok_(); ...` The honeypot is the only check. Every request that passes it runs `MailApp.sendEmail({ to: NOTIFY_EMAIL, ...`. There is no count or time limit anywhere.
**Fix:** In `doPost`, add a counter with `CacheService.getScriptCache()`. Count requests per minute and per day, and once a cap is reached (for example 10 per minute or 100 per day), return `ok_()` without writing. Keep writing rows below the cap, but send the email only while `MailApp.getRemainingDailyQuota() > 10`. Also ignore a second lead from the same phone number within 10 minutes (cache key = the phone number).
**Verify:** Send 15 test POSTs in a row. Only the capped number of rows and emails should appear, and a normal lead a few minutes later should still arrive.

### F-03 · MEDIUM · A02 Security Misconfiguration
**What can happen:** Anyone can download `https://fit-balance.co.il/apps-script/Code.gs` and read Yahav's private email address, the sheet layout and exactly how the bot trap works. That makes it easier to write a spam script that gets past it (see F-02).
**Where:** `fit-balance-site/apps-script/Code.gs:15`, `fit-balance-site/apps-script/Code.gs:53`
**Evidence:** The file sits inside the Netlify publish folder `fit-balance-site/` (scanner fact `publish.non-web-file`, confirmed). It contains `const NOTIFY_EMAIL = 'yaha…'` and `if (p.website) return ok_();`.
**Fix:** Move the file to a folder outside the publish folder, for example `apps-script/Code.gs` at the repo root next to `course-area/`, and update the path in `CLAUDE.md`.
**Verify:** After the next deploy, open `https://fit-balance.co.il/apps-script/Code.gs` in a private window. It must show "Page not found".

### F-04 · MEDIUM · A07 Authentication Failures
**What can happen:** When "remember me" is ticked (it is ticked by default), the shared course password is saved as plain text in the browser. Anyone who uses the same phone or computer, any browser extension, or any script that ever runs on the domain can read it and share it. Because every buyer uses the same password, one leak opens the course to everyone.
**Where:** `course-area/template.html:102`, `course-area/template.html:143`, `course-area/template.html:161`
**Evidence:** `var KEEP_KEY = 'fb_course_pw'` … `if (keep) store(KEEP_KEY, pw);` → `localStorage.setItem(k, v)`. The checkbox is `<input type="checkbox" id="keep" checked>`.
**Fix:** Save the derived key instead of the password. In `unlock()`, create the AES key with `extractable: false` and store that `CryptoKey` object in IndexedDB (IndexedDB can store keys that cannot be read back out). On return visits, decrypt with the stored key. Never write `pw` to storage. Also remove `checked` from the "remember me" box. Then run `node course-area/encrypt.mjs` again.
**Verify:** Log in with "remember me", then open DevTools → Application → Local Storage. There must be no `fb_course_pw` entry, and reloading the page must still open the course.

### F-05 · LOW · A01 Broken Access Control
**What can happen:** The paid course worksheets and workbook are Google Drive files shared as "anyone with the link". A buyer can forward the links (or the one shared password), and you cannot cancel one person's access, even after a refund. If this git repo is ever public, anyone can read the links without paying.
**Where:** `course-area/lessons.json:3`, `course-area/lessons.json:7`, `course-area/lessons.json:19`, `course-area/lessons.json:29`, `course-area/lessons.json:40`, `course-area/lessons.json:53`, `course-area/lessons.json:63`, `course-area/lessons.json:74`
**Evidence:** `"workbook": "https://drive.google.com/file/d/1UnK…/view"`. The `_help` text says `Google Drive, 'anyone with the link can view'`. The file is committed unencrypted (only the generated page is encrypted).
**Fix:** Keep the repo private, or keep `lessons.json` out of git (add it to `.gitignore` and keep a backup elsewhere). Plan to change the course password and the Drive links from time to time, for example each cohort, and email the new password to current buyers. If one-person-at-a-time access becomes important, move to a platform with per-buyer logins.
**Verify:** Open the repo's page while logged out of GitHub (or check its visibility setting). It must not be readable, and `git ls-files course-area/lessons.json` must print nothing if you choose to ignore it.

### F-06 · LOW · A02 Security Misconfiguration
**What can happen:** Without security headers, browsers get none of the extra protection against clickjacking (another site showing yours in a hidden frame) or injected scripts. That matters most for the course page, which keeps data in the browser (F-04).
**Where:** `fit-balance-site/`, `fit-balance-site/index.html:1`, `course-area/template.html:1`
**Evidence:** There is no `_headers` file, no `netlify.toml` and no CSP meta tag in the project (scanner fact `publish.no-header-config`, confirmed: the site is fully static, so no server code sends headers).
**Fix:** Add `fit-balance-site/_headers` with `/*` followed by `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, and a `Content-Security-Policy`. The CSP must allow `'self'`, `'unsafe-inline'` for the inline scripts and styles, `fonts.googleapis.com` and `fonts.gstatic.com`, `frame-src` for `www.youtube-nocookie.com` and `player.vimeo.com`, and `connect-src` for `script.google.com`. Check it on a Deploy Preview first, because a wrong CSP can break the forms or videos.
**Verify:** On the Deploy Preview, open DevTools → Network → the page → Response Headers and confirm all six headers. Then submit the form and play a video to confirm nothing broke.

### F-07 · LOW · A06 Insecure Design
**What can happen:** The "leave details to unlock" box is only a browser-side gate. The locked PDF paths are already in the page, so anyone can open them without leaving a name or phone number. That is fine for free content, but don't use the same pattern for anything paid.
**Where:** `fit-balance-site/index.html:433`, `fit-balance-site/index.html:443`, `fit-balance-site/index.html:847`
**Evidence:** `<a class="pdf-link" data-href="media/guides/fit-balance-3-recipes.pdf" href="#unlock">`. The unlock code just copies `pl.href=pl.dataset.href`.
**Fix:** If this is acceptable for free lead-magnet content, write that down in `CLAUDE.md` as an accepted risk. Never put paid PDFs (the recipe books) in `fit-balance-site/media/`.
**Verify:** Confirm that no paid product file is under `fit-balance-site/`: `Glob fit-balance-site/**/*.pdf` should list only the free guides.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name | Google Sheet "פניות", alert email to Yahav's Gmail | Calling back the lead / unlocking free content | No |
| Phone number | Google Sheet, alert email (plus a wa.me link) | Callback by phone or WhatsApp | No (personal contact) |
| "What is hardest for you" choice (e.g. "אכילה בערב / אכילה רגשית") | Google Sheet, alert email | Preparing the fit-call | Possibly: it hints at eating or health struggles |
| Lead source and date | Google Sheet | Knowing which form was used | No |
| Course password (shared) | Buyers' browser `localStorage` (`fb_course_pw`), Cardcom email | Entering the course area | Yes: an access secret (see F-04) |
| Course progress | Buyers' browser `localStorage` (`fb_course_done_v1`) | Showing watched lessons | No |
| Buyer name, contact and payment | Cardcom (outside this code) | Purchase, receipt, delivery | Payment data stays with Cardcom |
| Intake questionnaire (health info) | Outside the site (per `privacy.html:74`) | Building the personal plan | Yes: health data |

Questions for the owner:
- `privacy.html:68` says data is kept "as long as needed". What is the actual deletion rule for old leads in the sheet and in Gmail?
- Where is the health questionnaire stored, who can read it, and when is it deleted? (`CLAUDE.md:65` already lists this for the lawyer.)
- `privacy.html:50` still mentions a course waitlist form that `CLAUDE.md:35` says was removed. Should that line be updated?

## Accepted risks

None.

## Not checked

- Whether the live Netlify site sends any headers that are set in the Netlify dashboard rather than in the repo: no live URL was checked.
- Whether the Apps Script deployed in Google matches this copy of `Code.gs`, and who the deployment runs as.
- Who can open the Google Sheet "פניות מהאתר - Fit Balance" and the Drive worksheet files, and whether the Google, Netlify, Cardcom, Vimeo and GitHub accounts use 2FA.
- Whether the git repo is public or private, and whether older commits contain the course password or other secrets (git history was not given).
- `fit-balance-site/my-course/index.html` has not been generated yet, so the final encrypted course page and the strength of the real password could not be checked. `encrypt.mjs` already requires 14+ characters and PBKDF2 with 310,000 iterations.
- Vimeo's domain-restriction settings and Cardcom's email/delivery settings, which are only in those services' dashboards.
- `https://picks.fit-balance.co.il/`, linked from the footer, is a separate site not in this folder.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
