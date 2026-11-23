I've read the code; the facts file was blocked by a permission prompt. Here is the report.

# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. In `Code.gs`, put a `'` in front of any name or form value that starts with `= + - @` before it goes into the sheet, so form input can't become a spreadsheet formula.
2. Stop saving the course password in the browser (`localStorage`). Untick "remember me" by default, or remove it.
3. Add a per-hour cap on new leads in the Apps Script, and add security headers for the site in a `fit-balance-site/_headers` file (with a strict CSP on `/my-course/`).

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone can post to the public Apps Script address with a "name" such as `=HYPERLINK("https://evil…","Click")` or `=IMPORTXML(…)`. It is saved in Yahav's leads sheet as a live formula. It can trick her into opening a bad link, or try to send other leads' data to an outside site.
**Where:** `fit-balance-site/apps-script/Code.gs:55`, `fit-balance-site/apps-script/Code.gs:57`, `fit-balance-site/apps-script/Code.gs:58`, `fit-balance-site/apps-script/Code.gs:66`, `fit-balance-site/apps-script/Code.gs:86`
**Evidence:** `clean_` only removes `<>` (`String(v || '').replace(/[<>]/g, '')`). Then `sh.appendRow([new Date(), name, "'" + phone, hard, source, 'חדש', ''])` protects only the phone column with `'`.
**Fix:** In `clean_`, after trimming, add `if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;`. That protects `name`, `hard` and `source` too. Copy the new code into the live Apps Script project and make a new deployment.
**Verify:** Use curl to POST `name==1+1&phone=0501234567` to the `/exec` URL. The sheet should show the text `=1+1`, not `2`.

### F-02 · MEDIUM · A07 Authentication Failures
**What can happen:** The course password is saved in plain text in the browser, and "remember me" is ticked by default. Anyone who uses that device or browser profile later, any browser extension, or any script that runs on the site can read it and share it.
**Where:** `course-area/template.html:102`, `course-area/template.html:146`, `course-area/template.html:161`, `course-area/template.html:172`
**Evidence:** `<input type="checkbox" id="keep" checked>` … `if (keep) store(KEEP_KEY, pw);` → `localStorage.setItem(k, v)` with key `fb_course_pw`
**Fix:** Remove `checked` from the `keep` checkbox. Better still, drop the option completely and let the browser's password manager remember the password (the hidden `username` field and `autocomplete="current-password"` already support this). Then run `node course-area/encrypt.mjs` again to rebuild `my-course/index.html`.
**Verify:** Log in to `/my-course/`. In DevTools → Application → Local Storage there should be no `fb_course_pw` entry.

### F-03 · MEDIUM · A06 Insecure Design
**What can happen:** The lead endpoint has no login and no limit. A script can send thousands of fake leads. That fills the sheet, floods Yahav's inbox, and uses up the daily MailApp email quota, so real leads stop sending her an alert.
**Where:** `fit-balance-site/apps-script/Code.gs:49`, `fit-balance-site/apps-script/Code.gs:71`, `fit-balance-site/index.html:816`
**Evidence:** `function doPost(e) {` has only a honeypot check (`if (p.website) return ok_();`), and every valid post runs `MailApp.sendEmail({ to: NOTIFY_EMAIL, …`. The URL is public in `var LEADS_URL="https://script.google.com/macros/s/AKfy…/exec"`.
**Fix:** In `doPost`, count leads with `CacheService.getScriptCache()`: a counter per hour (for example, more than 30 → still save the row but skip the email), and refuse a phone number already seen in the last 10 minutes. Optionally, send one summary email instead of one per lead when the count is high.
**Verify:** Send 40 POSTs in a row with curl. The rows should be saved (or duplicates refused) and no more than about 30 emails should arrive.

### F-04 · MEDIUM · A02 Security Misconfiguration
**What can happen:** The site has no security headers. That means no Content-Security-Policy to limit injected scripts (this matters most for the course page that holds the password), no protection against being framed by another site, and no HSTS.
**Where:** `fit-balance-site/index.html:813`, `fit-balance-site/course.html:374`, `course-area/template.html:140`
**Evidence:** I found no `_headers` or `netlify.toml` file in the project, and no `<meta http-equiv="Content-Security-Policy">` in any page (searched for `http-equiv`, no match).
**Fix:** Add `fit-balance-site/_headers` with `/*` → `Strict-Transport-Security: max-age=31536000`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Add a CSP that allows only `'self'`, fonts.googleapis.com/fonts.gstatic.com, i.ytimg.com, youtube-nocookie.com, player.vimeo.com and script.google.com (`connect-src`). Inline scripts need `'unsafe-inline'` or hashes. Start with `Content-Security-Policy-Report-Only` on a Deploy Preview, so it costs no credits.
**Verify:** Open the Deploy Preview, then DevTools → Network → the document's Response Headers. The headers should be listed and the console should show no CSP errors.

### F-05 · LOW · A06 Insecure Design
**What can happen:** All buyers share one course password, and the encrypted course sits on a public page. Anyone who gets the password (forwarded email, a shared post) has access forever. It can't be taken back from one person without changing it for everyone.
**Where:** `course-area/encrypt.mjs:15`, `course-area/template.html:149`
**Evidence:** `encrypt.mjs` encrypts everything with one `pw`. The CLAUDE.md note says "one shared password (sent in the Cardcom email)". The key setup itself is strong (PBKDF2 310000, at least 14 characters).
**Fix:** Plan to change the password regularly: run `encrypt.mjs` with a new password and email buyers. Keep relying on Vimeo's domain-only embedding for the videos. If leaks become a real problem, move to a hosted course platform with a login for each buyer.
**Verify:** After a password change, the old password should show "הסיסמה לא נכונה" on `/my-course/`.

### F-06 · LOW · A01 Broken Access Control
**What can happen:** The "leave your details to unlock" gate exists only in the browser. The PDFs are public files, so anyone can open `media/guides/fit-balance-nutrition-guide.pdf` directly without leaving details.
**Where:** `fit-balance-site/index.html:433`, `fit-balance-site/index.html:443`, `fit-balance-site/index.html:847`
**Evidence:** `data-href="media/guides/fit-balance-3-recipes.pdf"`, and the "unlock" only sets `pl.href=pl.dataset.href`
**Fix:** This is fine for free marketing content. Just know that it is not a real lock. Never use this pattern for paid content, such as the recipe books sold through Cardcom.
**Verify:** No change needed unless the owner wants a real gate.

### F-07 · LOW · A02 Security Misconfiguration
**What can happen:** The Apps Script copy is inside the Netlify publish folder, so anyone can download it. It shows how the lead logic works (making F-01 and F-03 easier to find) and Yahav's notification email address.
**Where:** `fit-balance-site/apps-script/Code.gs:15`
**Evidence:** `const NOTIFY_EMAIL = 'yaha…'`, in a file under `fit-balance-site/`, which CLAUDE.md calls the "Netlify publish directory"
**Fix:** Move `apps-script/` out of `fit-balance-site/`, for example to the repo root next to `course-area/`.
**Verify:** After the next deploy, `https://fit-balance.co.il/apps-script/Code.gs` should return 404.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name (lead forms) | Google Sheet "פניות", plus an email to Yahav | Calling back, unlocking free content | No |
| Phone number (lead forms) | Google Sheet, plus an email to Yahav | Calling back / WhatsApp | No (personal contact) |
| "What is hardest for you" (e.g. "אכילה בערב / אכילה רגשית") | Google Sheet, plus an email | Filtering leads | Possibly: it hints at eating or emotional health |
| Course password | Buyer's browser `localStorage` (`fb_course_pw`) | Auto-login | Yes (credential), see F-02 |
| Lessons watched | Browser `localStorage` (`fb_course_done_v1`) | Progress bar | No |
| Buyer name/contact (Cardcom) | Cardcom, then Yahav | Sending the book, receipts | No |
| Coaching intake questionnaire (health) | Off-site (privacy page: "השאלון לא נמצא באתר") | Personal plan | Yes (health) |

Questions for the owner: leads are kept "as long as needed", with no end date. Should old rows be deleted after, say, 12 months? Where is the health questionnaire stored, and who can open it? (This is already on the lawyer list.)

## Accepted risks

- Course content sits encrypted on a public page and can be attacked offline. This is countered on purpose by PBKDF2 and a password of at least 14 characters (`course-area/encrypt.mjs:21-25`, comment explaining the choice).

## Not checked

- **The scanner facts file (`facts.json`) could not be opened.** Reading it needed a permission that was not granted, so I could not confirm or reject the 2 scanner facts. Every finding above comes from reading the code directly.
- The live site and its real HTTP headers (scope was code only; CLAUDE.md says Netlify returns 401 to bots).
- The deployed Apps Script: whether it matches this copy, and its access setting ("כל אחד").
- Who the Google Sheet is shared with, and the Google Drive worksheets ("anyone with the link").
- Vimeo domain restrictions, Netlify and Google account 2FA, and Cardcom account settings.
- The generated `fit-balance-site/my-course/index.html` (not in the folder), and whether git history ever held the course password or a generated page made with an old password.
- `course-terms.html`, `accessibility.html` and `links/index.html` were looked at only through searches for risky patterns. Nothing was found there.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
