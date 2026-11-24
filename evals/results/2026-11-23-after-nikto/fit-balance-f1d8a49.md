# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. In `apps-script/Code.gs`, escape every value before it goes into the Google Sheet, so a lead's name cannot become a formula.
2. Put a cap on how many leads per hour the Apps Script accepts and emails. Today anyone can flood the sheet and use up Yahav's daily email quota, so real leads would stop sending her emails.
3. Stop saving the course password as plain text in the browser's `localStorage`, and make "remember me" off by default.

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone can send a "lead" whose name or text starts with `=`, and Google Sheets runs it as a formula. For example, `=IMPORTXML(...)` or `=HYPERLINK("http://evil…","Click")` turns the sheet into a phishing link, or sends data from other cells to an outside site when Yahav opens it.
**Where:** `fit-balance-site/apps-script/Code.gs:66`, `fit-balance-site/apps-script/Code.gs:85`
**Evidence:** `sh.appendRow([new Date(), name, "'" + phone, hard, source, 'חדש', '']);`. Only `phone` gets the protective `'` prefix. `clean_` only removes `<` and `>`: `.replace(/[<>]/g, '')`. The `hard` and `source` fields come from the caller too. Anyone can POST to the public endpoint directly, not only through the dropdown on the site.
**Fix:** In `Code.gs`, add `function cell_(s){ return /^[=+\-@\t\r]/.test(s) ? "'" + s : s; }` and write `sh.appendRow([new Date(), cell_(name), "'" + phone, cell_(hard), cell_(source), 'חדש', '']);`. Also remove line breaks in `clean_` (`.replace(/[\r\n]+/g,' ')`), because `name` also goes into the email subject.
**Verify:** Run `testLead()` with `name: '=1+1'`. The cell in the sheet should show the text `=1+1`, not `2`.

### F-02 · MEDIUM · A06 Insecure Design
**What can happen:** The leads endpoint is public. Its only protection is a honeypot field, which any script can leave empty. A bot can send thousands of fake leads, fill the sheet and send Yahav one email per lead. After the Gmail/MailApp daily quota runs out, `MailApp.sendEmail` fails and real leads arrive with no email alert.
**Where:** `fit-balance-site/apps-script/Code.gs:49`, `fit-balance-site/apps-script/Code.gs:71`, `fit-balance-site/index.html:816`
**Evidence:** `if (p.website) return ok_();` is the only bot check. Then come `sh.appendRow(...)` and `MailApp.sendEmail({ to: NOTIFY_EMAIL, ...` on every request, with no count or limit. The endpoint URL is published in the page: `var LEADS_URL="https://script.google.com/macros/s/AKfy…/exec"`.
**Fix:** At the start of `doPost`, keep a counter in `CacheService.getScriptCache()`, for example a key per hour. Above about 30 leads an hour, still write the row but skip the email, and send one "too many leads, check the sheet" alert instead. Before each email, check `MailApp.getRemainingDailyQuota() > 5`. Also reject repeat submissions of the same phone number within 10 minutes, using a cache key with the phone number.
**Verify:** From the Apps Script editor, call `doPost` 40 times in a loop with test data. All rows should appear in the sheet, but only about 30 emails plus one alert should arrive.

### F-03 · MEDIUM · A07 Authentication Failures
**What can happen:** The shared course password is saved as plain text in the browser, and "remember me" is ticked by default. Anyone who uses the same phone or computer later (family, a shared work PC), or any browser extension, can read the password and pass it on. Every buyer shares that one password.
**Where:** `course-area/template.html:102`, `course-area/template.html:143`, `course-area/template.html:161`
**Evidence:** `<input type="checkbox" id="keep" checked>`, `var KEEP_KEY = 'fb_course_pw'`, `if (keep) store(KEEP_KEY, pw);` (which calls `localStorage.setItem`).
**Fix:** Remove `checked` from the "remember me" box. Change its label to say "only on your personal device". Better: do not store the password at all. Derive the key as non-extractable (already the case: `false` in `deriveKey`) and save the `CryptoKey` object in IndexedDB. The browser can keep it there and use it, but no script can read it back as text. Then run `node course-area/encrypt.mjs` again so the course page is rebuilt.
**Verify:** Log in to `/my-course/`, then open DevTools → Application → Local Storage. There should be no `fb_course_pw` entry.

### F-04 · LOW · A02 Security Misconfiguration
**What can happen:** The site sends no security headers. Another site can show your pages inside a hidden frame (clickjacking), and if a script injection ever happens, nothing in the browser limits it.
**Where:** `fit-balance-site/`
**Evidence:** The publish folder has no `_headers` file, the project has no `netlify.toml`, and there is no CSP `<meta>` tag in any HTML file. The scanner fact was confirmed: no server code sends headers, since this is a static Netlify site.
**Fix:** Create `fit-balance-site/_headers` with `/*` followed by these lines: `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, and a CSP. The pages use inline script and style, so the CSP has to allow them: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' https://i.ytimg.com data:; frame-src https://www.youtube-nocookie.com https://player.vimeo.com; connect-src https://script.google.com; frame-ancestors 'none'`. Test the CSP on a Deploy Preview first, because it costs no credits.
**Verify:** On the Deploy Preview, open DevTools → Network → the HTML request → Response Headers. All six headers should be there. Then test both forms, the YouTube embeds and the course videos, and check that nothing is blocked in the Console.

### F-05 · LOW · A02 Security Misconfiguration
**What can happen:** The source code of the leads script is published on the site, so anyone can download it. It shows Yahav's notification email address, the honeypot field name and the exact checks a bot needs to pass. That makes F-02 easier to exploit.
**Where:** `fit-balance-site/apps-script/Code.gs`
**Evidence:** The file is inside the Netlify publish folder (`fit-balance-site/`), so it is served at `/apps-script/Code.gs`. It contains `const NOTIFY_EMAIL = 'yaha…'` and `if (p.website) return ok_();`.
**Fix:** Move the folder out of the publish folder, to `apps-script/Code.gs` at the repo root. Your own `CLAUDE.md` already describes it as "reference only, deployed separately in Google".
**Verify:** After the next deploy, `https://fit-balance.co.il/apps-script/Code.gs` should return 404.

### F-06 · LOW · A06 Insecure Design
**What can happen:** All buyers share one course password, and the worksheets are Google Drive files set to "anyone with the link". Once one buyer posts the password or a link, anyone can open the whole course and its worksheets. You cannot lock out a single person without changing the password for everyone.
**Where:** `course-area/encrypt.mjs:15`, `course-area/lessons.json:3`, `course-area/lessons.json:7`
**Evidence:** `encrypt.mjs` encrypts everything with one password (`let pw = process.env.COURSE_PASSWORD;`). `lessons.json` says: "Worksheet links are per gate (Google Drive, 'anyone with the link can view')".
**Fix:** This is a business decision, not a code bug. At least change the password now and then: run `encrypt.mjs` again and send the new password to current buyers. Keep the Vimeo domain restriction on, which is the part that protects the videos. If the course grows, move to a platform with one login per buyer.
**Verify:** After you change the password, the old one should show "הסיסמה לא נכונה" on `/my-course/`.

### F-07 · LOW · A01 Broken Access Control
**What can happen:** The "unlock" box for the free PDFs only hides links in the browser. Anyone can open the PDFs directly without leaving a name or phone number, so the gate collects fewer leads than it seems to.
**Where:** `fit-balance-site/index.html:433`, `fit-balance-site/index.html:443`, `fit-balance-site/index.html:847`
**Evidence:** `data-href="media/guides/fit-balance-3-recipes.pdf"`, `data-href="media/guides/fit-balance-nutrition-guide.pdf"`. The files sit in the public `media/guides/` folder, and `open()` simply sets `pl.href=pl.dataset.href`.
**Fix:** If the gate only needs to be a gentle nudge, you can accept this and note it in `CLAUDE.md`. If not, stop hosting the gated PDFs on the site. Have the Apps Script email the PDF links, or return them only after a valid lead comes in.
**Verify:** Open `https://fit-balance.co.il/media/guides/fit-balance-3-recipes.pdf` in a private window. After the change it should not open.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name (first name) | Google Sheet "פניות", Yahav's email inbox | Calling back the lead | No |
| Phone number | Google Sheet, Yahav's email (also as a wa.me link) | Calling back / WhatsApp | Personal contact data |
| "Main difficulty" choice (`hard`), e.g. "אכילה בערב / אכילה רגשית", "אחרי הלידה" | Google Sheet, Yahav's email | Qualifying the lead | Possibly: it hints at eating behaviour or a recent birth. Question for the owner: is this health data under your privacy policy? |
| Lead source, date, status, notes | Google Sheet | Tracking leads | No |
| Course password | Buyer's browser `localStorage` (`fb_course_pw`) | Auto-login | Yes, it's a credential (see F-03) |
| Course progress (`fb_course_done_v1`) | Buyer's browser `localStorage` | Showing watched lessons | No |
| Buyer name, contact and card details | Cardcom (not in this code) | Payment, receipt, sending the book | Payment data, held by Cardcom |
| Intake health questionnaire | Outside the site (per `privacy.html:74`) | Personal program | Yes, health data |

Questions for the owner (not legal rulings):
- `privacy.html:68` says leads are kept "as long as needed". Is there a real end date, for example deleting leads who did not join after 12 months?
- Who else can open the Google Sheet and Yahav's mailbox?
- Where is the health questionnaire stored, and for how long?

## Accepted risks

None.

## Not checked

- The headers the live site actually sends: no live URL was given, and `CLAUDE.md` says Netlify returns 401 to bots.
- Apps Script deployment settings ("Execute as: me", "Anyone"), the Apps Script version that is live now, and whether it matches this copy.
- Who has access to the Google Sheet, Yahav's Gmail, the Google Drive worksheets and the Netlify account, and whether 2-step verification is on for the Google, Netlify, Vimeo, Cardcom and box.co.il domain-registrar accounts.
- The Vimeo embed domain restriction and the Cardcom setup (they are configured outside the code).
- The generated `fit-balance-site/my-course/index.html` is not in the folder, so the published encrypted page and the real password strength could not be checked. `encrypt.mjs` does require 14+ characters and PBKDF2 with 310,000 iterations.
- Git history: no scanner facts about secrets were given, and I could not inspect the history with read-only file tools.
- The contents of the PDFs and videos in `media/`.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
