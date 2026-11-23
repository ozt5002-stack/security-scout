# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. In `Code.gs`, escape lead fields before they go into the Google Sheet, so a typed `=` cannot become a live formula (F-01).
2. Add a limit to the lead endpoint, so one script cannot flood the sheet and use up the daily email allowance (F-02).
3. Before the course goes live, choose a long random course password and stop saving it in the browser. Also decide whether one shared password is enough protection for paid content (F-03, F-05).

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone can send the lead form a name like `=HYPERLINK("http://evil.example","Click")` or `=IMPORTXML(...)`. Google Sheets then runs it as a formula in Yahav's leads sheet. That can show her fake links, or send data out of the sheet when the sheet is opened.
**Where:** `fit-balance-site/apps-script/Code.gs:55`, `fit-balance-site/apps-script/Code.gs:57`, `fit-balance-site/apps-script/Code.gs:58`, `fit-balance-site/apps-script/Code.gs:66`, `fit-balance-site/apps-script/Code.gs:85-86`
**Evidence:** `sh.appendRow([new Date(), name, "'" + phone, hard, source, 'חדש', '']);`. Only `phone` gets the `'` guard. `clean_()` only removes `<` and `>`: `String(v || '').replace(/[<>]/g, '')`. The endpoint is public (`LEADS_URL` in `fit-balance-site/index.html:816`), so `hard` and `source` can be any text, not only the dropdown values.
**Fix:** Inside `clean_`, after trimming, add `if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;`. That covers name, hard and source. Also, in `doPost`, only accept `source` if it is in a fixed list (`['אתר','תוכן חינמי']`). Only accept `hard` if it is one of the five dropdown texts or the unlock text; save anything else as `'אחר'`. Deploy the new version in the Apps Script editor (Deploy → Manage deployments → new version).
**Verify:** Run `testLead()` with `name: '=1+1'`. The new row must show the text `=1+1`, not `2`.

### F-02 · MEDIUM · A06 Insecure Design
**What can happen:** A script can post to the public Apps Script URL thousands of times. Each post adds a row and sends Yahav an email. That buries real leads, fills her inbox, and uses up the daily MailApp quota (about 100 emails a day on a free Google account). After that, real leads arrive with no email alert.
**Where:** `fit-balance-site/apps-script/Code.gs:49-83`, `fit-balance-site/index.html:816`
**Evidence:** The only bot check is the honeypot: `if (p.website) return ok_();`. After that, every request with a name and a 9-digit phone reaches `sh.appendRow(...)` and `MailApp.sendEmail({...})`. Nothing counts requests per minute or per phone number.
**Fix:** In `doPost`, before the lock, use `CacheService.getScriptCache()`:
(a) If the same phone number was seen in the last 10 minutes (`cache.get('p'+digits)`), return `ok_()` and stop.
(b) Keep a global counter key for the current minute. If it goes above about 10, return `ok_()` without writing.
(c) Before sending, check `if (MailApp.getRemainingDailyQuota() > 5)` so a few emails stay in reserve.
**Verify:** Send the same phone number twice within a minute (for example from the Apps Script editor with `testLead()`). Only one row and one email should appear.

### F-03 · MEDIUM · A07 Authentication Failures
**What can happen:** The paid course is locked only by one password that every buyer shares. The encrypted course file will be public at `/my-course/`, so anyone can try guesses on their own computer without any limit. You also cannot block one buyer who passes the password on. Once someone opens it, the worksheet and workbook links are plain Google Drive links set to "anyone with the link", and they keep working for anyone they are shared with.
**Where:** `course-area/encrypt.mjs:21`, `course-area/encrypt.mjs:13`, `course-area/template.html:149-155`, `course-area/lessons.json:3`, `course-area/lessons.json:7`
**Evidence:** `if (!pw || pw.length < 8) { console.error('Password must be at least 8 characters.'); ...}`. The output goes to `fit-balance-site/my-course` (the public Netlify folder). `"worksheet": "https://drive.google.com/file/d/1us9…/view"` is in `lessons.json` as plain text. The project notes say: "Worksheets ... must be 'anyone with the link'".
**Fix:** Raise the minimum in `encrypt.mjs` to 16 characters and use a random password (for example four random words), not a word Yahav picks. Change the password from time to time and send it again to current buyers. Keep `course-area/lessons.json` out of any public repository, because the Drive links in it skip the password completely. If the course earns enough, move to a platform with one login per buyer (Vimeo OTT, Teachable and similar). For the videos, the Vimeo domain limit already helps.
**Verify:** Run `node course-area/encrypt.mjs` with a 10-character password: it should refuse. Check on GitHub (or wherever the repo lives) that it is private, or that `lessons.json` is not there.

### F-04 · LOW · A02 Security Misconfiguration
**What can happen:** The site sends none of the standard browser-protection headers. Another site can put the pages in a hidden frame, and if a script-injection bug is ever added, nothing stops it. This matters most for the course page, which will keep the course password in the browser.
**Where:** `fit-balance-site/`
**Evidence:** The publish folder has no `_headers` file and the project has no `netlify.toml`. No page has a `Content-Security-Policy` meta tag (searching for `http-equiv` finds nothing). There is no server code; Netlify serves the files as they are.
**Fix:** Add `fit-balance-site/_headers` with: `/*` then `  X-Frame-Options: DENY`, `  X-Content-Type-Options: nosniff`, `  Referrer-Policy: strict-origin-when-cross-origin`, `  Permissions-Policy: camera=(), microphone=(), geolocation=()`, `  Strict-Transport-Security: max-age=31536000`, and a CSP. The pages use inline scripts, so start with `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; media-src 'self'; frame-src https://www.youtube-nocookie.com https://player.vimeo.com; connect-src https://script.google.com; frame-ancestors 'none'`. Test it on a Deploy Preview first (it costs no credits).
**Verify:** Open the Deploy Preview, then DevTools → Network → the page → Response Headers. All six headers should be there. Then fill the forms, play a video and open the course page, and check the Console for CSP errors.

### F-05 · LOW · A07 Authentication Failures
**What can happen:** "Remember me" (ticked by default) saves the course password as plain text in the browser. Anyone who uses that device, or any script that runs on the site, can read it and share it.
**Where:** `course-area/template.html:102`, `course-area/template.html:143`, `course-area/template.html:161`, `course-area/template.html:172-173`
**Evidence:** `var KEEP_KEY = 'fb_course_pw'` … `if (keep) store(KEEP_KEY, pw);` → `localStorage.setItem(k, v)`. The checkbox is `<input type="checkbox" id="keep" checked>`.
**Fix:** Do not store `pw`. Let the browser's password manager remember it (the form already has `autocomplete="current-password"`). If you want to keep "remember me", leave the checkbox unticked by default.
**Verify:** Log in, then in DevTools → Application → Local Storage check that there is no `fb_course_pw` key.

### F-06 · LOW · A01 Broken Access Control
**What can happen:** The Apps Script source is inside the published folder, so anyone can download it from the site. It shows Yahav's private notification email and exactly how the bot trap and checks work, which makes F-01 and F-02 easier to abuse.
**Where:** `fit-balance-site/apps-script/Code.gs:15`
**Evidence:** `const NOTIFY_EMAIL = 'yaha…'` (her personal Gmail address) in a file under the Netlify publish directory `fit-balance-site/`.
**Fix:** Move `apps-script/` out of `fit-balance-site/`, for example to `apps-script/Code.gs` at the repo root, next to `course-area/`. The project notes already describe it as a "reference only" copy.
**Verify:** After the next deploy, `https://fit-balance.co.il/apps-script/Code.gs` should return 404.

### F-07 · LOW · A06 Insecure Design
**What can happen:** The "leave details to unlock" box only works in the browser. The locked PDFs' addresses are already in the page, so anyone can open them without leaving a name or phone number. The only cost is fewer leads; nothing secret leaks.
**Where:** `fit-balance-site/index.html:433`, `fit-balance-site/index.html:443`, `fit-balance-site/index.html:847-853`
**Evidence:** `<a class="pdf-link" data-href="media/guides/fit-balance-3-recipes.pdf" href="#unlock">`. Also `fetch(LEADS_URL,...).finally(open);` unlocks the content even if the send fails.
**Fix:** If this is fine (the content is free and used as lead bait), write that down in `CLAUDE.md` as an accepted risk. If not, have the Apps Script email or WhatsApp the links after a valid lead, instead of putting them in the page.
**Verify:** View the page source and check that no `data-href` points to a locked file.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name, phone number (lead and unlock forms) | Google Sheet "פניות מהאתר", tab "פניות"; email to Yahav's Gmail | Calling back; unlocking free content | No (personal contact data) |
| "What is hardest for you" choice (for example emotional eating, time after giving birth) | Same sheet and email | Filtering leads | Partly: it hints at health or postpartum status |
| Lead source, date, status, notes | Same sheet | Lead tracking | No |
| Course password | Buyer's browser `localStorage` (`fb_course_pw`); Cardcom email | Course access | Yes (credential) |
| Lessons watched | Buyer's browser `localStorage` (`fb_course_done_v1`) | Progress bar | No |
| Buyer name, contact, payment | Cardcom (outside this code) | Purchase, receipt, book delivery | Payment data stays at Cardcom |
| Intake questionnaire (personal and health information) | Outside the site (stated in `privacy.html:74`) | Personal coaching plan | Yes (health) |

Questions for the owner:
- `privacy.html:68` says data is kept "as long as needed". Is there a real date when old leads are deleted from the sheet?
- Where is the health questionnaire stored, and who can read it?
- `privacy.html:50` still mentions a course waitlist that was removed. Does that line still apply?

## Accepted risks

None.

## Not checked

- **Who can open the leads sheet and the Apps Script project, and whether Yahav's and Oz's Google and Netlify accounts use 2FA.** These are account settings, not in the code.
- **Whether the git repository is public.** If it is, `course-area/lessons.json` (Drive worksheet links) and `CLAUDE.md` (personal phone numbers and email) are public too. Git history was not available to review.
- **Vimeo domain limits and the "anyone with the link" sharing on Google Drive.** These are set in those services.
- **Cardcom payment pages and how the course password is sent to buyers.** These run outside this code.
- **The live site at https://fit-balance.co.il.** It was not in scope, so the real response headers and the deployed Apps Script version were not seen.
- **Whether a `my-course/index.html` has already been built and deployed.** It is not in this folder.
- **The PDFs and videos in `media/`.** Their content and metadata (for example location data in photos) were not reviewed.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
