I found six problems in fit-balance: three medium and three low. None is critical. The most urgent fix is the lead form, which anyone can post to. Both scanner facts turned out to be real.

# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. In the Apps Script that receives leads, make sure no form value can be read as a spreadsheet formula. Today a lead whose name starts with `=`, `+`, `-` or `@` lands in Yahav's Google Sheet as a formula.
2. Add a cap on the lead endpoint (how many leads per hour and per day, and how many alert emails). Right now anyone can flood the sheet and use up the daily email quota.
3. Stop saving the course password as plain text in the browser's storage ("remember me" is on by default). Also move `apps-script/Code.gs` out of the public folder.

## Findings

### F-01 · MEDIUM · A05 Injection
**What can happen:** Anyone can send a lead whose name or "difficulty" starts with `=`, for example `=IMPORTXML(...)` or `=HYPERLINK(...)`. Google Sheets then treats it as a formula: it can load an outside address when the sheet is opened, or show Yahav a misleading clickable link.
**Where:** `fit-balance-site/apps-script/Code.gs:55`, `fit-balance-site/apps-script/Code.gs:57`, `fit-balance-site/apps-script/Code.gs:58`, `fit-balance-site/apps-script/Code.gs:66`
**Evidence:** `sh.appendRow([new Date(), name, "'" + phone, hard, source, 'חדש', '']);`. Only `phone` gets the `'` prefix that forces plain text. `clean_()` removes only `<` and `>`.
**Fix:** In `clean_()`, put a `'` in front of any value that starts with one of the risky characters: `const s = String(v || '').replace(/[<>]/g, '').trim().slice(0, max); return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;`. Also check `source` against a fixed list (`['אתר','תוכן חינמי']`) and drop anything else. Paste the new code into the Apps Script editor and deploy a new version.
**Verify:** Post a test lead with name `=1+1`, for example from `testLead()` with that name. The sheet should show the text `=1+1`, not `2`.

### F-02 · MEDIUM · A06 Insecure Design
**What can happen:** The lead endpoint's address is public in the page source and accepts posts from anyone, with no limit. A script can send thousands of fake leads. That fills the sheet, floods Yahav's inbox, and uses up the daily Gmail sending quota, so real leads stop sending alerts.
**Where:** `fit-balance-site/apps-script/Code.gs:49`, `fit-balance-site/apps-script/Code.gs:71`, `fit-balance-site/index.html:816`
**Evidence:** `function doPost(e) { ... if (p.website) return ok_(); ... MailApp.sendEmail({ to: NOTIFY_EMAIL, ...` The only protection is the honeypot field, which a script simply leaves empty.
**Fix:** In `doPost`, keep counters in `CacheService.getScriptCache()`. Count leads per phone number (for example, ignore the same phone twice within 10 minutes). Also keep an overall count: past about 50 leads an hour, still write the row but skip `MailApp.sendEmail`. Once a day, send one summary email instead of one per lead.
**Verify:** Send the same phone number 3 times in a row. The sheet should get one row and Yahav one email. Send 60 different test leads. Emails should stop after the cap, while rows still appear.

### F-03 · MEDIUM · A07 Authentication Failures
**What can happen:** "Remember me" is checked by default and saves the shared course password as plain text in the browser's storage. Anyone else who uses that device, or any script that runs on the `fit-balance.co.il` domain, can read it and share it.
**Where:** `course-area/template.html:102`, `course-area/template.html:143`, `course-area/template.html:161`, `course-area/template.html:173`
**Evidence:** `<input type="checkbox" id="keep" checked>`, `var KEEP_KEY = 'fb_course_pw'`, `if (keep) store(KEEP_KEY, pw);` (`store` writes to `localStorage`)
**Fix:** Do not store the password. After a successful unlock, derive the key with `extractable: true`, export the raw key (`crypto.subtle.exportKey('raw', key)`) and store that instead. On a later visit, import it and decrypt directly. A stolen copy then opens only this build of the course, not the next one, because a new random salt is made on every build. Remove `checked` from the "remember me" box. Then run `node course-area/encrypt.mjs` again to rebuild the course page.
**Verify:** Log in with "remember me" on. In DevTools → Application → Local Storage, the password must not appear under `fb_course_pw` or any other key. Reloading the page should still open the course.

### F-04 · LOW · A02 Security Misconfiguration
**What can happen:** Netlify publishes everything in `fit-balance-site/`, so anyone can download the Apps Script source. It shows Yahav's alert email address, how the lead form is filtered (honeypot, length checks) and the sheet layout. This makes F-01 and F-02 easier to exploit.
**Where:** `fit-balance-site/apps-script/Code.gs`
**Evidence:** `const NOTIFY_EMAIL = 'yahav.sror27@gmail.com';`. The file sits inside the publish folder (`CLAUDE.md:16`: "`fit-balance-site/` = **Netlify publish directory**").
**Fix:** Move the folder to the repo root (`apps-script/Code.gs`), next to `course-area/`, and update the path in `CLAUDE.md:22`.
**Verify:** After deploy, opening `https://fit-balance.co.il/apps-script/Code.gs` should return 404.

### F-05 · LOW · A02 Security Misconfiguration
**What can happen:** The site sends none of the standard security headers. Other sites can embed it in a frame (clickjacking), and nothing in the browser limits damage if a bad script ever reaches the pages, including the course page that holds the password.
**Where:** `fit-balance-site/index.html`, `fit-balance-site/course.html`, `course-area/template.html`
**Evidence:** No `netlify.toml`, no `fit-balance-site/_headers` and no `<meta http-equiv="Content-Security-Policy">` exist anywhere in the project. Header settings made in the Netlify web dashboard cannot be seen from here.
**Fix:** Add a file `fit-balance-site/_headers` with: `/*` then indented lines `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Add a `Content-Security-Policy` that allows only what the pages use: `self`, `fonts.googleapis.com`, `fonts.gstatic.com`, `www.youtube-nocookie.com`, `player.vimeo.com`, `script.google.com`, and `'unsafe-inline'` for the inline scripts and styles until they are moved to files. Test it on a Deploy Preview first.
**Verify:** On the Deploy Preview, open DevTools → Network → the document → Response Headers and confirm all six headers are there. Then check that videos, fonts and both forms still work.

### F-06 · LOW · A06 Insecure Design
**What can happen:** All buyers share one course password. Anyone who has it, or who guesses it offline (the encrypted course is a public file and the minimum length is only 8 characters), gets every lesson. The worksheets are open to anyone with the link, so even without the password, one shared link is enough to get them.
**Where:** `course-area/encrypt.mjs:21`, `course-area/lessons.json:3`, `course-area/lessons.json:7`
**Evidence:** `if (!pw || pw.length < 8)`, `"Worksheet links are per gate (Google Drive, 'anyone with the link can view')"`
**Fix:** Use a long random password (for example 4 or more random words, 20+ characters), raise the minimum in `encrypt.mjs` to 16, and change it when you suspect it has leaked: rebuild and email current buyers. If this course becomes a meaningful income, move to a hosted course platform or Vimeo showcase with a login per buyer.
**Verify:** `node course-area/encrypt.mjs` should refuse a 10-character password, and the password in the Cardcom email should be long and random.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name | Google Sheet "פניות מהאתר - Fit Balance" + an alert email in Yahav's Gmail | Calling the lead back | No |
| Phone number | Google Sheet + Gmail alert (and a wa.me link built from it) | Calling back / WhatsApp | No (personal contact) |
| "Difficulty" chosen in the form (`hard`) | Google Sheet + Gmail alert | Qualifying the lead | Possibly: it may describe emotional eating or body-image struggles |
| Lead source and date | Google Sheet | Knowing which form the lead came from | No |
| Course password | Buyer's browser storage (`fb_course_pw`), Cardcom email | Opening the course | Yes (a secret, see F-03) |
| Course progress | Buyer's browser storage (`fb_course_done_v1`) | Progress bar | No |
| Buyer name and contact details | Cardcom (outside this code) | Delivery and receipt | No (personal) |
| Health intake questionnaire | Outside the site (`privacy.html:74`) | Personal coaching plan | Yes (health) |

## Accepted risks

None.

## Not checked

- **Who can open the Google Sheet and Gmail account, and whether 2FA is on.** These are account settings, not code.
- **Apps Script deployment settings.** I could not check that the deployed script matches `Code.gs`, or who else can edit the script.
- **Netlify account and Netlify settings.** I could not check 2FA, or any headers or redirects set in the Netlify dashboard rather than in files (F-05 assumes there are none).
- **Google Drive sharing of the course worksheets and workbook.** I can only see what `lessons.json` says about them.
- **Vimeo embed limits.** Whether Vimeo embedding is really limited to Yahav's domains is a Vimeo setting.
- **The generated course page.** `fit-balance-site/my-course/index.html` is not in the folder, so I could not check what is actually published; I reviewed only the template and the build script.
- **Cardcom.** How the password email is sent and where buyer data is kept are outside the code.
- **Git history.** I could not see it, so a committed course password or `lessons.json` export may still exist there.
- **The live site.** It was not in scope; the scope was code only.
- **Questions for the owner (privacy, not legal rulings):**
  - Leads are kept "as long as needed" (`privacy.html:68`). Should old or irrelevant leads be deleted after a set time, such as 12 months?
  - Where is the health questionnaire stored, who can read it, and when is it deleted?

---
This report is a second reader, not a penetration test, a certificate or legal advice.
