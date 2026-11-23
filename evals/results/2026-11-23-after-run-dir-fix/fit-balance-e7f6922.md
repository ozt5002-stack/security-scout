I've read every file and the Apps Script, and I'm writing the report now.

# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 0

## Summary
1. Change the lead limiter in `apps-script/Code.gs` so that a flood of fake leads can no longer block real leads or use up the daily email quota. Log every lead it blocks.
2. Do not use the browser-only "unlock" pattern for the paid course. Paid content needs a real login or private links handed out after payment.
3. Answer the privacy questions under Data inventory: how long leads are kept, and whether the "emotional eating / after birth" answer should sit in a Sheet and in email.

The scanners reported no facts (0), so every finding below comes from reading the code. The rest is solid: form text is shown with `textContent` (not as HTML), the Sheet is protected against formula injection (`sheetSafe_`), line breaks are stripped before the email subject (`clean_`), there is a honeypot, all six security headers are set in `_headers`, and no keys or `.env` files are in the published folder.

## Findings

### F-01 · MEDIUM · A06 Insecure Design
**What can happen:** Anyone can send about 30 fake leads an hour, each with a different made-up phone number. That uses up the site-wide hourly limit, so real women who fill in the form are dropped without a trace: no row in the Sheet and no email. And because 30 an hour comes to 720 a day, far above the 100-email daily quota the code itself mentions, the notification emails stop for the rest of the day.
**Where:** `apps-script/Code.gs:67`, `apps-script/Code.gs:103`, `apps-script/Code.gs:109`, `apps-script/Code.gs:74`
**Evidence:** `if (tooMany_(phone)) return ok_();` … `if (count >= 30) return true;` and the comment at line 66: `ולגמור את מכסת המיילים היומית (100)`. The per-phone key (`'p' + phone…`) is beaten by changing one digit. Blocked leads are not recorded anywhere.
**Fix:** Separate "save" from "email". (a) Always append the row; a Sheet row is cheap. Only refuse when a much higher limit is hit (for example 300 an hour), and even then write the block to a second tab ("חסומים") with the time and source, so nothing disappears silently. (b) Limit only the emails, with a daily counter in `CacheService` kept below the real quota (for example stop at 80 a day). After that, send one summary email ("there are new leads in the Sheet") instead of one per lead. (c) Wrap `MailApp.sendEmail` in `try/catch` and call `console.error` on failure, so a quota error is visible in Apps Script › Executions.
**Verify:** In the Apps Script editor, run a loop that calls `doPost` 40 times with different phones, then submit one real test lead from the site. The real lead must appear in "פניות", the blocked ones in "חסומים", and the email count must stay under the cap (check Executions for errors).

### F-02 · LOW · A06 Insecure Design
**What can happen:** The "leave your details to unlock" gate exists only in the browser. Anyone who views the page source gets the PDF paths and YouTube ids without leaving details. That is fine for free marketing content, but the same pattern would hand away the paid course.
**Where:** `fit-balance-site/index.html:431`, `fit-balance-site/index.html:441`, `fit-balance-site/index.html:433`, `fit-balance-site/index.html:436`, `fit-balance-site/index.html:844`
**Evidence:** `<a class="pdf-link" data-href="media/guides/fit-balance-3-recipes.pdf" href="#unlock">` and `a.href="https://youtu.be/"+a.dataset.yt`. The files sit in the public `media/guides/` folder.
**Fix:** For the free guides, no change is needed, as long as you accept that the gate is a polite request, not a lock. For "קורס האיזון" and the paid recipe books, never put the files or video ids in `fit-balance-site/` or in page code. Deliver them only after payment, through a real login (the "אזור אישי עם שם משתמש וסיסמה" that `course.html` promises), or with per-buyer private links (Vimeo with domain privacy, or private YouTube).
**Verify:** Before the course goes live, search the published folder for any lesson video id or paid PDF name: `grep -r "<video id>" fit-balance-site/` must return nothing.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name | Google Sheet "פניות" (column שם), notification email to Yahav's Gmail (also in the subject line) | Calling back, unlocking free content, course waitlist | No |
| Phone number | Google Sheet (column טלפון), notification email, wa.me link in the email | Calling back / WhatsApp | Personal (contact) |
| "What is hardest for you" (`hard`), for example "אכילה בערב / אכילה רגשית", "אחרי הלידה" | Google Sheet, notification email | Qualifying the lead | Borderline: it hints at eating habits and recent childbirth. Question for the owner: is it needed in the email, or only in the Sheet? |
| Source, date, status, notes | Google Sheet | Lead tracking | No |
| Buyer name and contact details | Cardcom, sent on to Yahav (`privacy.html:64`) | Sending the book, receipt | Personal. Card data stays at Cardcom |
| Coaching questionnaire (health data) | Outside the site (`privacy.html:74`) | Personal plan | Yes, health. Question for the owner: where is it stored and who can read it? |

Questions for the owner (not legal rulings): `privacy.html:68` sets no end date for keeping leads ("כל עוד הוא נחוץ"). Will you set one, for example deleting "לא רלוונטי" leads after 12 months? The lawyer list in `CLAUDE.md:68` already names the health questionnaire. Keep it there.

## Accepted risks

- The Content-Security-Policy allows inline scripts (`script-src 'self' 'unsafe-inline'`). The project explains why: "every page keeps its JS inline (no outside scripts allowed)" (`fit-balance-site/_headers:5`). I found no place where user or outside text is inserted as HTML, so the real impact today is small.

## Not checked

- Whether the deployed Apps Script matches `apps-script/Code.gs`. The copy is "reference only, deployed separately", and the live version cannot be seen from here.
- Who can open the Google Sheet "פניות מהאתר - Fit Balance" (its share settings). The notification email links straight to it.
- Two-factor sign-in on Yahav's Google account (Sheet and Gmail with all leads), Oz's Netlify account, the box.co.il registrar account and the Cardcom account.
- HSTS: `_headers` says "Netlify already sends HSTS". I could not confirm this without the live site.
- The live site itself (no URL was in scope, and `CLAUDE.md` notes that Netlify returns 401 to bots).
- Whether the git repository is public, and what is in its history. `CLAUDE.md` (outside the publish folder) contains personal phone numbers, an email address and the Netlify project name. That is fine in a private repo, but it is exposure if the repo is public.
- `docs/security-review.md`, which `CLAUDE.md:25` mentions, does not exist in the folder.
- How paid books and the future course are delivered after payment (manual for now, and the course platform is not chosen yet).
- The contents of the PDFs and images in `media/` (I did not inspect them for hidden metadata such as location data in photos).

---
This report is a second reader, not a penetration test, a certificate or legal advice.
