# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 0

## Summary
1. Change the site-wide limit of 30 leads per hour in `apps-script/Code.gs`. Right now a bot can use up all 30 slots, so real leads are thrown away while the visitor still sees "thank you". The bot can also use up the daily email quota.
2. Write a record of every blocked or failed lead (a "blocked" tab or a status column), so Yahav can tell when real leads are being lost.
3. Decide whether the "unlock" gift box should really protect anything. The locked PDFs and videos are public to anyone who has the link. If they only collect leads, that is fine, but write that decision down.

The scanners reported 0 facts, so every finding below comes from reading the code. Overall the project is in good shape. The lead script already blocks spreadsheet formulas, strips line breaks from email subjects, has a honeypot field, and the six security headers are set in `_headers`.

## Findings

### F-01 · MEDIUM · A06 Insecure Design
**What can happen:** A script that sends 30 fake leads an hour, each with a new phone number, fills the site-wide limit. Every real lead in that hour is then thrown away while the visitor sees "thank you". In about 3–4 hours the same script also uses up the daily email quota (about 100), so Yahav gets no lead emails for the rest of the day.
**Where:** `apps-script/Code.gs:67`, `apps-script/Code.gs:103-113`, `apps-script/Code.gs:74`
**Evidence:** `if (count >= 30) return true;` and `if (tooMany_(phone)) return ok_();`. The per-phone check (`'p' + phone.replace(/\D/g, '')`) is easy to get around by changing one digit.
**Fix:** Don't drop the lead when the site-wide limit is reached. Still `appendRow` it, with status `'חשוד'` ("suspicious") instead of `'חדש'` ("new"), and skip only the email. Put a separate cap on emails, for example `if (MailApp.getRemainingDailyQuota() > 10 && mailCount < 20 per hour)`. Above that cap, send one summary email ("many leads arrived, check the sheet") instead of one per lead. Keep the per-phone limit for emails only.
**Verify:** In the Apps Script editor, call `doPost` 35 times in a loop with different phone numbers. All 35 rows should appear in the sheet (the extra ones marked as suspicious), and only the capped number of emails should arrive.

### F-02 · LOW · A09 Security Logging & Alerting Failures
**What can happen:** When a lead is blocked (by the rate limit or the honeypot) or the script fails (a lock timeout or a full email quota), nothing is recorded anywhere. Because the site sends with `no-cors`, the browser always shows "thank you". Neither Yahav nor the visitor learns that the lead was lost.
**Where:** `apps-script/Code.gs:53`, `apps-script/Code.gs:67`, `apps-script/Code.gs:63`, `apps-script/Code.gs:74`, `fit-balance-site/index.html:825`, `fit-balance-site/course.html:392`
**Evidence:** `if (p.website) return ok_();`, `if (tooMany_(phone)) return ok_();` and `lock.waitLock(10000);` (this throws an error if the lock times out). In the browser: `fetch(LEADS_URL,{method:"POST",mode:"no-cors",body:body}).then(function(){ ... "תודה "+name+"! קיבלתי את הפרטים` (the "thank you, I got your details" message)
**Fix:** Wrap the body of `doPost` in `try/catch`. On every block or error, increase a counter in a small "log" tab: date, reason (`honeypot` / `rate` / `error`) and the error message, but no name or phone. Send Yahav at most one alert email a day when the count is above zero. Use `lock.tryLock(10000)` and handle a `false` result, instead of letting `waitLock` throw.
**Verify:** Send one lead with the `website` field filled in, then trigger the rate limit. The log tab should show one `honeypot` row and one `rate` row.

### F-03 · LOW · A01 Broken Access Control
**What can happen:** Anyone can open the "locked" gifts without leaving a name or phone. The PDF addresses and YouTube IDs are already in the page source, so the lock only exists in the browser.
**Where:** `fit-balance-site/index.html:431`, `fit-balance-site/index.html:433`, `fit-balance-site/index.html:436`, `fit-balance-site/index.html:441`, `fit-balance-site/index.html:844-845`
**Evidence:** `<a class="pdf-link" data-href="media/guides/fit-balance-3-recipes.pdf" href="#unlock">` and `data-yt="3zRcUj_5X5c"`. The files sit in `fit-balance-site/media/guides/`, which the project's own notes call "Everything in this folder is public."
**Fix:** If these are only lead magnets, keep things as they are and write down in `CLAUDE.md` that the gate is a soft gate on purpose. If anything must truly be protected (for example the paid course or the paid books later), never put it in `fit-balance-site/`. Deliver it from a place that checks access, such as Cardcom's delivery, private or unlisted links sent after payment, or a login area.
**Verify:** Open `https://fit-balance.co.il/media/guides/fit-balance-nutrition-guide.pdf` in a private window without filling in the form. Today it opens. After a real fix (only if you choose one), it should not.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name | Google Sheet "פניות" (column שם); lead email in Yahav's Gmail | Calling back, unlocking gifts, course waitlist | No |
| Phone number | Google Sheet (column טלפון); Gmail; WhatsApp link in the email | Calling back over phone or WhatsApp | No (personal contact data) |
| "What's hardest for you" answer (for example "אכילה בערב / אכילה רגשית", evening or emotional eating; "אחרי הלידה", after giving birth) | Google Sheet (column הקושי); Gmail | Qualifying the lead | Close to health data (eating behaviour, after giving birth) |
| Lead source and date | Google Sheet | Knowing which form the lead came from | No |
| Before/after photos and testimonial videos of clients | `fit-balance-site/media/` (public) | Marketing | Yes: body images of real people |
| Intake questionnaire for coaching clients (health) | Outside the site (as `privacy.html:74` says) | Personal plan | Yes: health |
| Buyer name and contact details | Cardcom (as `privacy.html:64` says) | Delivering the book, receipts | No (the card data stays at Cardcom) |

Questions for the owner (not legal rulings):
- `privacy.html:68` says data is kept "as long as needed". Should leads that never become clients be deleted after a set time, for example 12 months? That includes the copies in Gmail.
- The "emotional eating" and "after giving birth" answers are close to health data. Does the form need to collect them, or could that conversation happen on the phone?
- Is there written consent from every woman shown in the `ba*`/`hq*` photos and `t*.mp4` videos? Open item 7 in `CLAUDE.md` already lists this.

## Accepted risks

- CSP allows `'unsafe-inline'` for scripts and styles, because every page keeps its JavaScript inline (`fit-balance-site/_headers:5`). No page inserts user data as HTML, so the risk is small today.
- The Apps Script web app is open to "anyone" and its URL is public in the page code, because that is how the form works (`apps-script/Code.gs:10`, `apps-script/Code.gs:65-66`).

## Not checked

- The facts file could not be opened in this run (the file read was blocked), and the run reported 0 scanner facts. Secret and dependency scanning results were therefore not seen.
- The live site was not in scope. I could not confirm that Netlify really sends HSTS and the headers in `_headers`.
- I could not confirm that the script deployed in Google matches `apps-script/Code.gs`. The repo copy is reference only.
- Who can open the Google Sheet and Yahav's Gmail, and whether the Google, Netlify, Cardcom and registrar (box.co.il) accounts have 2FA.
- Git history and whether the repository is public. If it is, `CLAUDE.md` exposes Yahav's notify email, both personal phone numbers and the Netlify project name.
- `docs/security-review.md` is mentioned in `CLAUDE.md:25` but is not in the folder.
- The subdomain `https://picks.fit-balance.co.il/` (linked at `fit-balance-site/index.html:793`), the Cardcom payment pages, and the contents and metadata of the PDFs in `media/guides/`.
- How the paid books and the future course are delivered after payment (done by hand today; the course platform has not been chosen yet).

---
This report is a second reader, not a penetration test, a certificate or legal advice.
