# Security report: fit-balance

Date: 2026-11-23 · Scope: code only · Facts from scanners: 0

## Summary
1. Make the Apps Script record and alert when its hourly limit of 30 leads is hit. Today a bot can fill that limit and real leads are dropped without anyone knowing.
2. Decide whether the "unlock" PDFs and videos really need to be gated. Right now the gate only exists in the browser, so the files can be downloaded directly. Never put paid books in `media/`.
3. Check the things outside the code (listed under "Not checked"): who can open the leads sheet, 2FA on the Google and Netlify accounts, and the live headers.

The scanners reported no facts (0), so every finding below comes from reading the code. The code is generally careful. Spreadsheet formula injection is blocked (`sheetSafe_`). Line breaks are removed from names before they go into the email subject (`clean_`). Leads are rate-limited. There is a honeypot field. The `_headers` file sets CSP, X-Frame-Options, nosniff, Referrer-Policy and Permissions-Policy. No form or sheet value is ever inserted into the page as HTML. The one `innerHTML` (`index.html:832`) only uses values written in the page itself.

## Findings

### F-01 · MEDIUM · A06 Insecure Design
**What can happen:** A bot can send 30 fake leads an hour, each with a different made-up phone number. After that, every real lead that hour is thrown away. The visitor still sees "thank you" and no one is told.
**Where:** `apps-script/Code.gs:67`, `apps-script/Code.gs:103`
**Evidence:** `if (tooMany_(phone)) return ok_();` and `if (count >= 30) return true;`. The rejected lead is not saved and nothing is logged.
**Fix:** In `doPost`, when `tooMany_` returns true, do not drop the lead silently. Save it to a second tab (for example "חסומות") with `sheetSafe_` applied, but without sending an email. The first time the hourly cap is hit in a given hour, send Yahav one email ("over 30 leads this hour, check the sheet"). To send it only once, keep a cache key such as `'alert'+hourKey`. Then a flood costs at most one extra email, and real leads can still be found.
**Verify:** Run `testLead` 31 times from the editor with different phone numbers. The 31st should appear in the "חסומות" tab, and exactly one alert email should arrive.

### F-02 · LOW · A06 Insecure Design
**What can happen:** Anyone can open the "gated" free PDFs and videos without leaving a name or phone. The real addresses are written in the page, and the gate opens even when sending the lead fails.
**Where:** `fit-balance-site/index.html:431`, `fit-balance-site/index.html:441`, `fit-balance-site/index.html:433`, `fit-balance-site/index.html:436`, `fit-balance-site/index.html:850`
**Evidence:** `data-href="media/guides/fit-balance-3-recipes.pdf"`, `data-yt="3zRcUj_5X5c"`, `fetch(LEADS_URL,...).finally(open);`
**Fix:** This is fine for free marketing content: if that is the intent, write it down in `CLAUDE.md` as an accepted risk. Never use this pattern for anything paid. The paid recipe books and the future course must never go into `fit-balance-site/media/`, because everything there can be downloaded directly. For buyers, use Cardcom delivery or unlisted/private YouTube with a link sent after payment, as planned in "Open items".
**Verify:** In an incognito window, open `https://fit-balance.co.il/media/guides/` plus each PDF file name directly, and confirm that only free material is there.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| Name | Google Sheet "פניות", and the notification email to Yahav (Gmail) | Calling back, unlocking free content, course waitlist | No |
| Phone number | Google Sheet "פניות", the notification email, a `wa.me` link in the email; also as a CacheService key for 30 minutes | Calling back / WhatsApp | Personal (contact) |
| "What's hardest for you" (`hard`), e.g. "אכילה בערב / אכילה רגשית", "אחרי הלידה" | Google Sheet, notification email | Preparing the call | Somewhat: it hints at eating habits and recent childbirth (health-adjacent). Question for the owner: is it needed, and does the privacy page cover it? (it does mention the field) |
| Lead source (`source`) | Google Sheet | Knowing which form was used | No |
| Coaching questionnaire (health information) | Not on the site (privacy.html says so) | Building the personal plan | Yes, health. Not visible in this code |
| Buyer name and contact details | Cardcom, then Yahav | Sending the book, receipt | Personal; card data stays with Cardcom |

Questions for the owner, not legal rulings: the privacy page says data is kept "כל עוד הוא נחוץ" with no end date. Should old leads (for example "לא רלוונטי" ones older than 12 months) be deleted on a schedule? `CLAUDE.md` already puts the health questionnaire on the lawyer's list.

## Accepted risks

- CSP allows `'unsafe-inline'` for scripts, because every page keeps its JavaScript inline (`fit-balance-site/_headers`, lines 5 and 12). No outside script hosts are allowed, and no user data is inserted as HTML, so the remaining risk is small.
- The Apps Script web app URL is public in the page source, and the web app is deployed with access set to "כל אחד" (anyone) so the forms work (`apps-script/Code.gs:65-66`, `CLAUDE.md` "Lead forms"). It is limited by the honeypot, the per-phone and hourly rate limit, and length/character cleaning (see F-01 for the remaining gap).

## Not checked

- Live site headers: the scope was code only. HSTS is said to come from Netlify (`_headers` line 2) but was not seen, and it was not confirmed that Netlify actually serves `_headers`.
- Whether the deployed Apps Script matches `apps-script/Code.gs`. The file is a reference copy only; the live one is edited in Google.
- Sharing settings of the Google Sheet "פניות מהאתר - Fit Balance" (who can open it), and the Gmail inbox that receives every lead.
- 2FA and recovery settings on the Google account (Yahav), the Netlify account (Oz), the box.co.il registrar and Cardcom.
- Git history and whether this repository is public. `CLAUDE.md` contains private phone numbers and Yahav's email address; they are partly public on the site already, but check whether the repository needs to be public.
- `docs/security-review.md` is mentioned in `CLAUDE.md` but is not in the project folder, so it was not read.
- The PDF files and videos themselves (content and metadata such as author or location) were not opened.
- Cardcom payment pages and how books are delivered after payment.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
