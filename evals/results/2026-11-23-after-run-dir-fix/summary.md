# Eval: 2026-11-23-after-run-dir-fix

**Recall: 13/16** (target ≥ 13) · **must_pass missed: none** · **false alarms: 2** (target ≤ 2) · **design metric met**

| Known finding | Must | Found |
|---|---|---|
| aa-01 no limit on password guesses (fitbalance-ad-agents) | yes | yes |
| aa-02 POST accepted from other sites (CSRF) (fitbalance-ad-agents) |  | yes |
| aa-03 missing HSTS and Permissions-Policy, partial CSP (fitbalance-ad-agents) |  | **no** |
| aa-04 yaml 2.6.1 known advisory (fitbalance-ad-agents) |  | yes |
| aa-05 short APP_PASSWORD only warned about (fitbalance-ad-agents) |  | **no** |
| aa-06 failed logins not logged (fitbalance-ad-agents) |  | **no** |
| aa-07 CI actions pinned to tags (fitbalance-ad-agents) |  | yes |
| fb-01 Code.gs publicly readable in the publish folder (fit-balance) | yes | yes |
| fb-02 formula injection into the Google Sheet (fit-balance) | yes | yes |
| fb-03 no limit on lead submissions (sheet flood, mail quota) (fit-balance) |  | yes |
| fb-04 no security headers on the main site (fit-balance) |  | yes |
| fb-05 course password minimum 8 (offline guessing) (fit-balance) |  | yes |
| yp-01 javascript: links from Airtable not blocked (yahav-picks) | yes | yes |
| yp-02 sharp high-severity advisory (yahav-picks) | yes | yes |
| yp-03 no CSP or other security headers (yahav-picks) |  | yes |
| yp-04 workflow write permissions for every job, actions on tags (yahav-picks) |  | yes |

| Run | Findings in report | Note |
|---|---|---|
| fitbalance-ad-agents @ 2ff32bc (before) | 5 |  |
| fitbalance-ad-agents @ e83756d (after) | 1 |  |
| fit-balance @ 28c63b3 (before) | 7 |  |
| fit-balance @ e7f6922 (after) | 2 |  |
| fit-balance @ f1d8a49 (after) | 7 |  |
| yahav-picks @ 0e4ef64 (before) | 5 |  |
| yahav-picks @ 240e6ad (after) | 2 |  |

False alarms (still reported after the fix): fb-03 no limit on lead submissions (sheet flood, mail quota), yp-03 no CSP or other security headers

Real project folders unchanged (status, branches, worktrees): yes
