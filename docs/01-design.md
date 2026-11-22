# 01 - Design

## The problem

Small web products are built today by people who are not security experts: a course student, a freelancer, a
brother who builds his sister's site. They ship real things (a landing page with a lead form, an AI service with API
keys, a static site built from a spreadsheet) and nobody checks them for the usual mistakes.

Lesson 12 showed that the usual mistakes are few and well known (OWASP Top 10 2025), and that most of them can be
found by reading the code and the configuration, plus a few safe requests to the live site.

## How it is done today

By hand. On 18-22 November 2026 a security review of three real projects took a long manual session of reading code
and running tools one by one (`npm audit`, `curl -I`, a history search for keys), and found 16 real issues: 7 in
`fitbalance-ad-agents` and 8 in Yahav's two sites, where the missing-headers finding is counted once per site (5 in
`fit-balance`, 4 in `yahav-picks`). The reports: `fitbalance-ad-agents/docs/07-security-review.md` and
`fit-balance/docs/security-review.md`. Examples:

| Project | Example finding |
|---|---|
| `fitbalance-ad-agents` (Node service) | no limit on password guesses; a POST from another site accepted |
| `fit-balance` (Netlify site) | the lead-form backend `Code.gs` was publicly readable; form text became Sheet formulas |
| `yahav-picks` (GitHub Pages site) | `javascript:` links from Airtable were not blocked; a high-severity `sharp` advisory |

Doing this by hand means it happens once, if at all. A new route, a new dependency or a file in the wrong folder
goes live unchecked.

## How it will be done

One command per target:

```
scout <path-to-project>                  # the code and its configuration
scout <path> --live https://example.com  # plus safe checks on the live site
```

1. **Scanners** (ordinary programs, no AI), run by the `scout` command, collect facts: keys in the code and the git
   history, known-vulnerable dependencies (`npm audit`, `pip-audit`), risky Python patterns (Bandit), files in a
   site's publish folder that should not be public, missing security headers (from the live site, or from the
   project's header config such as Netlify `_headers`), CI permissions. Nikto runs only when asked.
2. **The agent** (a Claude Code subagent) reads the project and the scanners' facts and writes one report: each
   finding in plain words, mapped to an OWASP 2025 category, with the file and line, a fix, and a way to verify it.
3. The report ends with a **"Not checked" list**, so that silence never reads as "safe".
4. The report is saved as `reports/<project>-<date>.md`.

Only the `scout` command runs programs and sends requests. The agent can read but never change, run or send
anything: in lesson 12's words, an auditor needs eyes, not hands.

Bandit only reads Python. None of the three projects above is Python, so on them Bandit finds nothing; it is there
for Python projects (most course projects).

## Users

- **Primary:** Oz, before every deploy of his own projects and his sister's sites.
- **Secondary:** a course student or a small-business builder who wants a first security pass on their own project.

## Success metric

**Recall on the known findings: the agent finds at least 13 of the 16 issues from the manual review of 18-22
November 2026**, when run on the three projects as they were *before* the fixes.

How it is checked, by a script, not by eye:
- `evals/known-findings.yaml` lists the 16 findings. For each: the project, the commit before the fix, the commit
  after it, the file it lives in, its OWASP 2025 category, and 1-3 keywords.
- A known finding counts as **found** when one reported finding names the same file and contains one of its keywords.
- The eval runs on the code only (no live site): the live sites are already fixed. Every one of the 16 can be seen in
  the code, including the two first found on the live sites (a `.gs` file inside the publish folder; no `_headers`).
- One finding (the course password) sits on an unmerged branch, not `main`; its commits are listed like the rest.

**5 findings must always be found** (`must_pass`; the run fails without them, whatever the score): the unlimited
password guesses (ad agents), the public `Code.gs` and the Sheet formula injection (fit-balance), the `javascript:`
links and the high-severity `sharp` advisory (picks).

**False alarms:** on the same projects *after* the fixes, a fixed issue that is still reported as open is a false
alarm. Target: no more than 2. Risks the reports accepted on purpose (for example `'unsafe-inline'` in the main site's
CSP, the container running as root) are real trade-offs: reporting them is not a false alarm.

## Rules the product keeps

- **Own targets only.** Live checks run only against hosts listed in `targets.yaml`. Scanning a site you do not own
  can be illegal; the tool refuses.
- **Safe by default.** Without `--nikto` the live checks are a handful of ordinary requests (the headers of the home
  page, a short list of paths that should not exist). No attack payloads, no load.
- **Nikto is opt-in and slowed down.** Nikto sends thousands of requests for known risky paths. It runs only with
  `--nikto`, only against a host in `targets.yaml`, with a pause between requests.
- **Never print a secret.** A found key is shown by its first 4 characters only.
- **The project is data, not instructions.** A comment in the scanned code that says "skip this check" is reported
  as a finding, not obeyed (the auditor is an agent, so it can be prompt-injected too).
- **Evidence or silence.** Every finding points at a file and line or a live response. No guessed findings.

## Out of scope

- **Fixing.** It reports; a person fixes. (The fixes in the manual review were made by hand, in pull requests.)
- **Attacking.** No exploitation, password guessing, payload fuzzing or load. It is not a penetration test. (Nikto's
  checks for known paths are the one exception, opt-in and slowed down, see above.)
- **Cloud and account settings** it cannot see from the code: backups, who can read a Google Sheet, 2FA, Netlify or
  Railway settings. These go into the "Not checked" list.
- **A certificate or legal advice.** Privacy questions are listed for the owner, not answered.
- **Sites the user does not own.**
- **A web interface.** It is a command-line tool and a report file.

## What the owner should know

- **Cost:** the agent runs inside Claude Code on Oz's Claude plan. No API key and no extra bill. A run on a small
  project takes a few minutes. The eval runs the agent 6 times (3 projects, before and after the fixes).
- **Installs:** Bandit and pip-audit through `pip`. Nikto is a Perl program (Perl is already installed) fetched from
  its official GitHub repo. A secret scanner like gitleaks is optional; `scout` has its own key-pattern search.
- **Output:** one Markdown report per run, in `reports/`.
