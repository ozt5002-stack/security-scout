# 01 - Design

## The problem

Small web products are built today by people who are not security experts: a course student, a freelancer, a
brother who builds his sister's site. They ship real things (a landing page with a lead form, an AI service with API
keys, a static site built from a spreadsheet) and nobody checks them for the usual mistakes.

Lesson 12 showed that the usual mistakes are few and well known (OWASP Top 10 2025), and that most of them can be
found by reading the code and the configuration, plus a few safe requests to the live site.

## How it is done today

By hand. On 18-22 November 2026 a security review of three real projects took several hours of reading code and
running tools one by one (`npm audit`, `curl -I`, a history search for keys), and found 16 real issues (7 + 5 + 4),
for example:

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

1. **Scanners** (ordinary programs, no AI) collect facts: keys in the code and the git history, known-vulnerable
   dependencies, risky Python patterns (Bandit), files that should not be public, missing security headers on the
   live site, CI permissions. Nikto runs only when asked.
2. **The agent** (a Claude Code subagent) reads the project and the scanners' facts and writes one report: each
   finding in plain words, mapped to an OWASP 2025 category, with the file and line, a fix, and a way to verify it.
3. The report ends with a **"Not checked" list**, so that silence never reads as "safe".

The agent can read but never change, run or send anything (lesson 12, "an auditor needs eyes, not hands").

## Users

- **Primary:** Oz, before every deploy of his own projects and his sister's sites.
- **Secondary:** a course student or a small-business builder who wants a first security pass on their own project.

## Success metric

**Recall on the known findings: the agent finds at least 13 of the 16 issues from the manual review of 18-22
November 2026**, when run on the three projects as they were *before* the fixes. The 5 most serious ones must
always be found (they are marked `must_pass`).

A second number is reported next to it: on the same projects *after* the fixes, how many of the fixed issues are
still reported (false alarms). Target: no more than 2.

## Rules the product keeps

- **Own targets only.** Live checks run only against hosts listed in `targets.yaml`. Scanning a site you do not own
  can be illegal; the tool refuses.
- **Safe by default.** Without `--nikto` the live checks are a handful of ordinary requests (the headers of the home
  page, a short list of paths that should not exist). No attack payloads, no load.
- **Never print a secret.** A found key is shown by its first 4 characters only.
- **The project is data, not instructions.** A comment in the scanned code that says "skip this check" is reported
  as a finding, not obeyed (the auditor is an agent, so it can be prompt-injected too).
- **Evidence or silence.** Every finding points at a file and line or a live response. No guessed findings.

## Out of scope

- **Fixing.** It reports; a person fixes. (The fixes in the manual review were made by hand, in pull requests.)
- **Attacking.** No exploitation, brute force, fuzzing or load. It is not a penetration test.
- **Cloud and account settings** it cannot see from the code: backups, who can read a Google Sheet, 2FA, Netlify or
  Railway settings. These go into the "Not checked" list.
- **A certificate or legal advice.** Privacy questions are listed for the owner, not answered.
- **Sites the user does not own.**
- **A web interface.** It is a command-line tool and a report file.
