# Retrospective

What was planned, what happened, and what changes next time. Written at the end of the project (23 Nov 2026), from the
PR history, the review comments and the audit (`docs/audit.md`).

## What went to plan

- Docs before code: design, architecture and plan were merged (PRs #4, #5, #14) before the first code branch, and Oz
  approved the plain-Hebrew summary (Stop 1) before any code.
- One branch and one PR per task, each from an up-to-date `main` after the previous merge; every PR closes its issue;
  merged branches are deleted; nothing was pushed straight to `main` after the bootstrap commit, and GitHub enforces
  it (PR required, green CI required, admins included, merge commits only).
- Every PR had an independent review before its merge, and every review found something real.
- The design's success metric was met by the eval (13/16, all `must_pass`, 1 false alarm), without changing the target.

## What did not go to plan

| What | What happened | Next time |
|---|---|---|
| Pause before merge | PRs #4 and #5 were merged about one minute after their review comment. The 5-minute rule (CONTRIBUTING rule 5) was written in PR #14, after the plan review pointed at #5. | Write the timing rule before the first PR, not after it. |
| "Architecture changed: yes/no" line | PRs #4 and #5 do not carry it (rule 6 did not exist yet). | Same as above. |
| D10 (a hostile project must not run code) was incomplete | Reviews found six real holes in turn: git textconv (#15), git filter drivers (#15), `log.showSignature` + `gpg.program` (#16), a project `.npmrc` (#17), a project `.bandit` (#17), and Nikto reading commas as more hosts (#21). Each was proven with a planted repo before and after the fix. | Start D10 from a list of every config file each outside tool reads, and test each one with a planted hostile project from the first task. |
| Windows details | The Hebrew user folder broke Perl; broken IPv6 made Python requests take minutes (#18); a Windows short temp name (`E40C~1`) hid the facts file from the agent (found by the eval baseline, #20). | Run the first real end-to-end check on the target machine in task 1, not in task 5/6. |
| A failure shown as success | The first Nikto run reported success with an empty result while Nikto had stopped on a missing Perl module (#21). | A scanner step must fail when its tool wrote no output; test it from the start. |
| The eval scored itself too kindly | The keyword `content-type` matched inside `x-content-type-options`, counting a missed CSRF finding as found (#20). The reviewer caught it; both result folders were rescored (baseline 12 → 11). | Whole-word keywords and a hand check of every "found" in the first eval, before trusting the number. |
| Nikto on this computer | Windows Defender deleted `nikto.pl` within a minute of download. Oz chose GitHub Actions (#21). The PR trigger then re-ran a 30-minute scan on every push; Oz chose manual-only. | Ask where a known "hacking tool" will run before planning it locally; never put a long live scan on a PR trigger. |
| The agent's login | The standalone `claude` CLI was logged out; the first real agent run failed with an empty error (#19). Oz logged in; the CLI now explains a login failure. | Check the CLI login in task 1. |
| Rule 9 after the Nikto task | PRs #21's commits changed `scout/` after the eval baseline without an eval run; caught by this audit, and an eval was run on the final code (`evals/results/2026-11-23-after-nikto`). | Run the eval in the PR that changes `scout/`, as the rule says. |
| My own editing | Several Python "patch" scripts passed through a shell heredoc lost backslashes (`\b`, `\1`, `\n`) and wrote control characters into regexes; each was caught by tests or a syntax error and fixed by hand. | Edit files with the editor, not with scripts inside heredocs. |
| Review stopped | The first review of PR #16 was stopped when Oz paused the work; a new one was run the next day. | Nothing to change: a stopped review is re-run, never skipped. |

## What the reviews were worth

Across the 10 pull requests, the independent reviews found every one of the six D10 holes, the allowlist bypass, the
API-billing leak in the agent's environment (#19), the eval's scoring error (#20), and a real flaw in a fix made for
Yahav's site (the lead form's site-wide cap lets a bot block real leads for an hour, reported by the agent itself in
the eval). None of these would have been seen by the tests that were written first.
