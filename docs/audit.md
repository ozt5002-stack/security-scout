# Audit

Every rule in `CONTRIBUTING.md` and every "Done when" in `docs/03-plan.md`, checked on 23 Nov 2026 with the command
shown, on `origin/main` after PR #21. **OK** = the rule held; **GAP** = it did not, with what happened (and where it is
in `docs/retrospective.md`).

## CONTRIBUTING rules

| # | Rule | Command and result | |
|---|---|---|---|
| 1 | No direct pushes; merge commits only; `main` protected | `git log --first-parent --no-merges dff7fe7..origin/main` prints nothing. Repo: merge commits only (squash, rebase off). Protection: PR required, `test` check required, admins included, no force push. | **OK** |
| 2 | Docs before code | `gh pr list --state merged`: #4 design merged 18:40, #5 architecture 18:45, #14 plan 20:13 on 22 Nov; the first `feat/` PR (#15) was created 20:18. | **OK** |
| 3 | One branch per task, each after the previous merge | Each PR's `createdAt` is after the previous one's `mergedAt` (#14 20:13 → #15 created 20:18; #15 20:30 → #16 20:33; #16 08:46 → #17 08:49; #17 09:05 → #18 09:19; #18 09:33 → #19 11:25; #19 11:43 → #20 14:42; #20 19:38 → #21 19:44). Branch names: `design/`, `feat/`. | **OK** |
| 4 | Every PR closes an issue | `closingIssuesReferences`: #4→1, #5→2, #14→3, #15→6, #16→7, #17→8, #18→9, #19→10, #20→11, #21→12. | **OK** |
| 5 | CI green, independent review, fixes, review comment, merge ≥ 5 min later | Review comment → merge: #4 **1 min 8 s**, #5 **1 min 1 s**, #14 84 min, #15 5 min 35 s, #16 6 min 11 s, #17 5 min 13 s, #18 5 min 17 s, #19 5 min 14 s, #20 5 min 15 s, #21 5 min 13 s. Every review comment is after the PR's last commit. | **GAP** for #4 and #5 (the rule was written after them) |
| 6 | An architecture-changing finding stops the work until Oz decides | Review comments say "Architecture changed": #14 no, #15 yes, #16 yes, #17 yes, #18 no, #19 yes, #20 yes, #21 yes; each "yes" records Oz's answer (asked in chat with a question card). #4 and #5 have no such line. | **GAP** for #4 and #5 (rule written later); OK from #14 |
| 7 | Merged branches deleted | `git ls-remote --heads origin` lists only `main` (and this PR's branch while it is open). | **OK** |
| 8 | No secrets in the repo or history | `python -m scout.scanners.secrets .` prints nothing (also a test). | **OK** |
| 9 | After the baseline: prompt and tool changes in separate commits, eval before and after | Commits touching `scout/` or `.claude/agents/` after the baseline (01ebfdc): 5551170 (run folder) has the baseline before it and `2026-11-23-after-run-dir-fix` after it. b86f121 and 3b753ae (Nikto, PR #21) had no eval run: caught by this audit; `2026-11-23-after-nikto` was then run on the final code (result below). | **GAP** for PR #21, closed by the after-nikto run |
| 10 | Tests in CI, evals never in CI | `.github/workflows/test.yml` runs `python -m pytest -q`; `evals/` appears only in a comment. `nikto.yml` runs Nikto by hand only, not an eval. | **OK** |
| 11 | Live checks only for allowlisted hosts | `tests/test_live.py::test_host_not_in_allowlist_is_refused_before_any_request` (zero requests reach the server); `tests/test_nikto.py` bypass cases; the real `nikto` workflow refused `https://picks.fit-balance.co.il/,https://evil.test/` before fetching Nikto (run 45268028046, conclusion `failure` on purpose: the check step stops the run). | **OK** |
| 12 | The agent has read-only tools only | `tests/test_agent_report.py::test_the_agent_has_read_only_tools_exactly`; the run command has `--tools Read,Grep,Glob` and no `--allowedTools` (test). | **OK** |

## Plan: "Done when"

| Task | Done when | Evidence | |
|---|---|---|---|
| 1 Skeleton and CI | help; empty facts in `runs/`; non-listed host → exit 2 (test); CI green; protection requires the check | `tests/test_cli.py`; protection `checks: ["test"]` | **OK** |
| 2 Code scanners | one fact per planted problem; clean project gives none above info; ≤ 4 characters of a key; secrets module clean on this repo; CI green | `tests/test_code_scanners.py`, `tests/test_review_fixes.py` | **OK** |
| 3 Tool scanners | recorded npm audit → fact; Bandit finds `eval` with `# nosec`; missing tool → info; CI green | `tests/test_tool_scanners.py` (recorded `npm audit` of picks@0e4ef64, `pip-audit` of requests 2.19.0) | **OK** |
| 4 Live scanner | missing headers + public `.gs` found; all headers → none; non-listed host refused with zero requests; CI green | `tests/test_live.py` (local servers); real runs on both of Oz's sites in PR #18 | **OK** |
| 5 The agent | `python -m scout.report check examples/leaky-site.md` → 0; example names every planted file, reports the planted comment, no part of the key; tools exactly Read, Grep, Glob | `ok: 7 findings`; `tests/test_agent_report.py` | **OK** |
| 6 Evals | matching tests in CI; baseline committed; final run meets the metric or explains; real folders unchanged | `tests/test_eval_match.py`; `evals/results/2026-11-23-baseline` (11/16), `-after-run-dir-fix` (13/16, 0 must_pass missed, 1 false alarm: **met**) and the final run `-after-nikto` (13/16, 0 missed, 2 false alarms: **met**); "Real project folders unchanged: yes" | **OK** |
| 7 Nikto | the run against picks finishes with facts in the summary and the artifact; non-listed host refused (test); command and parser tested; local `--nikto` says where it runs | run 45252194198 (30 min, 17 facts, its JSON is `tests/data/nikto-picks.json`); `tests/test_nikto.py`; run 45268028046 refused | **OK** |
| 8 README, audit, retrospective | every audit line OK or explained; README numbers match the last eval summary | this file; `docs/retrospective.md`; README eval table | **OK** |

## The last eval

`evals/results/2026-11-23-after-nikto`, run on the final code (`main` after PR #21) to close the rule 9 gap:
**recall 13/16, must_pass missed: none, false alarms 2, runs with errors 0 of 7: design metric met.** Real project
folders unchanged (HEAD, refs, worktrees). Not found, the same three as in the previous run: aa-02 (CSRF via content
type), aa-05 (short password only warned about), aa-06 (failed logins not logged). The two false alarms are new real
weaknesses in the fixes, not the old problems (fb-03: the site-wide lead cap lets a bot block real leads; yp-03: the
headers GitHub Pages cannot send).

## Summary

All 12 rules hold from PR #14 on. Three gaps, all explained: #4 and #5 were merged about a minute after their review
and before rules 5 and 6 existed; PR #21 changed `scout/` without an eval run, which this audit caught and closed.
Every task's "Done when" is met. CI is green on `main` (129 tests).
