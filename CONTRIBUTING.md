# Contributing

Every rule here can be checked with a command. The final audit (`docs/audit.md`) runs each one.

| # | Rule | How to check |
|---|---|---|
| 1 | Nothing is pushed straight to `main`; every change arrives through a pull request. `main` is protected on GitHub (PR required, no force push, admins included). | `git log --first-parent --no-merges dff7fe7..main` prints nothing |
| 2 | Docs before code: design, architecture and plan are merged before the first code branch exists. | `git log --graph --oneline --all`: the merges of `design/spec`, `design/architecture`, `design/plan` come before the first `feat/` commit |
| 3 | One branch per plan task, created from an up-to-date `main` only after the previous task's PR is merged. Names: `design/`, `feat/`, `fix/`, `docs/`. | `git log --graph`: each branch starts at the previous merge commit |
| 4 | Every PR closes an issue. | `gh pr view <n> --json closingIssuesReferences` is not empty |
| 5 | Review before merge, in this order: CI green on the last commit, then an independent review (a reviewer that did not write the change), then fixes and green CI again, then a PR comment saying what was reviewed and fixed. The merge comes after that comment, not in the same minute. | `gh pr view <n> --json commits,comments,mergedAt`: a review comment after the last commit and at least a few minutes before `mergedAt` |
| 6 | A review finding that would change something the architecture describes stops the work until Oz decides. | Recorded in the PR comment ("architecture changed: yes/no") |
| 7 | Merged branches are deleted. | `git ls-remote --heads origin` lists only `main` (and the branch of an open PR) |
| 8 | No secrets in the repo or its history. | From task 2 on: `python -m scout.scanners.secrets .` reports nothing |
| 9 | A prompt change and a tool change go in separate commits, each with an eval run before and after, and both summaries are committed. | Each commit touching `.claude/agents/` has a matching pair of folders in `evals/results/` |
| 10 | Tests (`tests/`, pass/fail) run in CI on every PR; evals (`evals/`, scores) never run in CI. | `.github/workflows/` runs `pytest` and contains no `evals/` command |
| 11 | Live checks only against hosts in `targets.yaml`. | A test sends a non-listed host and expects exit code 2 and zero requests |
| 12 | The agent has read-only tools only. | A test reads `.claude/agents/security-scout.md` and expects exactly `Read, Grep, Glob` |

The bootstrap commit `dff7fe7` (README and `.gitignore`) was pushed to `main` before protection was switched on; it is
the only direct push.
