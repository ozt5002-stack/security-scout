# Contributing

Every rule here can be checked with a command. The final audit (`docs/audit.md`) runs each one.
`gh` commands use `--repo ozt5002-stack/security-scout`.

| # | Rule | How to check |
|---|---|---|
| 1 | Nothing is pushed straight to `main`; every change arrives through a pull request, merged with a merge commit (squash and rebase merges are switched off in the repo settings). `main` is protected on GitHub: PR required, no force push, admins included. | `git fetch && git log --first-parent --no-merges dff7fe7..origin/main` prints nothing |
| 2 | Docs before code: design, architecture and plan are merged before the first code branch exists. | `gh pr list --state merged --json number,headRefName,createdAt,mergedAt`: `design/spec`, `design/architecture`, `design/plan` are merged before the first `feat/` PR was created |
| 3 | One branch per plan task, created from an up-to-date `main` only after the previous task's PR is merged. Names: `design/`, `feat/`, `fix/`, `docs/`. | The same list, sorted by `createdAt`: each task PR is created after the previous one's `mergedAt`; its first commit's parent is the previous merge commit (`git log --graph --oneline origin/main`) |
| 4 | Every PR closes an issue. | `gh pr view <n> --json closingIssuesReferences` is not empty |
| 5 | Review before merge, in this order: CI green on the last commit; an independent review (a reviewer that did not write the change); fixes and green CI again; a PR comment saying what was reviewed and fixed. **The merge comes at least 5 minutes after that comment.** The three docs PRs (#4, #5, #14) come before CI exists, so for them the CI step does not apply. | `gh pr view <n> --json commits,comments,mergedAt`: a review comment after the last commit, and `mergedAt` at least 5 minutes after it |
| 6 | A review finding that would change something the architecture describes stops the work until Oz decides. | Every review comment says "architecture changed: yes/no", and a "yes" is followed by Oz's answer |
| 7 | Merged branches are deleted. | `git ls-remote --heads origin` lists only `main` and branches of open PRs |
| 8 | No secrets in the repo or its history. Test keys are assembled at test time, never written into a file. | From task 2 on: `python -m scout.scanners.secrets .` prints nothing |
| 9 | From the eval baseline (task 6) on: a change to the agent's prompt (`.claude/agents/`) and a change to a scanner or the CLI (`scout/`) go in separate commits, each with an eval run before and after, and both summaries are committed. | For each such commit after the baseline, `evals/results/` holds a run from before it and a run from after it |
| 10 | Tests (`tests/`, pass/fail) run in CI on every PR; evals (`evals/`, scores) never run in CI. | `.github/workflows/` runs `pytest` and contains no `evals/` command |
| 11 | Live checks only against hosts in the allowlist. | A test sends a non-listed host and expects exit code 2 and zero requests |
| 12 | The agent has read-only tools only. | A test reads `.claude/agents/security-scout.md` and expects exactly `Read, Grep, Glob` |

The bootstrap commit `dff7fe7` (README and `.gitignore`) was pushed to `main` before protection was switched on; it is
the only direct push.
