"""The eval (architecture D8): run scout on the three real projects before and after their fixes, and score it.

    python -m evals.run --label baseline          7 runs (needs Claude; a few minutes each), then the score
    python -m evals.run --rescore evals/results/<folder>     score saved reports again (after a matching-rule change)

Each run writes one project at one commit into a temporary folder from git's objects (ls-tree + cat-file: no checkout,
no filters, D10), runs `python -m scout <folder> --history head --out ...`, and parses the report. Results go to
evals/results/<date>-<label>/: one report per run, results.json and summary.md. Never run in CI (CONTRIBUTING rule 10).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import yaml

from evals.match import Known, RunResult, score
from scout import ROOT
from scout.report import check, parse
from scout.run import find, git_safe_options

EVALS = ROOT / "evals"
MAX_BLOB = 2_000_000  # videos and big images are not needed to judge security


def load_knowns() -> list[Known]:
    return [Known.from_dict(d) for d in yaml.safe_load((EVALS / "known-findings.yaml").read_text(encoding="utf-8"))]


def load_projects() -> dict[str, Path]:
    data = yaml.safe_load((EVALS / "projects.yaml").read_text(encoding="utf-8"))
    return {k: Path(v) for k, v in data.items()}


def planned_runs(knowns: list[Known]) -> list[tuple[str, str, str]]:
    """(project, commit, side): every distinct before and after commit, in a stable order."""
    runs: list[tuple[str, str, str]] = []
    for k in knowns:
        for side, commit in (("before", k.before), ("after", k.after)):
            if (k.project, commit, side) not in runs:
                runs.append((k.project, commit, side))
    return runs


# Commands that only read objects, refs or the .git folder: none applies a filter to a working tree (D10). `git status`
# is not used: it reads the working tree (clean filters) and rewrites the index.
READ_ONLY = ("ls-tree", "cat-file", "rev-parse", "for-each-ref", "worktree")


def _git_bytes(repo: Path, args: list[str]) -> bytes:
    """Read-only git with the hardened options, returning raw bytes."""
    assert args[0] in READ_ONLY and (args[0] != "worktree" or args[1] == "list"), args
    r = subprocess.run([find("git"), *git_safe_options(), *args], cwd=repo, capture_output=True,
                       stdin=subprocess.DEVNULL, timeout=120, check=True)
    return r.stdout


def safe_target(dest: Path, rel: str) -> Path | None:
    """Where a tree entry may be written, or None: never outside dest, never into .git, no drive or stream names."""
    parts = rel.replace("\\", "/").split("/")
    if any(p in ("", ".", "..") or ":" in p or p.lower() in (".git", "git~1") for p in parts):
        return None
    target = (dest / Path(*parts)).resolve()
    return target if target.is_relative_to(dest.resolve()) else None


def materialize(repo: Path, commit: str, dest: Path) -> tuple[int, list[str]]:
    """Write the files of `commit` into dest from git objects. Returns (files written, skipped names)."""
    n, skipped = 0, []
    for entry in _git_bytes(repo, ["ls-tree", "-r", "-z", "-l", commit]).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, sha, size = meta.split()
        if kind != b"blob" or mode not in (b"100644", b"100755") or int(size) > MAX_BLOB:
            continue  # symlinks, submodules and big media files are skipped
        rel = path.decode("utf-8", errors="replace")
        target = safe_target(dest, rel)
        if target is None or "�" in rel:
            skipped.append(rel)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_git_bytes(repo, ["cat-file", "blob", sha.decode()]))
        n += 1
    return n, skipped


def repo_state(repo: Path) -> str:
    """What must not change in a real project: HEAD, every ref (branches, tags) and the worktree list."""
    return b"\n".join(_git_bytes(repo, a) for a in (["rev-parse", "HEAD"],
                                                    ["for-each-ref", "--format=%(refname) %(objectname)"],
                                                    ["worktree", "list", "--porcelain"])).decode("utf-8", "replace")


def run_scout(folder: Path, out: Path, runs_dir: Path) -> tuple[int, str]:
    env = dict(os.environ, SCOUT_RUNS_DIR=str(runs_dir), PYTHONUTF8="1")
    r = subprocess.run([sys.executable, "-m", "scout", str(folder), "--history", "head", "--out", str(out)],
                       cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=40 * 60)
    return r.returncode, (r.stdout + r.stderr)[-500:]


def read_result(project: str, commit: str, side: str, report: Path, error: str = "") -> RunResult:
    """A run's findings. A missing report or a report that fails the format check is an error, never a quiet zero."""
    if not report.exists():
        return RunResult(project, commit, side, [], error or "no report")
    text = report.read_text(encoding="utf-8")
    problems = check(text)
    if problems and not error:
        error = "report format: " + "; ".join(problems)[:200]
    findings = [(f.wheres, f.text) for f in parse(text).findings]
    return RunResult(project, commit, side, findings, error)


def metric_met(s: dict, results: list[RunResult]) -> bool:
    """The design's success metric, and every run must have produced a valid report."""
    return (s["recall"] >= 13 and not s["must_pass_missed"] and len(s["false_alarms"]) <= 2
            and not any(r.error for r in results) and len(results) == 7)


def write_summary(out_dir: Path, knowns: list[Known], results: list[RunResult], s: dict, notes: list[str]) -> None:
    by_id = {k.id: k for k in knowns}
    ok = metric_met(s, results)
    errors = [r for r in results if r.error]
    lines = [
        f"# Eval: {out_dir.name}",
        "",
        f"**Recall: {s['recall']}/{s['total']}** (target ≥ 13) · **must_pass missed: "
        f"{', '.join(s['must_pass_missed']) or 'none'}** · **false alarms: {len(s['false_alarms'])}** (target ≤ 2) · "
        f"**runs with errors: {len(errors)} of {len(results)}** · **design metric {'met' if ok else 'NOT met'}**",
        "",
        "| Known finding | Must | Found |",
        "|---|---|---|",
    ]
    for k in knowns:
        lines.append(f"| {k.id} {k.title} ({k.project}) | {'yes' if k.must_pass else ''} | "
                     f"{'yes' if k.id in s['found'] else '**no**'} |")
    lines += ["", "| Run | Findings in report | Note |", "|---|---|---|"]
    for r in results:
        lines.append(f"| {r.project} @ {r.commit} ({r.side}) | {len(r.findings)} | {r.error or ''} |")
    if s["false_alarms"]:
        lines += ["", "False alarms (still reported after the fix): " +
                  ", ".join(f"{i} {by_id[i].title}" for i in s["false_alarms"])]
    lines += ["", *notes]
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "results.json").write_text(json.dumps({"score": s, "runs": [r.__dict__ for r in results]},
                                                     indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals.run")
    p.add_argument("--label", default="run")
    p.add_argument("--only", help="run only this project")
    p.add_argument("--rescore", type=Path, metavar="FOLDER", help="score the reports in an earlier results folder")
    args = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    knowns = load_knowns()
    plan = planned_runs(knowns)

    if args.rescore:
        out_dir = args.rescore
        results = [read_result(pr, c, sd, out_dir / f"{pr}-{c}.md") for pr, c, sd in plan]
        s = score(knowns, results)
        old = out_dir / "summary.md"
        kept = [ln for ln in old.read_text(encoding="utf-8").splitlines() if ln.startswith("Real project")] \
            if old.exists() else []
        write_summary(out_dir, knowns, results, s,
                      kept + [f"Rescored on {date.today().isoformat()} from the saved reports with the current "
                              f"known-findings.yaml and matching rule."])
        print(old.read_text(encoding="utf-8"))
        return 0 if metric_met(s, results) else 1

    projects = load_projects()
    out_dir = EVALS / "results" / f"{date.today().isoformat()}-{args.label}"
    out_dir.mkdir(parents=True, exist_ok=False)
    states_before = {name: repo_state(path) for name, path in projects.items()}
    results: list[RunResult] = []
    notes: list[str] = []
    for project, commit, side in plan:
        if args.only and project != args.only:
            continue
        print(f"eval: {project} @ {commit} ({side}) ...", flush=True)
        tmp = Path(tempfile.mkdtemp(prefix="scout-eval-"))
        try:
            folder = tmp / project
            folder.mkdir()
            n, skipped = materialize(projects[project], commit, folder)
            if skipped:
                notes.append(f"{project}@{commit}: skipped unsafe or undecodable tree names: {skipped[:5]}")
            report = out_dir / f"{project}-{commit}.md"
            code, log = run_scout(folder, report, tmp / "runs")
            results.append(read_result(project, commit, side, report, "" if code == 0 else f"exit {code}: {log[-200:]}"))
            print(f"eval:   {n} files, {len(results[-1].findings)} findings {results[-1].error}", flush=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    states_after = {name: repo_state(path) for name, path in projects.items()}
    changed = [n for n in projects if states_before[n] != states_after[n]]
    notes.append("Real project folders unchanged (HEAD, refs, worktrees): "
                 + ("yes" if not changed else f"**NO: {', '.join(changed)}**"))
    s = score(knowns, results)
    write_summary(out_dir, knowns, results, s, notes)
    print((out_dir / "summary.md").read_text(encoding="utf-8"))
    return 0 if not changed and metric_met(s, results) else 1


if __name__ == "__main__":
    sys.exit(main())
