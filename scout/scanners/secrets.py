"""Keys and passwords in the files and in the git history (OWASP A04/A07). Values are masked before they are stored.

    python -m scout.scanners.secrets <path> [--history all|head]     prints one line per finding, nothing if clean
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from scout.facts import Fact
from scout.redact import find_secrets, mask
from scout.run import ToolMissing, git
from scout.scanners import Context
from scout.scanners.files import read_text, rel, walk

NAME = "secrets"


def _tracked(project: Path) -> set[str] | None:
    """Files git tracks (`ls-files` reads the index only). None when the folder is not a git repo."""
    try:
        r = git(["ls-files", "-z"], cwd=project)
    except ToolMissing:
        return None
    if r.returncode != 0:
        return None
    return {p for p in r.stdout.split("\0") if p}


def _tree_facts(project: Path) -> tuple[list[Fact], set[tuple[str, str]]]:
    """One fact per (key, file): the same key in two files is two places to clean up."""
    facts, seen = [], set()
    tracked = _tracked(project)
    for path in walk(project):
        text = read_text(path)
        if text is None:
            continue
        name = rel(project, path)
        local = tracked is not None and name not in tracked
        for pat, value, line in find_secrets(text):
            if (value, name) in seen:
                continue
            seen.add((value, name))
            if local:
                # A .env that git does not track is where keys belong: report it for the inventory, not as a problem.
                facts.append(Fact(NAME, "secrets.local-file", pat.owasp, "info",
                                  f"{pat.name} in a file git does not track: {mask(value)}. Fine on this computer; "
                                  f"keep it out of git and out of anything that is deployed",
                                  file=name, line=line))
            else:
                facts.append(Fact(NAME, "secrets.in-file", pat.owasp, "high",
                                  f"{pat.name} in the file: {mask(value)}", file=name, line=line))
    return facts, seen


DIFF_FILE = re.compile(r"^\+\+\+ (?:b/(.+?)|/dev/null)\t?$")
COMMIT = re.compile(r"^commit ([0-9a-f]{40})")


def _not_checked(why: str) -> list[Fact]:
    return [Fact(NAME, "secrets.history-not-checked", "A04", "info", f"git history not checked: {why}")]


def _history_facts(project: Path, history: str, already: set[tuple[str, str]]) -> list[Fact]:
    """Keys that were committed at some point, even if the current files no longer have them."""
    try:
        if git(["rev-parse", "--git-dir"], cwd=project).returncode != 0:
            return []  # not a git repo: there is no history to check
        refs = ["--all"] if history == "all" else ["HEAD"]
        # Fixed prefixes (a repo's diff.noprefix must not change the parsing); --relative + "." keep the scan, and
        # the paths, inside the project when it is a subfolder of a bigger repo.
        out = git(["log", "-p", "--no-color", "--format=commit %H", "--src-prefix=a/", "--dst-prefix=b/",
                   "--relative", *refs, "--", "."], cwd=project, timeout=300)
    except ToolMissing:
        return _not_checked("git is not installed")
    except subprocess.TimeoutExpired:
        return _not_checked("git log took too long")
    if out.returncode != 0:
        return _not_checked(out.stderr.strip()[:200] or f"git log exited with {out.returncode}")
    facts, seen = [], set(already)
    commit, file = "", None
    for line in out.stdout.splitlines():
        if m := COMMIT.match(line):
            commit = m.group(1)[:7]
        elif m := DIFF_FILE.match(line):
            file = m.group(1)  # None for a deleted file
        elif line.startswith("+") and not line.startswith("+++"):
            for pat, value, _ in find_secrets(line[1:]):
                if any(v == value for v, _f in seen):
                    continue  # already reported (in the files, or an earlier commit)
                seen.add((value, file or ""))
                facts.append(Fact(NAME, "secrets.in-history", pat.owasp, "high",
                                  f"{pat.name} in git history (commit {commit}): {mask(value)}. "
                                  f"Removing it from the files is not enough: revoke the key.", file=file))
    return facts


def scan(project: Path, ctx: Context) -> list[Fact]:
    project = project.resolve()
    facts, seen = _tree_facts(project)
    return facts + _history_facts(project, ctx.history, seen)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m scout.scanners.secrets")
    p.add_argument("path", type=Path)
    p.add_argument("--history", choices=("all", "head"), default="all")
    args = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    for f in scan(args.path, Context(history=args.history)):
        where = f"{f.file}:{f.line}" if f.line else (f.file or "")
        print(f"{f.severity.upper()} {f.owasp} {where} {f.evidence}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
