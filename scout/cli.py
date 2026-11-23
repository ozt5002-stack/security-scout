"""The `scout` command (architecture: the CLI component).

    python -m scout <path> [--live URL] [--nikto] [--out FILE] [--history all|head] [--targets FILE] [--no-agent]

Exit codes: 0 done; 1 bad input; 2 live target not in the allowlist; 3 feature not available.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scout import targets
from scout.facts import new_run_dir, write_facts
from scout.scanners import Context, code_scanners


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scout",
        description="Review a project (and optionally its live site) for OWASP Top 10 2025 issues.",
    )
    p.add_argument("path", type=Path, help="the project folder to review")
    p.add_argument("--live", metavar="URL", help="also run safe checks on this live site (must be in the allowlist)")
    p.add_argument("--nikto", action="store_true", help="also run Nikto against the --live site (slow, opt-in)")
    p.add_argument("--out", type=Path, metavar="FILE", help="where to save the report (default: reports/<project>-<date>.md)")
    p.add_argument("--history", choices=("all", "head"), default="all",
                   help="git history to scan for keys: every ref (default) or only the checked-out commit")
    p.add_argument("--targets", type=Path, default=targets.DEFAULT_TARGETS, metavar="FILE",
                   help="the allowlist of live hosts (default: targets.yaml)")
    p.add_argument("--no-agent", action="store_true", help="stop after the scanners: write facts.json, no report")
    return p


def main(argv: list[str] | None = None) -> int:
    # A Windows console in a Hebrew code page cannot print every character; never crash on a message.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)

    project: Path = args.path.resolve()
    if not project.is_dir():
        print(f"scout: not a folder: {project}", file=sys.stderr)
        return 1

    # The allowlist is checked before anything else, so a refused host never receives a request.
    if args.live:
        try:
            targets.check_url(args.live, args.targets)
        except targets.NotAllowed as e:
            print(f"scout: refused: {e}", file=sys.stderr)
            return 2
    if args.nikto:
        if not args.live:
            print("scout: --nikto needs --live URL", file=sys.stderr)
            return 1
        print("scout: --nikto is not available yet (plan task 7)", file=sys.stderr)
        return 3

    run_dir = new_run_dir(project)
    ctx = Context(history=args.history, run_dir=run_dir)
    facts = []
    for _name, scan in code_scanners():
        facts.extend(scan(project, ctx))

    facts_path = write_facts(run_dir, facts)
    print(f"scout: {len(facts)} facts -> {facts_path}")

    if args.no_agent:
        return 0
    print("scout: the agent arrives in plan task 5; use --no-agent until then", file=sys.stderr)
    return 0
