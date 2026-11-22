"""GitHub Actions workflows: write permissions for every job, and actions pinned to a tag (OWASP A01/A08)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from scout.facts import Fact
from scout.scanners import Context
from scout.scanners.files import rel

NAME = "ci"
SHA = re.compile(r"^[0-9a-f]{40}$")


def _writes(perms) -> list[str]:
    if perms == "write-all":
        return ["write-all"]
    if isinstance(perms, dict):
        return [f"{k}: {v}" for k, v in perms.items() if str(v) == "write"]
    return []


def _uses(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from _uses(v)
    elif isinstance(node, list):
        for v in node:
            yield from _uses(v)


def scan(project: Path, ctx: Context) -> list[Fact]:
    facts: list[Fact] = []
    wf_dir = project / ".github" / "workflows"
    if not wf_dir.is_dir():
        return facts
    for f in sorted([*wf_dir.glob("*.yml"), *wf_dir.glob("*.yaml")]):
        if f.is_symlink():
            continue
        try:
            wf = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        name = rel(project, f)
        if not isinstance(wf, dict):
            continue
        if "permissions" not in wf:
            facts.append(Fact(NAME, "ci.no-top-level-permissions", "A01", "low",
                              "no top-level `permissions:`, so every job gets the repo's default token rights",
                              file=name))
        elif w := _writes(wf["permissions"]):
            facts.append(Fact(NAME, "ci.workflow-write", "A01", "medium",
                              f"write permissions for every job in the workflow ({', '.join(w)}); give them only to "
                              f"the job that needs them",
                              file=name))
        unpinned = sorted({u for u in _uses(wf.get("jobs") or {})
                           if "@" in u and not u.startswith(("./", "docker://")) and not SHA.match(u.split("@", 1)[1])})
        if unpinned:
            facts.append(Fact(NAME, "ci.unpinned-action", "A08", "low",
                              f"actions pinned to a tag, not a commit (a tag can be moved): {', '.join(unpinned)}",
                              file=name))
    return facts
