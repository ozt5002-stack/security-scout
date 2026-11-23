"""The eval's matching rule (architecture, "Matching rule"). Ordinary code, so it has pass/fail tests in CI.

1. Paths are normalised: forward slashes, lower case, no leading ./ or /, the run folder's prefix removed.
2. A known finding is found when any path in a reported finding's Where matches one of its files (or is inside a
   listed folder) and the finding's text contains one of its keywords (case-insensitive).
3. One reported finding matches at most one known finding (a maximum one-to-one matching, so an order of findings
   can never cost a match).
4. On an after-run, a known finding whose `after` is that commit and that still matches is a false alarm.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scout.report import LINE_SUFFIX


@dataclass(frozen=True)
class Known:
    id: str
    project: str
    title: str
    before: str
    after: str
    files: tuple[str, ...]
    owasp: str
    keywords: tuple[str, ...]
    must_pass: bool

    @staticmethod
    def from_dict(d: dict) -> "Known":
        return Known(d["id"], d["project"], d["title"], str(d["before"]), str(d["after"]),
                     tuple(d["files"]), d["owasp"], tuple(str(k) for k in d["keywords"]), bool(d["must_pass"]))


def norm(path: str, root: str = "") -> str:
    p = path.replace("\\", "/").strip().strip("`").lower()
    r = root.replace("\\", "/").lower().rstrip("/")
    if r and p.startswith(r + "/"):
        p = p[len(r) + 1:]
    p = re.sub(r"^(?:\./|/)+", "", p)
    return LINE_SUFFIX.sub("", p)


def path_matches(reported: str, known_file: str) -> bool:
    k = norm(known_file)
    if k.endswith("/"):
        return reported.startswith(k) or reported + "/" == k
    return reported == k


def candidates(known: Known, finding_wheres: list[str], finding_text: str, root: str = "") -> bool:
    wheres = [norm(w, root) for w in finding_wheres]
    if not any(path_matches(w, f) for w in wheres for f in known.files):
        return False
    text = finding_text.lower()
    return any(k.lower() in text for k in known.keywords)


def match(knowns: list[Known], findings: list[tuple[list[str], str]], root: str = "") -> dict[str, int]:
    """{known id: index of the reported finding it matched}, a maximum one-to-one matching (augmenting paths)."""
    edges = {k.id: [i for i, (wheres, text) in enumerate(findings) if candidates(k, wheres, text, root)]
             for k in knowns}
    owner: dict[int, str] = {}

    def assign(kid: str, seen: set[int]) -> bool:
        for i in edges[kid]:
            if i in seen:
                continue
            seen.add(i)
            if i not in owner or assign(owner[i], seen):
                owner[i] = kid
                return True
        return False

    for k in knowns:
        assign(k.id, set())
    return {kid: i for i, kid in owner.items()}


@dataclass
class RunResult:
    project: str
    commit: str
    side: str  # "before" | "after"
    findings: list[tuple[list[str], str]]
    error: str = ""


def score(knowns: list[Known], runs: list[RunResult]) -> dict:
    """Recall over the before-runs, must_pass misses, and false alarms on each finding's own after-run."""
    found: dict[str, bool] = {}
    false_alarms: list[str] = []
    for run in runs:
        if run.side == "before":
            todo = [k for k in knowns if k.project == run.project and k.before == run.commit]
            hits = match(todo, run.findings)
            for k in todo:
                found[k.id] = found.get(k.id, False) or k.id in hits
        else:
            todo = [k for k in knowns if k.project == run.project and k.after == run.commit]
            false_alarms += sorted(match(todo, run.findings))
    missed_must = sorted(k.id for k in knowns if k.must_pass and not found.get(k.id, False))
    return {
        "recall": sum(found.values()),
        "total": len(knowns),
        "found": sorted(k for k, v in found.items() if v),
        "missed": sorted(k.id for k in knowns if not found.get(k.id, False)),
        "must_pass_missed": missed_must,
        "false_alarms": false_alarms,
    }
