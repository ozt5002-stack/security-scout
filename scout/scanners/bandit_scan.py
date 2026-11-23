"""Risky Python patterns via Bandit (OWASP A05 and others). `--ignore-nosec`: a `# nosec` comment in the project is
data, not an instruction (D4), so it cannot hide a problem."""

from __future__ import annotations

import json
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

from scout.facts import Fact
from scout.run import ToolMissing, run
from scout.scanners import Context
from scout.scanners.files import SKIP_DIRS, walk

NAME = "bandit"
SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
# Vendored and generated folders only. Tests are scanned too: a project could otherwise hide code under tests/.
EXCLUDE = ",".join(f"*/{d}/*" for d in sorted(SKIP_DIRS))


# Bandit test id -> OWASP 2025 category. Anything not listed is treated as injection (A05).
OWASP_BY_TEST = {
    **dict.fromkeys(("B105", "B106", "B107"), "A07"),                          # hard-coded passwords
    **dict.fromkeys(("B301", "B302", "B403", "B506"), "A08"),                  # unsafe deserialization
    **dict.fromkeys(("B303", "B304", "B305", "B311", "B312", "B321", "B323", "B324", "B413",
                     "B501", "B502", "B503", "B504", "B505"), "A04"),           # weak crypto, cleartext, no TLS check
    **dict.fromkeys(("B104", "B108", "B201", "B306"), "A02"),                   # bind all, temp files, debug mode
    "B110": "A10",                                                               # try/except/pass
}


def owasp_for(test_id: str) -> str:
    return OWASP_BY_TEST.get(test_id, "A05")  # eval, subprocess, SQL strings, XML parsing, templates, ...


@lru_cache(maxsize=1)
def _empty_ini() -> Path:
    ini = Path(tempfile.mkdtemp(prefix="scout-bandit-")) / "bandit.ini"
    ini.write_text("[bandit]\n", encoding="utf-8")
    return ini


def parse_bandit(data: dict, project: Path) -> list[Fact]:
    facts = []
    for e in data.get("errors", []):
        facts.append(Fact(NAME, "bandit.file-not-checked", "A05", "info",
                          f"not checked: Bandit could not read this file ({str(e.get('reason', ''))[:100]})",
                          file=_rel(Path(e.get("filename", "")), project)))
    for r in data.get("results", []):
        file = _rel(Path(r["filename"]), project)
        facts.append(Fact(NAME, f"bandit.{r['test_id']}", owasp_for(r["test_id"]),
                          SEVERITY.get(r.get("issue_severity", ""), "low"),
                          f"{r['test_id']} {r.get('test_name', '')}: {r.get('issue_text', '')} "
                          f"(confidence {r.get('issue_confidence', '?').lower()})",
                          file=file, line=r.get("line_number")))
    return facts


def _rel(path: Path, project: Path) -> str:
    try:
        return path.resolve().relative_to(project).as_posix()
    except ValueError:
        return path.as_posix()


def scan(project: Path, ctx: Context) -> list[Fact]:
    project = project.resolve()
    if not any(p.suffix == ".py" for p in walk(project, SKIP_DIRS)):
        return []
    try:
        # --ini <our empty file>: Bandit would otherwise read the project's own `.bandit`, which can skip tests (D4).
        r = run(["bandit", "-r", str(project), "-f", "json", "-q", "--ignore-nosec", "--ini", str(_empty_ini()),
                 "-x", EXCLUDE], timeout=300)
    except ToolMissing:
        return [Fact(NAME, "bandit.not-checked", "A05", "info", "not checked: bandit is not installed")]
    except subprocess.TimeoutExpired:
        return [Fact(NAME, "bandit.not-checked", "A05", "info", "not checked: bandit took too long")]
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return [Fact(NAME, "bandit.not-checked", "A05", "info", f"not checked: bandit failed: {r.stderr.strip()[:150]}")]
    return parse_bandit(data, project)
