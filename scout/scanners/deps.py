"""Known-vulnerable packages (OWASP A03), from `npm audit` and `pip-audit`.

Both tools only read the lock/requirements file (D10): npm runs in a clean temp copy holding only package.json and
package-lock.json (no project `.npmrc`), with a fixed registry; pip-audit with `--no-deps --disable-pip`, so it never
builds or installs anything. Both need the network.
A tool that is missing, fails or times out gives an `info` "not checked" fact, never a crash.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from scout.facts import Fact
from scout.run import ToolMissing, run
from scout.scanners import Context
from scout.scanners.files import SKIP_DIRS, rel, walk

NAME = "deps"
NPM_REGISTRY = "https://registry.npmjs.org/"
NPM_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "info"}


def _not_checked(tool: str, why: str, file: str) -> Fact:
    return Fact(NAME, f"deps.{tool}-not-checked", "A03", "info", f"not checked: {tool} {why}", file=file)


def parse_npm_audit(data: dict, file: str) -> list[Fact]:
    """`npm audit --json` (report version 2) -> one fact per vulnerable package."""
    facts = []
    for name, v in sorted((data.get("vulnerabilities") or {}).items()):
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        if not advisories:
            continue  # only vulnerable through another package, which gets its own fact
        titles = "; ".join(sorted({a.get("title", "") for a in advisories if a.get("title")}))[:300]
        urls = ", ".join(sorted({a.get("url", "") for a in advisories if a.get("url")}))[:300]
        fix = v.get("fixAvailable")
        fix_text = f"fix: {fix.get('name')} {fix.get('version')}" if isinstance(fix, dict) else (
            "fix available" if fix else "no fix yet")
        facts.append(Fact(NAME, "deps.npm-advisory", "A03", NPM_SEVERITY.get(v.get("severity"), "medium"),
                          f"{name} {v.get('range', '')}: {titles} ({urls}); {fix_text}", file=file))
    return facts


def parse_pip_audit(data: dict, file: str) -> list[Fact]:
    """`pip-audit -f json` -> one fact per vulnerable package (pip-audit gives no severity: medium)."""
    facts = []
    for dep in data.get("dependencies", []):
        vulns = dep.get("vulns") or []
        if not vulns:
            continue
        ids = ", ".join(v.get("id", "") for v in vulns)[:300]
        fixes = sorted({f for v in vulns for f in v.get("fix_versions", [])})
        facts.append(Fact(NAME, "deps.pip-advisory", "A03", "medium",
                          f"{dep.get('name')} {dep.get('version')}: {len(vulns)} known advisories ({ids}); "
                          f"fixed in {', '.join(fixes) or 'no release yet'}", file=file))
    return facts


def _clean_copy(lock: Path) -> Path:
    """A fresh temp folder holding only package.json and package-lock.json (D10). npm reads `.npmrc` from the folder
    it runs in, and a project `.npmrc` can point npm at its own code (`prefix=`), a proxy, or another cache. In the
    copy there is no project `.npmrc`, so only the user's own npm settings apply."""
    clean = Path(tempfile.mkdtemp(prefix="scout-npm-"))
    for name in ("package.json", "package-lock.json"):
        src = lock.parent / name
        if src.is_file() and not src.is_symlink():
            shutil.copyfile(src, clean / name)
    return clean


def _npm(project: Path, lock: Path) -> list[Fact]:
    name = rel(project, lock)
    clean = _clean_copy(lock)
    try:
        r = run(["npm", "audit", "--json", f"--registry={NPM_REGISTRY}"], cwd=clean, timeout=180)
    except ToolMissing:
        return [_not_checked("npm", "is not installed", name)]
    except subprocess.TimeoutExpired:
        return [_not_checked("npm", "audit took too long", name)]
    finally:
        shutil.rmtree(clean, ignore_errors=True)
    try:
        data = json.loads(r.stdout)  # exit code 1 just means "vulnerabilities found"
    except json.JSONDecodeError:
        return [_not_checked("npm", f"audit failed: {r.stderr.strip()[:150]}", name)]
    if "error" in data and "vulnerabilities" not in data:
        return [_not_checked("npm", f"audit failed: {str(data['error'])[:150]}", name)]
    return parse_npm_audit(data, name)


SKIPPED_LINE = re.compile(r"^\s*(?:-e\s|--editable\s|\S+\s*@\s*\S+://|(?:git|hg|svn|bzr)\+|https?://)", re.I)


def _pip(project: Path, req: Path, out_dir: Path, n: int) -> list[Fact]:
    name = rel(project, req)
    out = out_dir / f"pip-audit-{n}-{req.stem}.json"  # one output per file, so results never mix
    out.unlink(missing_ok=True)
    skipped = [line.strip() for line in req.read_text(encoding="utf-8", errors="replace").splitlines()
               if SKIPPED_LINE.match(line)]
    extra = [_not_checked("pip-audit", f"cannot check this line (editable or URL install): {s[:80]}", name)
             for s in skipped]
    try:
        r = run(["pip-audit", "-r", str(req), "--no-deps", "--disable-pip", "-f", "json", "-o", str(out)],
                timeout=180)
    except ToolMissing:
        return [_not_checked("pip-audit", "is not installed", name)]
    except subprocess.TimeoutExpired:
        return [_not_checked("pip-audit", "took too long", name)]
    if not out.exists():
        return extra + [_not_checked("pip-audit", f"failed: {r.stderr.strip()[-150:]}", name)]
    return extra + parse_pip_audit(json.loads(out.read_text(encoding="utf-8")), name)


def scan(project: Path, ctx: Context) -> list[Fact]:
    project = project.resolve()
    facts: list[Fact] = []
    files = list(walk(project, SKIP_DIRS))
    for lock in (p for p in files if p.name == "package-lock.json"):
        facts += _npm(project, lock)
    reqs = [p for p in files if p.name.startswith("requirements") and p.suffix == ".txt"]
    if reqs:
        out_dir = ctx.run_dir or Path(tempfile.mkdtemp(prefix="scout-deps-"))  # never into the scanned project
        for n, req in enumerate(reqs):
            facts += _pip(project, req, out_dir, n)
    return facts
