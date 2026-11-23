"""Files that should not be public, and missing header config, in the folders a host publishes (OWASP A02).

A publish folder = the top-most folder holding an `index.html` (nested pages belong to it), or the `publish` folder
named in `netlify.toml`. Test folders are skipped.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from scout.facts import Fact
from scout.scanners import Context
from scout.scanners.files import SKIP_DIRS, read_text, rel, walk

NAME = "publish"
SKIP = SKIP_DIRS | {"tests", "test", "__tests__", "spec", "fixtures"}

# Served as-is by any static host, but not meant for visitors.
RISKY = {
    ".env": "high", ".key": "high", ".pem": "high", ".p12": "high", ".sql": "high", ".sqlite": "high", ".db": "high",
    ".bak": "high", ".old": "medium", ".zip": "medium", ".tar": "medium", ".gz": "medium",
    ".gs": "medium", ".py": "medium", ".sh": "medium", ".ps1": "medium", ".rb": "medium",
    ".java": "medium", ".cs": "medium", ".go": "medium", ".ts": "low", ".mjs": "low", ".yml": "low", ".yaml": "low",
    ".toml": "low", ".ini": "low", ".cfg": "low", ".conf": "low", ".log": "medium", ".md": "low",
}
NOT_RISKY_NAMES = {"robots.txt", "sitemap.xml", "manifest.json", "site.webmanifest", "_headers", "_redirects",
                   "netlify.toml", "CNAME", ".nojekyll", "humans.txt", "security.txt", "ads.txt"}
CSP_META = re.compile(r"""http-equiv\s*=\s*["']?Content-Security-Policy""", re.I)


def _netlify(project: Path) -> tuple[Path | None, bool]:
    """(publish folder, has [[headers]]) from netlify.toml. A publish folder outside the project is ignored (D10)."""
    f = project / "netlify.toml"
    if not f.is_file() or f.is_symlink():
        return None, False
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return None, False
    publish = (data.get("build") or {}).get("publish")
    folder = None
    if isinstance(publish, str) and publish:
        candidate = (project / publish).resolve()
        if candidate == project or project in candidate.parents:
            folder = candidate
    return folder, bool(data.get("headers"))


def publish_folders(project: Path) -> list[Path]:
    project = project.resolve()
    found = {p.parent for p in walk(project, SKIP) if p.name.lower() == "index.html"}
    netlify_folder, _ = _netlify(project)
    if netlify_folder and netlify_folder.is_dir():
        found.add(netlify_folder)
    tops = [f for f in found if not any(o != f and o in f.parents for o in found)]
    return sorted(tops)


def _has_header_config(project: Path, folder: Path) -> bool:
    if (folder / "_headers").is_file():
        return True
    if _netlify(project)[1]:
        return True
    for p in walk(folder, SKIP):
        if p.suffix.lower() == ".html" and (t := read_text(p)) and CSP_META.search(t):
            return True
    return False


def scan(project: Path, ctx: Context) -> list[Fact]:
    project = project.resolve()  # one form of the path (Windows short names like E40C~1, or ".")
    facts: list[Fact] = []
    for folder in publish_folders(project):
        folder_rel = rel(project, folder) + "/" if folder != project else "./"
        for p in walk(folder, SKIP):
            name = p.name
            if name in NOT_RISKY_NAMES:
                continue
            suffix = ".env" if name.startswith(".env") else p.suffix.lower()
            sev = RISKY.get(suffix)
            if sev:
                facts.append(Fact(NAME, "publish.non-web-file", "A02", sev,
                                  f"{name} is inside the publish folder {folder_rel}, so anyone can download it",
                                  file=rel(project, p)))
        if not _has_header_config(project, folder):
            facts.append(Fact(NAME, "publish.no-header-config", "A02", "low",
                              f"no security-header config for the publish folder {folder_rel}: no _headers file, no "
                              f"[[headers]] in netlify.toml, no CSP meta tag. If a server sends the headers, the agent "
                              f"checks that code.",
                              file=folder_rel))
    return facts
