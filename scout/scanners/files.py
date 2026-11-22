"""Walk a project's files safely: no symlinks (D10), no vendored or generated folders, text files only."""

from __future__ import annotations

import os
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
             ".next", ".cache", "vendor", "site-packages"}
MAX_BYTES = 1_000_000


def rel(project: Path, path: Path) -> str:
    return path.relative_to(project).as_posix()


def walk(project: Path, skip: set[str] = SKIP_DIRS):
    """Yield every regular file under project, without following symlinks."""
    for root, dirs, files in os.walk(project, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in skip and not Path(root, d).is_symlink())
        for name in sorted(files):
            p = Path(root, name)
            if not p.is_symlink() and p.is_file():
                yield p


def read_text(path: Path) -> str | None:
    """The file as text, or None for big or binary files."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")
