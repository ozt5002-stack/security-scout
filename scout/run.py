"""Run outside programs safely (architecture D10, D11).

A scanned project may be hostile: its git config can name a textconv driver, a pager, an fsmonitor or hooks, and any
of those would run the project's code on our machine. So:
- every program gets a list of arguments, never a shell string;
- every call has a timeout;
- git always runs with the options in GIT_SAFE, which switch those features off;
- child processes get PYTHONUTF8=1 (Windows, Hebrew paths) and never prompt for input.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

DEFAULT_TIMEOUT = 120

# An empty folder used as core.hooksPath, so no hook from the scanned repo can run (also on `git worktree add`).
EMPTY_HOOKS = Path(tempfile.gettempdir()) / "security-scout-empty-hooks"

GIT_SAFE = [
    "--no-pager",
    "-c", "core.fsmonitor=false",
    "-c", f"core.hooksPath={EMPTY_HOOKS.as_posix()}",
    "-c", "core.quotepath=off",
    "-c", "protocol.file.allow=never",
]


class ToolMissing(Exception):
    """The program is not installed. Scanners turn this into an `info` fact, never a crash."""


def find(name: str) -> str:
    """Full path of a program. On Windows this also finds `npm.cmd` for `npm` (PATHEXT)."""
    path = shutil.which(name)
    if not path:
        raise ToolMissing(name)
    return path


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "PYTHONUTF8": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "NO_COLOR": "1",
    })
    return env


def run(args: list[str], cwd: Path | None = None, timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a program with a list of arguments. Never raises on a non-zero exit: scanners read returncode."""
    if not isinstance(args, list) or not args:
        raise TypeError("args must be a non-empty list (never a shell string)")
    program = find(args[0])
    return subprocess.run(
        [program, *args[1:]],
        cwd=str(cwd) if cwd else None,
        env=child_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
        check=False,
    )


def git(args: list[str], cwd: Path, timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """git with the hardened options. `log -p` callers must also pass --no-textconv --no-ext-diff."""
    EMPTY_HOOKS.mkdir(parents=True, exist_ok=True)
    return run(["git", *GIT_SAFE, *args], cwd=cwd, timeout=timeout)
