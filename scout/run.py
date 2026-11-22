"""Run outside programs safely (architecture D10, D11).

A scanned project may be hostile: its git config can name a textconv driver, a pager, an fsmonitor, hooks or filter
drivers, and any of those would run the project's code on our machine. So:
- every program gets a list of arguments, never a shell string;
- every call has a timeout;
- git always runs with GIT_SAFE (no pager, no fsmonitor, an empty private hooks folder, no remote protocols);
- git is only used for commands that read objects (`log`, `ls-tree`, `cat-file`, `rev-parse`). Commands that touch a
  working tree (`checkout`, `worktree add`, `status`, `diff` against files) would run the repo's filter drivers, so
  `git()` refuses them;
- child processes get PYTHONUTF8=1 (Windows, Hebrew paths) and never prompt for input.

On Windows a `.cmd` program (npm) runs through cmd.exe, which does not escape arguments safely: never pass strings
taken from the scanned project as arguments to such a program.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

DEFAULT_TIMEOUT = 120

# git subcommands scout may run: they read objects and never apply filter drivers to a working tree.
GIT_READ_ONLY = {"log", "ls-tree", "ls-files", "cat-file", "rev-parse", "rev-list"}


class ToolMissing(Exception):
    """The program is not installed. Scanners turn this into an `info` fact, never a crash."""


@lru_cache(maxsize=1)
def empty_hooks_dir() -> Path:
    """A fresh, private, empty folder used as core.hooksPath (mkdtemp: nobody else can pre-create it)."""
    return Path(tempfile.mkdtemp(prefix="scout-hooks-"))


def git_safe_options() -> list[str]:
    return [
        "--no-pager",
        "-c", "core.fsmonitor=false",
        "-c", f"core.hooksPath={empty_hooks_dir().as_posix()}",
        "-c", "core.quotepath=off",
        "-c", "protocol.allow=never",
    ]


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
    """git with the hardened options, read-only subcommands only. `log -p` gets --no-textconv --no-ext-diff."""
    if not args or args[0] not in GIT_READ_ONLY:
        raise ValueError(f"scout only runs read-only git commands {sorted(GIT_READ_ONLY)}, not {args[:1]}")
    if args[0] == "log" and any(a in ("-p", "--patch") for a in args):
        args = [args[0], "--no-textconv", "--no-ext-diff", *args[1:]]
    return run(["git", *git_safe_options(), *args], cwd=cwd, timeout=timeout)
