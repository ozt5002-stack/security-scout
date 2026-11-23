"""Scanners. Each one is a module with NAME and `scan(project: Path, ctx: Context) -> list[Fact]`.

They arrive task by task (docs/03-plan.md). `code_scanners()` lists the ones that run on every code scan; it imports
them on demand, so `python -m scout.scanners.<name>` runs without importing itself twice.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scout.facts import Fact


@dataclass(frozen=True)
class Context:
    history: str = "all"  # "all" = every ref; "head" = only the checked-out commit and its ancestors (the eval)


Scanner = Callable[[Path, Context], list[Fact]]


def code_scanners() -> list[tuple[str, Scanner]]:
    from scout.scanners import ci, publish, secrets

    return [(m.NAME, m.scan) for m in (secrets, publish, ci)]
