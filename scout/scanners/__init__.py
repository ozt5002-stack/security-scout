"""Scanners. Each one is a function `scan(project: Path, ctx: Context) -> list[Fact]`.

They arrive task by task (docs/03-plan.md). SCANNERS lists the ones that run on every code scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scout.facts import Fact


@dataclass(frozen=True)
class Context:
    history: str = "all"  # "all" = every ref; "head" = only the checked-out commit (the eval)


Scanner = Callable[[Path, Context], list[Fact]]

SCANNERS: list[tuple[str, Scanner]] = []
