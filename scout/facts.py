"""The fact shape (architecture, "Data shapes") and the run folder."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from scout import ROOT

SEVERITIES = ("critical", "high", "medium", "low", "info")
OWASP_2025 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}


@dataclass(frozen=True)
class Fact:
    scanner: str
    id: str
    owasp: str
    severity: str
    evidence: str
    file: str | None = None
    line: int | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        if self.owasp not in OWASP_2025:
            raise ValueError(f"owasp must be an OWASP 2025 id (A01-A10), got {self.owasp!r}")
        if self.file is not None and "\\" in self.file:
            raise ValueError("file must use forward slashes, relative to the project root")


def runs_root() -> Path:
    """runs/ in this repo. SCOUT_RUNS_DIR overrides it (tests use a temp folder)."""
    override = os.environ.get("SCOUT_RUNS_DIR")
    return Path(override) if override else ROOT / "runs"


def new_run_dir(project: Path, root: Path | None = None) -> Path:
    """runs/<project>-<timestamp>/, outside the scanned project. The Windows clock can return the same time twice,
    so a taken name gets a counter (-2, -3, ...) instead of failing."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    base = (root or runs_root()) / f"{project.resolve().name}-{stamp}"
    base.parent.mkdir(parents=True, exist_ok=True)
    for n in range(1, 1000):
        run_dir = base if n == 1 else base.with_name(f"{base.name}-{n}")
        try:
            run_dir.mkdir(exist_ok=False)
            return run_dir
        except FileExistsError:
            continue
    raise FileExistsError(f"could not create a run folder next to {base}")


def write_facts(run_dir: Path, facts: list[Fact]) -> Path:
    path = run_dir / "facts.json"
    path.write_text(json.dumps([asdict(f) for f in facts], indent=2, ensure_ascii=False), encoding="utf-8")
    return path
