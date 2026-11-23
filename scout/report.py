"""Parse and check a report written by the agent (architecture: "A finding" data shape).

    python -m scout.report check <report.md>    exit 0 if the report has every part in the right format

The eval (task 6) uses `parse()` to read findings.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from scout.facts import OWASP_2025

SECTIONS = ["Summary", "Findings", "Data inventory", "Accepted risks", "Not checked"]
FINDING_HEAD = re.compile(r"^### (F-\d{2,})\s*·\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*·\s*(A\d\d)\b\s*(.*)$")
FIELDS = ["What can happen", "Where", "Evidence", "Fix", "Verify"]
FIELD_LINE = re.compile(r"^\*\*(What can happen|Where|Evidence|Fix|Verify):\*\*\s*(.*)$")
WHERE = re.compile(r"`([^`]+)`")


@dataclass
class Finding:
    id: str
    severity: str
    owasp: str
    title: str
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def where(self) -> str:
        """The path in `Where:`, without the line number."""
        m = WHERE.search(self.fields.get("Where", ""))
        raw = m.group(1) if m else self.fields.get("Where", "")
        return re.sub(r":\d+(?:-\d+)?$", "", raw.strip())

    @property
    def text(self) -> str:
        return " ".join([self.title, *self.fields.values()])


@dataclass
class Report:
    sections: dict[str, str]
    findings: list[Finding]


def parse(text: str) -> Report:
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    findings: list[Finding] = []
    f = None
    last_field = None
    for line in "\n".join(sections.get("Findings", [])).splitlines():
        if m := FINDING_HEAD.match(line):
            f = Finding(m.group(1), m.group(2), m.group(3), m.group(4).strip())
            findings.append(f)
            last_field = None
        elif f and (m := FIELD_LINE.match(line)):
            last_field = m.group(1)
            f.fields[last_field] = m.group(2).strip()
        elif f and last_field and line.strip() and not line.startswith("#"):
            f.fields[last_field] += " " + line.strip()  # a field that continues on the next line
    return Report({k: "\n".join(v).strip() for k, v in sections.items()}, findings)


def check(text: str) -> list[str]:
    """Problems with the report's format; an empty list means it is fine."""
    problems = []
    if not re.search(r"^# Security report: .+", text, re.M):
        problems.append("missing the '# Security report: <project>' title")
    report = parse(text)
    for s in SECTIONS:
        if s not in report.sections:
            problems.append(f"missing section '## {s}'")
        elif not report.sections[s]:
            problems.append(f"section '## {s}' is empty (write 'None.' if there is nothing)")
    findings_text = report.sections.get("Findings", "")
    if findings_text and not report.findings and "No findings." not in findings_text:
        problems.append("'## Findings' has neither findings in the required format nor 'No findings.'")
    for f in report.findings:
        missing = [x for x in FIELDS if not f.fields.get(x)]
        if missing:
            problems.append(f"{f.id}: missing {', '.join(missing)}")
        if f.owasp not in OWASP_2025:
            problems.append(f"{f.id}: {f.owasp} is not an OWASP 2025 id")
        if f.fields.get("Where") and not WHERE.search(f.fields["Where"]):
            problems.append(f"{f.id}: 'Where' must be a path in backticks")
    return problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m scout.report")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check a report's format")
    c.add_argument("report", type=Path)
    args = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    problems = check(args.report.read_text(encoding="utf-8"))
    for problem in problems:
        print(problem)
    if not problems:
        print(f"ok: {len(parse(args.report.read_text(encoding='utf-8')).findings)} findings")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
