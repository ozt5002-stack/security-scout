"""Nikto, through GitHub Actions (architecture D7, Oz's decision in PR #21).

On Oz's computer Windows Defender deletes Nikto as a "hacking tool", so it does not run there. It runs in the
`nikto` workflow on a GitHub (Linux) runner instead: started by hand, only against a host in targets.yaml, with a
pause between requests and a time limit. This module:
- builds Nikto's command line (used by the workflow),
- turns Nikto's JSON output into facts (`python -m scout.scanners.nikto parse <nikto.json>`).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from scout import __version__
from scout.facts import Fact

NAME = "nikto"
PAUSE_SECONDS = 1
MAX_TIME = "30m"
USER_AGENT = f"security-scout/{__version__} nikto (owner-authorized scan)"


def command(nikto_pl: str, url: str, out: str) -> list[str]:
    """Nikto with a pause between requests, a time limit, no prompts and JSON output."""
    return ["perl", nikto_pl, "-h", url, "-Pause", str(PAUSE_SECONDS), "-maxtime", MAX_TIME,
            "-Format", "json", "-output", out, "-ask", "no", "-nointeractive", "-useragent", USER_AGENT]


def _severity(msg: str) -> str:
    m = msg.lower()
    if any(w in m for w in ("backup", "password", "database", ".git", ".env", "config file", "phpinfo", "directory indexing")):
        return "medium"
    return "low"


def parse(data) -> list[Fact]:
    """Nikto's JSON (a host object, or a list of them) -> one fact per item it reported."""
    hosts = data if isinstance(data, list) else [data]
    facts: list[Fact] = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        base = f"http{'s' if str(h.get('port')) == '443' else ''}://{h.get('host', '')}"
        for v in h.get("vulnerabilities", []) or []:
            msg = str(v.get("msg", "")).strip()
            if not msg:
                continue
            url = v.get("url") or "/"
            facts.append(Fact(NAME, f"nikto.{v.get('id', 'item')}", "A02", _severity(msg),
                              f"Nikto: {msg[:300]}", url=base + url if url.startswith("/") else url))
    return facts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m scout.scanners.nikto")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("parse", help="turn Nikto's JSON into facts (printed as JSON)")
    c.add_argument("file", type=Path)
    args = p.parse_args(argv)
    text = args.file.read_text(encoding="utf-8", errors="replace").strip()
    facts = parse(json.loads(text)) if text else []
    print(json.dumps([asdict(f) for f in facts], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
