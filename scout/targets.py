"""The allowlist of live hosts the user owns (architecture D5, CONTRIBUTING rule 11).

Task 1 version: reads the host list. Task 4 adds the live scanner that depends on it.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import yaml

from scout import ROOT

DEFAULT_TARGETS = ROOT / "targets.yaml"


class NotAllowed(Exception):
    pass


def load_hosts(path: Path = DEFAULT_TARGETS) -> set[str]:
    if not path.exists():
        return set()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    hosts = data.get("hosts") or []
    return {str(h).strip().lower() for h in hosts if str(h).strip()}


def check_url(url: str, path: Path = DEFAULT_TARGETS) -> str:
    """Return the host of `url` if it is allowed; raise NotAllowed otherwise. No request is sent here."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise NotAllowed(f"not an http(s) URL: {url}")
    host = parts.hostname.lower()
    if host not in load_hosts(path):
        raise NotAllowed(
            f"{host} is not in {path.name}. Live checks run only against sites you own: add the host there first."
        )
    return host
