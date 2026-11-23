"""The allowlist of live hosts the user owns (architecture D5, CONTRIBUTING rule 11).

The CLI calls check_url() before any scanner runs, so a refused host never receives a request (tests: test_live.py).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import yaml

from scout import ROOT

DEFAULT_TARGETS = ROOT / "targets.yaml"


class NotAllowed(Exception):
    pass


def normalize_host(host: str) -> str:
    """Lower case, no trailing dot, international names in their ASCII (punycode) form, so both sides compare alike."""
    host = host.strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def load_hosts(path: Path = DEFAULT_TARGETS) -> set[str]:
    if not path.exists():
        return set()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    hosts = data.get("hosts") or []
    return {normalize_host(str(h)) for h in hosts if str(h).strip()}


def main(argv: list[str] | None = None) -> int:
    """`python -m scout.targets <url>`: exit 0 if the host is allowed, 2 if not (used by the nikto workflow)."""
    import sys

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m scout.targets <url>", file=sys.stderr)
        return 1
    try:
        print(f"allowed: {check_url(args[0])}")
        return 0
    except NotAllowed as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2


def check_url(url: str, path: Path = DEFAULT_TARGETS) -> str:
    """Return the host of `url` if it is allowed; raise NotAllowed otherwise. No request is sent here."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise NotAllowed(f"not an http(s) URL: {url}")
    if parts.username is not None or parts.password is not None:
        raise NotAllowed("the URL must not contain a user name or password")
    host = normalize_host(parts.hostname)
    if host not in load_hosts(path):
        raise NotAllowed(
            f"{host} is not in {path.name}. Live checks run only against sites you own: add the host there first."
        )
    return host


if __name__ == "__main__":
    raise SystemExit(main())
