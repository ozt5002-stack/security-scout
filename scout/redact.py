"""Key patterns (architecture D6). Used by the `secrets` scanner to find keys, and by the CLI to redact the report.

A found value is never shown in full: `mask()` keeps the first 4 characters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    owasp: str  # A04 for keys and tokens, A07 for passwords


PATTERNS = [
    Pattern("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "A04"),
    Pattern("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}"), "A04"),
    Pattern("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "A04"),
    Pattern("GitHub token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"), "A04"),
    Pattern("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "A04"),
    Pattern("Airtable token", re.compile(r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"), "A04"),
    Pattern("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), "A04"),
    Pattern("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "A04"),
    # A password or secret as a quoted literal in code: a password variable set to a quoted string
    Pattern(
        "Hard-coded password or secret",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[a-z0-9_]*"
            r"""["']?\s*[:=]\s*(["'])(?P<v>[^"'\s]{8,})\1"""
        ),
        "A07",
    ),
    # ...or as an unquoted NAME=value line in a config file (.env style). Upper-case names only, like env variables.
    Pattern(
        "Password or secret in a config line",
        re.compile(
            r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*"
            r"""[ \t]*=[ \t]*(?P<v>[^\s"'#]{8,})[ \t]*$"""
        ),
        "A07",
    ),
]

# Values that are obviously not real secrets.
PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|\.{3,}|<[^>]*>|\$\{?[A-Z_]+\}?|changeme|change[_-]?me|your[_-].*|example.*|placeholder|"
    r"redacted|dummy|test[_-]?(?:password|secret|key).*)$"
)


def mask(value: str) -> str:
    return value[:4] + "…"


def find_secrets(text: str):
    """Yield (pattern, value, line_number) for every key-like value in text."""
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            generic = "v" in pat.regex.groupindex
            value = m.group("v") if generic else m.group(0)
            if generic and PLACEHOLDER.match(value):
                continue
            yield pat, value, text.count("\n", 0, m.start()) + 1


def redact(text: str) -> str:
    """Replace every key-like value with its first 4 characters (used on the agent's report before it is saved)."""
    for _pat, value, _line in sorted(find_secrets(text), key=lambda t: -len(t[1])):
        text = text.replace(value, mask(value))
    return text
