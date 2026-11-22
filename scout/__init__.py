"""security-scout: scanners + a read-only agent that review a project for OWASP Top 10 2025 issues."""

from pathlib import Path

__version__ = "0.1.0"

# The repo folder: targets.yaml, runs/, reports/ and .claude/agents/ live here, never in the scanned project.
ROOT = Path(__file__).resolve().parent.parent
