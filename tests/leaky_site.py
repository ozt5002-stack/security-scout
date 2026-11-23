"""Builds small planted projects at test time (plan task 2), so no fake key is ever committed to this repo."""

from __future__ import annotations

import subprocess
from pathlib import Path

# Assembled from pieces: the full key never appears in this repo's files (CONTRIBUTING rule 8).
FAKE_KEY = "sk-" + "ant-" + "api03-" + "Zq7" + "Xw9Lm2Pd4Rt6Vb8Nc1Kf3Hs5"
FAKE_OLD_KEY = "AI" + "za" + "Sy" + "B" * 4 + "4kQ9mP2xL7wR3tN8vC1zH6jF5dS0aY"  # only in history
FAKE_LOCAL_KEY = "sk-" + "ant-" + "api03-" + "Lo" + "calOnly7Yt5Rw3Qe1Ui9Op"  # in an ignored .env

WORKFLOW_LEAKY = """\
name: deploy
on: push
permissions:
  contents: write
  pages: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
"""

WORKFLOW_CLEAN = """\
name: test
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _commit_all(repo: Path, msg: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", msg)


def build_leaky(root: Path) -> Path:
    """Planted problems, one fact each:
    1. a key in a file (config.js)          -> secrets.in-file
    2. a key only in the history            -> secrets.in-history
    3. a .gs file inside the publish folder -> publish.non-web-file
    4. no header config for the publish folder -> publish.no-header-config
    5. workflow write permissions at the top   -> ci.workflow-write
    6. actions pinned to tags                  -> ci.unpinned-action
    """
    repo = root / "leaky-site"
    (repo / "site" / "backend").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "t")

    (repo / "site" / "index.html").write_text("<!doctype html><title>Leaky</title><p>hi</p>\n", encoding="utf-8")
    (repo / "old-settings.js").write_text(f'const GOOGLE = "{FAKE_OLD_KEY}";\n', encoding="utf-8")
    _commit_all(repo, "first")

    (repo / "old-settings.js").unlink()
    (repo / "config.js").write_text(f'export const KEY = "{FAKE_KEY}";\n', encoding="utf-8")
    (repo / "site" / "backend" / "Code.gs").write_text("function doPost(e) { /* leads */ }\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "deploy.yml").write_text(WORKFLOW_LEAKY, encoding="utf-8")
    _commit_all(repo, "second")
    return repo


def build_clean(root: Path) -> Path:
    repo = root / "clean-site"
    (repo / "site").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "t")
    (repo / "site" / "index.html").write_text("<!doctype html><title>Clean</title>\n", encoding="utf-8")
    (repo / "site" / "_headers").write_text("/*\n  X-Frame-Options: DENY\n", encoding="utf-8")
    (repo / "site" / "robots.txt").write_text("User-agent: *\n", encoding="utf-8")
    (repo / "app.js").write_text("const key = process.env.API_KEY;\nconst password = getPassword();\n", encoding="utf-8")
    (repo / ".env.example").write_text("API_KEY=\nAPP_PASSWORD=your-password-here\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "test.yml").write_text(WORKFLOW_CLEAN, encoding="utf-8")
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    _commit_all(repo, "clean")
    # A local .env that git ignores: where keys belong. Only an `info` fact, never a problem.
    (repo / ".env").write_text(f"ANTHROPIC_API_KEY={FAKE_LOCAL_KEY}\n", encoding="utf-8")
    return repo
