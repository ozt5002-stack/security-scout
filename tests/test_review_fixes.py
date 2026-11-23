"""Regression tests for the review of PR #16: each one reproduces a bug the reviewer found."""

import shutil
import subprocess

import pytest

from scout.scanners import Context, publish, secrets
from tests.leaky_site import FAKE_KEY

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")


def g(repo, *args, **kw):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True, **kw)


def new_repo(path):
    path.mkdir(parents=True)
    g(path, "init", "-q")
    g(path, "config", "user.email", "t@t.test")
    g(path, "config", "user.name", "t")
    return path


def test_signed_commit_does_not_run_the_repos_gpg_program(tmp_path):
    """log.showSignature=true + gpg.program=<script> must not run during the history scan."""
    repo = new_repo(tmp_path / "signed")
    marker = tmp_path / "PWNED"
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    g(repo, "add", ".")
    g(repo, "commit", "-qm", "1")
    # a commit object with a (fake) signature header, written by hand
    tree = g(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    parent = g(repo, "rev-parse", "HEAD").stdout.strip()
    body = (f"tree {tree}\nparent {parent}\nauthor t <t@t.test> 1700000000 +0000\n"
            f"committer t <t@t.test> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n fake\n"
            f" -----END PGP SIGNATURE-----\n\nsigned\n")
    obj = tmp_path / "commit.txt"
    obj.write_bytes(body.encode())  # bytes: no \r\n on Windows
    sha = g(repo, "hash-object", "-t", "commit", "-w", str(obj)).stdout.strip()
    g(repo, "update-ref", "HEAD", sha)
    # git runs gpg.program as a program file (not through a shell), so plant a script
    script = tmp_path / "evil-gpg.sh"
    script.write_bytes(f"#!/bin/sh\ntouch '{marker.as_posix()}'\nexit 1\n".encode())
    script.chmod(0o755)
    g(repo, "config", "log.showSignature", "true")
    g(repo, "config", "gpg.program", script.as_posix())

    # the trap works: plain `git log` runs the planted program...
    subprocess.run(["git", "log"], cwd=repo, capture_output=True)
    assert marker.exists(), "test setup: plain git should have run the planted program"
    marker.unlink()
    # ...and the scanner's git does not
    secrets.scan(repo, Context())
    assert not marker.exists(), "the repo's gpg.program ran"


def test_history_paths_with_spaces_and_noprefix(tmp_path):
    repo = new_repo(tmp_path / "spaces")
    g(repo, "config", "diff.noprefix", "true")
    (repo / "sub dir").mkdir()
    (repo / "sub dir" / "my file.js").write_text(f'const K = "{FAKE_KEY}";\n', encoding="utf-8")
    g(repo, "add", ".")
    g(repo, "commit", "-qm", "1")
    (repo / "sub dir" / "my file.js").unlink()
    g(repo, "commit", "-qam", "2")
    facts = [f for f in secrets.scan(repo, Context()) if f.id == "secrets.in-history"]
    assert [f.file for f in facts] == ["sub dir/my file.js"]


def test_subfolder_of_a_repo_only_sees_its_own_history(tmp_path):
    repo = new_repo(tmp_path / "mono")
    (repo / "app").mkdir()
    (repo / "other").mkdir()
    (repo / "other" / "k.js").write_text(f'const K = "{FAKE_KEY}";\n', encoding="utf-8")
    (repo / "app" / "index.js").write_text("console.log(1)\n", encoding="utf-8")
    g(repo, "add", ".")
    g(repo, "commit", "-qm", "1")
    assert secrets.scan(repo / "app", Context()) == []


def test_same_key_in_two_files_gives_two_facts(tmp_path):
    repo = new_repo(tmp_path / "twice")
    for name in ("a.js", "b.js"):
        (repo / name).write_text(f'const K = "{FAKE_KEY}";\n', encoding="utf-8")
    g(repo, "add", ".")
    g(repo, "commit", "-qm", "1")
    files = sorted(f.file for f in secrets.scan(repo, Context()) if f.id == "secrets.in-file")
    assert files == ["a.js", "b.js"]


def test_failed_git_log_is_reported_as_not_checked(tmp_path, monkeypatch):
    repo = new_repo(tmp_path / "broken")
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    g(repo, "add", ".")
    g(repo, "commit", "-qm", "1")
    real_git = secrets.git

    def failing(args, cwd, timeout=120):
        if args[0] == "log":
            raise subprocess.TimeoutExpired("git log", timeout)
        return real_git(args, cwd=cwd, timeout=timeout)

    monkeypatch.setattr(secrets, "git", failing)
    facts = secrets.scan(repo, Context())
    assert [f.id for f in facts] == ["secrets.history-not-checked"]


def test_netlify_publish_outside_the_project_is_ignored(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.html").write_text("<p>x</p>", encoding="utf-8")
    (outside / "secret.sql").write_text("x", encoding="utf-8")
    project = tmp_path / "proj"
    project.mkdir()
    (project / "netlify.toml").write_text('[build]\npublish = "../outside"\n', encoding="utf-8")
    assert publish.scan(project, Context()) == []


def test_unresolved_project_path_does_not_crash(tmp_path, monkeypatch):
    site = tmp_path / "proj" / "site"
    site.mkdir(parents=True)
    (site / "index.html").write_text("<p>x</p>", encoding="utf-8")
    (tmp_path / "proj" / "netlify.toml").write_text('[build]\npublish = "site"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path / "proj")
    facts = publish.scan(publish.Path("."), Context())
    assert [f.file for f in facts] == ["site/"]
