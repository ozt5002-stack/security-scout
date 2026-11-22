"""Architecture D5 and D10: the allowlist edge cases, and a hostile repo cannot run code through git."""

import shutil
import subprocess

import pytest

from scout.run import git
from scout.targets import NotAllowed, check_url


@pytest.fixture
def allow(tmp_path):
    f = tmp_path / "targets.yaml"
    f.write_text("hosts: [mysite.test, bücher.test]\n", encoding="utf-8")
    return f


@pytest.mark.parametrize("url", [
    "https://MySite.test/",
    "https://mysite.test:8443/x",
    "https://mysite.test./",
    "https://bücher.test/",
    "https://xn--bcher-kva.test/",
])
def test_allowed_forms_of_a_listed_host(url, allow):
    check_url(url, allow)


@pytest.mark.parametrize("url", [
    "https://mysite.test@evil.test/",   # the real host is evil.test
    "https://evil@mysite.test/",        # credentials never pass
    "https://evil.test/",
    "ftp://mysite.test/",
    "not a url",
])
def test_refused(url, allow):
    with pytest.raises(NotAllowed):
        check_url(url, allow)


def test_git_refuses_commands_that_touch_a_working_tree(tmp_path):
    for cmd in (["checkout", "HEAD"], ["worktree", "add", "x"], ["status"], ["diff"], ["stash"]):
        with pytest.raises(ValueError):
            git(cmd, cwd=tmp_path)


@pytest.mark.skipif(not shutil.which("git"), reason="git not installed")
def test_hostile_textconv_driver_does_not_run(tmp_path):
    """A repo that sets a textconv driver for *.txt: our `log -p` must not run it."""
    repo = tmp_path / "hostile"
    repo.mkdir()
    marker = tmp_path / "PWNED"

    def g(*a):
        subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "t@t.test")
    g("config", "user.name", "t")
    g("config", "diff.evil.textconv", f"touch '{marker.as_posix()}'; cat")
    (repo / ".gitattributes").write_text("*.txt diff=evil\n", encoding="utf-8")
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    g("add", ".")
    g("commit", "-qm", "1")
    (repo / "a.txt").write_text("two\n", encoding="utf-8")
    g("commit", "-qam", "2")

    r = git(["log", "-p"], cwd=repo)
    assert r.returncode == 0, r.stderr
    assert "+two" in r.stdout
    assert not marker.exists(), "the repo's textconv driver ran"
