"""Plan task 2: each planted problem gives exactly one fact; a clean project gives none; keys are masked."""

import json
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict

import pytest

from scout import ROOT
from scout.redact import mask, redact
from scout.scanners import Context, ci, publish, secrets
from tests.leaky_site import FAKE_KEY, FAKE_OLD_KEY, build_clean, build_leaky

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")


@pytest.fixture
def leaky(tmp_path):
    return build_leaky(tmp_path)


@pytest.fixture
def clean(tmp_path):
    return build_clean(tmp_path)


def all_facts(project):
    ctx = Context()
    return secrets.scan(project, ctx) + publish.scan(project, ctx) + ci.scan(project, ctx)


def test_each_planted_problem_gives_exactly_one_fact(leaky):
    facts = all_facts(leaky)
    by_id = Counter(f.id for f in facts)
    assert by_id == Counter({
        "secrets.in-file": 1, "secrets.in-history": 1,
        "publish.non-web-file": 1, "publish.no-header-config": 1,
        "ci.workflow-write": 1, "ci.unpinned-action": 1,
    }), facts
    where = {f.id: (f.file, f.owasp) for f in facts}
    assert where["secrets.in-file"] == ("config.js", "A04")
    assert where["secrets.in-history"] == ("old-settings.js", "A04")
    assert where["publish.non-web-file"] == ("site/backend/Code.gs", "A02")
    assert where["publish.no-header-config"] == ("site/", "A02")
    assert where["ci.workflow-write"] == (".github/workflows/deploy.yml", "A01")
    assert where["ci.unpinned-action"] == (".github/workflows/deploy.yml", "A08")


def test_clean_project_gives_no_problem_facts(clean):
    facts = all_facts(clean)
    assert [f for f in facts if f.severity != "info"] == []
    # the ignored .env is listed for the inventory only
    assert [(f.id, f.file, f.severity) for f in facts] == [("secrets.local-file", ".env", "info")]


def test_no_fact_holds_more_than_four_characters_of_a_key(leaky):
    dumped = json.dumps([asdict(f) for f in all_facts(leaky)], ensure_ascii=False)
    for key in (FAKE_KEY, FAKE_OLD_KEY):
        assert key[:5] not in dumped
        assert mask(key) in dumped


def test_history_head_only_sees_the_checked_out_branch(leaky):
    # the old key is in an ancestor of HEAD, so it is still found with --history head
    assert any(f.id == "secrets.in-history" for f in secrets.scan(leaky, Context(history="head")))


# Sample secrets are assembled from pieces, so this repo's own secrets scan stays clean (rule 8).
PW1, PW2, PW3 = "hunter2" * 2, "abcd" + "efgh1234", "Sup3r" + "S3cretValue"


@pytest.mark.parametrize("text,want", [
    (f'password = "{PW1}"', [PW1]),
    ('x = {"secret": "' + PW2 + '"}', [PW2]),
    ("APP_PASSWORD=" + PW3, [PW3]),
    ("password = getPassword();", []),
    ("APP_PASSWORD=your-password-here", []),
    ("API_KEY=", []),
    ("const key = process.env.API_KEY;", []),
    ('cfg = {"api_key": os.environ["KEY"]}', []),
])
def test_password_patterns(text, want):
    from scout.redact import find_secrets
    assert [v for _, v, _ in find_secrets(text)] == want


def test_redact_masks_keys_in_text():
    text = f"the key is {FAKE_KEY} and also {FAKE_OLD_KEY}."
    out = redact(text)
    assert FAKE_KEY not in out and FAKE_OLD_KEY not in out
    assert mask(FAKE_KEY) in out


def test_cli_lists_the_planted_facts(leaky, runs_in_tmp):
    r = subprocess.run([sys.executable, "-m", "scout", str(leaky), "--no-agent"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("scout: 6 facts")


def test_secrets_module_finds_nothing_in_this_repo():
    """CONTRIBUTING rule 8, as a test."""
    r = subprocess.run([sys.executable, "-m", "scout.scanners.secrets", str(ROOT)], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""


def test_secrets_module_prints_one_line_per_finding(leaky):
    r = subprocess.run([sys.executable, "-m", "scout.scanners.secrets", str(leaky)], cwd=ROOT,
                       capture_output=True, text=True)
    assert len(r.stdout.strip().splitlines()) == 2
    assert FAKE_KEY not in r.stdout
