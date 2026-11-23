"""Plan task 3: deps (npm audit, pip-audit) and Bandit. Tool output is recorded (tests/data), so CI needs no network.

tests/data/npm-audit-sharp.json  = `npm audit --json` on yahav-picks at 0e4ef64 (sharp 0.33.5), recorded 2026-11-23
tests/data/pip-audit-requests.json = `pip-audit -f json` on `requests==2.19.0`, recorded 2026-11-23
"""

import json
import subprocess
from pathlib import Path

import pytest

from scout.run import ToolMissing, find
from scout.scanners import Context, bandit_scan, deps

DATA = Path(__file__).parent / "data"


def recorded(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def test_npm_audit_advisory_becomes_one_fact():
    facts = deps.parse_npm_audit(recorded("npm-audit-sharp.json"), "package-lock.json")
    assert len(facts) == 1
    f = facts[0]
    assert (f.id, f.owasp, f.severity, f.file) == ("deps.npm-advisory", "A03", "high", "package-lock.json")
    assert f.evidence.startswith("sharp ") and "fix: sharp 0.35.5" in f.evidence


def test_pip_audit_advisories_become_one_fact_per_package():
    facts = deps.parse_pip_audit(recorded("pip-audit-requests.json"), "requirements.txt")
    assert len(facts) == 1
    assert facts[0].evidence.startswith("requests 2.19.0: 5 known advisories")
    assert facts[0].owasp == "A03"


def test_deps_scan_runs_npm_with_a_fixed_registry_and_reads_its_json(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    calls = []

    def fake_run(args, cwd=None, timeout=0):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, stdout=(DATA / "npm-audit-sharp.json").read_text(encoding="utf-8"),
                                           stderr="")

    monkeypatch.setattr(deps, "run", fake_run)
    facts = deps.scan(tmp_path, Context())
    assert calls == [["npm", "audit", "--json", "--registry=https://registry.npmjs.org/"]]
    assert [f.id for f in facts] == ["deps.npm-advisory"]


def test_pip_audit_never_installs_or_writes_into_the_project(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    calls = []

    def fake_run(args, cwd=None, timeout=0):
        calls.append(args)
        out = Path(args[args.index("-o") + 1])
        out.write_text((DATA / "pip-audit-requests.json").read_text(encoding="utf-8"), encoding="utf-8")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr(deps, "run", fake_run)
    facts = deps.scan(project, Context(run_dir=run_dir))
    assert "--no-deps" in calls[0] and "--disable-pip" in calls[0]
    assert Path(calls[0][calls[0].index("-o") + 1]).parent == run_dir
    assert sorted(p.name for p in project.iterdir()) == ["requirements.txt"]
    assert [f.id for f in facts] == ["deps.pip-advisory"]


def test_missing_tools_give_info_facts_not_a_crash(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("x==1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")

    def missing(args, cwd=None, timeout=0):
        raise ToolMissing(args[0])

    monkeypatch.setattr(deps, "run", missing)
    monkeypatch.setattr(bandit_scan, "run", missing)
    facts = deps.scan(tmp_path, Context()) + bandit_scan.scan(tmp_path, Context())
    assert sorted(f.id for f in facts) == ["bandit.not-checked", "deps.npm-not-checked", "deps.pip-audit-not-checked"]
    assert all(f.severity == "info" for f in facts)


def _has_bandit():
    try:
        find("bandit")
        return True
    except ToolMissing:
        return False


@pytest.mark.skipif(not _has_bandit(), reason="bandit not installed")
def test_bandit_finds_eval_even_with_nosec(tmp_path):
    (tmp_path / "app.py").write_text("x = eval(input())  # nosec\n", encoding="utf-8")
    facts = bandit_scan.scan(tmp_path, Context())
    assert [(f.id, f.file, f.line, f.owasp) for f in facts] == [("bandit.B307", "app.py", 1, "A05")]


def test_no_python_files_means_bandit_does_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(bandit_scan, "run", lambda *a, **k: pytest.fail("bandit should not run"))
    (tmp_path / "index.js").write_text("1\n", encoding="utf-8")
    assert bandit_scan.scan(tmp_path, Context()) == []


@pytest.mark.parametrize("test_id,owasp", [
    ("B105", "A07"), ("B301", "A08"), ("B506", "A08"), ("B303", "A04"), ("B501", "A04"),
    ("B201", "A02"), ("B110", "A10"), ("B602", "A05"), ("B608", "A05"), ("B307", "A05"),
])
def test_bandit_owasp_mapping(test_id, owasp):
    assert bandit_scan.owasp_for(test_id) == owasp


# --- review of PR #17: hostile project config must not steer the tools (D4, D10) ---

def test_npm_runs_in_a_clean_copy_without_the_projects_npmrc(tmp_path, monkeypatch):
    (tmp_path / ".npmrc").write_text("prefix=./evil\nhttps-proxy=http://127.0.0.1:9\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    seen = {}

    def fake_run(args, cwd=None, timeout=0):
        seen["cwd"] = Path(cwd)
        seen["files"] = sorted(p.name for p in Path(cwd).iterdir())
        return subprocess.CompletedProcess(args, 1, stdout=(DATA / "npm-audit-sharp.json").read_text(encoding="utf-8"),
                                           stderr="")

    monkeypatch.setattr(deps, "run", fake_run)
    facts = deps.scan(tmp_path, Context())
    assert seen["files"] == ["package-lock.json", "package.json"]  # no .npmrc
    assert tmp_path not in seen["cwd"].parents and seen["cwd"] != tmp_path
    assert not seen["cwd"].exists()  # the copy is removed afterwards
    assert [f.file for f in facts] == ["package-lock.json"]


@pytest.mark.skipif(not _has_bandit(), reason="bandit not installed")
def test_a_projects_bandit_file_cannot_skip_checks(tmp_path):
    (tmp_path / ".bandit").write_text("[bandit]\nskips: B307\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = eval(input())\n", encoding="utf-8")
    assert [f.id for f in bandit_scan.scan(tmp_path, Context())] == ["bandit.B307"]


@pytest.mark.skipif(not _has_bandit(), reason="bandit not installed")
def test_code_under_tests_is_scanned_too(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "helper.py").write_text("x = eval(input())\n", encoding="utf-8")
    assert [f.file for f in bandit_scan.scan(tmp_path, Context())] == ["tests/helper.py"]


def test_two_requirements_files_with_the_same_name_never_mix(tmp_path, monkeypatch):
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    calls = []

    def fake_run(args, cwd=None, timeout=0):
        calls.append(args)
        if len(calls) == 1:  # the first file succeeds, the second fails without output
            Path(args[args.index("-o") + 1]).write_text(
                (DATA / "pip-audit-requests.json").read_text(encoding="utf-8"), encoding="utf-8")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="boom")

    monkeypatch.setattr(deps, "run", fake_run)
    facts = deps.scan(tmp_path, Context(run_dir=run_dir))
    assert [(f.file, f.id) for f in facts] == [("a/requirements.txt", "deps.pip-advisory"),
                                              ("b/requirements.txt", "deps.pip-audit-not-checked")]


def test_editable_and_url_lines_are_reported_as_not_checked(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text(
        "-e .\nfoo @ https://example.test/foo.whl\ngit+https://example.test/bar.git\nrequests==2.19.0\n",
        encoding="utf-8")

    def fake_run(args, cwd=None, timeout=0):
        Path(args[args.index("-o") + 1]).write_text(
            (DATA / "pip-audit-requests.json").read_text(encoding="utf-8"), encoding="utf-8")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr(deps, "run", fake_run)
    ids = [f.id for f in deps.scan(tmp_path, Context(run_dir=tmp_path))]
    assert ids.count("deps.pip-audit-not-checked") == 3 and ids.count("deps.pip-advisory") == 1
