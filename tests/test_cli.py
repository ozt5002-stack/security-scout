import json
import subprocess
import sys
from pathlib import Path

import pytest

from scout import ROOT
from scout.cli import main
from scout.facts import Fact
from scout.run import run

EMPTY = ROOT / "tests" / "fixtures" / "empty"


def scout(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "scout", *args], cwd=ROOT, capture_output=True, text=True)


def test_help_lists_the_options():
    out = scout("--help").stdout
    for opt in ("--live", "--nikto", "--out", "--history", "--targets", "--no-agent"):
        assert opt in out


def test_empty_project_writes_empty_facts_in_runs(runs_in_tmp):
    r = scout(str(EMPTY), "--no-agent")
    assert r.returncode == 0, r.stderr
    facts_path = Path(r.stdout.strip().split("-> ")[1])
    assert facts_path.parent.parent == runs_in_tmp
    assert json.loads(facts_path.read_text(encoding="utf-8")) == []


def test_default_runs_folder_is_in_this_repo(monkeypatch):
    from scout.facts import runs_root
    monkeypatch.delenv("SCOUT_RUNS_DIR")
    assert runs_root() == ROOT / "runs"


def test_two_runs_in_the_same_second_do_not_collide():
    from scout.facts import new_run_dir
    assert new_run_dir(EMPTY) != new_run_dir(EMPTY)


def test_live_host_not_in_allowlist_is_refused_with_exit_2(tmp_path):
    allow = tmp_path / "targets.yaml"
    allow.write_text("hosts: [mysite.test]\n", encoding="utf-8")
    r = scout(str(EMPTY), "--live", "https://example.com", "--targets", str(allow), "--no-agent")
    assert r.returncode == 2
    assert "example.com is not in targets.yaml" in r.stderr


def test_real_targets_file_never_lists_localhost():
    from scout.targets import load_hosts
    assert not {"127.0.0.1", "localhost"} & load_hosts()


def test_nikto_is_refused_off_the_allowlist_and_not_available_yet(tmp_path):
    assert main([str(EMPTY), "--live", "https://x.test", "--nikto", "--targets", str(tmp_path / "none.yaml")]) == 2
    allow = tmp_path / "targets.yaml"
    allow.write_text("hosts: [x.test]\n", encoding="utf-8")
    assert main([str(EMPTY), "--live", "https://x.test", "--nikto", "--targets", str(allow)]) == 3


def test_missing_folder_is_exit_1(tmp_path):
    assert main([str(tmp_path / "nope"), "--no-agent"]) == 1


def test_fact_rejects_bad_values():
    with pytest.raises(ValueError):
        Fact("s", "x", "A99", "high", "e")
    with pytest.raises(ValueError):
        Fact("s", "x", "A01", "urgent", "e")
    with pytest.raises(ValueError):
        Fact("s", "x", "A01", "low", "e", file="a\\b.txt")


def test_run_refuses_shell_strings():
    with pytest.raises(TypeError):
        run("git status")  # type: ignore[arg-type]


def test_run_folder_is_a_full_path_never_a_windows_short_name(tmp_path):
    """The eval baseline found the agent could not read facts.json when its folder was given by a short name (E40C~1)."""
    from scout.facts import new_run_dir
    import os
    short = os.environ.get("TEMP", str(tmp_path))  # on Windows TEMP is often the short form
    run_dir = new_run_dir(EMPTY, root=Path(short) / "scout-test-runs")
    try:
        assert run_dir == run_dir.resolve()
        assert "~" not in str(run_dir)
    finally:
        import shutil
        shutil.rmtree(run_dir.parent, ignore_errors=True)
