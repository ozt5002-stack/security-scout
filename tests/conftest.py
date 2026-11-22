import pytest


@pytest.fixture(autouse=True)
def runs_in_tmp(tmp_path, monkeypatch):
    """Tests never write into the real runs/ folder (also for `python -m scout` child processes, via the env)."""
    runs = tmp_path / "runs"
    monkeypatch.setenv("SCOUT_RUNS_DIR", str(runs))
    return runs
