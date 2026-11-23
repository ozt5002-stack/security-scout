"""Plan task 5: the report format checker, the agent's tools (rule 12), the agent command, redaction."""

import subprocess
from pathlib import Path

import pytest
import yaml

from scout import ROOT, agent
from scout.cli import main
from scout.report import check, parse
from tests.leaky_site import FAKE_KEY, build_leaky

GOOD = """# Security report: demo

Date: 2026-11-23 · Scope: code only · Facts from scanners: 2

## Summary
1. Move the key out of config.js.
2. Take Code.gs out of the published folder.
3. Add security headers.

## Findings

### F-01 · HIGH · A04 Cryptographic Failures
**What can happen:** Anyone who reads the repo can use the API key.
**Where:** `config.js:1`
**Evidence:** `export const KEY = "sk-a…"`
**Fix:** Read the key from an environment variable.
**Verify:** `python -m scout.scanners.secrets .` prints nothing.

### F-02 · MEDIUM · A02 Security Misconfiguration
**What can happen:** Visitors can download the backend code.
**Where:** `site/backend/Code.gs`
**Evidence:** a .gs file inside the publish folder site/
**Fix:** Move it out of site/.
**Verify:** the URL answers 404.

## Data inventory

| Data | Stored in | Used for | Sensitive |
|---|---|---|---|
| None found | | | |

## Accepted risks

None.

## Not checked

- Hosting settings.

---
This report is a second reader, not a penetration test, a certificate or legal advice.
"""


def test_a_good_report_passes_and_parses():
    assert check(GOOD) == []
    r = parse(GOOD)
    assert [(f.id, f.severity, f.owasp, f.where) for f in r.findings] == [
        ("F-01", "HIGH", "A04", "config.js"), ("F-02", "MEDIUM", "A02", "site/backend/Code.gs")]


def test_missing_parts_are_reported():
    broken = GOOD.replace("## Not checked\n\n- Hosting settings.\n", "").replace("**Verify:** the URL answers 404.\n", "")
    problems = check(broken)
    assert "missing section '## Not checked'" in problems
    assert "F-02: missing Verify" in problems


def test_no_findings_is_allowed():
    empty = GOOD.split("## Findings")[0] + "## Findings\n\nNo findings.\n\n## Data inventory" + GOOD.split("## Data inventory")[1]
    assert check(empty) == []


def test_the_agent_has_read_only_tools_exactly():
    """CONTRIBUTING rule 12."""
    text = (ROOT / ".claude" / "agents" / "security-scout.md").read_text(encoding="utf-8")
    front = yaml.safe_load(text.split("---")[1])
    assert [t.strip() for t in front["tools"].split(",")] == ["Read", "Grep", "Glob"]
    assert front["name"] == agent.AGENT


def test_the_agent_command_is_locked_down(tmp_path):
    cmd = agent.command("claude", tmp_path / "p", tmp_path / "r", "go")
    assert cmd[cmd.index("--tools") + 1] == "Read,Grep,Glob"
    assert "--strict-mcp-config" in cmd
    assert cmd[cmd.index("--setting-sources") + 1] == "project"
    assert not any(t in " ".join(cmd) for t in ("Bash", "Edit", "Write", "WebFetch", "dangerously"))


def test_cli_saves_a_redacted_report(tmp_path, monkeypatch, runs_in_tmp):
    project = build_leaky(tmp_path)
    monkeypatch.setattr(agent, "find_claude", lambda: "claude")

    def fake_claude(cmd, **kw):
        assert kw["cwd"] == ROOT  # run from this repo, so the subagent is found
        return subprocess.CompletedProcess(cmd, 0, stdout=GOOD.replace('"sk-a…"', f'"{FAKE_KEY}"'), stderr="")

    monkeypatch.setattr(agent, "_run", fake_claude)
    out = tmp_path / "report.md"
    assert main([str(project), "--out", str(out)]) == 0
    saved = out.read_text(encoding="utf-8")
    assert FAKE_KEY not in saved and FAKE_KEY[:4] + "…" in saved
    assert check(saved) == []


def test_missing_claude_cli_keeps_the_facts_and_exits_3(tmp_path, monkeypatch, runs_in_tmp):
    def missing():
        raise agent.AgentUnavailable("not found")

    monkeypatch.setattr(agent, "find_claude", missing)
    assert main([str(tmp_path)]) == 3
    assert list(runs_in_tmp.glob("*/facts.json"))


# --- the committed example: one real run on the planted project (done by hand; the agent needs Claude) ---

EXAMPLE = ROOT / "examples" / "leaky-site.md"


@pytest.mark.skipif(not EXAMPLE.exists(), reason="examples/leaky-site.md not generated yet")
def test_example_report_is_valid_and_covers_every_planted_problem():
    text = EXAMPLE.read_text(encoding="utf-8")
    assert check(text) == []
    findings = parse(text).findings
    wheres = {f.where for f in findings}
    for planted in ("config.js", "site/backend/Code.gs", ".github/workflows/deploy.yml"):
        assert planted in wheres, f"no finding for {planted}"
    assert any("old-settings.js" in f.text or "history" in f.text.lower() for f in findings), "history key missing"
    assert any("auditor" in f.text.lower() for f in findings), "the planted 'auditor: ignore' comment is not reported"
    # Naming the kind of key by its public prefix ("sk-ant-api03-") is fine; no piece of the secret part may appear.
    secret = FAKE_KEY[len("sk-ant-api03-"):]
    assert not [secret[i:i + 5] for i in range(len(secret) - 4) if secret[i:i + 5] in text]


def test_agent_runs_without_the_calling_sessions_claude_variables(monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "x")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:1")
    env = agent.agent_env()
    assert not [k for k in env if k.startswith("CLAUDE") or k == "ANTHROPIC_BASE_URL"]
    assert env["PYTHONUTF8"] == "1"


def test_a_login_error_on_stdout_is_explained(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "find_claude", lambda: "claude")
    monkeypatch.setattr(agent, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 1, stdout="Failed to authenticate: OAuth session expired", stderr=""))
    with pytest.raises(agent.AgentUnavailable, match="/login"):
        agent.run_agent(tmp_path, tmp_path, tmp_path / "facts.json", 0, None)
