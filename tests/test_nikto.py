"""Plan task 7: Nikto runs in GitHub Actions (D7). Here: its command and the parser of its JSON output."""

import json
from pathlib import Path

import yaml

from scout import ROOT
from scout.scanners import nikto

SAMPLE = {
    "host": "picks.fit-balance.co.il", "ip": "185.199.111.153", "port": "443", "banner": "GitHub.com",
    "vulnerabilities": [
        {"id": "999986", "references": "", "method": "GET", "url": "/",
         "msg": "Retrieved via header: 1.1 varnish."},
        {"id": "013587", "references": "", "method": "GET", "url": "/",
         "msg": "The anti-clickjacking X-Frame-Options header is not present."},
        {"id": "000001", "method": "GET", "url": "/backup.zip", "msg": "Possible backup file found."},
    ],
}


def test_command_is_paused_time_limited_and_non_interactive():
    cmd = nikto.command("nikto.pl", "https://x.test/", "out.json")
    assert cmd[cmd.index("-Pause") + 1] == "1"
    assert cmd[cmd.index("-maxtime") + 1] == "30m"
    assert "-nointeractive" in cmd and cmd[cmd.index("-ask") + 1] == "no"
    assert cmd[cmd.index("-h") + 1] == "https://x.test/"


def test_parse_turns_items_into_facts():
    facts = nikto.parse(SAMPLE)
    assert [f.severity for f in facts] == ["low", "low", "medium"]
    assert facts[1].url == "https://picks.fit-balance.co.il/"
    assert facts[2].url == "https://picks.fit-balance.co.il/backup.zip"
    assert all(f.owasp == "A02" and f.evidence.startswith("Nikto: ") for f in facts)


def test_parse_accepts_a_list_and_empty_output():
    assert len(nikto.parse([SAMPLE])) == 3
    assert nikto.parse([]) == []


def test_cli_parse_prints_facts(tmp_path, capsys):
    f = tmp_path / "nikto.json"
    f.write_text(json.dumps(SAMPLE), encoding="utf-8")
    assert nikto.main(["parse", str(f)]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 3


def test_the_workflow_checks_the_allowlist_before_fetching_nikto_and_never_inlines_the_target():
    wf = (ROOT / ".github" / "workflows" / "nikto.yml").read_text(encoding="utf-8")
    steps = yaml.safe_load(wf)["jobs"]["nikto"]["steps"]
    names = [s.get("name", "") for s in steps]
    assert names.index("Check the target against the allowlist") < names.index("Fetch Nikto at the pinned commit")
    for s in steps:  # the form input reaches scripts only through env, never pasted into `run`
        assert "inputs." not in s.get("run", "")
    assert yaml.safe_load(wf)["permissions"] == {"contents": "read"}


def test_targets_cli(capsys):
    from scout.targets import main
    assert main(["https://picks.fit-balance.co.il/"]) == 0
    assert main(["https://example.com/"]) == 2


def test_the_workflow_fails_when_nikto_writes_no_output():
    """The first run 'succeeded' with an empty result while Nikto had stopped on a missing Perl module."""
    wf = (ROOT / ".github" / "workflows" / "nikto.yml").read_text(encoding="utf-8")
    assert 'echo "[]" > nikto.json' not in wf
    assert "Nikto wrote no output" in wf and "exit 1" in wf
    assert "libxml-writer-perl" in wf
