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
    assert capsys.readouterr().out.strip() == "https://picks.fit-balance.co.il/"
    assert main(["https://example.com/"]) == 2


def test_the_workflow_fails_when_nikto_writes_no_output():
    """The first run 'succeeded' with an empty result while Nikto had stopped on a missing Perl module."""
    wf = (ROOT / ".github" / "workflows" / "nikto.yml").read_text(encoding="utf-8")
    assert 'echo "[]" > nikto.json' not in wf
    assert "Nikto wrote no output" in wf and "exit 1" in wf
    assert "libxml-writer-perl" in wf


def test_real_nikto_output_from_the_first_run():
    """tests/data/nikto-picks.json: the real output of the nikto workflow on picks.fit-balance.co.il
    (run 45252194198, 2026-11-23, 30 minutes)."""
    data = json.loads((Path(__file__).parent / "data" / "nikto-picks.json").read_text(encoding="utf-8"))
    facts = nikto.parse(data)
    assert len(facts) == 17
    assert all(f.url.startswith("https://picks.fit-balance.co.il/") for f in facts)
    missing = [f for f in facts if "Suggested security header missing" in f.evidence]
    assert len(missing) == 5


# --- review of PR #21: Nikto must never be steered to another host ---

import pytest  # noqa: E402

from scout.targets import NotAllowed, check_url, clean_url  # noqa: E402

PICKS = "https://picks.fit-balance.co.il/"


@pytest.mark.parametrize("url", [
    PICKS + ",https://evil.test/",                 # Nikto splits -h on commas
    "https://picks.fit-balance.co.il:443,evil.test/",
    PICKS + " evil.test",                          # Nikto strips spaces
    PICKS + "\nBASH_ENV=/tmp/x",                   # a newline would set variables in $GITHUB_ENV
    PICKS + "\r",
    "https://picks.fit-balance.co.il;evil.test/",
    "https://picks.fit-balance.co.il:abc/",
])
def test_inputs_that_could_reach_another_host_are_refused(url):
    with pytest.raises(NotAllowed):
        check_url(url)


def test_tools_get_a_url_rebuilt_from_its_parts():
    assert clean_url("HTTPS://Picks.Fit-Balance.co.il") == PICKS
    assert clean_url("https://picks.fit-balance.co.il:8443/a b".replace(" ", "")) == "https://picks.fit-balance.co.il:8443/ab"
    assert clean_url("https://picks.fit-balance.co.il/x?y=1#z") == "https://picks.fit-balance.co.il/x"


def test_the_workflow_runs_only_by_hand_and_passes_only_the_clean_url():
    wf_text = (ROOT / ".github" / "workflows" / "nikto.yml").read_text(encoding="utf-8")
    wf = yaml.safe_load(wf_text)
    triggers = wf.get(True) or wf.get("on")  # PyYAML reads the key `on` as True
    assert list(triggers) == ["workflow_dispatch"]
    assert "GITHUB_ENV" not in "".join(s.get("run", "") for s in wf["jobs"]["nikto"]["steps"])
    nikto_step = next(s for s in wf["jobs"]["nikto"]["steps"] if s.get("name", "").startswith("Run Nikto"))
    assert nikto_step["env"]["TARGET"] == "${{ steps.target.outputs.url }}"


def test_parser_reads_https_from_ssl_info_and_keeps_a_non_default_port():
    h = {"host": "x.test", "port": 8443, "ssl_info": {"cn": "x.test"},
         "vulnerabilities": [{"id": "1", "url": "/a", "msg": "m"}]}
    assert nikto.parse(h)[0].url == "https://x.test:8443/a"
    h = {"host": "x.test", "port": "80", "vulnerabilities": [{"id": "1", "url": "/a", "msg": "m"}]}
    assert nikto.parse(h)[0].url == "http://x.test/a"
