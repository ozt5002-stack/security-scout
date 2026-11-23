"""The eval's matching rule is ordinary code: pass/fail tests in CI (plan task 6). The eval itself never runs in CI."""

from pathlib import Path

import yaml

from evals.match import Known, RunResult, match, norm, score
from evals.run import planned_runs

ROOT = Path(__file__).resolve().parent.parent


def K(id, files, keywords, project="p", before="b1", after="a1", must=False):
    return Known(id, project, id, before, after, tuple(files), "A01", tuple(keywords), must)


def test_norm():
    assert norm("`.\\Src\\Server.mjs`") == "src/server.mjs"
    assert norm("C:/tmp/run/proj/src/a.js", root="C:\\tmp\\run\\proj") == "src/a.js"
    assert norm("/site/x.gs") == "site/x.gs"


def test_file_and_keyword_must_both_match():
    k = K("x", ["src/server.mjs"], ["rate limit"])
    assert match([k], [(["src/server.mjs:40"], "no rate limit on login")]) == {"x": 0}
    assert match([k], [(["src/server.mjs"], "missing CSP header")]) == {}
    assert match([k], [(["src/other.mjs"], "no rate limit")]) == {}


def test_any_where_path_and_folders():
    k = K("h", ["site/"], ["header"])
    assert match([k], [(["netlify.toml", "site/index.html:1"], "no security header")]) == {"h": 0}


def test_one_finding_matches_at_most_one_known_and_order_cannot_cost_a_match():
    a = K("a", ["s.mjs"], ["limit", "csrf"])   # could take either finding
    b = K("b", ["s.mjs"], ["csrf"])            # can only take the CSRF finding
    findings = [(["s.mjs"], "csrf: origin not checked"), (["s.mjs"], "no rate limit")]
    assert match([a, b], findings) == {"a": 1, "b": 0}


def test_score_recall_must_pass_and_false_alarms_only_on_own_after():
    k1 = K("k1", ["a.js"], ["xss"], must=True)
    k2 = K("k2", ["b.js"], ["sql"], after="a2")
    runs = [
        RunResult("p", "b1", "before", [(["a.js"], "XSS via innerHTML")]),
        RunResult("p", "a1", "after", [(["a.js"], "xss still there"), (["b.js"], "sql")]),
        RunResult("p", "a2", "after", []),
    ]
    s = score([k1, k2], runs)
    assert (s["recall"], s["missed"], s["must_pass_missed"]) == (1, ["k2"], [])
    assert s["false_alarms"] == ["k1"]  # k2's sql match on a1 is not k2's own after commit


def test_known_findings_file_is_complete_and_consistent():
    data = yaml.safe_load((ROOT / "evals" / "known-findings.yaml").read_text(encoding="utf-8"))
    knowns = [Known.from_dict(d) for d in data]
    assert len(knowns) == 16
    assert len({k.id for k in knowns}) == 16
    by_project = {}
    for k in knowns:
        by_project[k.project] = by_project.get(k.project, 0) + 1
    assert by_project == {"fitbalance-ad-agents": 7, "fit-balance": 5, "yahav-picks": 4}
    assert sorted(k.id for k in knowns if k.must_pass) == ["aa-01", "fb-01", "fb-02", "yp-01", "yp-02"]
    assert all(k.files and k.keywords for k in knowns)


def test_seven_runs_planned():
    data = yaml.safe_load((ROOT / "evals" / "known-findings.yaml").read_text(encoding="utf-8"))
    runs = planned_runs([Known.from_dict(d) for d in data])
    assert len(runs) == 7
    assert sum(1 for r in runs if r[2] == "before") == 3
