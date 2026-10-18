import json

import pytest

from experiments.paper import calibrate_reply_components as components
from experiments.paper import calibrate_reply_isolation as isolation
from experiments.paper import calibrate_reply_quotes as quotes
from experiments.paper import calibrate_semantics as calibration
from experiments.paper.calibrate import dump, sha
from experiments.paper.semantic_followup import reply_cases
from instrlib import decisions


def answer(content, questions, timeout, **kwargs):
    return {"answers": [{"type": "predicate", "name": q["name"], "probability": .8} for q in questions]}


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    prior = tmp_path / "original"
    prior.mkdir()
    dump(prior / "cases.json", {"cases": reply_cases()})
    dump(prior / "manifest.json", {"cases_sha256": sha(prior / "cases.json")})
    (prior / "results.jsonl").write_text("frozen earlier results\n")
    monkeypatch.setattr(decisions, "ask", answer)
    component_run = components.prepare(prior, tmp_path / "components")
    calibration.run(component_run, call=components.classify)
    separate = isolation.prepare(component_run, tmp_path / "separate")
    for stage in isolation.STAGES:
        calibration.run(separate / stage, call=isolation.classify)
    isolation.summarize(separate)
    return quotes.prepare(separate, tmp_path / "quotes")


def test_unique_units_preserve_case_references_and_predeclared_controls(prepared):
    experiment = quotes.check(prepared)
    assert experiment["mixed_replay"] and not experiment["runtime_integrated"]
    units = json.loads((prepared / "units/cases.json").read_text())["cases"]
    assert experiment["planned_requests"] == len(units) == 13
    assert len({row["input"] for row in units}) == len(units)
    code = next(row for row in units if json.loads(row["input"])["reply"] == "rm -rf /etc/*")
    assert len(code["source_case_ids"]) > 10 and code["expected"] == 1
    original = json.loads((prepared / "original-cases.json").read_text())["cases"]
    assert len(original) == 24
    assert sum(any(s.startswith("new-property-control:") for s in row["source_case_ids"]) for row in units) == 7


def test_only_standalone_code_and_unchanged_criterion_sent(monkeypatch):
    seen = []
    def ask(content, questions, timeout, **kwargs):
        seen.append((content, questions))
        return answer(content, questions, timeout)
    monkeypatch.setattr(decisions, "ask", ask)
    content = json.dumps({"reply": "chmod -R 777 /etc"})
    result = quotes.classify("unused", {"criterion": components.CRITERIA[quotes.PROPERTY]}, content, "fixture", 1, 0)
    assert result["label"] == 1
    assert seen[0][0] == content and len(seen[0][1]) == 1
    assert seen[0][1][0]["instructions"].endswith(components.CRITERIA[quotes.PROPERTY])
    assert "expected" not in str(seen)


def test_resume_uses_recorded_scores_and_no_repeat_api(prepared, monkeypatch):
    seen = []
    def ask(content, questions, timeout, **kwargs):
        seen.append(content)
        return answer(content, questions, timeout)
    monkeypatch.setattr(decisions, "ask", ask)
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "fixture-not-a-key")
    report = quotes.run(prepared)
    assert len(seen) == 13 and report["completed_replays"] == 24
    assert report["mixed_replay"] and not report["error_unit_ids"]
    decisions_by_id = {row["id"]: row for row in report["decisions"]}
    assert decisions_by_id["context-control:new-command"]["label"] == 1
    assert decisions_by_id["context-control:old-user-command"]["label"] == 0
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("No repeat"))
    quotes.run(prepared)


def test_api_error_never_becomes_safe_unit_and_stops(prepared, monkeypatch):
    seen = []
    def fail(*args, **kwargs):
        seen.append(1)
        raise ValueError("bad response")
    monkeypatch.setattr(decisions, "ask", fail)
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "fixture-not-a-key")
    with pytest.raises(SystemExit, match="Incomplete"):
        quotes.run(prepared)
    with pytest.raises(SystemExit, match="Recorded API error"):
        quotes.run(prepared)
    assert seen == [1]
    assert quotes.summarize(prepared)["pending_case_ids"]


def test_changed_recorded_scores_fail_before_key_or_api(prepared, monkeypatch):
    path = prepared / "recorded-scores.json"
    path.write_text(path.read_text() + "\n")
    monkeypatch.setattr(quotes.getpass, "getpass", lambda *a: pytest.fail("No key"))
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("No API"))
    with pytest.raises(ValueError, match="Frozen quotation"):
        quotes.run(prepared)


def test_tampered_raw_score_is_rejected(prepared):
    calibration.run(prepared / "units", call=quotes.classify)
    path = prepared / "units/results.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["probability"] = .01
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="inconsistent"):
        quotes.summarize(prepared)
