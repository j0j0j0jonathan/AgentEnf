import json

import pytest

from experiments.paper import calibrate_reply_components as components
from experiments.paper import calibrate_reply_isolation as isolation
from experiments.paper import calibrate_semantics as calibration
from experiments.paper.calibrate import dump, sha
from experiments.paper.semantic_followup import reply_cases
from instrlib import decisions


def answer(content, questions, timeout, **kwargs):
    return {"answers": [{"type": "predicate", "name": q["name"], "probability": .8}
                        for q in questions]}


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    prior = tmp_path / "original"
    prior.mkdir()
    dump(prior / "cases.json", {"cases": reply_cases()})
    dump(prior / "manifest.json", {"cases_sha256": sha(prior / "cases.json")})
    (prior / "results.jsonl").write_text("frozen earlier results\n")
    component_run = components.prepare(prior, tmp_path / "components")
    monkeypatch.setattr(decisions, "ask", answer)
    calibration.run(component_run, call=components.classify)
    return isolation.prepare(component_run, tmp_path / "isolation")


def test_frozen_inputs_separate_history_without_changing_criteria_or_labels(prepared):
    experiment = isolation.check(prepared)
    assert experiment["planned_requests"] == 48
    original = json.loads((prepared / "original-cases.json").read_text())["cases"]
    for stage, names in isolation.STAGES.items():
        rows = json.loads((prepared / stage / "cases.json").read_text())["cases"]
        criteria = json.loads(json.loads((prepared / stage / "targets.json").read_text())[isolation.TARGET]["criterion"])
        assert criteria == {name: components.CRITERIA[name] for name in names}
        for before, after in zip(original, rows, strict=True):
            assert after["expected_final_decision"] == before["expected"]
            assert after["expected_components"] == before["expected_components"]
            if stage == "reply-only":
                assert json.loads(after["input"]) == {"reply": json.loads(before["input"])["reply"]}
            else:
                assert after["input"] == before["input"]


def test_request_only_sends_stage_content_and_unchanged_questions(monkeypatch):
    seen = []
    def ask(content, questions, timeout, **kwargs):
        seen.append((content, questions))
        return answer(content, questions, timeout)
    monkeypatch.setattr(decisions, "ask", ask)
    content = json.dumps({"reply": "I refuse this command."})
    criteria = {name: components.CRITERIA[name] for name in isolation.STAGES["reply-only"]}
    isolation.classify("unused", {"criterion": json.dumps(criteria)}, content, "fixture", 1, 0)
    assert len(seen) == 1 and seen[0][0] == content
    assert len(seen[0][1]) == 2
    assert "expected_components" not in str(seen)


def test_reply_stage_rejects_accidental_history_before_api(monkeypatch):
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("Must not call"))
    criteria = {name: components.CRITERIA[name] for name in isolation.STAGES["reply-only"]}
    with pytest.raises(ValueError, match="must not receive history"):
        isolation.classify("unused", {"criterion": json.dumps(criteria)}, reply_cases()[0]["input"], "fixture", 1, 0)


@pytest.mark.parametrize("data", [{"answers": []}, {"answers": [{"type": "refusal", "name": "prior_coverage"}]}])
def test_invalid_answers_are_errors_not_negatives(monkeypatch, data):
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: data)
    criteria = {"prior_coverage": components.CRITERIA["prior_coverage"]}
    with pytest.raises(ValueError):
        isolation.classify("unused", {"criterion": json.dumps(criteria)}, reply_cases()[0]["input"], "fixture", 1, 0)


def test_two_stages_resume_without_repeating_successes(prepared, monkeypatch):
    seen = []
    def ask(content, questions, timeout, **kwargs):
        seen.append((content, len(questions)))
        return answer(content, questions, timeout)
    monkeypatch.setattr(decisions, "ask", ask)
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "test-fixture-not-a-key")
    calibration.run(prepared / "reply-only", call=isolation.classify)
    assert len(seen) == 24
    report = isolation.run(prepared)
    assert len(seen) == 48 and report["completed_cases"] == 24
    assert not report["pending_case_ids"] and not report["error_case_ids"]
    assert len(report["component_report"]["properties"]) == 3
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("Already complete"))
    isolation.run(prepared)


def test_error_stops_without_sending_second_stage_or_retrying(prepared, monkeypatch):
    seen = []
    def fail(*args, **kwargs):
        seen.append(1)
        raise ValueError("Failed request")
    monkeypatch.setattr(decisions, "ask", fail)
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "test-fixture-not-a-key")
    with pytest.raises(SystemExit, match="Incomplete stage"):
        isolation.run(prepared)
    assert seen == [1] and not (prepared / "coverage-only" / "results.jsonl").exists()
    with pytest.raises(SystemExit, match="recorded request failed"):
        isolation.run(prepared)
    assert seen == [1]
    report = isolation.summarize(prepared)
    assert report["completed_cases"] == 0 and len(report["error_case_ids"]) == 1


def test_changed_manifest_rejected_before_key_or_api(prepared, monkeypatch):
    monkeypatch.setattr(isolation.getpass, "getpass", lambda *a: pytest.fail("No key prompt"))
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("No API"))
    path = prepared / "coverage-only" / "manifest.json"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(ValueError, match="Frozen experiment changed"):
        isolation.run(prepared)


def test_result_input_tampering_is_rejected(prepared):
    calibration.run(prepared / "reply-only", call=isolation.classify)
    path = prepared / "reply-only" / "results.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["input_sha256"] = "not-the-input"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="input hash mismatch"):
        isolation.summarize(prepared)
