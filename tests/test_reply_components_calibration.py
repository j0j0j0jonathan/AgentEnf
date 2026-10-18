import itertools
import json

import pytest

from experiments.paper import calibrate_reply_components as c
from experiments.paper import calibrate_semantics as calibration
from experiments.paper.semantic_followup import reply_cases
from experiments.paper.calibrate import dump, sha
from instrlib import decisions


def previous(tmp_path):
    prior = tmp_path / "prior"
    prior.mkdir()
    dump(prior / "cases.json", {"cases": reply_cases()})
    dump(prior / "manifest.json", {"cases_sha256": sha(prior / "cases.json")})
    (prior / "results.jsonl").write_text("frozen previous results\n")
    return prior


@pytest.mark.parametrize("payload,refusal,coverage", list(itertools.product((0, 1), repeat=3)))
def test_combination_truth_table(payload, refusal, coverage):
    properties = dict(zip(c.CRITERIA, (payload, refusal, coverage), strict=True))
    expected = 1 if payload and (not refusal or not coverage) else 0
    assert c.decision(properties) == expected


def test_original_decisions_unchanged_with_new_predeclared_components(tmp_path):
    prior = previous(tmp_path)
    before = sha(prior / "cases.json")
    rows = c.cases(prior)
    original = json.loads((prior / "cases.json").read_text())["cases"]
    assert len(rows) == 24
    for a, b in zip(original, rows[:18], strict=True):
        assert {k: b[k] for k in a} == a
        assert c.decision(b["expected_components"]) == a["expected"]
    assert sha(prior / "cases.json") == before


def test_one_request_exact_evidence_three_questions_no_expected_labels(monkeypatch):
    content = reply_cases()[0]["input"]
    seen = []
    def ask(text, questions, timeout, **kw):
        seen.append((text, questions))
        return {"answers": [{"type": "predicate", "name": q["name"], "probability": score}
                            for q, score in zip(questions, (.99, .99, .99), strict=True)]}
    monkeypatch.setattr(decisions, "ask", ask)
    result = c.classify("name", {"criterion": json.dumps(c.CRITERIA)}, content, "fixed-model", 10, 1)
    assert result["label"] == 0
    assert len(seen) == 1 and seen[0][0] == content and len(seen[0][1]) == 3
    assert "expected_components" not in str(seen)


@pytest.mark.parametrize("answers", [[], [{"type": "refusal", "name": "dangerous_payload_present"}],
    [{"type": "predicate", "name": name, "probability": None} for name in c.CRITERIA]])
def test_bad_components_are_errors_not_negative(monkeypatch, answers):
    monkeypatch.setattr(decisions, "ask", lambda *a, **kw: {"answers": answers})
    with pytest.raises(ValueError):
        c.classify("x", {"criterion": json.dumps(c.CRITERIA)}, "input", "fixture", 1, 1)


def test_frozen_and_resumable_runner_uses_computed_decisions(tmp_path, monkeypatch):
    prior = previous(tmp_path)
    out = c.prepare(prior, tmp_path / "run")
    assert calibration.check(out)["planned"] == 24
    exp = json.loads((out / "experiment.json").read_text())
    assert exp["driver_sha256"] == sha(c.__file__) and not exp["runtime_integrated"]
    seen = []
    def call(target, spec, content, *args):
        seen.append(content)
        assert set(json.loads(spec["criterion"])) == set(c.CRITERIA)
        return {"status": "ok", "label": 0}
    summary = calibration.run(out, call=call)
    assert summary["attempted"] == 24 and summary["pending"] == 0
    calibration.run(out, call=lambda *a: pytest.fail("Repeat request"))
    assert len(seen) == 24


def test_component_report_does_not_hide_opposite_errors():
    row = {"id": "a", "expected_components": dict(zip(c.CRITERIA, (1, 1, 0), strict=True))}
    result = {"id": "a", "status": "ok", "components": dict(zip(c.CRITERIA, (False, True, True), strict=True)),
              "component_scores": dict(zip(c.CRITERIA, (.1, .9, .9), strict=True))}
    report = c.summarize_components([row], [result])
    assert len(report["disagreements"]) == 2
    assert report["properties"]["refusal_only"]["agree"] == 1
