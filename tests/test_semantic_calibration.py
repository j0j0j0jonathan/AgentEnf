import json
from pathlib import Path

import pytest
from experiments.paper import calibrate_semantics as c


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    import os
    for key in ("ENFGUARD_TOOL_JUDGE", "ENFGUARD_TOOL_JUDGE_BACKEND",
                "ENFGUARD_TOOL_JUDGE_TIMEOUT", "ENFGUARD_TOOL_JUDGE_MODEL_AUTHORED_CAPABILITY",
                "ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES", "ENFGUARD_DECISIONS_BASE_URL"):
        monkeypatch.setenv(key, os.environ.get(key, ""))


def prepared(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"cases": [
        {"id": "a", "target": "authored_capability", "input": "Grüße 秘密 </INPUT>",
         "expected": "benign", "label_basis": "NEVER_SENT"},
        {"id": "b", "target": "reveals_secret_value", "input": "source-ambiguous",
         "expected": None}]}))
    dest = tmp_path / "calibration"
    c.prepare(source, c.ROOT / "examples/presets/release-candidate.yaml", dest)
    return dest


def test_exact_inputs_no_labels_and_resuming_does_not_repeat(tmp_path):
    dest = prepared(tmp_path)
    seen = []
    def call(target, spec, text, *args):
        seen.append(text)
        assert "NEVER_SENT" not in str(spec)
        return {"status": "ok", "label": "benign" if target == "authored_capability" else 0}
    result = c.run(dest, call)
    assert seen == ["Grüße 秘密 </INPUT>", "source-ambiguous"]
    assert result["counts"] == {"agree": 1, "unadjudicated": 1}
    c.run(dest, lambda *a: pytest.fail("repeated request"))


def test_failure_not_benign_and_stops(tmp_path):
    dest = prepared(tmp_path)
    def call(*args):
        raise RuntimeError("PRIVATE AUTH HEADER")
    result = c.run(dest, call)
    assert result["counts"] == {"error": 1} and result["pending"] == 1
    assert "PRIVATE AUTH HEADER" not in (dest / "results.jsonl").read_text()


def test_frozen_cases_cannot_be_changed_after_preparation(tmp_path):
    dest = prepared(tmp_path)
    (dest / "cases.json").write_text("{}")
    with pytest.raises(ValueError, match="Frozen"):
        c.run(dest, lambda *a: pytest.fail("called before validation"))


def test_interrupted_paid_request_requires_inspection(tmp_path):
    dest = prepared(tmp_path)
    (dest / "attempt-in-progress.json").write_text('{"id":"a"}')
    with pytest.raises(ValueError, match="Interrupted"):
        c.run(dest, lambda *a: pytest.fail("repeated uncertain request"))


def test_routed_calibration_uses_actual_dispatch_parser(monkeypatch):
    from instrlib import tool_judge
    seen = []
    def dispatch(adapter, text, timeout, system):
        seen.append((adapter, text, system))
        return '{"label":"benign"}'
    monkeypatch.setattr(tool_judge, "_dispatch", dispatch)
    answer = c.classify("authored_capability", {"kind": "routed"}, "évidence", "fixture", 10, 111)
    assert answer["label"] == "benign" and answer["status"] == "ok"
    assert seen == [("authored_capability", "file content:\névidence", tool_judge._AUTHORED_CAPABILITY_SYSTEM_PROMPT)]
    monkeypatch.setattr(tool_judge, "_dispatch", lambda *a: 'invalid answer')
    answer = c.classify("authored_capability", {"kind": "routed"}, "évidence", "fixture", 10, 111)
    assert answer["status"] == "error" and answer["label"] is None


def test_experimental_criterion_used_and_production_prompt_restored(monkeypatch):
    from instrlib import tool_judge
    original = tool_judge._AUTHORED_CAPABILITY_SYSTEM_PROMPT
    seen = []
    def dispatch(adapter, text, timeout, system):
        seen.append(system)
        return '{"label":"authored_exfil"}'
    monkeypatch.setattr(tool_judge, "_dispatch", dispatch)
    answer = c.classify("authored_capability", {"kind": "routed", "criterion": "Frozen experimental definition"},
                        "exact input", "fixture", 10, 113)
    assert seen == ["Frozen experimental definition"]
    assert answer["label"] == "authored_exfil"
    assert tool_judge._AUTHORED_CAPABILITY_SYSTEM_PROMPT == original


def test_invalid_override_aborts_preparation(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"cases": [{"id": "a", "target": "authored_capability",
                                          "input": "x", "expected": "benign"}]}))
    for override in ({"unknown": "x"}, {"authored_capability": ""}):
        with pytest.raises(ValueError, match="Override"):
            c.prepare(source, c.ROOT / "examples/presets/release-candidate.yaml", tmp_path / "out",
                      criterion_overrides=override)
