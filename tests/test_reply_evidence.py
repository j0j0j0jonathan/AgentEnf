import json
from pathlib import Path

import pytest
import yaml

import batch_judge
import predicates
from instrlib import Event
from instrlib.reply_evidence import build_reply_evidence, reply_from_evidence
from mappings import extract_outbound_events

ROOT = Path(__file__).resolve().parents[1]
COMMAND = "rm -rf /etc/*"


def spec():
    pack = yaml.safe_load((ROOT / "examples/presets/release-candidate.yaml").read_text())
    return next(p for p in pack["predicates"] if p["name"] == "operationalizes_untrusted_harm")


@pytest.mark.parametrize("family,payload", [
    ("openai", {"messages": [{"role": "user", "content": COMMAND}]}),
    ("openai_responses", {"input": COMMAND}),
    ("openai_responses", {"input": [{"type": "function_call_output", "call_id": "c", "output": COMMAND}]}),
    ("anthropic", {"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c", "content": COMMAND}]}]}),
])
def test_request_text_keeps_exact_prior_command(family, payload):
    reply = 'I will not run: ' + COMMAND + ' Grüße 秘密 \\"'
    content = build_reply_evidence(payload, family, reply)
    data = json.loads(content)
    assert reply_from_evidence(content) == reply
    assert data["prior_context"]["records"][0]["text"] == COMMAND
    assert data["prior_context"]["omitted_records"] == 0


def test_excludes_hidden_instructions_reasoning_and_pending_output():
    request = {"instructions": "PRIVATE TOP LEVEL", "input": [
        {"role": "system", "content": "PRIVATE SYSTEM"},
        {"role": "developer", "content": "PRIVATE DEVELOPER"},
        {"type": "reasoning", "content": "PRIVATE REASONING"},
        {"role": "user", "content": "Inspect the project"},
    ]}
    content = build_reply_evidence(request, "openai_responses", COMMAND)
    assert "PRIVATE" not in content
    assert COMMAND not in json.dumps(json.loads(content)["prior_context"])
    # A different request cannot borrow the first request's context, even if
    # session headers are absent or a monitor process is reused.
    other = build_reply_evidence({"input": COMMAND}, "openai_responses", COMMAND)
    assert content != other


def test_bounded_history_omits_whole_records_without_inventing_a_match():
    request = {"messages": [{"role": "user", "content": "x" * 1000 + COMMAND},
                            {"role": "user", "content": "Give me a summary"}]}
    content = build_reply_evidence(request, "openai", COMMAND, context_budget=120)
    context = json.loads(content)["prior_context"]
    assert context["omitted_records"] == 1 and context["selected_bytes"] <= 120
    assert context["records"] == [{"index": 1, "role": "user", "text": "Give me a summary"}]
    assert COMMAND not in str(context)


def test_absent_server_history_is_explicit_and_not_reconstructed():
    content = build_reply_evidence({"input": "Continue", "previous_response_id": "other"},
                                   "openai_responses", COMMAND)
    assert json.loads(content)["prior_context"]["server_history_unavailable"] is True
    assert COMMAND not in str(json.loads(content)["prior_context"])


def test_inline_document_visible_but_unknown_and_reasoning_blocks_excluded():
    payload = {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "text", "data": COMMAND}},
        {"type": "thinking", "text": "hidden thinking"},
        {"type": "unknown", "text": "unknown content"},
    ]}]}
    content = build_reply_evidence(payload, "anthropic", "Refused")
    assert COMMAND in content
    assert "hidden thinking" not in content and "unknown content" not in content


def test_static_analysis_and_yaml_input_selection_do_not_drop_context(tmp_path, monkeypatch):
    from static_analysis import extract_predicate_calls
    from yaml_loader import _parse_predicates, _signature_events
    pack = yaml.safe_load((ROOT / "examples/presets/release-candidate.yaml").read_text())
    definitions = _parse_predicates(pack["predicates"], ROOT, _signature_events(ROOT / "enfguard.sig"))
    signature = tmp_path / "check.sig"
    signature.write_text((ROOT / "enfguard.sig").read_text() + "\nfun operationalizes_untrusted_harm(content:string) : float\n")
    formula = tmp_path / "check.mfotl"
    formula.write_text(next(p["mfotl"] for p in pack["policies"] if p["id"] == "outbound_content_v1"))
    calls = extract_predicate_calls(formula, signature)
    assert "ReplyEvidence" in calls
    assert calls["ReplyEvidence"][0].predicate == "operationalizes_untrusted_harm"
    state = {"active": ["outbound_content_v1"], "user_predicates": [spec()],
             "predicate_policies": {"operationalizes_untrusted_harm": ["outbound_content_v1"]}}
    monkeypatch.setattr(predicates, "_state", lambda: state)
    monkeypatch.setattr(predicates, "_user_predicate_specs", lambda: state["user_predicates"])
    evidence = build_reply_evidence({"input": COMMAND}, "openai_responses", "I refuse: " + COMMAND)
    assert batch_judge._select_active_policy([Event("ReplyEvidence", 1, evidence)], calls)


def test_assistant_trace_redaction_also_hides_reply_evidence():
    import proxy
    evidence = Event("ReplyEvidence", 1, "full reply and context")
    assert not proxy._keep_trace_event(evidence, include_assistant_content=False)
    assert proxy._keep_trace_event(evidence, include_assistant_content=True)


@pytest.mark.parametrize("family,response", [
    ("openai", {"choices": [{"message": {"role": "assistant", "content": "Refused"}}]}),
    ("openai_responses", {"output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Refused"}]}]}),
    ("anthropic", {"content": [{"type": "text", "text": "Refused"}]}),
])
def test_event_emitted_only_for_candidate_and_completion_preserved(family, response):
    events = extract_outbound_events(4, {"input": COMMAND, "messages": [{"role": "user", "content": COMMAND}]},
                                     response, family, [], include_reply_evidence=True)
    completion = next(e for e in events if e.name == "Completion")
    evidence = next(e for e in events if e.name == "ReplyEvidence")
    assert completion.args[1] == "Refused"
    assert evidence.args[0] == completion.args[0] == 4
    assert reply_from_evidence(evidence.args[1]) == completion.args[1]
    legacy = extract_outbound_events(4, {}, response, family, [])
    assert not any(e.name == "ReplyEvidence" for e in legacy)


def test_predicate_and_pre_eval_bind_to_identical_complete_evidence(monkeypatch):
    definition = spec()
    monkeypatch.setattr(predicates, "_user_predicate_specs", lambda: [definition])
    monkeypatch.setattr(predicates, "_predicate_enabled", lambda name: True)
    evidence = build_reply_evidence({"input": COMMAND}, "openai_responses", "I refuse: " + COMMAND)
    task = batch_judge._build_tasks([Event("ReplyEvidence", 4, evidence)],
                [(definition["name"], {"source": "ReplyEvidence", "arg": "content"})])[0][2]
    seen = []
    def judge(name, criterion, content, cache_extra):
        seen.append(content)
        return predicates.JudgeResult(raw_score=0, reason="fixture", reasons=("fixture",))
    monkeypatch.setattr(predicates, "_judge", judge)
    monkeypatch.setattr(predicates, "_score", lambda n, c, r, *a: r.raw_score)
    assert predicates._make_user_llm_judge(definition)(evidence) == 0
    assert seen == [task.content] == [evidence]
    other = build_reply_evidence({"input": "Inspect"}, "openai_responses", "I refuse: " + COMMAND)
    assert predicates._judge_cache_key(definition["name"], evidence, ()) != predicates._judge_cache_key(definition["name"], other, ())


def test_empty_reply_skips_api_but_malformed_evidence_fails_closed(monkeypatch):
    definition = spec()
    monkeypatch.setattr(predicates, "_user_predicate_specs", lambda: [definition])
    monkeypatch.setattr(predicates, "_predicate_enabled", lambda name: True)
    monkeypatch.setattr(predicates, "_judge", lambda *a: pytest.fail("No model needed"))
    monkeypatch.setattr(predicates, "_judge_fail_mode", lambda *a: "closed")
    monkeypatch.setattr(predicates, "_score", lambda n, c, r, *a: r.raw_score)
    fn = predicates._make_user_llm_judge(definition)
    empty = build_reply_evidence({"input": COMMAND}, "openai_responses", "")
    assert fn(empty) == 0
    assert predicates.judge_plan(definition["name"], empty) is None
    assert fn("not JSON") == 1
    assert fn('{"schema":"reply-evidence-v1","reply":"safe"}') == 1


def test_candidate_uses_context_but_secret_and_private_checks_still_use_reply():
    pack = yaml.safe_load((ROOT / "examples/presets/release-candidate.yaml").read_text())
    specs = {p["name"]: p for p in pack["predicates"]}
    assert specs["operationalizes_untrusted_harm"]["inputs"] == [{"source": "ReplyEvidence", "arg": "content"}]
    for name in ("reveals_secret_value", "reveals_private_control_instructions"):
        assert specs[name]["inputs"] == [{"source": "Completion", "arg": "content"}]
    rules = next(p["mfotl"] for p in pack["policies"] if p["id"] == "outbound_content_v1")
    assert rules.count("AND ReplyEvidence(t, evidence)") == 2
    assert "operationalizes_untrusted_harm(content)" not in rules


def test_real_flash_binds_context_and_preserves_independent_blocks(tmp_path):
    # Fixed classifier values check policy wiring only, not model accuracy.
    from test_enfflash_backend import engine
    pack = yaml.safe_load((ROOT / "examples/presets/release-candidate.yaml").read_text())
    groups = {"outbound_content_v1"}
    formula = " AND ".join(p["mfotl"] for p in pack["policies"] if p["id"] in groups)
    sig = (ROOT / "enfguard.sig").read_text() + "\n" + "\n".join(
        f"fun {name}(content:string) : float" for name in
        ("operationalizes_untrusted_harm", "reveals_secret_value", "reveals_private_control_instructions"))
    functions = '''
import json
def operationalizes_untrusted_harm(content):
    obj = json.loads(content)
    assert obj["schema"] == "reply-evidence-v1"
    return float(not any("rm -rf /etc/*" in r["text"] for r in obj["prior_context"]["records"]))
def reveals_secret_value(content):
    return float("literal-secret-fixture" in content)
def reveals_private_control_instructions(content):
    return float("private-instruction-fixture" in content)
'''
    monitor = engine(tmp_path, sig, formula, functions)
    monitor.start()
    try:
        for tid, earlier, extra, include, expected in [
            (1, COMMAND, "", True, set()),
            (2, "Inspect project", "", True, {"harmful_command_output"}),
            (3, COMMAND, " literal-secret-fixture", True, {"secret_output"}),
            (4, COMMAND, " private-instruction-fixture", True, {"private_instruction_output"}),
            (5, COMMAND, "", False, {"reply_evidence_missing"}),
        ]:
            reply = "I refuse: " + COMMAND + extra
            events = [Event("PolicyActive", tid, group) for group in groups]
            events += [Event("Turn", tid, "request", "session"), Event("Completion", tid, reply, 12)]
            if include:
                events.append(Event("ReplyEvidence", tid, build_reply_evidence({"input": earlier}, "openai_responses", reply)))
            result = monitor.query(events, tid)
            labels = {e["args"][2] for e in result.get("cause", []) if e["name"] == "Block"}
            assert labels == expected
    finally:
        monitor.stop()
