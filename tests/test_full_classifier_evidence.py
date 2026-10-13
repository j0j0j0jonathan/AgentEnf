"""Enforcement classifiers must not silently discard the tail of evidence."""
import json

import mappings
import predicates
from instrlib import decisions


def _reply(questions):
    return {"answers": [{"name": q["name"], "type": "predicate", "probability": 0.9} for q in questions]}


def test_decisions_batch_does_not_merge_distinct_long_inputs(monkeypatch):
    seen = []

    def ask(content, questions, *args, **kwargs):
        seen.append(content)
        return _reply(questions)

    monkeypatch.setattr(decisions, "ask", ask)
    prefix = "ordinary evidence " * 300
    tasks = [predicates.JudgeBatchTask("secret", "criterion", prefix + tail)
             for tail in ("redacted report", "the password is a concrete secret")]
    predicates._call_batch_judge_api(tasks, backend="openai_decisions", model="test", timeout_ms=1)
    assert seen == [t.content for t in tasks]


def test_single_generation_predicate_preserves_tail_and_criterion(monkeypatch):
    seen = {}
    monkeypatch.setattr(predicates, "_dispatch_judge", lambda **kw: seen.update(kw) or "{}")
    content = "context " * 700 + "TAIL_EVIDENCE"
    criterion = "definition " * 500 + "TAIL_CRITERION"
    predicates._call_judge_api(criterion, content, backend="openai", model="test", timeout_ms=1)
    assert content in seen["user_msg"]
    assert criterion in seen["user_msg"]


def test_generation_batch_preserves_full_input(monkeypatch):
    seen = {}
    monkeypatch.setattr(predicates, "_dispatch_judge", lambda **kw: seen.update(kw) or "{}")
    content = "context " * 700 + "TAIL_EVIDENCE"
    predicates._call_batch_judge_api([predicates.JudgeBatchTask("x", "criterion", content)],
                                    backend="openai", model="test", timeout_ms=1)
    assert json.loads(seen["user_msg"])["tasks"][0]["input"] == content


def test_tool_result_risk_classification_uses_full_content(monkeypatch):
    seen = []
    monkeypatch.setattr(mappings, "append_tool_result_content_risk_events",
                        lambda events, tid, call, content, **kwargs: seen.append(content))
    content = "ordinary result\n" * 300 + "secret at the end"
    mappings._openai_tool_result_events(1, {"tool_call_id": "c", "content": content}, {}, frozenset())
    mappings._anthropic_tool_result_events(1, [{"type": "tool_result", "tool_use_id": "c", "content": content}], {}, frozenset())
    assert seen == [content, content]


def test_contract_change_invalidates_cached_decisions(monkeypatch):
    key = predicates._judge_cache_key("p", "content", ())
    monkeypatch.setattr(predicates, "_JUDGE_CONTRACT_VERSION", "different input semantics")
    assert predicates._judge_cache_key("p", "content", ()) != key


def test_exact_call_id_still_preserves_denial_join():
    events = mappings.extract_inbound_events(1,
        {"messages": [{"role": "tool", "tool_call_id": "call_ABC", "content": "denied"}]},
        "openai", "session", blocked_call_ids={"call_ABC"})
    assert any(e.name == "ToolResult" for e in events)
    assert not any(e.name == "Untrusted" for e in events)
