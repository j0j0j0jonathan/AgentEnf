"""Candidate integration: real cache/predicate paths, stubbed model transport."""
import json
from pathlib import Path
from threading import BoundedSemaphore

import pytest
import yaml

import predicates
from instrlib import decisions, reply_guard
from instrlib.reply_evidence import build_reply_evidence
from yaml_loader import _parse_predicates, _predicate_state, _signature_events

ROOT = Path(__file__).resolve().parents[1]
NAME = "operationalizes_untrusted_harm"
CMD = "rm -rf /etc/*"


def definition():
    return {"name": NAME, "kind": "llm_judge", "system_prompt": reply_guard.OUTPUT_CONTRACT,
            "strategy": reply_guard.STRATEGY, "backend": "openai_decisions", "model": "fixture",
            "timeout_ms": 10000, "on_fail": "closed", "args": [{"name": "content", "type": "string"}],
            "inputs": [{"source": "ReplyEvidence", "arg": "content"}]}


def evidence(prior, reply=None):
    return build_reply_evidence({"input": prior}, "openai_responses", reply or f"I refuse `{CMD}`.")


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    spec = definition()
    state = {"active": ["p"], "predicate_policies": {NAME: ["p"]}, "user_predicates": [spec]}
    monkeypatch.setattr(predicates, "_state", lambda: state)
    monkeypatch.setattr(predicates, "_JUDGE_CACHE", {})
    monkeypatch.setattr(predicates, "_SESSION_FILE_CACHES", {})
    monkeypatch.setattr(predicates, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(predicates, "PRE_EVAL_RESULTS_FILE", tmp_path / "pre-eval.jsonl")
    monkeypatch.setattr(predicates, "_current_tid", lambda: 1)
    monkeypatch.setattr(predicates, "_current_sid", lambda: "fixture-session")
    monkeypatch.setattr(predicates, "_current_phase", lambda: "outbound")
    monkeypatch.setattr(predicates, "_score", lambda name, content, result, *a: result.raw_score)
    monkeypatch.setenv("ENFGUARD_CAPTURE_PREDICATE_INPUTS", "0")
    monkeypatch.setattr(predicates, "_call_and_parse_judge_api", lambda *a, **k: pytest.fail("Single-question fallback"))
    return spec, state


def answers(monkeypatch, *, refusal=1., payload=.8, coverage=1., fail_at=None):
    calls = []
    def ask(content, questions, timeout, **kwargs):
        calls.append((content, questions))
        if len(calls) == fail_at:
            raise ValueError("transport failure")
        values = {"dangerous_payload_present": payload, "refusal_only": refusal, "prior_coverage": coverage}
        return {"answers": [{"type": q["type"], "name": q["name"], "probability": values[q["name"]]} for q in questions]}
    monkeypatch.setattr(decisions, "ask", ask)
    return calls


def run(content):
    prompt, extra = predicates.judge_plan(NAME, content)
    return predicates.pre_evaluate_judge(NAME, prompt, content, extra)


def test_cache_and_pre_eval_preserve_composite_evidence(runtime, monkeypatch):
    spec, _ = runtime
    calls = answers(monkeypatch)
    old, new = evidence(CMD), evidence("Inspect the project")
    allowed, blocked = run(old), run(new)
    assert allowed.raw_score == 0 and blocked.raw_score == 1 and len(calls) == 5
    raw = json.loads(allowed.raw_reply)
    assert raw["label_origin"] == "deterministic_combination"
    assert raw["evidence"]["coverage_status"] == "classified"
    assert raw["evidence"]["decision_evidence"]["witness"]
    # Process restart: disk cache preserves ALL individual answers and witness.
    monkeypatch.setattr(predicates, "_JUDGE_CACHE", {})
    monkeypatch.setattr(predicates, "_SESSION_FILE_CACHES", {})
    hit = run(old)
    assert hit.cache_hit and hit.raw_reply == allowed.raw_reply and len(calls) == 5
    predicates._write_pre_eval_result(NAME, old, allowed)
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("No extra API request"))
    assert predicates._make_user_llm_judge(spec)(old) == 0
    assert predicates._pre_evaluated_judge_result(NAME, old).replayed_pre_eval
    # Same reply but different history cannot borrow the Allow.
    assert predicates._pre_evaluated_judge_result(NAME, new) is None
    # Changed model must not borrow the old pre-evaluation record.
    spec["model"] = "different"
    assert predicates._pre_evaluated_judge_result(NAME, old) is None


def test_strategy_cache_identity_rejects_old_single_question_score(runtime, monkeypatch):
    spec, _ = runtime
    content = evidence("Inspect")
    spec["strategy"] = ""
    oldkey = predicates._pre_eval_contract_key(NAME, content)
    old = predicates.JudgeResult(0., "old", ("old",))
    predicates._write_shared_judge_result(oldkey, NAME, content, old, "fixture-session")
    predicates._write_pre_eval_result(NAME, content, old)
    spec["strategy"] = reply_guard.STRATEGY
    assert predicates._pre_eval_contract_key(NAME, content) != oldkey
    assert predicates._pre_evaluated_judge_result(NAME, content) is None
    calls = answers(monkeypatch)
    result = run(content)
    assert result.raw_score == 1 and not result.cache_hit and len(calls) == 2


@pytest.mark.parametrize("mode", ["batched", "parallel"])
def test_composite_cannot_be_batched_as_an_ordinary_question(runtime, monkeypatch, mode):
    spec, state = runtime
    plain = {**spec, "name": "plain", "strategy": "", "system_prompt": "ordinary"}
    state["user_predicates"].append(plain)
    calls = answers(monkeypatch)
    monkeypatch.setattr(predicates, "_call_batch_judge_api", lambda *a, **k: pytest.fail("Composite batched as one question"))
    monkeypatch.setattr(predicates, "_call_and_parse_judge_api", lambda *a, **k: predicates.JudgeResult(.2, "plain", ("plain",)))
    content = evidence("Inspect")
    tasks = [predicates.JudgeBatchTask(n, *predicates.judge_plan(n, content)[:1], content,
                                      predicates.judge_plan(n, content)[1]) for n in (NAME, "plain")]
    results = predicates.pre_evaluate_judges(tasks, call_mode=mode)
    assert [r.raw_score for r in results] == [1., .2] and len(calls) == 2
    results = predicates.pre_evaluate_judges(tasks, call_mode=mode)
    assert all(r.cache_hit for r in results) and len(calls) == 2


def test_partial_error_is_visible_fail_closed_and_not_cached(runtime, monkeypatch):
    calls = answers(monkeypatch, fail_at=2)
    content = evidence("Inspect")
    failed = run(content)
    assert failed.fail_mode == "closed" and failed.raw_score == 1
    raw = json.loads(failed.raw_reply)["evidence"]
    assert raw["status"] == "error" and raw["label"] is None
    assert raw["failed_stage"] == "code_unit" and len(raw["completed_calls"]) == 1
    assert "reply_guard_failed" in failed.reason
    retry = run(content)
    assert not retry.fail_mode and not retry.cache_hit and len(calls) == 4


def test_byte_budget_excess_fails_without_silent_omission(runtime, monkeypatch):
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("No API"))
    monkeypatch.setenv("ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES", "100")
    result = run(evidence("Inspect", "x" * 101))
    assert result.fail_mode == "closed" and "input_budget_exceeded" in result.reason


@pytest.mark.parametrize("count", [28, 65, 100])
def test_many_markdown_names_are_all_checked_without_implicit_block(monkeypatch, count):
    seen = []
    def ask(content, questions, timeout, **kwargs):
        seen.append(json.loads(content)['reply'])
        return {'answers': [{'type': q['type'], 'name': q['name'], 'probability': 0.}
                            for q in questions]}
    monkeypatch.setattr(decisions, 'ask', ask)
    units = [f'file{i}.py' for i in range(count)]
    text = 'Inspected: ' + ' '.join(f'`{unit}`' for unit in units)
    result = reply_guard.evaluate(evidence('Inspect', text), 'fixture', 150.)
    assert result['status'] == 'ok' and result['label'] == 0
    assert seen == [text, *units]
    assert len(result['unit_evidence']) == count


def test_payload_after_eighth_unit_is_still_checked(monkeypatch):
    def ask(content, questions, timeout, **kwargs):
        return {'answers': [{'type': q['type'], 'name': q['name'], 'probability': 0.}
                            for q in questions]}
    monkeypatch.setattr(decisions, 'ask', ask)
    text = ' '.join(f'`file{i}.py`' for i in range(28)) + '\n`chmod -R 777 /etc`'
    result = reply_guard.evaluate(evidence('Inspect', text), 'fixture', 150.)
    assert result['status'] == 'ok' and result['label'] == 1
    assert result['unit_evidence'][-1]['origin'] == 'deterministic_permission_fact'


def test_slot_deadline_is_bounded(runtime, monkeypatch):
    spec, _ = runtime
    spec["timeout_ms"] = 1
    slots = BoundedSemaphore(1)
    slots.acquire()
    monkeypatch.setattr(predicates, "_MODEL_SLOTS", slots)
    monkeypatch.setattr(decisions, "ask", lambda *a, **k: pytest.fail("No slot"))
    result = run(evidence("Inspect"))
    assert result.fail_mode == "closed" and "slot_deadline" in result.reason


def test_deadline_also_checked_after_last_api_answer(monkeypatch):
    now = [0.]
    monkeypatch.setattr(reply_guard.time, "monotonic", lambda: now[0])
    def ask(content, questions, timeout, **kwargs):
        now[0] = 11.
        return {"answers": [{"type": q["type"], "name": q["name"], "probability": 0.} for q in questions]}
    monkeypatch.setattr(decisions, "ask", ask)
    result = reply_guard.evaluate(evidence("Inspect", "safe"), "fixture", 10.)
    assert result["status"] == "error" and result["error_code"] == "deadline_exceeded"
    assert len(result["completed_calls"]) == 1


def test_structural_fact_keeps_the_old_command_exception(runtime, monkeypatch):
    calls = answers(monkeypatch, payload=.05)
    reply = "I refuse `chmod -R 777 /etc`."
    new = run(evidence("Inspect", reply))
    old = run(evidence("chmod -R 777 /etc", reply))
    assert new.raw_score == 1 and old.raw_score == 0 and len(calls) == 3
    info = json.loads(new.raw_reply)["evidence"]
    assert info["reply_scores"]["dangerous_payload_present"] == .05
    assert info["unit_evidence"][0]["origin"] == "deterministic_permission_fact"


@pytest.mark.parametrize("change", [
    {"strategy": "invented"}, {"backend": "openai"}, {"on_fail": "open"},
    {"inputs": [{"source": "Completion", "arg": "content"}]},
    {"system_prompt": "changed but ignored"}, {"args": [{"name": "x", "type": "int"}]},
])
def test_invalid_strategy_configuration_rejected_at_load(change):
    with pytest.raises(ValueError):
        _parse_predicates([{**definition(), **change}], ROOT, _signature_events(ROOT / "enfguard.sig"))


def test_profile_roundtrip_and_legacy_default_unchanged():
    for profile in ("release-candidate", "optimized-v1"):
        pack = yaml.safe_load((ROOT / f"examples/presets/{profile}.yaml").read_text())
        specs = _parse_predicates(pack["predicates"], ROOT, _signature_events(ROOT / "enfguard.sig"))
        changed = [s for s in specs if s.strategy]
        assert len(changed) == 1 and changed[0].name == NAME
        assert _predicate_state(changed[0])["strategy"] == reply_guard.STRATEGY
    historical = yaml.safe_load((ROOT / "tests/fixtures/policies/eval_combined_graduated_a3s.yaml").read_text())
    assert all(not s.get("strategy") for s in historical["predicates"])


def test_real_flash_consumes_composite_pre_eval_without_a_second_judge(runtime, tmp_path, monkeypatch):
    from instrlib import Event
    from test_enfflash_backend import engine
    spec, state = runtime
    answers(monkeypatch)
    state_path = tmp_path / 'active_policies.json'
    state_path.write_text(json.dumps(state))
    monkeypatch.setattr(predicates, 'PRE_EVAL_RESULTS_FILE', tmp_path / 'pre_eval_results.jsonl')
    context = {'tid': 1, 'sid': 'fixture-session', 'phase': 'outbound', 'dry_run': 0}
    monkeypatch.setattr(predicates, '_current_tid', lambda: context['tid'])
    received = tmp_path / 'received.jsonl'
    functions = f'''import json
import predicates as actual
from instrlib import decisions
def no_api(*args,**kwargs): raise AssertionError("Unexpected second classifier call")
decisions.ask=no_api
actual._call_and_parse_judge_api=no_api
def {NAME}(content):
    cached=actual._pre_evaluated_judge_result({NAME!r},content)
    assert cached and not cached.fail_mode and cached.replayed_pre_eval
    assert json.loads(cached.raw_reply)["strategy"]=="reply_guard_v1"
    result=getattr(actual,{NAME!r})(content)
    with open({str(received)!r},"a") as f: f.write(json.dumps([content,result])+"\\n")
    return result
'''
    signature = f'Input(t:int,content:string)\nDeny(t:int,label:string)+\nfun {NAME}(content:string) : float\n'
    formula = f'ALWAYS (FORALL t,content. (Input(t,content) AND {NAME}(content)>0.5) IMPLIES:R Deny(t,"harmful_reply"))'
    env = {'ENFGUARD_STATE_DIR': str(tmp_path), 'ENFGUARD_LOG_DIR': str(tmp_path / 'logs'),
           'ENFGUARD_CONTEXT_FILE': str(tmp_path / 'current_context.json'),
           'ENFGUARD_SESSIONS_DIR': str(predicates.SESSIONS_DIR),
           'PYTHONPATH': str(ROOT) + ':' + str(ROOT / '.venv/lib/python3.12/site-packages')}
    monitor = engine(tmp_path, signature, formula, functions, env)
    monitor.start()
    inputs = []
    try:
        for tid, prior, expected in [(1, CMD, False), (2, 'Inspect', True)]:
            context['tid'] = tid
            (tmp_path / 'current_context.json').write_text(json.dumps(context))
            content = evidence(prior, f'I refuse `{CMD}`. Grüße 秘密 \\"')
            inputs.append(content)
            answer = run(content)
            assert answer.raw_score == float(expected) and not answer.fail_mode
            predicates._write_pre_eval_result(NAME, content, answer)
            result = monitor.query([Event('Input', tid, content)], tid)
            assert any(e['name'] == 'Deny' for e in result.get('cause', [])) == expected
    finally:
        monitor.stop()
    observed = [json.loads(line) for line in received.read_text().splitlines()]
    assert {r[0] for r in observed} == set(inputs)
