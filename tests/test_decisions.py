"""Contract and integration tests; no live API calls or paid requests."""
import json

import httpx
import pytest

import predicates
from instrlib import decisions as d, tool_judge as tj
from yaml_loader import _parse_backend, _parse_predicates
from pathlib import Path


def reply(questions, probability=.9):
    return {'model': d.DEFAULT_MODEL, 'usage': {'input_tokens': 10}, 'answers': [
        {'name': q['name'], 'type': q['type'], **(
            {'probability': probability} if q['type'] == 'predicate' else
            {'choice': q['choices'][0]['value'], 'confidence': .98})} for q in questions]}


@pytest.mark.parametrize('answer', [
    {'type': 'refusal', 'name': 'x'},
    {'type': 'predicate', 'name': 'x', 'probability': float('nan')},
    {'type': 'predicate', 'name': 'x', 'probability': True},
    {'type': 'predicate', 'name': 'x', 'probability': 1.01},
    {'type': 'predicate', 'name': 'wrong', 'probability': .9},
    None,
])
def test_invalid_or_refused_answers_are_errors(answer):
    with pytest.raises(ValueError):
        d.validate({'answers': [answer]}, [d.predicate_question('x', 'criterion')])


def test_count_and_choice_contract():
    question = {'type': 'choice', 'name': 'x', 'choices': [{'value': 'benign'}]}
    for answers in [[], [{'type': 'choice', 'name': 'x', 'choice': 'invented', 'confidence': 1}]]:
        with pytest.raises(ValueError):
            d.validate({'answers': answers}, [question])


def test_transport_uses_dedicated_endpoint_and_keeps_api_metadata(monkeypatch):
    monkeypatch.setenv('JUDGE_OPENAI_API_KEY', 'test-key')
    monkeypatch.setenv('OPENAI_BASE_URL', 'http://agent-proxy.invalid')
    monkeypatch.setenv('ENFGUARD_DECISIONS_BASE_URL', 'https://decisions.example/v1')
    def handler(request):
        assert str(request.url) == 'https://decisions.example/v1/decisions'
        assert request.headers['Authorization'] == 'Bearer test-key'
        body = json.loads(request.content)
        assert body['input'] == 'input'
        assert 'messages' not in body
        return httpx.Response(200, json=reply(body['questions']))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        monkeypatch.setattr(d, '_client', client)
        data = d.ask('input', [d.predicate_question('x', 'criterion')], 1)
        assert data['usage']['input_tokens'] == 10


def test_transport_missing_key_and_http_error(monkeypatch):
    monkeypatch.delenv('JUDGE_OPENAI_API_KEY', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    with pytest.raises(RuntimeError, match='key missing'):
        d.ask('input', [], 1)
    monkeypatch.setenv('OPENAI_API_KEY', 'test-key')
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(429))) as client:
        monkeypatch.setattr(d, '_client', client)
        with pytest.raises(httpx.HTTPStatusError):
            d.ask('input', [], 1)


def test_single_probability_reaches_policy_parser(monkeypatch):
    monkeypatch.setattr(d, 'ask', lambda content, qs, timeout, **kw: reply(qs, .99))
    monkeypatch.setattr(predicates, '_dispatch_judge', lambda **kw: pytest.fail('Generation fallback'))
    result = predicates._call_and_parse_judge_api('criterion', 'text', backend='openai_decisions', model=d.DEFAULT_MODEL, timeout_ms=1000)
    assert result.raw_score == .99
    assert 'no textual explanation' in result.reason
    assert json.loads(result.raw_reply)['decisions']['model'] == d.DEFAULT_MODEL


def test_batch_separates_inputs_and_preserves_indices(monkeypatch):
    seen = []
    def ask(content, qs, timeout, **kw):
        seen.append((content, len(qs)))
        return reply(qs, .9 if content == 'A' else .1)
    monkeypatch.setattr(d, 'ask', ask)
    tasks = [predicates.JudgeBatchTask('a', 'criterion', 'A'), predicates.JudgeBatchTask('b', 'criterion', 'B'), predicates.JudgeBatchTask('c', 'criterion', 'A')]
    raw = predicates._call_batch_judge_api(tasks, backend='openai_decisions', model=d.DEFAULT_MODEL, timeout_ms=1000)
    parsed = predicates._parse_batch_judge_reply(raw, tasks)
    assert [parsed[i].raw_score for i in range(3)] == [.9, .1, .9]
    assert seen == [('A', 2), ('B', 1)]


@pytest.mark.parametrize('adapter', ['unknown_tool', 'unknown_tool_gate', 'url_risk', 'package_name', 'webshell', 'persistence_instruction', 'secret_material', 'content_disclosure', 'content_semantics', 'memory_poison', 'authored_capability', 'uncertain_action', 'semantic_command'])
def test_routed_adapters_use_typed_answers_without_generation(monkeypatch, adapter):
    monkeypatch.setenv('ENFGUARD_TOOL_JUDGE_BACKEND', 'openai_decisions')
    monkeypatch.setattr(d, 'ask', lambda content, qs, timeout, **kw: reply(qs))
    monkeypatch.setattr(tj, '_call_openai', lambda *a, **kw: pytest.fail('Generation fallback'))
    result = json.loads(tj._dispatch(adapter, 'input', 1, 'criterion'))
    assert result['decisions']['model'] == d.DEFAULT_MODEL
    assert len(result) > 1


def test_refusal_propagates_without_generation_fallback(monkeypatch):
    monkeypatch.setenv('ENFGUARD_TOOL_JUDGE_BACKEND', 'openai_decisions')
    def fail(*a, **kw):
        raise ValueError('Decisions API refused')
    monkeypatch.setattr(d, 'ask', fail)
    monkeypatch.setattr(tj, '_call_openai', lambda *a, **kw: pytest.fail('Generation fallback'))
    with pytest.raises(ValueError, match='refused'):
        tj._dispatch('secret_material', 'input', 1, 'criterion')
    with pytest.raises(ValueError, match='refused'):
        predicates._call_and_parse_judge_api('criterion', 'text', backend='openai_decisions', model=d.DEFAULT_MODEL, timeout_ms=1000)


def test_configuration_and_per_predicate_override(monkeypatch):
    backend = _parse_backend({'judge_backend': 'openai_decisions'}, Path('.'))
    assert backend.judge_decisions_model == d.DEFAULT_MODEL
    monkeypatch.setenv('JUDGE_BACKEND', 'openai_decisions')
    monkeypatch.setenv('JUDGE_DECISIONS_MODEL', d.DEFAULT_MODEL)
    monkeypatch.setattr(predicates, '_user_predicate_specs', lambda: [{'name': 'legacy', 'backend': 'openai', 'model': 'gpt-4o-mini'}])
    assert predicates._judge_config('new')[:2] == ('openai_decisions', d.DEFAULT_MODEL)
    assert predicates._judge_config('legacy')[:2] == ('openai', 'gpt-4o-mini')


def test_yaml_accepts_decisions_predicate():
    specs = _parse_predicates([{'name': 'secret_request', 'kind': 'llm_judge',
        'backend': 'openai_decisions', 'model': d.DEFAULT_MODEL,
        'system_prompt': 'Requests exact values',
        'inputs': [{'source': 'Message', 'arg': 'content'}]}], Path('.'),
        {'Message': ('tid', 'role', 'content', 'n')})
    assert specs[0].backend == 'openai_decisions'


@pytest.mark.parametrize('mode, expected', [('closed', 1.0), ('open', 0.0)])
def test_predicate_fail_mode_is_preserved_and_failure_not_cached(monkeypatch, mode, expected):
    monkeypatch.setattr(predicates, '_judge_config', lambda name: ('openai_decisions', d.DEFAULT_MODEL, 1000))
    monkeypatch.setattr(predicates, '_pre_evaluated_judge_result', lambda *a: None)
    monkeypatch.setattr(predicates, '_cached_judge_result', lambda *a: None)
    monkeypatch.setattr(predicates, '_judge_fail_mode', lambda name: mode)
    monkeypatch.setattr(predicates, '_write_shared_judge_result', lambda *a: pytest.fail('Cached failure'))
    calls = []
    def fail(*a, **kw):
        calls.append(1)
        raise ValueError('Decisions API refused')
    monkeypatch.setattr(d, 'ask', fail)
    for _ in range(2):
        result = predicates._judge('secret_request', 'criterion', 'input')
        assert result.raw_score == expected
        assert result.fail_mode == mode
    assert len(calls) == 2


def test_routed_classifier_preserves_fail_open(monkeypatch):
    monkeypatch.setenv('ENFGUARD_TOOL_JUDGE_BACKEND', 'openai_decisions')
    def fail(*a, **kw):
        raise ValueError('Decisions API refused')
    monkeypatch.setattr(d, 'ask', fail)
    assert tj.classify_secret_material_with_status('the password is example') == (None, 'failed_open')
