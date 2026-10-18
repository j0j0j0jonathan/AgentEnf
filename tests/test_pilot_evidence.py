import json
from pathlib import Path

import pytest

from experiments.paper.fixture_snapshot import capture
from experiments.paper.pilot_evidence import export_run


def test_snapshot_exact_unicode_binary_and_explicit_absence(tmp_path):
    (tmp_path / 'a').write_text('Grüße 秘密')
    (tmp_path / 'binary').write_bytes(b'\xff\x00')
    result = capture([str(tmp_path), str(tmp_path / 'missing')])
    rows = {r['path']: r for r in result['records']}
    assert rows[str(tmp_path / 'a')]['text'] == 'Grüße 秘密'
    assert rows[str(tmp_path / 'binary')]['base64'] == '/wA='
    assert rows[str(tmp_path / 'missing')]['status'] == 'absent'
    assert result['complete_within_declared_roots']


def test_snapshot_no_symlink_escape_or_silent_budget_drop(tmp_path):
    fixture = tmp_path / 'fixture'; fixture.mkdir()
    (tmp_path / 'private').write_text('DO NOT READ')
    (fixture / 'link').symlink_to(tmp_path / 'private')
    (fixture / 'large').write_text('x' * 100)
    result = capture([str(fixture)], max_file_bytes=20)
    assert not result['complete_within_declared_roots']
    assert not result['records']
    assert {r['reason'] for r in result['gaps']} == {'ValueError', 'byte_budget'}
    assert 'DO NOT READ' not in json.dumps(result)


def test_export_preserves_runtime_evidence_but_removes_rule_labels(tmp_path):
    run = {'turn_results': [{'user_message': 'request', 'agent_response': 'response', 'success': True,
           'new_logs': [{'phase': 'start', 'tool_call_id': 'c', 'args': {'path': '/app/a'}},
                        {'phase': 'result', 'tool_call_id': 'c', 'result': 'denied'}]}]}
    (tmp_path / 'rollout.json').write_text(json.dumps(run))
    (tmp_path / 'runtime').mkdir()
    row = {'phase': 'after_tool_call', 'call_id': 'c', 'effect_executed': False,
           'exit_code': 0, 'policy_decision': 'Block', 'reason': 'SECRET_RULE',
           'raw': {'decision_trace': {'tool_execution': {'outcome': 'not_executed'}}}}
    (tmp_path / 'runtime/enfguard-verdicts.jsonl').write_text(json.dumps(row) + '\n')
    for phase in ['before', 'after']:
        (tmp_path / f'fixture-{phase}.json').write_text(json.dumps({'records': [], 'gaps': []}))
    (tmp_path / 'agent_requests').mkdir()
    (tmp_path / 'agent_requests/r.json').write_text(json.dumps({'request': {'input': 'hello'},
                                                              'response_body': 'generated only'}))
    bundle = export_run(tmp_path, {'id': 'h', 'effects': [{'id': 'e'}]}, run_id='opaque')
    assert bundle['coverage']['complete_tool_logs'] == 2
    payload = next(r['payload'] for r in bundle['evidence'] if r['kind'] == 'trusted_runtime_observation')
    assert payload['reported_outcome'] == 'not_executed' and 'exit_code' not in payload
    assert 'SECRET_RULE' not in json.dumps(bundle)
    assert any(r['kind'] == 'observed_model_response_body' for r in bundle['evidence'])
    assert any(g['gap'] == 'no trusted startup-context manifest' for g in bundle['gaps'])
