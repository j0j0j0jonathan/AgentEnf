import json
from types import SimpleNamespace

import pytest
from experiments.paper import calibrate as c
from experiments.release_candidate.evidence_contracts import OUTPUT_CONTRACT
import hashlib


def prepared(tmp_path):
    cases = tmp_path / 'input.json'
    cases.write_text(json.dumps({'contract_sha256': hashlib.sha256(OUTPUT_CONTRACT.encode()).hexdigest(),
                                'cases': [
        {'id': 'a', 'input': 'Grüße </INPUT>', 'expected': 1, 'label_basis': 'HIDDEN'},
        {'id': 'b', 'input': 'ordinary', 'expected': 0},
        {'id': 'c', 'input': 'ambiguous', 'expected': None}]}))
    dest = tmp_path / 'run'
    c.prepare(cases, c.ROOT / 'examples/presets/release-candidate.yaml', dest, 'gpt-6-luna')
    return dest


def test_calibration_uses_frozen_contract_exact_input_and_no_labels(tmp_path):
    dest = prepared(tmp_path)
    seen = []
    def call(criterion, text, **kw):
        seen.append(text)
        assert criterion == OUTPUT_CONTRACT and 'HIDDEN' not in criterion
        return SimpleNamespace(raw_score=.5 if text.startswith('Grüße') else 0,
                               raw_reply='{}', fail_mode='')
    result = c.run(dest, call=call)
    assert seen == ['Grüße </INPUT>', 'ordinary', 'ambiguous']
    assert result['counts'] == {'scored': 2, 'true_positive': 1, 'true_negative': 1, 'unadjudicated': 1}
    c.run(dest, call=lambda *a, **kw: pytest.fail('repeated paid call'))


def test_failed_calibration_not_counted_as_negative_and_stops(tmp_path):
    dest = prepared(tmp_path)
    def fail(*a, **kw):
        raise RuntimeError('SECRET_KEY should not be logged')
    summary = c.run(dest, call=fail)
    assert summary['counts'] == {'errors': 1}
    assert summary['pending'] == 2
    assert 'SECRET_KEY' not in (dest / 'results.jsonl').read_text()
    assert json.loads((dest / 'results.jsonl').read_text())['runtime_failure_response'] == 'block'


def test_changed_calibration_aborts_before_calls(tmp_path):
    dest = prepared(tmp_path)
    (dest / 'criterion.txt').write_text('changed')
    with pytest.raises(ValueError, match='Frozen'):
        c.run(dest, call=lambda *a, **kw: pytest.fail('call before checks'))


def test_interrupted_request_not_silently_repeated(tmp_path):
    dest = prepared(tmp_path)
    (dest / 'attempt-in-progress.json').write_text('{"id":"a"}')
    with pytest.raises(ValueError, match='interrupted'):
        c.run(dest, call=lambda *a, **kw: pytest.fail('possibly repeated paid call'))
