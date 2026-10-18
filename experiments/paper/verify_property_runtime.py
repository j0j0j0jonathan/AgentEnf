"""Replay the 20 frozen property answers through actual candidate registrations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
import yaml

import proxy
from instrlib import decisions, judge_capture, tool_mapper
from instrlib.property_contracts import VERSION, VALUE_CRITERION, FLOW_CRITERION
from yaml_loader import _parse_ingest_judges
from experiments.paper.calibrate import dump, sha

ROOT = Path(__file__).resolve().parents[2]


def verify(previous, output):
    previous, output = Path(previous).resolve(), Path(output).resolve()
    checked = json.loads((previous.parent.parent / 'semantic-followup-review/verified-results.json').read_text())
    assert sha(previous / 'results.jsonl') == checked['arms']['candidate']['results_sha256']
    manifest = json.loads((previous / 'manifest.json').read_text())
    assert sha(previous / 'cases.json') == manifest['cases_sha256']
    assert sha(previous / 'targets.json') == manifest['targets_sha256']
    targets = json.loads((previous / 'targets.json').read_text())
    criteria = {'content_disclosure': VALUE_CRITERION, 'authored_capability': FLOW_CRITERION}
    assert all(criteria[name] == targets[name]['criterion'] for name in criteria)
    cases = json.loads((previous / 'cases.json').read_text())['cases']
    rows = [json.loads(line) for line in (previous / 'results.jsonl').read_text().splitlines()]
    assert len(cases) == len(rows) == 20
    assert len({row['id'] for row in rows}) == 20
    output.mkdir(parents=True, exist_ok=False)
    pack = yaml.safe_load((ROOT / 'examples/presets/release-candidate.yaml').read_text())
    config = _parse_ingest_judges(pack['backend']['ingest_judges'], True)
    assert config.property_contract == VERSION
    results = []
    with patch.object(proxy.state, 'ingest_judges', config), patch.dict(os.environ, {
        'ENFGUARD_TOOL_JUDGE': '1', 'ENFGUARD_TOOL_JUDGE_BACKEND': 'openai_decisions',
        'ENFGUARD_TOOL_JUDGE_MODEL': manifest['model'],
        **{'ENFGUARD_TOOL_JUDGE_MODEL_' + name.upper(): manifest['model'] for name in criteria}}):
        proxy._configure_ingest_judges()
        for tid, (case, row) in enumerate(zip(cases, rows, strict=True), 1):
            assert case['id'] == row['id'] and row['status'] == 'ok'
            assert hashlib.sha256(case['input'].encode()).hexdigest() == row['input_sha256']
            name = row['target']; raw = json.loads(row['calls'][0]['raw_reply'])['decisions']
            calls = []
            def ask(content, questions, timeout, **kwargs):
                assert content == 'file content:\n' + case['input']
                assert len(questions) == 1 and questions[0]['name'] == name
                assert criteria[name] in questions[0]['instructions']
                assert kwargs['model'] == manifest['model'] and kwargs['tool'] is True
                calls.append(content)
                return raw
            fn = tool_mapper._CONTENT_DISCLOSURE_JUDGE if name == 'content_disclosure' else tool_mapper._AUTHORED_CAPABILITY_JUDGE
            with patch.object(decisions, 'ask', ask), judge_capture.capturing(tid):
                label, status = fn(case['input'])
            assert len(calls) == 1
            assert (label or 'benign') == row['label'] == case['expected']
            assert status == row['adapter_status']
            captured = judge_capture.pop_judge_calls(tid)
            assert len(captured) == 1 and captured[0]['prompt_sha8'] == row['calls'][0]['prompt_sha8']
            results.append({'id': row['id'], 'target': name, 'label': label or 'benign', 'status': status})
    dump(output / 'results.json', results)
    sources = ['proxy.py', 'yaml_loader.py', 'instrlib/tool_judge.py', 'instrlib/property_contracts.py',
               'instrlib/decisions.py', 'examples/presets/release-candidate.yaml', 'experiments/paper/verify_property_runtime.py']
    summary = {'cases': 20, 'agreements': 20, 'new_api_calls': 0, 'recorded_calls_replayed': 20,
               'source_hashes': {p: sha(ROOT / p) for p in sources},
               'claim': 'registered candidate adapters replay; recorded answers, not new model accuracy'}
    dump(output / 'summary.json', summary)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--previous', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); print(json.dumps(verify(a.previous, a.output), indent=2))
