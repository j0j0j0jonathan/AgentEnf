"""Collect only frozen disposable-fixture evidence; never infer effects from verdicts."""
import json
from pathlib import Path
import subprocess

from experiments.paper.evidence_bundle import build


def snapshot_container(container_id, destination, roots):
    source = Path(__file__).with_name('fixture_snapshot.py').read_text()
    result = subprocess.run(['docker', 'exec', '-i', container_id, 'python3', '-c', source,
                             json.dumps(roots)], capture_output=True, text=True, timeout=60)
    if result.returncode:
        data = {'records': [], 'gaps': [{'reason': 'snapshot_process_failed',
                                       'returncode': result.returncode}],
                'complete_within_declared_roots': False}
    else:
        data = json.loads(result.stdout)
    Path(destination).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    return data


def export_run(path, contract, *, run_id):
    path = Path(path)
    run = json.loads((path / 'rollout.json').read_text())
    observations, artifacts = [], []
    for source in sorted((path / 'runtime').rglob('enfguard-verdicts.jsonl')):
        for line in source.read_text().splitlines():
            row = json.loads(line)
            # Strip rule names, verdict categories, rationales and raw responses.
            # Before-hook means pending/denied; after-hook does not prove effects.
            allowed = {'ts', 'phase', 'call_id', 'tool', 'effect_executed', 'runtime_decision',
                       'infrastructure_fault', 'result_enforcement_supported'}
            observation = {k: v for k, v in row.items() if k in allowed}
            execution = row.get('raw', {}).get('decision_trace', {}).get('tool_execution', {})
            if 'outcome' in execution:
                observation['reported_outcome'] = execution['outcome']
            # Do not copy fallback exit_code=0 as proof of success; a tool may
            # return a failing exit status only inside its result structure.
            observations.append(observation)
    for phase in ('before', 'after'):
        source = path / ('fixture-' + phase + '.json')
        if source.exists():
            artifacts.append({'phase': phase, 'snapshot': json.loads(source.read_text())})
    bundle = build(run, contract, run_id=run_id, runtime_observations=observations, artifacts=artifacts)
    for phase in ('before', 'after'):
        if not (path / ('fixture-' + phase + '.json')).exists():
            bundle['gaps'].append({'gap': f'missing {phase} fixture snapshot'})
    for artifact in artifacts:
        for gap in artifact['snapshot'].get('gaps', []):
            bundle['gaps'].append({'phase': artifact['phase'], **gap})
    # These are observed API bodies, not loader receipts and not user delivery.
    from experiments.paper.evidence_bundle import digest
    for i, source in enumerate(sorted((path / 'agent_requests').glob('*.json'))):
        row = json.loads(source.read_text())
        if 'request' not in row:
            bundle['gaps'].append({'gap': 'failed model request capture', 'ordinal': i})
            continue
        for name in ('request', 'response_body'):
            if name not in row:
                bundle['gaps'].append({'gap': 'missing model ' + name, 'ordinal': i})
                continue
            payload = row[name]
            bundle['evidence'].append({'ref': f'tested/{run_id}/model/{i}/{name}',
                                      'kind': 'observed_model_' + name,
                                      'payload': payload, 'sha256': digest(payload)})
    bundle['coverage']['evidence_utf8_bytes'] = len(json.dumps(bundle['evidence'], ensure_ascii=False).encode())
    (path / 'harm-evidence.json').write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + '\n')
    return bundle
