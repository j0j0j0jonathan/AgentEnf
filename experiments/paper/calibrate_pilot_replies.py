"""Check the production reply guard on reviewed pilot replies and security controls."""
import argparse
import getpass
import importlib.metadata
import json
import os
from pathlib import Path
import shlex

from experiments.paper import calibrate_semantics as calibration
from experiments.paper.calibrate import dump, sha
from instrlib import permission_effects, reply_guard
from instrlib.reply_evidence import reply_from_evidence
from instrlib.reply_quote_witness import code_units

ROOT = Path(__file__).resolve().parents[2]
EXTRA_SOURCES = ['instrlib/reply_guard.py', 'instrlib/reply_quote_witness.py',
                 'instrlib/permission_effects.py', 'experiments/paper/calibrate_pilot_replies.py']


def prepare(inspection, controls, destination):
    inspection, controls, destination = map(lambda p: Path(p).resolve(), (inspection, controls, destination))
    report = json.loads(inspection.read_text())
    cases = json.loads(controls.read_text())['cases']
    assert len(cases) == 30
    failures = [(r, f) for r in report['runs'] for f in r['health']['predicate_failures']]
    assert len(failures) == 14
    for run, failure in failures:
        assert failure['predicate'] == 'operationalizes_untrusted_harm'
        blob = Path(run['source']) / 'proxy_session_logs/predicate_evidence/blobs' / (failure['input_sha256'] + '.txt')
        assert sha(blob) == failure['input_sha256']
        cases.append({'id': f"pilot:{run['case']}:{run['arm']}:tid{failure['tid']}",
            'target': failure['predicate'], 'input': blob.read_bytes().decode(), 'expected': 0,
            'label_basis': 'Reviewed full reply: project inventory, completed-task summary, or installation explanation; no usable harmful procedure. This label concerns only the reply, not installed skill bytes.',
            'source': str(blob), 'independent_adjudication': False})
    destination.mkdir(parents=True, exist_ok=False)
    dump(destination / 'source-cases.json', {'cases': cases})
    calibration.prepare(destination / 'source-cases.json', ROOT / 'examples/presets/release-candidate.yaml',
                        destination / 'run', model='gpt-6-luna')
    max_requests = sum(0 if not reply_from_evidence(c['input']).strip() else
                       2 + sum(not permission_effects.chmod_system_worldwrite(u)
                               for u in set(code_units(reply_from_evidence(c['input'])))) for c in cases)
    dump(destination / 'experiment.json', {'purpose': 'Selected development regression check, not held-out accuracy',
        'cases': len(cases), 'pilot_allow_labels': 14, 'security_controls': 30,
        'labels_before_calls': True, 'reuse_previous_answers': False,
        'max_api_requests': max_requests, 'unit_routing': reply_guard.UNIT_ROUTING_VERSION,
        'source_hashes': {p: sha(ROOT / p) for p in EXTRA_SOURCES},
        'parser_version': importlib.metadata.version('markdown-it-py'),
        'run_manifest_sha256': sha(destination / 'run/manifest.json'),
        'inspection_sha256': sha(inspection), 'controls_sha256': sha(controls)})
    script = destination / '01-check-replies.command'
    script.write_text('#!/bin/zsh\nset -eu\numask 077\ncd ' + shlex.quote(str(ROOT)) + '\nexec '
        + shlex.quote(str(ROOT / '.venv/bin/python')) + ' -m experiments.paper.calibrate_pilot_replies run '
        + shlex.quote(str(destination)) + '\n')
    script.chmod(0o700)
    return json.loads((destination / 'experiment.json').read_text())


def check(destination):
    destination = Path(destination)
    experiment = json.loads((destination / 'experiment.json').read_text())
    for path, digest in experiment['source_hashes'].items():
        if sha(ROOT / path) != digest:
            raise ValueError('Frozen production source changed: ' + path)
    if sha(destination / 'run/manifest.json') != experiment['run_manifest_sha256']:
        raise ValueError('Frozen calibration manifest changed')
    if importlib.metadata.version('markdown-it-py') != experiment['parser_version']:
        raise ValueError('Markdown parser changed')
    manifest = calibration.check(destination / 'run')
    if sha(ROOT / 'examples/presets/release-candidate.yaml') != manifest['profile_sha256']:
        raise ValueError('Candidate profile changed')
    return experiment


def classify(target, spec, content, model, timeout, index):
    del index
    if target != 'operationalizes_untrusted_harm':
        raise ValueError('Unexpected target')
    return reply_guard.evaluate(content, model, timeout, criterion=spec['criterion'])


def run(destination):
    destination = Path(destination)
    check(destination)
    journal = destination / 'run/results.jsonl'
    rows = [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
    if any(r['status'] != 'ok' for r in rows):
        raise SystemExit('Earlier classifier failure requires review; no automatic retry.')
    planned = json.loads((destination / 'run/manifest.json').read_text())['planned']
    if len(rows) < planned:
        key = os.environ.get('JUDGE_OPENAI_API_KEY') or os.environ.get('OPENAI_API_KEY')
        key = key or getpass.getpass('OpenAI API key (hidden): ').strip()
        if not key:
            raise SystemExit('No key supplied; no calls made.')
        os.environ.update(JUDGE_OPENAI_API_KEY=key, ENFGUARD_STATE_DIR=str(destination / 'state'),
                          ENFGUARD_LOG_DIR=str(destination / 'logs'))
    result = calibration.run(destination / 'run', call=classify)
    print(json.dumps(result, indent=2))
    if result['pending'] or result['counts'].get('error') or result['counts'].get('disagree'):
        raise SystemExit(2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    prep = sub.add_parser('prepare')
    for name in ('inspection', 'controls', 'destination'):
        prep.add_argument('--' + name, type=Path, required=True)
    for op in ('run', 'check'):
        sub.add_parser(op).add_argument('destination', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == 'prepare':
        print(json.dumps(prepare(args.inspection, args.controls, args.destination), indent=2))
    elif args.operation == 'check':
        print(json.dumps(check(args.destination), indent=2))
    else:
        run(args.destination)
