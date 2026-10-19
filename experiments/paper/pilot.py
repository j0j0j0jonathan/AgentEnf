"""Run a frozen three-arm development pilot, using the retained A3S launcher.

Startup guidance is unchanged unless the frozen manifest explicitly enables
the pinned prompt-builder experiment, identically in every arm. This is not a
thesis reproduction or a held-out panel.
"""
import argparse
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from experiments.paper.pilot_evidence import export_run, snapshot_container
from experiments.paper.pilot_health import require_healthy


def load_legacy(root):
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location('paper_legacy_runner', root / 'legacy_runner.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original_environment = module.environment
    def environment(path, arm, key):
        env = original_environment(path, arm, key)
        manifest = json.loads((root / 'manifest.json').read_text())
        env.update(AGENTENF_MONITOR_BACKEND='enfflash',
                   ENFFLASH_COMPILER=manifest['monitor']['compiler']['path'],
                   ENFFLASH_BIN=manifest['monitor']['runtime']['path'],
                   ENFGUARD_CAPTURE_PREDICATE_INPUTS='1',
                   ENFGUARD_DECISIONS_BASE_URL='https://api.openai.com',
                   JUDGE_DECISIONS_MODEL=manifest['classifier_model'])
        return env
    module.environment = environment
    original_validate = module.validate_run
    def validate(data, directory):
        original_validate(data, directory)
        require_healthy(directory, data)
    module.validate_run = validate
    original_collect = module.ct.collect_runtime_evidence
    def collect(cid, evidence_dir, *args):
        path = Path(evidence_dir).parent
        try:
            snapshot_container(cid, path / 'fixture-after.json', module.ROOTS)
        except Exception as exc:
            (path / 'fixture-after.json').write_text(json.dumps({
                'records': [], 'gaps': [{'reason': 'snapshot_failed', 'type': type(exc).__name__}],
                'complete_within_declared_roots': False}))
        return original_collect(cid, evidence_dir, *args)
    module.ct.collect_runtime_evidence = collect
    original_setup = module.ct.run_setup
    def setup(cid, commands):
        ok = original_setup(cid, commands)
        if ok:
            snapshot_container(cid, module.ACTIVE['paper_path'] / 'fixture-before.json', module.ROOTS)
        return ok
    module.ct.run_setup = setup
    # ACTIVE is reset by the retained launcher, so set the path during injection.
    original_inject = module.ct.inject_config
    def inject(*args, **kwargs):
        module.ACTIVE['paper_path'] = Path(module.relay.CURRENT['directory']).parent
        result = original_inject(*args, **kwargs)
        manifest = json.loads((root / 'manifest.json').read_text())
        if manifest.get('startup_guidance') == 'full-supplied-only-v1':
            from experiments.startup_context.install import install
            install(args[0], module.ACTIVE['paper_path'] / 'startup-guidance-install.json')
        elif manifest.get('startup_guidance') not in (None, 'unchanged'):
            raise ValueError('Unknown startup guidance experiment')
        return result
    module.ct.inject_config = inject
    return module


def check(root, *, docker=False):
    m = json.loads((root / 'manifest.json').read_text())
    hashes = json.loads((root / 'frozen-hashes.json').read_text())
    for name, expected in hashes.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Frozen pilot source changed: ' + name)
    for component in m['monitor'].values():
        if hashlib.sha256(Path(component['path']).read_bytes()).hexdigest() != component['sha256']:
            raise ValueError('Monitor binary differs from frozen build')
    if docker:
        result = subprocess.run(['docker', 'image', 'inspect', m['reference_image']],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Start Docker Desktop; the pinned reference image must be available.')
    return m


def calibration_ready(m):
    if 'validation' in m:
        from experiments.paper.validation_bundle import check, check_monitor
        runtime = Path(__file__).resolve().parents[2]
        path = runtime.parent / m['validation']['directory']
        if hashlib.sha256((path / 'manifest.json').read_bytes()).hexdigest() != m['validation']['manifest_sha256']:
            raise ValueError('Reviewed validation manifest changed')
        validation = check(path, runtime)
        check_monitor(validation, m['monitor'])
        if validation['model'] != m['classifier_model'] or validation['backend'] != m['classifier_backend']:
            raise ValueError('Validated classifier model/backend differs from pilot')
        return validation
    path = Path(m['calibration']['directory'])
    if hashlib.sha256((path / 'manifest.json').read_bytes()).hexdigest() != m['calibration']['manifest_sha256']:
        raise ValueError('Calibration manifest differs from the frozen pilot')
    cm = json.loads((path / 'manifest.json').read_text())
    runtime = Path(__file__).resolve().parents[2]
    for file, expected in cm['source_hashes'].items():
        if hashlib.sha256((runtime / file).read_bytes()).hexdigest() != expected:
            raise ValueError('Pilot and calibration classifier implementations differ: ' + file)
    if cm['model'] != m['classifier_model']:
        raise ValueError('Classifier model differs from calibration')
    # Recompute from the journal, not an editable aggregate summary.
    from experiments.paper.calibrate import summarize
    cases = json.loads((path / 'cases.json').read_text())['cases']
    if hashlib.sha256((path / 'cases.json').read_bytes()).hexdigest() != cm['case_sha256']:
        raise ValueError('Calibration cases changed')
    rows = [json.loads(x) for x in (path / 'results.jsonl').read_text().splitlines()]
    ids = [r['id'] for r in rows]
    if len(ids) != len(set(ids)) or set(ids) != {c['id'] for c in cases}:
        raise ValueError('Complete unique calibration results are required')
    inputs = {c['id']: hashlib.sha256(c['input'].encode()).hexdigest() for c in cases}
    for row in rows:
        if row.get('input_sha256') != inputs[row['id']]:
            raise ValueError('Calibration result references another input')
    summary = summarize(cases, rows)
    counts = summary['counts']
    if summary['pending'] or any(counts.get(k) for k in ('errors', 'false_positive', 'false_negative')):
        raise ValueError('Calibration failures/disagreements require review before this pilot')
    return summary


def select_schedule(manifest, *, full=False):
    if full:
        if manifest.get('status') == 'frozen_for_smoke_only':
            raise ValueError('Full collection is disabled until smoke review and a new freeze')
        return manifest['schedule']
    selected = manifest.get('smoke_schedule')
    if selected is None:
        return [row for row in manifest['schedule'] if row['rep'] == 1]
    if not selected or any(row not in manifest['schedule'] for row in selected):
        raise ValueError('Smoke schedule must be a nonempty subset of full schedule')
    identities = [(row['case'], row['arm'], row['rep']) for row in selected]
    if len(identities) != len(set(identities)):
        raise ValueError('Duplicate smoke trajectory')
    return selected


def main(root):
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--offline-check', action='store_true')
    g.add_argument('--check', action='store_true')
    g.add_argument('--smoke', action='store_true')
    g.add_argument('--full', action='store_true')
    args = p.parse_args()
    os.umask(0o077)
    root = Path(root).resolve()
    m = check(root, docker=not args.offline_check)
    if args.full:
        select_schedule(m, full=True)
    if 'validation' in m:
        calibration_ready(m)
    if args.check or args.offline_check:
        print(f"Frozen {len(m['cases'])}-case development pilot verified. No API calls.")
        return
    calibration_ready(m)
    r = load_legacy(root)
    for port in (9003, 19032):
        if not r.free(port):
            raise RuntimeError(f'Port {port} occupied; no existing service stopped.')
    key = os.environ.get('A3S_API_KEY') or os.environ.get('OPENAI_API_KEY')
    if not key:
        key = getpass.getpass('OpenAI API key (hidden): ').strip()
    if not key:
        raise SystemExit('No key supplied; no calls made.')
    os.environ['A3S_API_KEY'] = key
    server = r.relay.start()
    try:
        schedule = select_schedule(m, full=args.full)
        cases = {c['id']: c for c in m['cases']}
        arms = {a['name']: a for a in m['arms']}
        print(f'Collecting {len(schedule)} trajectories; official and additional judging remain separate.', flush=True)
        for row in schedule:
            case, arm = cases[row['case']], arms[row['arm']]
            path = root / 'live' / case['id'] / arm['name'] / f"run{row['rep']}"
            if (path / 'COMPLETE.json').exists():
                require_healthy(path, json.loads((path / 'rollout.json').read_text()))
            print(f"Starting {case['id']} {arm['name']} run{row['rep']}", flush=True)
            try:
                r.live(case, arm, row['rep'], m, key)
            finally:
                if (path / 'rollout.json').exists():
                    contract = json.loads((root / case['contract']).read_text())
                    identity_path = path / 'evidence-id.txt'
                    if not identity_path.exists():
                        identity_path.write_text(uuid.uuid4().hex)
                    bundle = export_run(path, contract, run_id=identity_path.read_text().strip())
                    r.dump(path / 'EVIDENCE_CHECK.json', {'coverage': bundle['coverage'],
                           'gaps': bundle['gaps'], 'additional_judge': 'not_run'})
    finally:
        server.shutdown(); server.server_close()
    print('Collection finished. Review evidence gaps and changed outcomes before extending the panel.')
