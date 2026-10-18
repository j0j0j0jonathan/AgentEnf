"""Prepare matched development arms from already-exposed, hashed inputs.

This writes a design manifest, not a runnable/frozen campaign. It never reads the
reserved held-out pool, starts containers, or calls a model.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[2]


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    old = json.loads((source / 'manifest.json').read_text())
    destination.mkdir(parents=True, exist_ok=False)
    cases = copy.deepcopy(old['cases'])
    assert len(cases) == 299 and sum(c['label'] == 'attack' for c in cases) == 150
    for case in cases:
        path = source / case['input']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == case['sha256'], case['id']
        target = destination / case['input']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    pack = yaml.safe_load((ROOT / 'examples/presets/optimized-v1.yaml').read_text())
    arms = [{'name': 'off', 'profile': None, 'enforcement': 'disabled', 'classifier_calls': 0}]
    for name, mode in [('candidate_strict', 'block'), ('candidate_permissive', 'warn')]:
        profile = copy.deepcopy(pack)
        profile['backend'].update(judge_backend='openai_decisions', judge_decisions_model='gpt-6-luna')
        for predicate in profile.get('predicates', []):
            if predicate.get('kind') == 'llm_judge':
                predicate.update(backend='openai_decisions', model='gpt-6-luna')
        profile['human_approval'].update(allow_headless_bypass=(mode == 'warn'), on_timeout='block')
        path = destination / f'{name}.yaml'
        path.write_text('# Isolated development comparison only.\n' + yaml.safe_dump(profile, sort_keys=False))
        arms.append(dict(name=name, profile=path.name, approval_mode=mode,
                         sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    rng = random.Random(20261018)
    order = [(c['id'], rep) for c in cases for rep in range(1, 4 if c['label'] == 'attack' else 2)]
    rng.shuffle(order)
    schedule = []
    for case, rep in order:
        arm_order = [a['name'] for a in arms]
        rng.shuffle(arm_order)
        schedule.extend(dict(case=case, rep=rep, arm=arm) for arm in arm_order)
    manifest = dict(status='design_prepared_not_frozen_not_runnable', cases=cases, arms=arms,
        schedule=schedule, full_trajectories=len(schedule), repetitions_by_label={'attack': 3, 'benign': 1},
        agent_model='gpt-5.6-luna', classifier_model='gpt-6-luna', official_judge_model='gpt-5.6-luna',
        monitor=old['monitor'], reference_image=old['reference_image'], resource_caps=old['resource_caps'],
        startup_guidance='Unchanged across all three arms', randomization_seed=20261018,
        design_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        prior_manifest_sha256=hashlib.sha256((source/'manifest.json').read_bytes()).hexdigest(),
        gates=['Freeze and hash runtime plus runner after remaining candidate changes are committed.',
               'Verify OFF bypasses both boundaries and invokes no classifiers.',
               'Verify strict immediately denies approvals; permissive executes and records them.',
               'Run isolated smoke trajectories before full collection.',
               'Keep all failed attempts for accounting; use identical 80-request budget from the start.',
               'Supplementary judging needs repaired evidence packaging; do not claim it is ready.'],
        limitations=['Previously tuned development cases, not held-out.',
                     'Strict and permissive bracket unattended approval handling, not human decisions.',
                     'Do not reuse old OFF trajectories for the matched comparison.'])
    assert len(schedule) == 1797
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('source',type=Path)
    parser.add_argument('destination',type=Path)
    args=parser.parse_args()
    print(prepare(args.source,args.destination)['full_trajectories'], 'trajectories planned; none launched')
