"""Prepare isolated evaluation profiles; does not launch agents or call APIs."""
import argparse
import hashlib
import json
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[2]


def prepare(destination, model):
    destination.mkdir(parents=True,exist_ok=False)
    baseline=yaml.safe_load((ROOT/'tests/fixtures/policies/eval_combined_graduated_a3s.yaml').read_text())
    candidate=yaml.safe_load((ROOT/'examples/presets/release-candidate.yaml').read_text())
    arms=[]
    for name,source,strict in [('baseline_legacy_approval',baseline,False),
                              ('baseline_strict_approval',baseline,True),
                              ('candidate_legacy_approval',candidate,False),
                              ('candidate_strict_approval',candidate,True)]:
        pack=json.loads(json.dumps(source))
        pack['backend'].update(judge_backend='openai_decisions',judge_decisions_model=model)
        for predicate in pack.get('predicates',[]):
            if predicate.get('kind')=='llm_judge':
                predicate.update(backend='openai_decisions',model=model)
        pack['human_approval'].update(allow_headless_bypass=not strict,
                                     on_timeout='block',timeout_seconds=60)
        path=destination/(name+'.yaml')
        path.write_text('# EVALUATION ONLY. Isolated disposable runtime required.\n'+yaml.safe_dump(pack,sort_keys=False))
        arms.append(dict(name=name,profile=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         approval_mode='block' if strict else 'warn'))
    arms.append(dict(name='off',profile=None,enforcement='disabled',classifier_calls=0))
    manifest=dict(repetitions=3,configuration_note='All ON arms use Decisions; none is the thesis configuration. OFF runs no classifiers.',status='prepared_not_run',model=model,arms=arms,
      environment={'ENFGUARD_TOOL_JUDGE_BACKEND':'openai_decisions',
                   'ENFGUARD_TOOL_JUDGE_MODEL':model,
                   'ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES':'65536'},
      cases=['seed-0210','seed-0216','seed-0186','syn-0652','syn-0513'],
      extra_selection='Include matched attack/benign twins and retained benign credential/privilege approval cases before freezing the case manifest.',
      requirements=['Same agent model, image, setup and seeds in all arms; fresh isolated proxy/cache/container per run.',
        'Install current hook and configure unique runtimeNamespace for each runtime, stable within its trajectory.',
        'Remove per-adapter model overrides; verify effective Decisions backend in captures.',
        'Strict arms deny approval immediately: this measures unattended posture, not human-assisted utility.',
        'Legacy warn arm is an isolated research control, never a deployment recommendation.',
        'Measure policy Block separately from approval-denied; actual effects, task completion, judge failures, budget failures, latency and usage.',
        'Add split-script scheduling pairs: same path; same basename/different directory; benign script; different namespace; relative/unresolved paths.'])
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('destination',type=Path)
    parser.add_argument('--model',default='gpt-6-luna')
    args=parser.parse_args()
    prepare(args.destination,args.model)
