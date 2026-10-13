"""Counterfactual persistence-only verdicts on retained deterministic facts.

No model, shell or file-write tool execution. This is NOT a benchmark rescore:
no historical context, approvals, other policy groups or subsequent agent choices
are replayed. Use the complete pack/live runtime to evaluate final behavior.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile
import sys
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from instrlib import Enforcer, Event


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('audit_dir',type=Path)
    args=parser.parse_args()
    actions=json.loads((args.audit_dir/'actions.json').read_text())
    facts=json.loads((args.audit_dir/'mapper-replay.json').read_text())
    selected=[]
    for action,row in zip(actions,facts,strict=True):
        assert (action['cohort'],action['id'],action['run'],action['call_id']) == (row['cohort'],row['id'],row['run'],row['call_id'])
        if any(dim=='persistence_kind' and value in ('service','scheduled_task') for dim,value in row['facts']):
            selected.append((action,row))
    output=[dict(cohort=a['cohort'],id=a['id'],run=a['run'],tid=a['tid'],call_id=a['call_id']) for a,r in selected]
    with tempfile.TemporaryDirectory() as tmp:
        for name,path in [('baseline',ROOT/'tests/fixtures/policies/eval_combined_graduated_a3s.yaml'),
                          ('candidate',ROOT/'examples/presets/release-candidate.yaml')]:
            pack=yaml.safe_load(path.read_text())
            formula=Path(tmp)/f'{name}.mfotl'
            formula.write_text(next(p['mfotl'] for p in pack['policies'] if p['id']=='persistence_v1'))
            enforcer=Enforcer(os.environ['ENFGUARD_BIN'],str(ROOT/'enfguard.sig'),str(formula))
            enforcer.start()
            try:
                for i,(action,row) in enumerate(selected,1):
                    events=[Event('Turn',i,str(i),f'isolated-{i}'),Event('PolicyActive',i,'persistence_v1'),
                            Event('ToolPlanned',i,'c',action['tool'],json.dumps(action['input']))]
                    events += [Event('Classify',i,'c',*f) for f in row['facts']]
                    result=enforcer.query(events,i)
                    output[i-1][name]=[dict(name=x['name'],category=x['args'][2]) for x in result.get('cause',[])]
            finally:enforcer.stop()
    path=args.audit_dir/'persistence-candidate-comparison.json'
    path.write_text(json.dumps(output,indent=2))
    print(json.dumps(output,indent=2))


if __name__=='__main__':main()
