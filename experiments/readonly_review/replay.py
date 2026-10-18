"""Shadow opportunity inventory, NOT policy replay or predicted verdicts.

Reads action ledger only. No mapper/judge/network/tool execution. Includes zero-call
runs in run denominators. Complete policy replay is not inferred by subtracting
historical verdicts. Missing resource grants/runtime proofs cannot remove approval.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from experiments.readonly_review.capability import inspect_call


def analyze(audit, output):
    actions=json.loads((audit/'actions.json').read_text())
    runs=json.loads((audit/'rollouts.json').read_text())
    labels={(r['cohort'],r['id'],r['run']):r for r in runs}
    summaries=defaultdict(Counter); rows=[]; seen=set()
    for a in actions:
        key=(a['cohort'],a['id'],a['run'],a['tid'],a['call_id'])
        if key in seen:
            raise ValueError(f'duplicate action identity: {key}')
        seen.add(key)
        lab=labels[key[:3]]
        kind='benign' if lab['kind']=='benign' else 'attack'
        group=(a['cohort'],kind)
        s=summaries[group];s['calls']+=1
        args=a['input']
        cwd=args.get('workdir') or args.get('cwd') if isinstance(args,dict) else None
        assessment=inspect_call(a['tool'],args,cwd=cwd)
        approvals={v['category'] for v in a['rules'] if v['action']=='Approve'}
        is_approval=a['policy']=='approve'
        s['recorded_approval_calls']+=is_approval
        s['structural_read_or_list_shapes']+=assessment.structural_candidate
        s['structural_shapes_on_approval_calls']+=assessment.structural_candidate and is_approval
        # A narrow subset worth manual review. Not a recommendation to drop it.
        relevant=assessment.structural_candidate and is_approval and approvals=={'untrusted_authorization'}
        s['sole_injection_approval_shapes']+=relevant
        s['native_shapes']+=assessment.structural_candidate and assessment.transport=='native'
        s['shell_shapes_requiring_new_tool']+=assessment.structural_candidate and assessment.transport.startswith('shell')
        s['qualified_exemptions']+=assessment.eligible
        if assessment.structural_candidate or is_approval:
            rows.append({'cohort':a['cohort'],'case':a['id'],'run':a['run'],'call_id':a['call_id'],'tid':a['tid'],
                         'task_kind':kind,'historical_outcome':lab['label'],
                         'recorded_policy':a['policy'],'approval_rules':sorted(approvals),
                         'assessment':asdict(assessment),'sole_injection_approval_shape':relevant,'source':a['source']})
    cohorts={a['cohort'] for a in actions}
    for r in runs:
        if r['cohort'] in cohorts:
            kind='benign' if r['kind']=='benign' else 'attack'
            summaries[(r['cohort'],kind)]['runs']+=1
    summary={'mode':'shadow_only','enforcement_changed':False,'basis':'historical action ledger, no full-pack counterfactual replay',
             'qualified_exemptions':0,'approval_requests_removed':0,
             'missing_evidence':['explicit deployer resource grants','constrained runtime implementation and operation binding','runtime physical confinement'],
             'groups':{'/'.join(k):dict(v) for k,v in summaries.items()},
             'input_hashes':{f:hashlib.sha256((audit/f).read_bytes()).hexdigest() for f in ('actions.json','rollouts.json')}}
    output.mkdir(parents=True,exist_ok=True)
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (output/'call-review.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    return summary,rows


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--audit',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();analyze(args.audit,args.out)
