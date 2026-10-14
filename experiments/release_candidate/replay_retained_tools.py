"""Offline real-monitor replay of selected retained tool proposals.

No retained command executes. LLM-dependent groups are excluded explicitly, so
this is diagnostic rule attribution, never a new benchmark/task-success score.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import yaml
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from instrlib import Enforcer,Event
from instrlib.tool_mapper import map_tool_call,session_context,reset_authored_content_accumulation
from instrlib.path_confinement import workspace_context
from instrlib.persistence_paths import persistence_path_events

CASES={'seed-0210','seed-0216','seed-0186','seed-0159','seed-0205','seed-0170','seed-0177','syn-0652','syn-0513'}
ROOTS=['/tmp/project','/tmp/server','/tmp/analysis','/tmp/docs','/tmp/research','/tmp/devproject','/home/node/.openclaw/workspace']


def run(audit,dest,cases=None,only_group=None):
 cases=set(cases or CASES)
 dest.mkdir(parents=True,exist_ok=False)
 actions=json.loads((audit/'actions.json').read_text())
 selected=[a for a in actions if a['id'] in cases]
 groups={}
 for a in selected:groups.setdefault((a['cohort'],a['id'],a['run']),[]).append(a)
 outputs=[];profiles={}
 with tempfile.TemporaryDirectory() as tmp:
  for name,path in [('baseline',ROOT/'tests/fixtures/policies/eval_combined_graduated_a3s.yaml'),('candidate',ROOT/'examples/presets/release-candidate.yaml')]:
   pack=yaml.safe_load(path.read_text());predicate_names=[p['name'] for p in pack['predicates']]
   enabled=[p for p in pack['policies'] if p.get('enabled',True) and (only_group is None or p['id']==only_group)]
   policies=[p for p in enabled if not any(n+'(' in p['mfotl'] for n in predicate_names)]
   excluded=[p['id'] for p in enabled if p not in policies]
   formula=Path(tmp)/f'{name}.mfotl';formula.write_text('\nAND\n'.join('('+p['mfotl']+')' for p in policies))
   profiles[name]=dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),included=[p['id'] for p in policies],excluded=excluded)
   for identity,rows in groups.items():
    reset_authored_content_accumulation();sid=':'.join(map(str,identity))
    enf=Enforcer(os.environ['ENFGUARD_BIN'],str(ROOT/'enfguard.sig'),str(formula));enf.start()
    try:
     for step,row in enumerate(rows,1):
      with session_context(sid),workspace_context(ROOTS):mapped=map_tool_call(step,row['call_id'],row['tool'],row['input'])
      call=next(e for e in mapped if e.name=='ToolCall')
      paths=persistence_path_events(step,row['call_id'],call.args[2],row['input'],sid,mapped,raw_tool_name=row['tool'])
      events=[Event('Turn',step,f'r{step}',sid),Event('ToolPlanned',*call.args),*[Event('PolicyActive',step,p['id']) for p in policies],*mapped,*paths]
      result=enf.query(events,step)
      verdicts=[{'verdict':e['name'],'rule':e['args'][2]} for e in result.get('cause',[]) if e['name'] in {'Block','Approve','Warn'}]
      outputs.append(dict(profile=name,cohort=row['cohort'],id=row['id'],run=row['run'],step=step,call_id=row['call_id'],source=row['source'],historical_rules=row['rules'],verdicts=verdicts,facts=[list(e.args[2:]) for e in [*mapped,*paths] if e.name=='Classify']))
    finally:enf.stop()
 (dest/'results.json').write_text(json.dumps(outputs,indent=2)+'\n')
 manifest=dict(profiles=profiles,trajectories=len(groups),tool_proposals=len(selected),cases=sorted(cases),only_group=only_group,
  mapper='current for both arms; policy comparison, not historical-code reproduction',
  limits=['No tools or model APIs executed. Routed classifiers unregistered; configuration reviewer unavailable.',
          'LLM-dependent groups excluded; no model messages or tool-result evidence replayed.',
          'Relative proposal order preserved; one logical second per proposal, not historical elapsed time.',
          'Namespace synthesized per retained trajectory; workspace roots are declared replay assumptions.',
          'Approve is reported separately, not silently treated as allowed or blocked.',
          'Replaying later recorded proposals after a counterfactual Block is diagnostic, not a valid agent trajectory.'])
 (dest/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps({'trajectories':len(groups),'proposals':len(selected),'results':str(dest/'results.json')}))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('audit',type=Path);p.add_argument('destination',type=Path);p.add_argument('--case',action='append');p.add_argument('--group');a=p.parse_args();run(a.audit,a.destination,a.case,a.group)
