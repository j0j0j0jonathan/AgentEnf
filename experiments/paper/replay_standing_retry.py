"""Replay the narrow retry rule with recorded semantic facts and Block outcomes.

No model calls. Does not estimate counterfactual agent success or recalibrate
new document-classifier questions. Source identities are derived from captured
write bodies; missing reconstruction is reported explicitly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import yaml
from instrlib import Event
from instrlib import tool_mapper as tm
from instrlib.enfflash import EnfFlashEnforcer
from experiments.paper.temporal_replay import batches, lines

ROOT = Path(__file__).resolve().parents[2]
CATEGORIES = {'control_artifact_write', 'memory_standing_instruction',
              'standing_rule_after_untrusted_instruction', 'blocked_standing_rule_retry'}


def writes(tool, data):
    if tool == 'file_write':
        body = tm._extract_write_content(data)
        return [(tm._extract_path(data), body)] if body else []
    command = data.get('command') or data.get('cmd') or ''
    if isinstance(command, str):
        return tm.local_literal_write_contents(command) + tm.local_python_literal_write_contents(command)
    return []


def recorded_blocks(run):
    out = {}
    for path in (run / 'runtime').rglob('enfguard-verdicts.jsonl'):
        for row in lines(path):
            for v in row.get('raw', {}).get('decision_trace', {}).get('policy_verdicts', []):
                if v['action'] in {'Block', 'BlockToolCall'} and v['category'] in CATEGORIES:
                    out.setdefault(v['tid'], set()).add(v['category'])
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('inputs', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--extra-root', type=Path)
    args = parser.parse_args()
    runs = {str(Path(r['source']) / r['run']) for r in json.loads(args.inputs.read_text())}
    if args.extra_root:
        runs.update(str(p.parent.resolve()) for p in args.extra_root.glob('live/*/*/run*/COMPLETE.json') if (p.parent/'proxy_session_logs').exists())
    args.output.mkdir(parents=True, exist_ok=True)
    pack = yaml.safe_load((ROOT/'examples/presets/release-candidate.yaml').read_text())
    text = next(p['mfotl'] for p in pack['policies'] if p['id']=='persistence_v1')
    rule = re.search(r'\{"blocked_standing_rule_retry"\}\{(.*?)\n\}', text, re.S).group(1)
    signature = '''PolicyActive(t:int,p:string)
Turn(t:int,r:string,s:string)
ToolPlanned(t:int,c:string,tool:string,input:string)
Classify(t:int,c:string,d:string,v:string)
RecordedBlock(t:int,category:string)
Block(t:int,phase:string,category:string,reason:string)+
'''
    formula = '(ALWAYS (FORALL t,cat. RecordedBlock(t,cat) IMPLIES:R Block(t,"tool",cat,"recorded outcome"))) AND ('+rule+')'
    (args.output/'events.sig').write_text(signature)
    (args.output/'policy.mfotl').write_text(formula)
    binary = ROOT.parent/'outputs/paper-live-pilot-2026-10-15/enfflash-framing-v2/target/release/enfflash'
    compiler = ROOT.parent/'outputs/paper-preparation-2026-10-14/enfflash-source/bin/enfflash.exe'
    import instrlib.enforcer as monitor
    monitor._log = lambda *a, **kw: None
    results = []
    for ordinal, path in enumerate(sorted(runs)):
        run = Path(path)
        resultfile = args.output/(hashlib.sha256(path.encode()).hexdigest()[:16]+'.json')
        if resultfile.exists():
            results.append(json.loads(resultfile.read_text()));continue
        tm.reset_substitution_tracking()
        result = dict(run=path, batches=0, recorded_retries=[], reconstructed_retries=[], missing=[], blocks=[], error=None)
        enf = EnfFlashEnforcer(str(binary),str(args.output/'events.sig'),str(args.output/'policy.mfotl'),compiler=compiler,cache_dir=args.output/'compiled')
        try:
            blocks = recorded_blocks(run)
            result['recorded_block_batches'] = len(blocks)
            enf.start()
            for batch in batches(run):
                original = [Event(e['name'],*e['args']) for e in batch['events']]
                es = [e for e in original if e.name in {'PolicyActive','Turn','ToolPlanned','Classify'}]
                session = next((str(e.args[2]) for e in original if e.name=='Turn' and e.args[0]==batch['tid']), '')
                for call in (e for e in original if e.name in {'ToolPlanned','ToolCall'}):
                    t,c,tool,raw = call.args
                    data = json.loads(raw)
                    facts = [e for e in original if e.name=='Classify' and e.args[:2]==(t,c)]
                    old_retry = any(e.args[2]=='substitution_retry' for e in facts)
                    added = list(facts)
                    with tm.session_context(session):
                        for dest, body in writes(tool,data):
                            tm._append_substitution_retry_events(added,t,c,body,path=dest)
                    new = added[len(facts):]
                    identities = [e for e in new if e.args[2] in {'authored_content_id','substitution_source_content_id'}]
                    es.extend(identities)
                    matched = any(e.args[2]=='substitution_source_content_id' for e in identities)
                    info = dict(tid=t,call=c,phase=batch['phase'],facts=[list(e.args[2:]) for e in facts if e.args[2] in {'memory_stance','memory_content_kind','substitution_retry'}])
                    if old_retry: result['recorded_retries'].append(info)
                    if matched: result['reconstructed_retries'].append(info)
                    if old_retry and not matched: result['missing'].append(info)
                if batch['phase']=='tool':
                    es.extend(Event('RecordedBlock',batch['tid'],cat) for cat in sorted(blocks.get(batch['tid'],[])))
                reply = enf.query(es,batch['tid'],trace_ts=batch['ms']//1000)
                for event in reply.get('cause',[]):
                    if event['name']=='Block' and event['args'][2]=='blocked_standing_rule_retry':
                        result['blocks'].append(dict(tid=batch['tid'],phase=batch['phase'],event=event))
                result['batches']+=1
        except Exception as exc:
            result['error']=f'{type(exc).__name__}: {exc}'
        finally:
            enf.stop()
        resultfile.write_text(json.dumps(result,indent=2))
        results.append(result)
        summary=dict(runs=len(results),errors=sum(bool(r['error']) for r in results),missing=sum(len(r['missing']) for r in results),batches=sum(r['batches'] for r in results),blocks=[dict(run=r['run'],blocks=r['blocks']) for r in results if r['blocks']],recorded_retry_runs=[r for r in results if r['recorded_retries']])
        (args.output/'summary.json').write_text(json.dumps(summary,indent=2))
        if ordinal%25==0 or result['error']:print(ordinal+1,len(runs),result['error'],flush=True)

if __name__=='__main__':main()
