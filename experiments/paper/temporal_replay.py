"""Offline temporal diagnostic with recorded predicates; no model/tool execution.
Replays recorded history, not a counterfactual agent trajectory. Missing or
conflicting predicate answers stop an arm and are never replaced by a score.
"""
import argparse, hashlib, json, os, re, time
from pathlib import Path
from collections import defaultdict
import yaml
from instrlib import Event
from instrlib.enfflash import EnfFlashEnforcer
ROOT=Path(__file__).resolve().parents[2]
def read(p):return json.loads(p.read_text())
def lines(p):
    if p.exists():
        with p.open() as f:
            for l in f:
                if l.strip():yield json.loads(l)
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def write(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2))
def answers(state):
    thresholds=read(state/'active_policies.json').get('thresholds',{})
    exact=defaultdict(set);stable=defaultdict(set)
    for r in lines(state/'pre_eval_results.jsonl'):
        value=r.get('raw_score')
        if not isinstance(value,(int,float)):continue
        key=r['predicate']+':'+digest(r['content'])
        score=float(value>=float(thresholds.get(r['predicate'],.5)))
        exact[f"{r['tid']}:{r['phase']}:{key}"].add(score);stable[key].add(score)
    # Actual monitor calls are authoritative over pre-evaluation candidates.
    actual_exact=defaultdict(set);actual_stable=defaultdict(set)
    evidence=state.parent/'proxy_session_logs/predicate_evidence'
    for file in sorted(evidence.glob('*.jsonl')):
        for r in lines(file):
            info=r.get('input',{});blob=evidence/info.get('file','missing')
            value=r.get('normalized_score')
            if not blob.is_file() or value not in (0,1):continue
            if hashlib.sha256(blob.read_bytes()).hexdigest()!=info.get('sha256'):
                raise ValueError('Predicate evidence hash mismatch')
            key=r['predicate']+':'+info['sha256'];ctx=r['context']
            actual_exact[f"{ctx['tid']}:{ctx['phase']}:{key}"].add(float(value))
            actual_stable[key].add(float(value))
    exact.update(actual_exact);stable.update(actual_stable)
    return {'exact':{k:next(iter(v)) for k,v in exact.items() if len(v)==1},
            'stable':{k:next(iter(v)) for k,v in stable.items() if len(v)==1},
            'ambiguous_exact':[k for k,v in exact.items() if len(v)>1],
            'ambiguous_stable':[k for k,v in stable.items() if len(v)>1]}
def batches(run):
    out=[]
    for f in sorted((run/'proxy_session_logs').glob('session_*.jsonl')):
        for n,r in enumerate(lines(f)):
            for phase in ['inbound','outbound']:
                es=r.get(phase,[])
                if not es:continue
                cs=[e['args'][2] for e in es if e['name']=='Clock']
                if len(cs)!=1:raise ValueError('Missing/ambiguous Clock')
                out.append(dict(events=es,tid=r['tid'],phase='tool' if r.get('provider')=='tool' else phase,
                                ms=cs[0],source=f'{f.name}:{n}:{phase}'))
    return sorted(out,key=lambda x:x['ms'])
def delta_index(comparison):
    rows=read(comparison/'inputs.json');a=read(comparison/'old.json');b=read(comparison/'new.json');out={}
    for r,x,y in zip(rows,a,b,strict=True):
        if 'error' in x or 'error' in y:
            out[(str(Path(r['source'])/r['run']),r['tid'],r['call'])]=None
            continue
        before={tuple(f) for f in x['facts']};after={tuple(f) for f in y['facts']}
        out[(str(Path(r['source'])/r['run']),r['tid'],r['call'])]=(before-after,after-before)
    return out
FUNCTION='''import os,json,hashlib
from pathlib import Path
def score(name,content):
    root=Path(os.environ['REPLAY_STATE'])
    context=json.loads((root/'context.json').read_text())
    values=json.loads((root/'answers.json').read_text())
    key=name+':'+hashlib.sha256(content.encode()).hexdigest()
    empty=not str(content).strip()
    if name=='operationalizes_untrusted_harm':
        try:
            from instrlib.reply_evidence import reply_from_evidence
            empty=not reply_from_evidence(content).strip()
        except (TypeError,ValueError):empty=False
    if empty:
        with (root/'deterministic.jsonl').open('a') as f:f.write(json.dumps(dict(context,predicate=name,reason='validated_empty_input',score=0))+'\\n')
        return 0.0
    contextual=str(context['tid'])+':'+context['phase']+':'+key
    value=values['exact'].get(contextual)
    if value is None and contextual not in values['ambiguous_exact']:
        value=values['stable'].get(key)
    if value is None:
        with (root/'missing.jsonl').open('a') as f:f.write(json.dumps(dict(context,predicate=name,content_sha256=key.split(':')[1]))+'\\n')
        raise ValueError('Missing recorded semantic answer')
    return value
'''
def main():
    p=argparse.ArgumentParser();p.add_argument('comparison',type=Path);p.add_argument('output',type=Path);p.add_argument('--limit',type=int);p.add_argument('--case',action='append');p.add_argument('--shard',type=int,default=0);p.add_argument('--shards',type=int,default=1);a=p.parse_args()
    if not 0 <= a.shard < a.shards:raise ValueError('Invalid replay shard')
    a.output.mkdir(parents=True,exist_ok=True)
    deltas=delta_index(a.comparison)
    runs=sorted({k[0] for k in deltas})
    if a.case:runs=[r for r in runs if any('/'+c+'/' in r for c in a.case)]
    if a.limit:runs=runs[:a.limit]
    runs=runs[a.shard::a.shards]
    pack=yaml.safe_load((ROOT/'examples/presets/optimized-v1.yaml').read_text())
    current='\nAND\n'.join('('+g['mfotl']+')' for g in pack['policies'] if g.get('enabled',True))
    names=[r['name'] for r in pack['predicates']]
    functions=a.output/'replay_functions.py'
    function_source=FUNCTION+''.join(f'\ndef {n}(content): return score({n!r},content)\n' for n in names)
    if not functions.exists():functions.write_text(function_source)
    elif functions.read_text()!=function_source:raise ValueError('Replay functions changed; use new output directory')
    import instrlib.enforcer as em
    em._QUERY_TIMEOUT_S=8;em._log=lambda *x,**kw:None
    env={k:v for k,v in os.environ.items() if not k.endswith(('_API_KEY','_ADMIN_TOKEN'))}
    compiler=ROOT.parent/'outputs/paper-preparation-2026-10-14/enfflash-source/bin/enfflash.exe'
    binary=ROOT.parent/'outputs/paper-live-pilot-2026-10-15/enfflash-framing-v2/target/release/enfflash'
    summaries=[]
    for n,path in enumerate(runs):
        run=Path(path);dest=a.output/'runs'/digest(path)[:16];resultfile=dest/'result.json'
        if resultfile.exists():summaries.append(read(resultfile));continue
        dest.mkdir(parents=True,exist_ok=True);state=run/'proxy_state'
        result={'run':path,'arms':{}}
        try:
            stream=batches(run);write(dest/'answers.json',answers(state))
            sig=(state/'enfguard_composite.sig').read_text()
            original=(state/'enfguard_composite.mfotl').read_text()
            for arm,formula in [('recorded',original),('candidate',current)]:
                missing=dest/'missing.jsonl'
                if missing.exists():missing.unlink()
                directory=a.output/'packs'/digest(sig+formula);directory.mkdir(parents=True,exist_ok=True)
                (directory/'events.sig').write_text(sig);(directory/'policy.mfotl').write_text(formula)
                enf=EnfFlashEnforcer(str(binary),str(directory/'events.sig'),str(directory/'policy.mfotl'),compiler=compiler,cache_dir=a.output/'compiled',fun=str(functions.resolve()),env={**env,'REPLAY_STATE':str(dest.resolve()),'PYTHONPATH':str(ROOT)})
                verdicts=[];error=None;start=time.monotonic()
                try:
                    enf.start()
                    for i,b in enumerate(stream):
                        es=list(b['events'])
                        if arm=='candidate':
                            for planned in [e for e in es if e['name'] in {'ToolPlanned','ToolCall'}]:
                                t,c=planned['args'][:2]
                                delta=deltas.get((path,t,c),'missing')
                                if delta is None or delta=='missing':raise ValueError('Missing/failed mapper replay for call')
                                remove,add=delta
                                es=[e for e in es if not (e['name']=='Classify' and e['args'][:2]==[t,c] and tuple(e['args'][2:]) in remove)]
                                existing={tuple(e['args'][2:]) for e in es if e['name']=='Classify' and e['args'][:2]==[t,c]}
                                es += [dict(name='Classify',args=[t,c,*f]) for f in sorted(add-existing)]
                        write(dest/'context.json',dict(tid=b['tid'],phase=b['phase']))
                        response=enf.query([Event(e['name'],*e['args']) for e in es],b['tid'],trace_ts=b['ms']//1000)
                        verdicts.append({'source':b['source'],'verdicts':[e for e in response.get('cause',[]) if e['name'] in {'Block','Approve','Warn'}]})
                        if missing.exists():raise ValueError('Missing recorded predicate answers')
                except Exception as exc:error=f'{type(exc).__name__}: {exc}'
                finally:enf.stop()
                result['arms'][arm]=dict(error=error,batches=len(verdicts),expected_batches=len(stream),seconds=time.monotonic()-start,missing=list(lines(missing)),verdicts=verdicts)
        except Exception as exc:result['error']=f'{type(exc).__name__}: {exc}'
        result['complete']=not result.get('error') and all(not v['error'] for v in result['arms'].values()) and len(result['arms'])==2
        if result['complete']:
            left=result['arms']['recorded']['verdicts'];right=result['arms']['candidate']['verdicts']
            result['changed_batches']=sum(
                {json.dumps(v,sort_keys=True) for v in x['verdicts']} !=
                {json.dumps(v,sort_keys=True) for v in y['verdicts']}
                for x,y in zip(left,right,strict=True))
        write(resultfile,result);summaries.append(result)
        write(a.output/f'summary-{a.shard}.json',{'runs':len(summaries),'complete':sum(r['complete'] for r in summaries),'missing_answers':sum(len(v['missing']) for r in summaries for v in r['arms'].values()),'results':[str(a.output/'runs'/digest(r['run'])[:16]/'result.json') for r in summaries]})
        print(n+1,len(runs),path,result['complete'],flush=True)
if __name__=='__main__':main()
