"""Offline replay of frozen fresh API answers through candidate runtime + EnfFlash.

Does not call an API or run an agent/tool. Inputs/question identities are checked
before each recorded answer is supplied. The actual monitor calls the actual
predicate, which must find exact pre-evaluated evidence rather than classify again.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import yaml

import batch_judge
import predicates
from instrlib import Event, decisions, reply_guard
from instrlib.enfflash import EnfFlashEnforcer
from instrlib.reply_evidence import reply_from_evidence
from experiments.paper.calibrate import dump, sha

ROOT = Path(__file__).resolve().parents[2]
NAME = 'operationalizes_untrusted_harm'


def verify(previous, output, *, production_followup=False):
    previous, output = Path(previous).resolve(), Path(output).resolve()
    if production_followup:
        from experiments.paper.calibrate_pilot_replies import check
        check(previous)
    else:
        review = previous.parent / 'reply-fresh-review'
        verified = json.loads((review / 'verified-results.json').read_text())
        assert sha(previous / 'run/results.jsonl') == verified['results_sha256']
        for name, digest in json.loads((review / 'frozen-source/manifest.json').read_text()).items():
            assert sha(review / 'frozen-source' / name) == digest
    original = json.loads((previous / 'run/manifest.json').read_text())
    assert sha(previous / 'run/cases.json') == original['cases_sha256']
    cases = json.loads((previous / 'run/cases.json').read_text())['cases']
    rows = [json.loads(line) for line in (previous / 'run/results.jsonl').read_text().splitlines()]
    assert len(cases) == len(rows) and len({r['id'] for r in rows}) == len(rows)
    assert all(row['status'] == 'ok' and row['label'] == case['expected']
               for case, row in zip(cases, rows, strict=True))
    output.mkdir(parents=True, exist_ok=False)
    state_dir = output / 'state'; state_dir.mkdir()
    pack = yaml.safe_load((ROOT / 'examples/presets/release-candidate.yaml').read_text())
    spec = next(p for p in pack['predicates'] if p['name'] == NAME)
    spec = {**spec, 'model': original['model'], 'timeout_ms': 150000}
    state = {'active': ['outbound_content_v1'], 'predicate_policies': {NAME: ['outbound_content_v1']},
             'user_predicates': [spec], 'runtime': {'judge_strategy': 'active_policy', 'judge_call_mode': 'batched'}}
    dump(state_dir / 'active_policies.json', state)
    sig = output / 'test.sig'
    sig.write_text((ROOT / 'enfguard.sig').read_text() + '\n' + '\n'.join(
        f'fun {n}(content:string) : float' for n in (NAME, 'reveals_secret_value', 'reveals_private_control_instructions')))
    formula = output / 'test.mfotl'
    formula.write_text(next(p['mfotl'] for p in pack['policies'] if p['id'] == 'outbound_content_v1'))
    fun = output / 'monitor_functions.py'
    received = output / 'monitor-calls.jsonl'
    fun.write_text(f'''import json
import predicates as actual
from instrlib.reply_evidence import reply_from_evidence
from instrlib import decisions
def unavailable(*args,**kwargs):
    raise AssertionError("Unexpected model call in offline monitor replay")
decisions.ask=unavailable
actual._call_and_parse_judge_api=unavailable
def {NAME}(content):
    cached=actual._pre_evaluated_judge_result({NAME!r},content)
    if reply_from_evidence(content).strip():
        assert cached is not None and not cached.fail_mode
        assert json.loads(cached.raw_reply)["strategy"]=="reply_guard_v1"
    result=getattr(actual,{NAME!r})(content)
    with open({str(received)!r},"a") as f:
        f.write(json.dumps({{"input":content,"value":result,"replayed":bool(cached and cached.replayed_pre_eval)}})+"\\n")
    return result
def reveals_secret_value(content): return 0.0
def reveals_private_control_instructions(content): return 0.0
''')
    env = {**os.environ, 'ENFGUARD_STATE_DIR': str(state_dir), 'ENFGUARD_LOG_DIR': str(output / 'logs'),
           'ENFGUARD_CONTEXT_FILE': str(state_dir / 'current_context.json'), 'ENFGUARD_SESSIONS_DIR': str(state_dir / 'sessions'),
           'ENFGUARD_CAPTURE_PREDICATE_INPUTS': '1',
           'PYTHONPATH': os.pathsep.join([str(ROOT), str(ROOT / '.venv/lib/python3.12/site-packages')])}
    engine = EnfFlashEnforcer(os.environ['ENFFLASH_BIN'], str(sig), str(formula),
                             compiler=os.environ['ENFFLASH_COMPILER'], cache_dir=output / 'compiled', fun=str(fun), env=env)
    context = {}
    results = []
    with patch.multiple(predicates, _state=lambda: state, _current_context=lambda: context,
                        _JUDGE_CACHE={}, _SESSION_FILE_CACHES={}, SESSIONS_DIR=state_dir / 'sessions',
                        PRE_EVAL_RESULTS_FILE=state_dir / 'pre_eval_results.jsonl',
                        TRACE_INDEX_DIR=output / 'traces', LOGS_DIR=output / 'logs'), \
         patch.dict(os.environ, {'ENFGUARD_CAPTURE_PREDICATE_INPUTS': '0'}):
        engine.start()
        try:
            for tid, (case, row) in enumerate(zip(cases, rows, strict=True), 1):
                assert case['id'] == row['id'] and row['status'] == 'ok'
                content = case['input']; assert hashlib.sha256(content.encode()).hexdigest() == row['input_sha256']
                context.update(tid=tid, sid=f'case-{tid}', phase='outbound', dry_run=0)
                dump(state_dir / 'current_context.json', context)
                queue = list(row['calls'])
                def ask(text, questions, timeout, **kwargs):
                    recorded = queue.pop(0)
                    assert hashlib.sha256(text.encode()).hexdigest() == recorded['input_sha256']
                    assert [q['name'] for q in questions] == recorded['question_names']
                    assert questions == [decisions.predicate_question(n, reply_guard.CRITERIA[n]) for n in recorded['question_names']]
                    assert kwargs['model'] == original['model'] and timeout > 0
                    decisions.validate(recorded['raw_reply'], questions)
                    return recorded['raw_reply']
                reply = reply_from_evidence(content)
                events = [Event('PolicyActive', tid, 'outbound_content_v1'), Event('Turn', tid, f'r{tid}', context['sid']),
                          Event('Completion', tid, reply, 0), Event('ReplyEvidence', tid, content)]
                with patch.object(decisions, 'ask', ask):
                    pre = batch_judge.pre_evaluate(events)
                assert not queue, case['id']
                if reply.strip():
                    assert len(pre) == 1 and pre[0].raw_score == case['expected']
                    computed = predicates._pre_evaluated_judge_result(NAME, content)
                    assert computed and not computed.fail_mode
                    actual = json.loads(computed.raw_reply)['evidence']
                    for field in ('label', 'reply_scores', 'coverage_probability', 'coverage_status', 'unit_evidence', 'decision_evidence'):
                        assert actual[field] == row[field], (case['id'], field)
                result = engine.query(events, tid)
                labels = {e['args'][2] for e in result.get('cause', []) if e['name'] == 'Block'}
                expected = {'harmful_command_output'} if case['expected'] else set()
                assert labels == expected, (case['id'], labels, expected)
                results.append({'id': case['id'], 'expected': case['expected'], 'blocks': sorted(labels),
                                'recorded_calls_replayed': len(row['calls'])})
        finally:
            engine.stop()
    observed = [json.loads(line) for line in received.read_text().splitlines()]
    assert {r['input'] for r in observed} == {c['input'] for c in cases}
    assert all(r['replayed'] for r in observed if reply_from_evidence(r['input']).strip())
    dump(output / 'results.json', results)
    sources = ['predicates.py', 'yaml_loader.py', 'batch_judge.py', 'instrlib/reply_guard.py',
               'instrlib/reply_quote_witness.py', 'instrlib/permission_effects.py', 'instrlib/reply_evidence.py',
               'instrlib/decisions.py', 'instrlib/evidence_budget.py', 'enfguard.sig',
               'proxy.py', 'instrlib/tool_judge.py', 'instrlib/property_contracts.py',
               'instrlib/enfflash.py', 'instrlib/flash_formula.py',
               'examples/presets/release-candidate.yaml', 'pyproject.toml', 'experiments/paper/verify_reply_runtime.py']
    summary = {'cases': len(results), 'agreements': len(results), 'new_api_calls': 0,
               'calibration_results_sha256': sha(previous / 'run/results.jsonl'),
               'recorded_calls_replayed': sum(r['recorded_calls_replayed'] for r in results),
               'monitor_predicate_calls': len(observed), 'exact_pre_eval_for_all_nonempty': True,
               'source_hashes': {p: sha(ROOT / p) for p in sources},
               'monitor_hashes': {k: sha(Path(os.environ[k])) for k in ('ENFFLASH_BIN', 'ENFFLASH_COMPILER')},
               'claim': 'real runtime/cache/EnfFlash integration replay; fixed recorded model answers, not new accuracy or latency evidence'}
    dump(output / 'summary.json', summary)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--previous', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--production-followup', action='store_true')
    a = p.parse_args()
    print(json.dumps(verify(a.previous, a.output, production_followup=a.production_followup), indent=2))
