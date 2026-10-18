"""Verify every retained pilot tool-result string through real EnfFlash, offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from instrlib import Event
from instrlib.enfflash import EnfFlashEnforcer


def verify(pilot, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    sig = output / 'probe.sig'
    sig.write_text('Input(t:int,content:string)\nBlock(t:int,phase:string,category:string,reason:string)+\n')
    formula = output / 'probe.mfotl'
    formula.write_text('ALWAYS (FORALL t,content. Input(t,content) IMPLIES:R Block(t,"probe","roundtrip",content))')
    engine = EnfFlashEnforcer(os.environ['ENFFLASH_BIN'], str(sig), str(formula),
        compiler=os.environ['ENFFLASH_COMPILER'], cache_dir=output / 'compiled')
    records, unique = [], set()
    engine.start()
    try:
        for file in sorted((Path(pilot) / 'live').glob('*/*/run1/rollout.json')):
            data = json.loads(file.read_text())
            for turn in data['turn_results']:
                for log in turn['new_logs']:
                    if log.get('phase') != 'result':
                        continue
                    content = log.get('result')
                    if not isinstance(content, str):
                        raise ValueError('Unexpected non-text tool result; inspect explicitly')
                    tid = len(records) + 1
                    verdict = engine.query([Event('Input', tid, content)], tid)
                    values = [e['args'][3] for e in verdict.get('cause', []) if e['name'] == 'Block']
                    assert values == [content], (str(file), turn['turn_index'], log['tool_call_id'])
                    digest = hashlib.sha256(content.encode()).hexdigest()
                    unique.add(digest)
                    records.append({'file': str(file.resolve()), 'turn': turn['turn_index'],
                        'call_id': log['tool_call_id'], 'sha256': digest,
                        'bytes': len(content.encode()), 'exact_roundtrip': True})
    finally:
        engine.stop()
    summary = {'tool_results': len(records), 'unique_strings': len(unique),
               'exact_roundtrip': True, 'api_calls': 0,
               'monitor_sha256': hashlib.sha256(Path(os.environ['ENFFLASH_BIN']).read_bytes()).hexdigest(),
               'scope': 'Real parser and event-string roundtrip; not full-policy equivalence.'}
    (output / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pilot', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.pilot, args.output), indent=2))
