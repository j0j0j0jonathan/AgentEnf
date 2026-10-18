"""Distinguish a collected trajectory from a functioning enforcement experiment."""
import json
from pathlib import Path
import re


def inspect_health(directory, data=None):
    directory = Path(directory)
    if data is None:
        data = json.loads((directory / 'rollout.json').read_text())
    faults, failures = [], {}
    if not data.get('overall_success') or not data.get('turn_results'):
        faults.append({'kind': 'incomplete_trajectory'})
    for turn in data.get('turn_results', []):
        text = (turn.get('agent_response') or '').strip()
        # OpenClaw may report an upstream error as a successful text response.
        status = re.match(r'(?:HTTP\s+)?([45]\d\d)\s+(?:status code|[A-Za-z ]*error)', text, re.I)
        if turn.get('error') or not turn.get('success') or status:
            faults.append({'kind': 'agent_turn_infrastructure_error',
                           'turn_index': turn.get('turn_index'),
                           'status': int(status[1]) if status else None})
    log = directory / 'proxy.log'
    if log.exists():
        stopping = False
        lines = [re.sub(r'\x1b\[[0-9;]*m', '', line)
                 for line in log.read_text(errors='replace').splitlines()]
        panicked = False
        for number, line in enumerate(lines, 1):
            if re.match(r'^\[[^\]]+\] \[reader\s*\]: Skipping non-JSON: thread .*panicked at', line):
                panicked = True
            if re.match(r'^\[[^\]]+\] \[writer\s*\]: Starting policy monitor:', line):
                stopping = False
            if re.match(r'^\[[^\]]+\] \[writer\s*\]: Stopping EnfGuard\.', line):
                stopping = True
            if line == 'INFO:     Shutting down':
                stopping = True
            # Match operational log prefixes, not words in observed file text.
            if not stopping and re.match(r'^\[[^\]]+\] \[reader\s*\]: .*\[guard\] monitor unavailable:', line):
                # The retained launcher SIGTERMs the entire process group. The
                # child can exit just before Uvicorn prints its shutdown line.
                # Accept that terminal sequence only without a panic or any
                # later HTTP request; do not hide a mid-trajectory outage.
                tail = lines[number:]
                group_shutdown = (not panicked and 'INFO:     Shutting down' in tail[:8]
                                  and not any(re.match(r'^INFO:.*"(?:POST|GET) ', x) for x in tail))
                if group_shutdown:
                    continue
                faults.append({'kind': 'monitor_unavailable', 'file': 'proxy.log', 'line': number})
    for file in (directory / 'proxy_session_logs/predicate_evidence').glob('calls-*.jsonl'):
        for number, line in enumerate(file.read_text().splitlines(), 1):
            row = json.loads(line)
            if not row.get('failure'):
                continue
            key = (row['context'].get('tid'), row['predicate'], row['input']['sha256'])
            raw = json.loads(row['raw_reply']) if row.get('raw_reply') else {}
            failures.setdefault(key, {'tid': key[0], 'predicate': key[1], 'input_sha256': key[2],
                'failure_mode': row['failure'], 'reason': row.get('reason'),
                'error_code': raw.get('evidence', {}).get('error_code'),
                'file': str(file.relative_to(directory)), 'line': number})
    return {'schema': 1, 'infrastructure_faults': faults,
            'predicate_failures': list(failures.values()),
            'valid_for_effectiveness': not faults,
            'ready_for_expansion': not faults and not failures,
            'meaning': 'Collection completeness is separate from runtime health and task success.'}


def require_healthy(directory, data):
    report = inspect_health(directory, data)
    (Path(directory) / 'HEALTH_CHECK.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['ready_for_expansion']:
        raise RuntimeError('Pilot infrastructure/classifier failure; inspect HEALTH_CHECK.json before continuing')
    return report
