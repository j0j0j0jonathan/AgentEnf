"""Derived judge view: retain observations, deduplicate payloads, normalize SSE.

Original evidence stays immutable. Stream normalization requires a terminal full
response; otherwise the exact stream is retained and a gap is reported. No
result is inferred from a proposal, and coverage is never upgraded here.
"""
import copy
import json
from experiments.paper.evidence_bundle import digest


def stream_response(value):
    if not isinstance(value, str) or not value.lstrip().startswith('event:'):
        return value, None
    finals = []
    for line in value.split('\n'):
        if not line.startswith('data:'):
            continue
        raw = line[5:].strip()
        if raw == '[DONE]':
            continue
        try:
            event = json.loads(raw)
        except ValueError:
            return value, 'malformed_stream_retained'
        if event.get('type') in {'response.completed','response.incomplete','response.failed'}:
            if isinstance(event.get('response'),dict):
                finals.append(event)
    if len(finals)!=1:
        return value, 'missing_or_multiple_terminal_response_retained'
    # Terminal response contains the assembled output; streamed deltas are not
    # a second delivered answer. Keep status/error/usage and all output items.
    return {'representation':'terminal_response_from_recorded_sse',
            'terminal_event':finals[0]}, None


def compact(bundle):
    result = copy.deepcopy(bundle)
    shared = {}
    transforms = []

    def intern(value):
        if isinstance(value, dict):
            reduced={k:intern(v) for k,v in value.items()}
        elif isinstance(value,list):
            reduced=[intern(v) for v in value]
        else:
            reduced=value
        if isinstance(value,(dict,list,str)) and len(json.dumps(reduced,ensure_ascii=False).encode())>=256:
            key=digest(reduced)
            shared.setdefault(key,reduced)
            return {'$shared_payload':key}
        return reduced

    for record in result['evidence']:
        original=record['payload']
        if digest(original)!=record['sha256']:
            raise ValueError('Evidence hash mismatch: '+record['ref'])
        normalized=original
        if record['kind']=='observed_model_response_body':
            normalized,gap=stream_response(original)
            if gap:
                result['gaps'].append({'gap':gap,'ref':record['ref']})
            if normalized!=original:
                transforms.append({'ref':record['ref'],'original_sha256':record['sha256'],
                                   'normalized_sha256':digest(normalized),'method':'terminal_sse_response'})
        record['payload']=intern(normalized)
        record['original_sha256']=record['sha256']
        record['sha256']=digest(record['payload'])
    result['shared_payloads']=shared
    result['representation']={
        'version':'deduplicated-evidence-v1',
        'instructions':'Resolve {"$shared_payload": HASH} recursively using shared_payloads. References preserve each observation and its order. Repeated payloads are repeated observations, not new effects. Terminal SSE responses replace streaming fragments only; they do not prove delivery.',
        'source_bundle_sha256':digest(bundle),'transforms':transforms,
        'coverage_unchanged':True}
    # Verify the reversible part and every unchanged record, before accepting.
    for before,after in zip(bundle['evidence'],result['evidence'],strict=True):
        expanded=expand(after['payload'],shared)
        if before['kind']=='observed_model_response_body':
            expected,_=stream_response(before['payload'])
        else:expected=before['payload']
        if expanded!=expected:raise ValueError('Lossy compaction: '+before['ref'])
    return result


def expand(value,shared):
    if isinstance(value,dict):
        if set(value)=={'$shared_payload'}:
            return expand(shared[value['$shared_payload']],shared)
        return {k:expand(v,shared) for k,v in value.items()}
    if isinstance(value,list):return [expand(v,shared) for v in value]
    return value


def expanded_bundle(bundle):
    result=copy.deepcopy(bundle)
    for record in result['evidence']:
        record['payload']=expand(record['payload'],result['shared_payloads'])
        record['sha256']=digest(record['payload'])
    return result
