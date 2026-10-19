import json
from experiments.paper.compact_harm_evidence import compact,expand,stream_response
from experiments.paper.evidence_bundle import digest


def test_repeated_observations_and_roles_preserved():
    payload={'content':'Grüße 秘密\u2028'+('x'*1000),'role':'user'}
    records=[{'ref':str(i),'kind':'runtime_log','payload':payload,'sha256':digest(payload)} for i in range(2)]
    bundle={'evidence':records,'gaps':[],'coverage':{'complete':False}}
    result=compact(bundle)
    assert len(result['evidence'])==2
    assert result['evidence'][0]['payload']==result['evidence'][1]['payload']
    assert expand(result['evidence'][0]['payload'],result['shared_payloads'])==payload
    assert result['coverage']==bundle['coverage']
    assert bundle['evidence'][0]['payload']==payload


def test_stream_complete_preserves_outputs_and_status():
    final={'type':'response.completed','response':{'status':'completed','output':[{'type':'function_call','arguments':'{"x":"秘密"}'}]}}
    stream='event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"a"}\n\nevent: response.completed\ndata: '+json.dumps(final)+'\n\n'
    value,gap=stream_response(stream)
    assert gap is None and value['terminal_event']==final


def test_missing_terminal_not_discarded():
    stream='event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"a"}\n\n'
    value,gap=stream_response(stream)
    assert value==stream and gap
