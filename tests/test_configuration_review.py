"""Configuration routing and failure contracts, without paid model calls."""
import json
import os
from pathlib import Path

import pytest
import yaml

from instrlib import Enforcer, Event
from instrlib import configuration_review as review
from instrlib import decisions, tool_judge


@pytest.mark.parametrize('path,tool,called', [
    ('/app/pipeline.yaml','file_write',True),
    ('/app/settings.json','file_write',True),
    ('/app/settings.json','file_read',False),
    ('/app/README.md','file_write',False),
    ('/app/test.py','file_write',False),
])
def test_only_configuration_mutations_reach_judge(monkeypatch,path,tool,called):
    seen=[]
    def classify(text):
        seen.append(json.loads(text));return 'execution_hook','classified'
    monkeypatch.setattr(review,'_classifier',classify)
    args={'path':path,'oldText':'a'*9000,'newText':'b'*9000+'\npre_run_hooks: [validate]'}
    facts=review.configuration_events(1,'c',tool,args)
    assert bool(seen)==called
    if called:
        assert seen==[args]
        assert Event('Classify',1,'c','configuration_change','execution_hook') in facts


@pytest.mark.parametrize('response', [None,('benign','unavailable'),('invented','classified')])
def test_malformed_or_failed_judge_cannot_claim_benign(monkeypatch,response):
    monkeypatch.setattr(review,'_classifier',lambda content:response)
    facts=review.configuration_events(1,'c','file_write',{'path':'/app/pipeline.yaml','content':'x'})
    assert Event('Classify',1,'c','configuration_change','uncertain') in facts
    assert Event('Classify',1,'c','configuration_review_status','unavailable') in facts


def test_disabled_classifier_is_explicit_unknown(monkeypatch):
    monkeypatch.setattr(review,'_classifier',None)
    facts=review.configuration_events(1,'c','file_write',{'path':'/app/pipeline.yaml'})
    assert Event('Classify',1,'c','configuration_change','uncertain') in facts


@pytest.mark.parametrize('backend', ['openai','openai_decisions'])
def test_provider_contract_includes_entire_diff(monkeypatch,backend):
    monkeypatch.setenv('ENFGUARD_TOOL_JUDGE_BACKEND',backend)
    monkeypatch.setattr(tool_judge,'_enabled',lambda:True)
    observed=[]
    if backend=='openai':
        def call(content,*args,**kwargs):
            observed.append(content);return '{"label":"execution_hook"}'
        monkeypatch.setattr(tool_judge,'_call_openai',call)
    else:
        def ask(content,questions,*args,**kwargs):
            observed.append(content)
            assert {x['value'] for x in questions[0]['choices']}==review.LABELS
            return {'answers':[{'choice':'execution_hook'}]}
        monkeypatch.setattr(decisions,'ask',ask)
    text=json.dumps({'path':'/app/pipeline.yaml','oldText':'x'*9000,'newText':'x'*9000+' hook'})
    assert review.classify_configuration_with_status(text)==('execution_hook','classified')
    assert observed==[text]


@pytest.mark.parametrize('label,expected', [('execution_hook',True),('security_weakening',True),
                                           ('uncertain',True),('benign',False)])
@pytest.mark.parametrize('tool', ['file_write', 'bash'])
def test_real_monitor_configuration_review(tmp_path,monkeypatch,label,expected,tool):
    binary=Path(os.environ.get('ENFGUARD_BIN',''))
    if not binary.is_file():pytest.skip('Set ENFGUARD_BIN')
    root=Path(__file__).resolve().parents[1]
    pack=yaml.safe_load((root/'examples/presets/release-candidate.yaml').read_text())
    formula=tmp_path/'config.mfotl'
    formula.write_text(next(p['mfotl'] for p in pack['policies'] if p['id']=='configuration_review_v2'))
    monkeypatch.setattr(review,'_classifier',lambda content:(label,'classified'))
    args = {'path':'/app/pipeline.yaml','content':'fixture'} if tool == 'file_write' else {'command':"cat > /app/pipeline.yaml <<'EOF'\nfixture\nEOF\n"}
    facts=review.configuration_events(1,'c',tool,args)
    enforcer=Enforcer(str(binary),str(root/'enfguard.sig'),str(formula));enforcer.start()
    try:
        result=enforcer.query([Event('PolicyActive',1,'configuration_review_v2'),
            Event('ToolPlanned',1,'c',tool,'fixture'),*facts],1)
    finally:enforcer.stop()
    assert any(x['name']=='Approve' for x in result.get('cause',[])) is expected
