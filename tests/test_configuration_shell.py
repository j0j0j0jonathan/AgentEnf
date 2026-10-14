import json
import pytest
from instrlib import configuration_review as review
from instrlib.configuration_shell import shell_configuration_writes
from instrlib.tool_mapper import map_tool_call
from instrlib.event import Event


def here(content='runtime:\n  pre_run_hooks: []', path='/tmp/analysis/config/pipeline.yaml'):
    return f"cat > {path} <<'EOF'\n{content}\nEOF\n"


@pytest.mark.parametrize('content,label', [('runtime:\n  pre_run_hooks: []','benign'),
 ('runtime:\n  pre_run_hooks: [scripts/validate.py]','execution_hook'),
 ('security:\n  authentication: false','security_weakening')])
def test_recovered_content_reaches_existing_judge(monkeypatch,content,label):
    seen=[]
    def classifier(value):
        seen.append(json.loads(value));return label,'classified'
    monkeypatch.setattr(review,'_classifier',classifier)
    command=here(content)
    facts=map_tool_call(1,'c','bash',{'command':command})
    assert seen[0]['writes'][0]['content']==content+'\n'
    assert seen[0]['shell_command']==command
    assert Event('Classify',1,'c','artifact_write','configuration') in facts
    assert Event('Classify',1,'c','configuration_change',label) in facts


@pytest.mark.parametrize('command', [
 'cat /tmp/analysis/config/pipeline.yaml',
 "grep hooks /tmp/analysis/config/pipeline.yaml",
 "sed -n '1,80p' /tmp/analysis/config/pipeline.yaml",
 here('ordinary report', '/tmp/report.md'),
])
def test_reads_and_nonconfigs_not_routed(command):
    assert not shell_configuration_writes(command)


@pytest.mark.parametrize('command', [
 'generate-config > /app/pipeline.yaml',
 "cat > /app/pipeline.yaml <<EOF\n$(get-config)\nEOF",
 "sed -i 's/true/false/' /app/settings.yaml",
 'cp /tmp/generated /app/settings.yaml',
 "python3 -c \"from pathlib import Path; Path('/app/settings.yaml').write_text(payload)\"",
 here('x').replace('cat >','cat >>'),
 here('x', '"$ROOT/pipeline.yaml"'),
 here('safe: true')+'generate > /app/other.yaml',
])
def test_unresolved_cannot_be_cleared_by_judge(monkeypatch,command):
    monkeypatch.setattr(review,'_classifier',lambda _:pytest.fail('Unresolved bytes must not be labelled benign'))
    events=review.configuration_events(1,'c','bash',{'command':command})
    assert Event('Classify',1,'c','configuration_change','uncertain') in events
    assert Event('Classify',1,'c','configuration_review_status','shell_write_unresolved') in events


def test_multiple_writes_are_one_judgment(monkeypatch):
    seen=[]
    monkeypatch.setattr(review,'_classifier',lambda text:(seen.append(json.loads(text)) or ('execution_hook','classified')))
    review.configuration_events(1,'c','bash',{'command':here('safe: true')+here('hooks: [evil]','/app/other.yaml')})
    assert len(seen)==1 and len(seen[0]['writes'])==2


def test_whole_single_quoted_shell_wrapper():
    command='bash -lc '+__import__('shlex').quote(here('hooks: []').replace("'EOF'",'"EOF"'))
    result=shell_configuration_writes(command)
    assert result['writes'][0]['content']=='hooks: []\n'


def test_recorded_smoke_command(monkeypatch):
    from pathlib import Path
    args=json.loads((Path(__file__).parent/'fixtures/configuration_shell_observed.json').read_text())
    seen=[]
    monkeypatch.setattr(review,'_classifier',lambda text:(seen.append(json.loads(text)) or ('benign','classified')))
    events=map_tool_call(41,'recorded','bash',args)
    assert seen and seen[0]['writes'][0]['path']=='/tmp/analysis/config/pipeline.yaml'
    assert 'pre_run_hooks: []' in seen[0]['writes'][0]['content']
    assert Event('Classify',41,'recorded','configuration_change','benign') in events
