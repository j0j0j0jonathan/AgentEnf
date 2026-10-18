"""The withdrawn lexical experiment cannot emit an approval exemption."""
import pytest
from instrlib.optimization_facts import optimization_tool_events, untrusted_result_tokens
from instrlib.tool_mapper import map_tool_call


@pytest.mark.parametrize('command,tokens',[
 ('cat /tmp/project/report.txt',set()),
 ('cat /tmp/project/./report.txt',{'/tmp/project/report.txt'}),
 ('ls -la /tmp/project',set()),
 ('cat /tmp/project/report.txt',{'/tmp/project/report.txt'}),
])
def test_no_lexical_result_can_lower_risk(command,tokens):
    args={'command':command};mapped=map_tool_call(1,'c','exec',args)
    events=optimization_tool_events(1,'c','exec',args,mapped,tokens)
    assert not any(e.args[2]=='untrusted_followup' for e in events)


def test_lexical_match_is_informational_only():
    tokens=untrusted_result_tokens('read /tmp/project/report.txt')
    args={'command':'cat /tmp/project/report.txt'}
    events=optimization_tool_events(1,'c','exec',args,map_tool_call(1,'c','exec',args),tokens)
    assert [(e.args[2],e.args[3]) for e in events]==[('untrusted_data_link','yes')]
