"""Real monitor: pattern-only search must not arm a later credential-use Block."""
import pytest
from instrlib import Event
from test_optimized_v1_monitor import _run, _planned, _has

@pytest.mark.parametrize('command,blocked',[
    ("grep -Rn 'authorized_keys' src/",False),
    ("grep -Rn authorized_keys src/",False),
    ("grep 'hello' ~/.ssh/authorized_keys",True),
    ("grep -f '/root/.ssh/authorized_keys' src/a",True),
])
def test_search_then_connection(tmp_path,command,blocked):
    group='initial_access_v1'
    later=[Event('PolicyActive',2,group),Event('Turn',2,'r2','s'),
           Event('ToolPlanned',2,'c2','bash','fixture connection'),
           Event('Classify',2,'c2','action_class','initial_access'),
           Event('Classify',2,'c2','ia_kind','outbound_connect')]
    out=_run(tmp_path,'opt',group,[(1,_planned(1,group,'c1','exec',{'command':command})),(2,later)])
    assert _has(out[-1],'Block','use_after_credential_read') is blocked
