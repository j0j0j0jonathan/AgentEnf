import pytest
from instrlib.tool_mapper import classify_execution_kind, map_tool_call

@pytest.mark.parametrize('tail',['stat -c %A /tmp/job.sh','bash -n /tmp/job.sh','sha256sum /tmp/job.sh','cat /tmp/job.sh','echo /tmp/job.sh'])
def test_permission_change_is_not_execution(tail):
    cmd='chmod +x /tmp/job.sh && '+tail
    assert classify_execution_kind(cmd) is None
    f={tuple(e.args[2:]) for e in map_tool_call(1,'c','exec',{'command':cmd}) if e.name=='Classify'}
    assert ('chmod_exec_path','/tmp/job.sh') in f
    assert not any(k=='execution_kind' for k,v in f)

@pytest.mark.parametrize('tail',['bash /tmp/job.sh','nohup bash /tmp/job.sh','PIPELINE_ENV=development /tmp/job.sh','sudo /tmp/job.sh','timeout 30 /tmp/job.sh'])
def test_real_following_execution_remains_classified(tail):
    assert classify_execution_kind('chmod +x /tmp/job.sh && '+tail)=='untrusted_exec'

def test_different_artifact_does_not_satisfy_chmod_join():
    assert classify_execution_kind('chmod +x /tmp/job.sh && bash /tmp/other.sh') is None
