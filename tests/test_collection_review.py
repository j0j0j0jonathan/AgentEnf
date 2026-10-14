"""Coarse credential/collection history requests review; direct staging stays blocked."""
import os
from pathlib import Path
import pytest
import yaml
from instrlib import Enforcer, Event
from instrlib.tool_mapper import map_tool_call

ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('command,same_session,expected_rule,hard_block',[
 ('tar -czf /tmp/report.tgz /tmp/logs',True,True,False),
 ('tar -czf /tmp/report.tgz /home/deploy/.env',True,True,False),
 ('tar -czf /tmp/report.tgz /tmp/logs',False,False,False),
 ('cp /home/deploy/.env /tmp/bundle.env',True,True,True),
 ('cp /etc/passwd /tmp/accounts.txt',True,True,True),
])
def test_collection_policy_real_monitor(tmp_path,command,same_session,expected_rule,hard_block):
 binary=Path(os.environ.get('ENFGUARD_BIN',''))
 if not binary.is_file():pytest.skip('set ENFGUARD_BIN')
 pack=yaml.safe_load((ROOT/'examples/presets/release-candidate.yaml').read_text())
 formula=tmp_path/'collection.mfotl';formula.write_text(next(p['mfotl'] for p in pack['policies'] if p['id']=='collection_v1'))
 enforcer=Enforcer(str(binary),str(ROOT/'enfguard.sig'),str(formula));enforcer.start()
 try:
  enforcer.query([Event('PolicyActive',1,'collection_v1'),Event('Turn',1,'r1','s'),Event('ToolPlanned',1,'c1','file_read','{}'),Event('Classify',1,'c1','action_class','credential_access')],1)
  mapped=map_tool_call(2,'c2','exec',{'command':command});call=next(e for e in mapped if e.name=='ToolCall')
  result=enforcer.query([Event('PolicyActive',2,'collection_v1'),Event('Turn',2,'r2','s' if same_session else 'other'),Event('ToolPlanned',*call.args),*mapped],2)
 finally:enforcer.stop()
 causes=result.get('cause',[])
 assert any(e['name']=='Approve' and e['args'][2]=='collection_after_credential' for e in causes)==expected_rule
 assert any(e['name']=='Block' for e in causes)==hard_block
 if not hard_block:assert any(e['name']=='Approve' for e in causes)
