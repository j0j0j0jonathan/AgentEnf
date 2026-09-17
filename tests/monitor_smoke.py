"""Live monitor acceptance check used by test_monitor_service.py."""
import asyncio, os, tempfile, sys
from pathlib import Path
root=Path.cwd(); sys.path.insert(0,str(root))
with tempfile.TemporaryDirectory(prefix='agentenf-smoke-') as tmp:
 os.environ.update(ENFGUARD_ADMIN_TOKEN='local-smoke-test', ENFGUARD_TOOL_JUDGE='0', ENFGUARD_YAML=str(root/'examples/nanoclaw/enfguard.nanoclaw-tools.yaml'),ENFGUARD_STATE_DIR=tmp+'/state',ENFGUARD_LOG_DIR=tmp+'/logs',ENFGUARD_SESSIONS_DIR=tmp+'/sessions',ENFGUARD_TIME_MODE='wall_seconds',ENFGUARD_BIN=os.environ['ENFGUARD_BIN'])
 import httpx,proxy
 async def check():
  async with proxy.app.router.lifespan_context(proxy.app):
   async with httpx.AsyncClient(transport=httpx.ASGITransport(app=proxy.app),base_url='http://test',headers={'X-Admin-Token':'local-smoke-test'}) as c:
    r=await c.post('/v1/tool_execute',json={'sid':'smoke','call_id':'ok-1','tool_name':'bash','tool_input':{'command':'echo hello'}})
    assert r.status_code==200,r.text
    assert r.json()['decision']=='allow',r.text
    r=await c.post('/v1/tool_execute',json={'sid':'smoke','call_id':'deny-1','tool_name':'bash','tool_input':{'command':'rm -rf /important'}})
    assert r.status_code==200 and r.json()['decision']=='block',r.text
    pending=asyncio.create_task(c.post('/v1/tool_execute',json={'sid':'smoke','call_id':'approve-1','tool_name':'read_file','tool_input':{'path':'/etc/shadow'}}))
    for _ in range(100):
     if proxy.state.pending_approvals: break
     await asyncio.sleep(.05)
    assert not pending.done(),'Approval did not wait'
    tid=next(iter(proxy.state.pending_approvals))
    reply=await c.post('/feedback',json={'tid':tid,'kind':'deny','payload':'smoke test'})
    assert reply.status_code==200,reply.text
    r=await asyncio.wait_for(pending,5)
    assert r.json()['decision']=='block',r.text
    print('PASS: real monitor allow, block, pending approval and denial')
 asyncio.run(check())
