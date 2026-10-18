import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {attestFullWrite} from './enfguard-gate/artifact.js';
import {pluginDefinition} from './enfguard-gate/gate.js';
function fixture(t) {
  const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'agent-artifact-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const p=path.join(root,'job.py');const content='print("Grüße 秘密")\n';fs.writeFileSync(p,content);
  return {p,content,ticket:{path:p,token:'nonce',sha256:createHash('sha256').update(content).digest('hex'),bytes:Buffer.byteLength(content)}};
}
test('only a complete matching snapshot attests content', t=>{
  const {p,ticket}=fixture(t);const execution={effect_executed:true,outcome:'unknown'};
  assert.equal(attestFullWrite(ticket,{},execution).sha256,ticket.sha256);
  for(const outcome of ['failed','running','not_executed'])assert.equal(attestFullWrite(ticket,{}, {...execution,outcome}),null);
  assert.equal(attestFullWrite(ticket,{}, {effect_executed:false}),null);
  assert.equal(attestFullWrite({...ticket,sha256:'0'.repeat(64)}, {},execution),null);
  fs.writeFileSync(p,'different');assert.equal(attestFullWrite(ticket,{},execution),null);
});
test('symlink and oversized ticket cannot attest', t=>{
  const {p,ticket}=fixture(t);const link=p+'.link';fs.symlinkSync(p,link);
  assert.equal(attestFullWrite({...ticket,path:link},{},{effect_executed:true}),null);
  assert.equal(attestFullWrite({...ticket,bytes:200001},{},{effect_executed:true}),null);
});
test('pre-hook ticket is tied to runtime completion and background arguments survive', async t=>{
  const {p,content,ticket}=fixture(t);const calls=[];const cb={};
  t.mock.method(globalThis,'fetch',async (_,opts)=>{
    calls.push(JSON.parse(opts.body));return {ok:true,status:200,json:async()=>({decision:'allow',artifact_ticket:ticket})};
  });
  pluginDefinition.register({pluginConfig:{adminToken:'test',sid:'s',runtimeNamespace:'N'},on:(name,fn)=>cb[name]=fn});
  const e={toolName:'write',params:{path:p,content},toolCallId:'write-unique'};
  await cb.before_tool_call(e);await cb.after_tool_call({...e,result:'done'});
  assert.equal(calls[0].tool_input.operation,'replace');assert.deepEqual(calls[1].artifact_attestation,{kind:'verified_full_write',...ticket});
  await cb.before_tool_call({toolName:'exec',params:{command:'python job.py',background:true,workdir:'/app'},toolCallId:'exec-unique'});
  assert.equal(calls[2].tool_input.background,true);assert.equal(calls[2].tool_input.workdir,'/app');
});
