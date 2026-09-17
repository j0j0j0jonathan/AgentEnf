import assert from 'node:assert/strict';
import test from 'node:test';
import { pluginDefinition } from './enfguard-gate/gate.js';
function register(config = {}) {
  const callbacks = {};
  pluginDefinition.register({ pluginConfig: { adminToken: 'test', ...config }, on: (name, fn) => { callbacks[name] = fn; } });
  return callbacks;
}
const event = { toolName: 'exec', params: { command: 'echo hello' }, toolCallId: 'call-1' };
test('gate awaits an explicit allow with proxy-allocated timepoint', async (t) => {
  const payloads = [];
  t.mock.method(globalThis, 'fetch', async (_, options) => {
    payloads.push(JSON.parse(options.body));
    return { ok: true, status: 200, json: async () => ({ decision: 'allow', tid: 41 }) };
  });
  const h = register();
  assert.equal(await h.before_tool_call(event, { sessionKey: 'session-1' }), undefined);
  assert.equal(payloads[0].sid, 'session-1');
  assert.equal('tid' in payloads[0], false);
  await h.after_tool_call({ ...event, result: 'hello' }, { sessionKey: 'session-1' });
  assert.equal(payloads[1].call_id, payloads[0].call_id);
});
test('invalid or unavailable gate responses fail closed', async (t) => {
  for (const value of [{}, { decision: 'nonsense' }, { decision: 'block' }]) {
    const mock = t.mock.method(globalThis, 'fetch', async () => ({ ok: true, status: 200, json: async () => value }));
    assert.equal((await register().before_tool_call(event)).block, true);
    mock.mock.restore();
  }
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('offline'); });
  assert.equal((await register().before_tool_call(event)).block, true);
});
test('missing token is rejected at registration', () => {
  const previous = process.env.ENFGUARD_ADMIN_TOKEN;
  delete process.env.ENFGUARD_ADMIN_TOKEN;
  try { assert.throws(() => register({ adminToken: '' }), /ADMIN_TOKEN/); }
  finally { if (previous !== undefined) process.env.ENFGUARD_ADMIN_TOKEN = previous; }
});
