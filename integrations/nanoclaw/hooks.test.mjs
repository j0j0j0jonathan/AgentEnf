import assert from 'node:assert/strict';
import test from 'node:test';
import { createAgentEnfHooks } from './hooks.mjs';
const input = { tool_use_id: 'call-1', tool_name: 'Bash', tool_input: { command: 'echo hello' } };
function hooks(fetchImpl, extra = {}) {
  return createAgentEnfHooks({ apiUrl: 'http://localhost:9000', adminToken: 'test', sessionId: 'session-1', fetchImpl, ...extra });
}
test('allows only an explicit allow and preserves runtime permission handling', async () => {
  let payload;
  const h = hooks(async (_, options) => {
    payload = JSON.parse(options.body);
    return { ok: true, json: async () => ({ decision: 'allow' }) };
  });
  assert.deepEqual(await h.preToolUse(input), { continue: true });
  assert.equal(payload.call_id, 'call-1');
  assert.equal(payload.sid, 'session-1');
  assert.equal('tid' in payload, false);
});
test('blocks denial, malformed response, HTTP failure and transport failure', async () => {
  for (const response of [
    async () => ({ ok: true, json: async () => ({ decision: 'block', reason: 'rule' }) }),
    async () => ({ ok: true, json: async () => ({}) }),
    async () => ({ ok: false, status: 503 }),
    async () => { throw new Error('connection refused'); },
  ]) assert.equal((await hooks(response).preToolUse(input)).hookSpecificOutput.permissionDecision, 'deny');
});
test('waits for approval response before returning', async () => {
  let resolve;
  const h = hooks(() => new Promise((r) => { resolve = r; }));
  let finished = false;
  const pending = h.preToolUse(input).then((r) => { finished = true; return r; });
  await Promise.resolve();
  assert.equal(finished, false);
  resolve({ ok: true, json: async () => ({ decision: 'allow' }) });
  await pending;
  assert.equal(finished, true);
});
test('result failures are reported without claiming to reverse execution', async () => {
  const errors = [];
  const h = hooks(async () => { throw new Error('offline'); }, { onObservationError: (e) => errors.push(e) });
  assert.deepEqual(await h.postToolUse({ ...input, tool_response: 'done' }), { continue: true });
  assert.equal(errors.length, 1);
});
