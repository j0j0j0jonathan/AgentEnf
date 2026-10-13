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

test('a misspelled failure mode cannot silently allow tool execution', () => {
  assert.throws(() => register({ failMode: 'closed' }), /failMode/);
  assert.throws(() => register({ failMode: 'blok' }), /failMode/);
});

test('after callback for a blocked call preserves non-execution', async (t) => {
  const payloads = [];
  t.mock.method(globalThis, 'fetch', async (_, options) => {
    payloads.push(JSON.parse(options.body));
    return { ok: true, status: 200, json: async () => ({ decision: 'block' }) };
  });
  const h = register({ sid: 'denial-result' });
  assert.equal((await h.before_tool_call(event)).block, true);
  await h.after_tool_call({ ...event, result: 'Operation blocked by AgentEnf' });
  assert.equal(payloads[1].tool_execution.effect_executed, false);
  assert.equal(payloads[1].tool_execution.effective_verdict, 'block');
});

test('failed result delivery does not suppress the next identical observation', async (t) => {
  for (const failure of ['transport', 'http', 'malformed']) {
    const payloads = [];
    let attempt = 0;
    const mock = t.mock.method(globalThis, 'fetch', async (_, options) => {
      payloads.push(JSON.parse(options.body));
      if (attempt++ === 0) {
        if (failure === 'transport') throw new Error('offline');
        return { ok: failure !== 'http', status: failure === 'http' ? 503 : 200,
          json: async () => failure === 'http' ? { decision: 'allow' } : {} };
      }
      return { ok: true, status: 200, json: async () => ({ decision: 'allow' }) };
    });
    const h = register({ sid: `retry-${failure}` });
    const result = { toolName: 'process', params: { sessionId: 'worker' },
      toolCallId: 'poll', result: 'result containing relevant evidence' };
    await h.after_tool_call(result);
    await h.after_tool_call(result);
    await h.after_tool_call(result);
    assert.equal(payloads[1].tool_response, result.result);
    assert.equal(payloads[1].result_duplicate, false);
    assert.equal(payloads[2].result_duplicate, true);
    mock.mock.restore();
  }
});

test('large repeated results deduplicate without confusing a changed suffix', async (t) => {
  const payloads = [];
  t.mock.method(globalThis, 'fetch', async (_, options) => {
    payloads.push(JSON.parse(options.body));
    return { ok: true, status: 200, json: async () => ({ decision: 'allow' }) };
  });
  const h = register({ sid: 'long-result' });
  const result = { toolName: 'process', params: { sessionId: 'worker' },
    toolCallId: 'poll', result: 'x'.repeat(200_001) };
  await h.after_tool_call(result);
  await h.after_tool_call(result);
  await h.after_tool_call({ ...result, result: `${result.result}changed` });
  assert.equal(payloads[1].result_duplicate, true);
  assert.equal(payloads[2].result_duplicate, false);
});

test('policy blocks carry structured attribution and rule identifiers', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => ({ok: true, status: 200,
    json: async () => ({decision: 'block', reason: 'credential read denied', tid: 42,
      decision_trace: {policy_decision: 'block', policy_verdicts: [
        {action: 'BlockToolCall', category: 'credential_read_for_requested_disclosure'}]}})}));
  const result = await register().before_tool_call(event, {sessionKey: 'demo'});
  assert.equal(result.block, true);
  const record = JSON.parse(result.blockReason.split('[EnfAgent enforcement] ')[1]);
  assert.equal(record.kind, 'policy_block');
  assert.deepEqual(record.rules, ['credential_read_for_requested_disclosure']);
  assert.equal(record.timepoint, 42);
});

test('connection failure is distinguished from a policy block', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {throw new Error('offline');});
  const result = await register().before_tool_call(event);
  const record = JSON.parse(result.blockReason.split('[EnfAgent enforcement] ')[1]);
  assert.equal(record.kind, 'service_failure');
  assert.deepEqual(record.rules, []);
});

test('after hook distinguishes reported process completion from a returned callback', async (t) => {
  const payloads = [];
  t.mock.method(globalThis, 'fetch', async (_, options) => {
    payloads.push(JSON.parse(options.body));
    return { ok: true, status: 200, json: async () => ({ decision: 'allow' }) };
  });
  const h = register({ sid: 'outcomes' });
  for (const [result, expected] of [
    ['Done!', 'unknown'],
    [{ details: { status: 'running', exitCode: 0 } }, 'running'],
    [{ exitCode: 0 }, 'completed'],
    [{ exitCode: 2 }, 'failed'],
    [{ isError: true, exitCode: 0 }, 'failed'],
  ]) {
    await h.after_tool_call({ ...event, result });
    assert.equal(payloads.at(-1).tool_execution.outcome, expected);
  }
});

test('runtime namespace comes from operator config, not tool arguments', async (t) => {
  const payloads = [];
  t.mock.method(globalThis, 'fetch', async (_, options) => {
    payloads.push(JSON.parse(options.body));
    return { ok: true, status: 200, json: async () => ({ decision: 'allow', tid: 42 }) };
  });
  await register({ runtimeNamespace: 'container-A' }).before_tool_call({
    ...event, params: { command: 'echo hello', runtime_namespace: 'spoofed-B' }
  });
  assert.equal(payloads[0].runtime_namespace, 'container-A');
});
