"""A response is a new trace position, not a continuation of inbound facts."""
import os
from pathlib import Path

import pytest

from instrlib import Enforcer, Event
from proxy import _response_turn_events


def test_response_context_keeps_exact_request_identity_only():
    original = Event('Turn', 9, 'client-request', 'session-A')
    assert _response_turn_events([original, Event('Message', 9, 'user', 'text', 1)]) == [original]


@pytest.mark.parametrize('include_turn,same_session,expected', [
    (False, True, False),  # former response batch: same tid is insufficient
    (True, True, True),
    (True, False, False),
])
def test_real_monitor_response_history_join(tmp_path, include_turn, same_session, expected):
    binary = Path(os.environ.get('ENFGUARD_BIN', ''))
    if not binary.is_file():
        pytest.skip('Set ENFGUARD_BIN for actual monitor semantics')
    root = Path(__file__).resolve().parents[1]
    formula = tmp_path / 'response.mfotl'
    formula.write_text('''ALWAYS (FORALL t, rid, s, content, n.
      (Turn(t, rid, s) AND Completion(t, content, n)
       AND ONCE [0, 600] (EXISTS t2, rid2, c.
         Turn(t2, rid2, s) AND NOT (t = t2)
         AND Classify(t2, c, "content_risk", "secret_material")))
      IMPLIES:R Block(t, "response", "test_history", "earlier secret result"))''')
    enforcer = Enforcer(str(binary), str(root / 'enfguard.sig'), str(formula))
    enforcer.start()
    try:
        enforcer.query([Event('Turn', 1, 'tool-result', 'session-A'),
            Event('Classify', 1, 'c', 'content_risk', 'secret_material')], 1, trace_ts=100)
        inbound = [Event('Turn', 2, 'request', 'session-A' if same_session else 'session-B'),
                   Event('Message', 2, 'user', 'continue', 1)]
        enforcer.query(inbound, 2, trace_ts=101)
        outbound = [Event('Completion', 2, 'fixture output', 2)]
        if include_turn:
            outbound = _response_turn_events(inbound) + outbound
        # Even identical wall-clock timestamps don't merge the two positions.
        result = enforcer.query(outbound, 2, trace_ts=101)
        blocked = any(e['name']=='Block' for e in result.get('cause', []))
        assert blocked is expected
    finally:
        enforcer.stop()


@pytest.mark.parametrize('api_format', ['openai', 'anthropic', 'openai_responses'])
@pytest.mark.parametrize('stream', [False, True])
def test_actual_response_routes_submit_turn(monkeypatch, api_format, stream):
    import asyncio
    import proxy
    from starlette.requests import Request

    class Captured(Exception):
        pass

    async def inbound(*args):
        return {}, {}, 0

    async def outbound(tid, sid, events, *args):
        turn = next(e for e in events if e.name == 'Turn')
        assert turn.args == (tid, 'req-' + str(tid), 'session-A')
        assert any(e.name == 'Completion' for e in events)
        raise Captured

    async def upstream():
        pytest.fail('Synthetic route must not call a provider')

    monkeypatch.setattr(proxy, '_phase1_enforce', inbound)
    monkeypatch.setattr(proxy, '_phase2_enforce', outbound)
    monkeypatch.setattr(proxy.state, 'enforcer', None)
    request = Request({'type':'http', 'headers':[
        (b'x-session-id', b'session-A'), (b'x-synthetic-completion', b'fixture reply')]})
    body = {'model':'fixture', 'stream':stream, 'messages':[{'role':'user','content':'continue'}]}
    with pytest.raises(Captured):
        asyncio.run(proxy._run_enforced_request(request, body, api_format, api_format,
            upstream, None, None, None))
