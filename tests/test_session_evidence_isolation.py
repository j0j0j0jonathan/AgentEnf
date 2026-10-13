"""Repeated runtime call IDs must not suppress or contaminate another session."""
import pytest

import proxy
from config import CONFIG
from runtime_state import ProxyState


def test_blocked_call_ids_are_session_local():
    state = ProxyState(CONFIG)
    state.record_blocked_call("call-1", "alice")
    assert state.is_blocked_call("call-1", "alice")
    assert not state.is_blocked_call("call-1", "bob")
    assert not state.is_blocked_call("call-1", "")
    assert state.blocked_call_ids_snapshot("alice") == frozenset({"call-1"})
    assert state.blocked_call_ids_snapshot("bob") == frozenset()


@pytest.mark.parametrize("format,body", [
    ("openai", {"messages": [{"role": "tool", "tool_call_id": "call-1", "content": "result"}]}),
    ("openai_responses", {"input": [{"type": "function_call_output", "call_id": "call-1", "output": "result"}]}),
    ("anthropic", {"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call-1", "content": "result"}]}]}),
])
def test_warning_for_other_session_is_not_injected_or_consumed(monkeypatch, format, body):
    state = ProxyState(CONFIG)
    monkeypatch.setattr(proxy, "state", state)
    state.record_tool_warning("call-1", "Alice private policy warning", "alice")
    assert proxy._inject_tool_warning_advisories(body, format, "bob") == 0
    assert "Alice private" not in str(body)
    assert proxy._inject_tool_warning_advisories(body, format, "alice") == 1
    assert "Alice private" in str(body)
    assert proxy._inject_tool_warning_advisories(body, format, "alice") == 0


@pytest.mark.anyio
async def test_real_result_is_classified_despite_block_in_another_session(monkeypatch):
    state = ProxyState(CONFIG)
    state.record_blocked_call("call-1", "alice")
    monkeypatch.setattr(proxy, "state", state)
    monkeypatch.setattr(proxy, "_require_admin", lambda request: None)
    monkeypatch.setattr(proxy, "_active_policies", lambda: [])
    monkeypatch.setattr(proxy, "_append_session_log", lambda *args, **kwargs: None)
    observed = []
    monkeypatch.setattr(proxy, "_tool_result_content_risk_events",
                        lambda *args: observed.append(args) or [])

    async def enforce(*args, **kwargs):
        return {}, {}, 0

    monkeypatch.setattr(proxy, "_tool_phase_enforce", enforce)

    class Request:
        headers = {"x-session-id": "bob"}

        async def json(self):
            return {"call_id": "call-1", "tool_response": "external instructions", "exit_code": 0}

    await proxy.tool_result(Request())
    assert len(observed) == 1
    assert observed[0][1:3] == ("call-1", "external instructions")
