import httpx
import pytest

import predicates


class _FakeClient:
    def __init__(self, response, captured, *args, **kwargs):
        self.response = response
        self.captured = captured

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, *, headers, json):
        self.captured.update(url=url, headers=headers, body=json)
        return self.response


def _response(status_code=200, payload=None):
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    return httpx.Response(
        status_code,
        request=request,
        json=payload or {"choices": [{"message": {"content": '{"label":0}'}}]},
    )


def test_gpt5_predicate_judge_uses_modern_completion_contract(monkeypatch):
    captured = {}
    response = _response()
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("JUDGE_OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setattr(
        predicates.httpx,
        "Client",
        lambda *args, **kwargs: _FakeClient(response, captured, *args, **kwargs),
    )

    reply = predicates._call_openai_judge(
        "system", "input", "gpt-5.6", 10.0, 120, True
    )

    assert reply == '{"label":0}'
    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    assert captured["body"]["max_completion_tokens"] == 2048
    assert "max_tokens" not in captured["body"]
    assert "temperature" not in captured["body"]
    assert captured["body"]["response_format"] == {"type": "json_object"}


def test_legacy_predicate_judge_keeps_deterministic_chat_contract(monkeypatch):
    captured = {}
    response = _response()
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        predicates.httpx,
        "Client",
        lambda *args, **kwargs: _FakeClient(response, captured, *args, **kwargs),
    )

    predicates._call_openai_judge("system", "input", "gpt-4o-mini", 10.0, 120, True)

    assert captured["body"]["max_tokens"] == 120
    assert captured["body"]["temperature"] == 0
    assert "max_completion_tokens" not in captured["body"]


def test_predicate_judge_http_error_preserves_provider_detail(monkeypatch):
    captured = {}
    response = _response(
        400,
        {"error": {"message": "Unsupported parameter: temperature", "type": "invalid_request"}},
    )
    monkeypatch.setenv("JUDGE_OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        predicates.httpx,
        "Client",
        lambda *args, **kwargs: _FakeClient(response, captured, *args, **kwargs),
    )

    with pytest.raises(httpx.HTTPStatusError, match="Unsupported parameter: temperature"):
        predicates._call_openai_judge("system", "input", "gpt-5.6", 10.0, 120, True)
