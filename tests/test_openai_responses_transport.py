import json

import proxy
from handlers import normalize_openai_responses


def _response_with_text_and_call():
    return {
        "id": "resp-1",
        "object": "response",
        "created_at": 1,
        "status": "completed",
        "completed_at": 2,
        "error": None,
        "incomplete_details": None,
        "model": "gpt-test",
        "output": [
            {
                "id": "msg-1",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {"type": "output_text", "text": "Checking now.", "annotations": []}
                ],
            },
            {
                "id": "fc-1",
                "type": "function_call",
                "status": "completed",
                "call_id": "call-1",
                "name": "exec",
                "arguments": json.dumps({"command": "pwd"}),
            },
        ],
        "parallel_tool_calls": True,
        "tools": [],
        "usage": {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7},
    }


def test_responses_stream_round_trip_retains_text_and_function_call():
    original = _response_with_text_and_call()

    stream = proxy._openai_responses_to_sse(original)
    recovered = proxy._openai_responses_stream_to_response(stream, "fallback")

    assert normalize_openai_responses(recovered).content == "Checking now."
    assert recovered["output"][1]["type"] == "function_call"
    assert recovered["output"][1]["call_id"] == "call-1"


def test_responses_synthetic_completion_uses_responses_shape():
    response = proxy._build_synthetic_upstream(
        "openai_responses", "Synthetic answer", "gpt-test"
    )

    assert response["object"] == "response"
    assert response["model"] == "gpt-test"
    assert normalize_openai_responses(response).content == "Synthetic answer"


def test_proxy_exposes_openai_responses_route():
    assert any(route.path == "/v1/responses" for route in proxy.app.routes)
