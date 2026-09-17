from handlers import (
    handle_block_response,
    handle_warn_response,
    normalize_anthropic,
    normalize_openai,
    normalize_openai_responses,
    serialize_anthropic,
    serialize_openai,
    serialize_openai_responses,
    surface_warning_on_block,
    synthetic_anthropic,
    synthetic_openai,
)


def test_openai_block_response_replaces_all_choices():
    raw = {
        "choices": [
            {"message": {"role": "assistant", "content": "first"}, "finish_reason": "stop"},
            {"message": {"role": "assistant", "content": "second"}, "finish_reason": "stop"},
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 4, "total_tokens": 6},
    }

    response = normalize_openai(raw)
    response = handle_block_response(response, [(1, "safety", "not allowed")])
    out = serialize_openai(response)

    assert out["choices"][0]["message"]["content"] == response.block_reason
    assert out["choices"][1]["message"]["content"] == response.block_reason
    assert all(choice["finish_reason"] == "stop" for choice in out["choices"])


def test_openai_block_response_removes_proposed_tool_calls():
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "I will do that.",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "exec", "arguments": "{}"},
                        }
                    ],
                    "function_call": {"name": "legacy_exec", "arguments": "{}"},
                },
                "finish_reason": "tool_calls",
            }
        ]
    }

    response = normalize_openai(raw)
    response = handle_block_response(response, [(1, "chat_policy", "unsafe response")])
    out = serialize_openai(response)

    message = out["choices"][0]["message"]
    assert "tool_calls" not in message
    assert "function_call" not in message
    assert out["choices"][0]["finish_reason"] == "stop"


def test_openai_warning_is_prepended_to_each_choice():
    raw = {
        "choices": [
            {"message": {"role": "assistant", "content": "first"}, "finish_reason": "stop"},
            {"message": {"role": "assistant", "content": "second"}, "finish_reason": "stop"},
        ],
    }

    response = normalize_openai(raw)
    response = handle_warn_response(response, [(1, "token_budget", "too long")])
    out = serialize_openai(response)

    assert out["choices"][0]["message"]["content"].endswith("\n\nfirst")
    assert out["choices"][1]["message"]["content"].endswith("\n\nsecond")
    assert out["choices"][0]["message"]["content"].startswith("Policy warning")


def test_responses_block_replaces_text_and_function_calls():
    raw = {
        "id": "resp-1",
        "object": "response",
        "status": "completed",
        "model": "test",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "secret", "annotations": []}],
            },
            {
                "type": "function_call",
                "call_id": "call-1",
                "name": "exec",
                "arguments": "{}",
            },
        ],
        "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5},
    }

    response = normalize_openai_responses(raw)
    assert response.content == "secret"
    response = handle_block_response(response, [(1, "chat_policy", "unsafe response")])
    out = serialize_openai_responses(response)

    assert [item["type"] for item in out["output"]] == ["message"]
    assert out["output"][0]["content"][0]["text"] == response.block_reason
    assert out["output_text"] == response.block_reason


def test_responses_warning_preserves_function_calls():
    raw = {
        "id": "resp-1",
        "object": "response",
        "status": "completed",
        "output": [
            {
                "id": "msg-1",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "continuing", "annotations": []}],
            },
            {
                "id": "fc-1",
                "type": "function_call",
                "call_id": "call-1",
                "name": "exec",
                "arguments": "{}",
            },
        ],
    }

    response = normalize_openai_responses(raw)
    response = handle_warn_response(response, [(1, "chat_policy", "review output")])
    out = serialize_openai_responses(response)

    assert [item["type"] for item in out["output"]] == ["message", "function_call"]
    assert out["output"][0]["content"][0]["text"].startswith("Policy warning")
    assert out["output"][1]["call_id"] == "call-1"


def test_anthropic_normalization_counts_cache_tokens():
    raw = {
        "content": [{"type": "text", "text": "answer"}],
        "usage": {
            "input_tokens": 10,
            "cache_creation_input_tokens": 2,
            "cache_read_input_tokens": 3,
            "output_tokens": 4,
        },
    }

    response = normalize_anthropic(raw)

    assert response.content == "answer"
    assert response.prompt_tokens == 15
    assert response.completion_tokens == 4
    assert response.total_tokens == 19


def test_anthropic_warning_inserts_text_block_when_needed():
    raw = {
        "content": [{"type": "tool_use", "id": "call_1", "name": "x", "input": {}}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }

    response = normalize_anthropic(raw)
    response = handle_warn_response(response, [(1, "safety", "careful")])
    out = serialize_anthropic(response)

    assert out["content"][0]["type"] == "text"
    assert out["content"][0]["text"].startswith("Policy warning")
    assert out["content"][1]["type"] == "tool_use"


def test_synthetic_blocked_responses_are_api_shaped():
    anthropic = synthetic_anthropic("blocked")
    openai = synthetic_openai("blocked")

    assert anthropic["content"][0]["text"] == "blocked"
    assert anthropic["role"] == "assistant"
    assert openai["choices"][0]["message"]["content"] == "blocked"
    assert openai["choices"][0]["message"]["role"] == "assistant"


def test_warning_details_stay_visible_when_block_overrides():
    raw = {"choices": [{"message": {"role": "assistant", "content": "first"}}]}

    response = normalize_openai(raw)
    response = handle_block_response(response, [(1, "safety", "not allowed")])
    response = surface_warning_on_block(response, "Policy warning: [token_budget] too long")
    out = serialize_openai(response)

    assert "Response blocked" in response.block_reason
    assert "Also fired" in response.block_reason
    assert "token_budget" in response.block_reason
    assert out["choices"][0]["message"]["content"] == response.block_reason
