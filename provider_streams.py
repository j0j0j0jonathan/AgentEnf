"""Buffered provider SSE parsing and serialization, independent of enforcement state."""

from __future__ import annotations
import json
import time
from typing import Any
from fastapi.responses import Response

JsonObject = dict[str, Any]


def _anthropic_sse_response(message: JsonObject, headers: dict[str, str] | None = None) -> Response:
    return Response(
        content=_anthropic_message_to_sse(message),
        media_type="text/event-stream",
        headers=headers,
    )


def _openai_sse_response(message: JsonObject, headers: dict[str, str] | None = None) -> Response:
    return Response(
        content=_openai_message_to_sse(message),
        media_type="text/event-stream",
        headers=headers,
    )


def _openai_responses_sse_response(
    response: JsonObject, headers: dict[str, str] | None = None
) -> Response:
    return Response(
        content=_openai_responses_to_sse(response),
        media_type="text/event-stream",
        headers=headers,
    )


def _openai_stream_to_message(stream_text: str, fallback_model: Any = None) -> JsonObject:
    """Reconstruct a final OpenAI chat.completion JSON from a buffered SSE body.

    Mirrors _anthropic_stream_to_message: parse the buffered `data: {...}` chunks,
    concatenate `choices[0].delta.content` and any streamed tool-call arguments,
    and build the non-streamed chat.completion shape that normalize_openai expects.
    """
    message_id = "chatcmpl-stream-buffered"
    model = str(fallback_model or "")
    created = int(time.time())
    role = "assistant"
    content_parts: list[str] = []
    finish_reason: Any = None
    tool_calls: dict[int, JsonObject] = {}
    tool_arg_parts: dict[int, list[str]] = {}
    usage: JsonObject = {}

    for payload in _sse_json_payloads(stream_text):
        if payload.get("id"):
            message_id = str(payload["id"])
        if payload.get("model"):
            model = str(payload["model"])
        if payload.get("created"):
            created = _int(payload.get("created"), created)
        if isinstance(payload.get("usage"), dict) and payload["usage"]:
            usage = payload["usage"]
        choices = payload.get("choices") if isinstance(payload.get("choices"), list) else []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            if choice.get("finish_reason"):
                finish_reason = choice.get("finish_reason")
            delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
            if delta.get("role"):
                role = str(delta.get("role"))
            piece = delta.get("content")
            if isinstance(piece, str):
                content_parts.append(piece)
            tcs = delta.get("tool_calls") if isinstance(delta.get("tool_calls"), list) else []
            for tc in tcs:
                if not isinstance(tc, dict):
                    continue
                idx = _int(tc.get("index"), 0)
                slot = tool_calls.setdefault(
                    idx, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}}
                )
                if tc.get("id"):
                    slot["id"] = str(tc.get("id"))
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                if fn.get("name"):
                    slot["function"]["name"] = str(fn.get("name"))
                if isinstance(fn.get("arguments"), str):
                    tool_arg_parts.setdefault(idx, []).append(fn["arguments"])

    msg: JsonObject = {"role": role, "content": "".join(content_parts)}
    if tool_calls:
        assembled = []
        for idx in sorted(tool_calls):
            slot = tool_calls[idx]
            slot["function"]["arguments"] = "".join(tool_arg_parts.get(idx, []))
            assembled.append(slot)
        msg["tool_calls"] = assembled
    return {
        "id": message_id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish_reason}],
        "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _openai_message_to_sse(message: JsonObject) -> str:
    """Serialize an OpenAI chat.completion response as a minimal SSE stream."""
    choices = message.get("choices") if isinstance(message.get("choices"), list) else []
    first = choices[0] if choices and isinstance(choices[0], dict) else {}
    inner = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = inner.get("content")
    content = content if isinstance(content, str) else ""
    finish = first.get("finish_reason") or "stop"
    base = {
        "id": str(message.get("id") or "chatcmpl-enfguard"),
        "object": "chat.completion.chunk",
        "created": _int(message.get("created"), int(time.time())),
        "model": str(message.get("model") or ""),
    }

    def _chunk(delta: JsonObject, finish_reason: Any = None) -> str:
        payload = dict(base)
        payload["choices"] = [{"index": 0, "delta": delta, "finish_reason": finish_reason}]
        return "data: " + json.dumps(payload) + "\n\n"

    parts = [_chunk({"role": "assistant"})]
    if content:
        parts.append(_chunk({"content": content}))
    parts.append(_chunk({}, finish))
    parts.append("data: [DONE]\n\n")
    return "".join(parts)


def _openai_responses_stream_to_response(
    stream_text: str, fallback_model: Any = None
) -> JsonObject:
    """Recover the final Responses object from a buffered Responses SSE stream."""

    completed: JsonObject | None = None
    output_items: dict[int, JsonObject] = {}
    response_id = "resp_stream_buffered"
    model = str(fallback_model or "")
    usage: JsonObject = {}

    for payload in _sse_json_payloads(stream_text):
        event_type = str(payload.get("type") or "")
        response = payload.get("response")
        if isinstance(response, dict):
            if response.get("id"):
                response_id = str(response["id"])
            if response.get("model"):
                model = str(response["model"])
            if isinstance(response.get("usage"), dict):
                usage = dict(response["usage"])
            if event_type in {"response.completed", "response.failed", "response.incomplete"}:
                completed = dict(response)
        if event_type == "response.output_item.done" and isinstance(payload.get("item"), dict):
            output_items[_int(payload.get("output_index"), len(output_items))] = dict(
                payload["item"]
            )

    if completed is not None:
        return completed
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "completed_at": int(time.time()),
        "error": None,
        "incomplete_details": None,
        "model": model,
        "output": [output_items[index] for index in sorted(output_items)],
        "parallel_tool_calls": True,
        "tools": [],
        "usage": usage or {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }


def _openai_responses_to_sse(response: JsonObject) -> str:
    """Serialize a complete Responses object as a minimal valid SSE sequence."""

    final = dict(response)
    output = final.get("output") if isinstance(final.get("output"), list) else []
    initial = dict(final)
    initial["status"] = "in_progress"
    initial["output"] = []
    initial["completed_at"] = None

    events: list[JsonObject] = [
        {"type": "response.created", "response": initial},
        {"type": "response.in_progress", "response": initial},
    ]
    sequence = 0
    for output_index, item in enumerate(output):
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "")
        events.append(
            {
                "type": "response.output_item.added",
                "output_index": output_index,
                "item": item,
            }
        )
        if item_type == "message":
            content = item.get("content") if isinstance(item.get("content"), list) else []
            for content_index, part in enumerate(content):
                if not isinstance(part, dict):
                    continue
                events.append(
                    {
                        "type": "response.content_part.added",
                        "item_id": item.get("id"),
                        "output_index": output_index,
                        "content_index": content_index,
                        "part": part,
                    }
                )
                text = part.get("text") if isinstance(part.get("text"), str) else ""
                if text:
                    events.append(
                        {
                            "type": "response.output_text.delta",
                            "item_id": item.get("id"),
                            "output_index": output_index,
                            "content_index": content_index,
                            "delta": text,
                        }
                    )
                events.append(
                    {
                        "type": "response.output_text.done",
                        "item_id": item.get("id"),
                        "output_index": output_index,
                        "content_index": content_index,
                        "text": text,
                    }
                )
                events.append(
                    {
                        "type": "response.content_part.done",
                        "item_id": item.get("id"),
                        "output_index": output_index,
                        "content_index": content_index,
                        "part": part,
                    }
                )
        elif item_type == "function_call":
            arguments = str(item.get("arguments") or "")
            if arguments:
                events.append(
                    {
                        "type": "response.function_call_arguments.delta",
                        "item_id": item.get("id"),
                        "output_index": output_index,
                        "delta": arguments,
                    }
                )
            events.append(
                {
                    "type": "response.function_call_arguments.done",
                    "item_id": item.get("id"),
                    "output_index": output_index,
                    "arguments": arguments,
                }
            )
        events.append(
            {
                "type": "response.output_item.done",
                "output_index": output_index,
                "item": item,
            }
        )

    events.append({"type": "response.completed", "response": final})
    chunks: list[str] = []
    for event in events:
        event["sequence_number"] = sequence
        sequence += 1
        chunks.append(f"event: {event['type']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n")
    return "".join(chunks)


def _anthropic_message_to_sse(message: JsonObject) -> str:
    """Serialize an Anthropic Messages response as a minimal SSE stream."""

    msg = dict(message)
    content = msg.get("content") if isinstance(msg.get("content"), list) else []
    msg["content"] = []
    events: list[tuple[str, JsonObject]] = [
        ("message_start", {"type": "message_start", "message": msg}),
    ]
    for index, block in enumerate(content):
        if not isinstance(block, dict):
            continue
        block_type = str(block.get("type") or "")
        if block_type == "text":
            events.append(
                (
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
            )
            text = str(block.get("text") or "")
            if text:
                events.append(
                    (
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": index,
                            "delta": {"type": "text_delta", "text": text},
                        },
                    )
                )
            events.append(("content_block_stop", {"type": "content_block_stop", "index": index}))
        elif block_type == "tool_use":
            events.append(
                (
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": str(block.get("id") or ""),
                            "name": str(block.get("name") or ""),
                            "input": {},
                        },
                    },
                )
            )
            events.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps(block.get("input") or {}),
                        },
                    },
                )
            )
            events.append(("content_block_stop", {"type": "content_block_stop", "index": index}))

    events.append(
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {
                    "stop_reason": message.get("stop_reason") or "end_turn",
                    "stop_sequence": message.get("stop_sequence"),
                },
                "usage": {
                    "output_tokens": (
                        message.get("usage", {}).get("output_tokens", 0)
                        if isinstance(message.get("usage"), dict)
                        else 0
                    )
                },
            },
        )
    )
    events.append(("message_stop", {"type": "message_stop"}))
    return "".join(
        f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        for event, data in events
    )


def _anthropic_stream_to_message(stream_text: str, fallback_model: Any = None) -> JsonObject:
    """Reconstruct final Anthropic message JSON from a buffered SSE body."""

    message: JsonObject = {
        "id": "msg_stream_buffered",
        "type": "message",
        "role": "assistant",
        "model": str(fallback_model or ""),
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
    blocks: dict[int, JsonObject] = {}
    input_json_parts: dict[int, list[str]] = {}

    for payload in _sse_json_payloads(stream_text):
        event_type = str(payload.get("type") or "")
        if event_type == "message_start" and isinstance(payload.get("message"), dict):
            started = dict(payload["message"])
            started["content"] = []
            message.update(started)
            continue
        if event_type == "content_block_start":
            index = _int(payload.get("index"), len(blocks))
            block = (
                payload.get("content_block")
                if isinstance(payload.get("content_block"), dict)
                else {}
            )
            blocks[index] = dict(block)
            if blocks[index].get("type") == "tool_use":
                blocks[index].setdefault("input", {})
                input_json_parts.setdefault(index, [])
            continue
        if event_type == "content_block_delta":
            index = _int(payload.get("index"), 0)
            delta = payload.get("delta") if isinstance(payload.get("delta"), dict) else {}
            delta_type = str(delta.get("type") or "")
            block = blocks.setdefault(index, {"type": "text", "text": ""})
            if delta_type == "text_delta":
                block["type"] = "text"
                block["text"] = str(block.get("text") or "") + str(delta.get("text") or "")
            elif delta_type == "input_json_delta":
                input_json_parts.setdefault(index, []).append(str(delta.get("partial_json") or ""))
            continue
        if event_type == "content_block_stop":
            index = _int(payload.get("index"), 0)
            if index in input_json_parts:
                raw_input = "".join(input_json_parts[index])
                try:
                    blocks.setdefault(index, {})["input"] = json.loads(raw_input or "{}")
                except json.JSONDecodeError:
                    blocks.setdefault(index, {})["input"] = {"_raw": raw_input}
            continue
        if event_type == "message_delta":
            delta = payload.get("delta") if isinstance(payload.get("delta"), dict) else {}
            if "stop_reason" in delta:
                message["stop_reason"] = delta.get("stop_reason")
            if "stop_sequence" in delta:
                message["stop_sequence"] = delta.get("stop_sequence")
            usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
            if usage:
                current = message.get("usage") if isinstance(message.get("usage"), dict) else {}
                message["usage"] = {**current, **usage}

    message["content"] = [blocks[index] for index in sorted(blocks)]
    return message


def _sse_json_payloads(stream_text: str) -> list[JsonObject]:
    payloads: list[JsonObject] = []
    data_lines: list[str] = []
    for line in stream_text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
            continue
        if line.strip():
            continue
        if data_lines:
            raw = "\n".join(data_lines)
            data_lines = []
            if raw and raw != "[DONE]":
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    payloads.append(value)
    if data_lines:
        raw = "\n".join(data_lines)
        if raw and raw != "[DONE]":
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                value = None
            if isinstance(value, dict):
                payloads.append(value)
    return payloads


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
