"""Request-local evidence for the candidate's refusal-quotation exception.

This is a snapshot of text actually supplied in this model request, not a
mutable session cache or a claim that every earlier message was delivered.
System/developer instructions, reasoning and the pending reply are excluded.
Whole records may be omitted to fit the context budget; never silently clip a
record or treat an omitted record as proof that a command was already supplied.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CONTEXT_BUDGET_BYTES = 24576  # leaves space for reply and framing in the 64 KiB judge budget
SCHEMA = "reply-evidence-v1"


def reply_from_evidence(content: str) -> str:
    """Validate our wire envelope before taking the empty-reply shortcut."""
    obj = json.loads(content)
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA or not isinstance(obj.get("reply"), str):
        raise ValueError("invalid_reply_evidence")
    context = obj.get("prior_context")
    if not isinstance(context, dict) or not isinstance(context.get("records"), list):
        raise ValueError("invalid_reply_context")
    for record in context["records"]:
        if (not isinstance(record, dict) or record.get("role") not in {"user", "assistant", "tool"}
                or not isinstance(record.get("text"), str)):
            raise ValueError("invalid_reply_context_record")
    return obj["reply"]


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _visible_text(content: Any) -> str:
    """Conservative text extraction: never guess that unknown blocks are public."""
    if isinstance(content, str):
        return content
    parts = []
    for block in content if isinstance(content, list) else []:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind in {"text", "input_text", "output_text"} and isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif kind == "refusal" and isinstance(block.get("refusal"), str):
            parts.append(block["refusal"])
        elif kind in {"tool_result", "search_result"}:
            parts.append(_visible_text(block.get("content")))
        elif kind == "document" and isinstance(block.get("source"), dict):
            source = block["source"]
            if source.get("type") == "text" and isinstance(source.get("data"), str):
                parts.append(source["data"])
            elif source.get("type") == "content":
                parts.append(_visible_text(source.get("content")))
    return "\n".join(part for part in parts if part)


def _records(request: dict, family: str) -> list[dict]:
    records = []

    def add(role, value):
        if isinstance(value, str) and value.strip():
            records.append({"role": role, "text": value})

    raw = request.get("input") if family == "openai_responses" else request.get("messages")
    if isinstance(raw, str) and family == "openai_responses":
        add("user", raw)
        return records
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        role, kind = item.get("role"), item.get("type")
        if family == "openai_responses" and kind == "function_call_output":
            add("tool", _visible_text(item.get("output")))
            continue
        # Only actual text messages qualify. Tool arguments, reasoning items
        # and system/developer instructions are not conversation quotations.
        if role not in {"user", "assistant", "tool"}:
            continue
        content = item.get("content")
        if family == "anthropic" and isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    add(role, block.get("text"))
                elif block.get("type") == "tool_result":
                    add("tool", _visible_text(block.get("content")))
                elif block.get("type") in {"document", "search_result"}:
                    add(role, _visible_text([block]))
        else:
            add(role, _visible_text(content))
            if role == "assistant":
                add(role, item.get("refusal"))
    return records


def build_reply_evidence(request: dict, family: str, reply: str,
                         *, context_budget: int = CONTEXT_BUDGET_BYTES) -> str:
    """Serialize exact reply + bounded, ordered, whole prior text records.

    A retained record can support the exception even if other history is
    unavailable. Missing/omitted text cannot. No cross-request state is read.
    The enclosing request/response timepoint binds this snapshot to the reply.
    """
    if context_budget < 0:
        raise ValueError("Reply context budget must be nonnegative")
    records = _records(request, family)
    kept, used = [], 0
    for index in range(len(records) - 1, -1, -1):
        record = {"index": index, **records[index]}
        size = len(_json(record).encode("utf-8")) + 1
        if used + size <= context_budget:
            kept.append(record)
            used += size
    kept.reverse()
    return _json({
        "schema": SCHEMA,
        "reply": reply,
        "prior_context": {
            "scope": "text supplied in this model request; not hidden instructions or pending output",
            "records": kept,
            "omitted_records": len(records) - len(kept),
            "selected_bytes": used,
            "budget_bytes": context_budget,
            "source_text_sha256": hashlib.sha256(_json(records).encode()).hexdigest(),
            "server_history_unavailable": bool(request.get("previous_response_id") or request.get("conversation")),
            "missing_history_does_not_justify_exception": True,
        },
    })
