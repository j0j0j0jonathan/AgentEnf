"""Retired lexical experiment: matches may raise concern, never lower risk.

Not connected to the proxy. No untrusted_followup exemption is emitted.
The original experiment is archived in the audit output.
"""
import re
import json
from typing import Any, Iterable, List, Set
from instrlib.event import Event

# Distinctive tokens: urls, absolute paths, filenames with a common extension.
_TOKEN_RE = re.compile(
    r"https?://[^\s\"'<>)]+"
    r"|(?<![\w.])/(?:[\w.+-]+/)*[\w.+-]+"
    r"|\b[\w-]{2,}\.(?:sh|py|js|json|ya?ml|toml|conf|cfg|env|txt|md|log|zip|tar|gz|tgz|key|pem|sql|db)\b",
    re.IGNORECASE,
)
# Common workspace roots / interpreters that carry no provenance on their own.
_COMMON = {
    "/home/node/.openclaw/workspace", "/home/node", "/tmp", "/tmp/project",
    "/tmp/server", "/tmp/docs", "/tmp/analysis", "/bin/bash", "/bin/sh",
    "/usr/bin/env", "/dev/null", "/usr/bin/python3", "/usr/bin/python",
    "/etc/hosts", "/etc/passwd",
}
# Historical overflow input remains a positive match in offline regressions.
OVERFLOW = "\x00overflow"


def distinctive_tokens(text: str) -> Set[str]:
    """Distinctive path/url/filename tokens in ``text`` (>=6 chars, not common)."""
    if not isinstance(text, str) or not text:
        return set()
    out = set()
    for tok in _TOKEN_RE.findall(text):
        tok = tok.rstrip(".,;:)]}\"'")
        if len(tok) >= 6 and tok not in _COMMON:
            out.add(tok)
    return out


def _input_text(tool_input: Any) -> str:
    if isinstance(tool_input, dict):
        try:
            return json.dumps(tool_input, ensure_ascii=False)
        except Exception:
            return str(tool_input)
    return str(tool_input or "")


def _facts(mapped_events: Iterable[Event], call_id: str) -> Set[tuple]:
    out = set()
    for e in mapped_events:
        if e.name == "Classify" and len(e.args) >= 4 and e.args[1] == call_id:
            out.add((e.args[2], e.args[3]))
    return out


def optimization_tool_events(tid: int, call_id: str, tool_name: str,
                             tool_input: Any, mapped_events: List[Event],
                             untrusted_tokens: Set[str]) -> List[Event]:
    """Emit the optimized-v1 provenance facts for this planned call."""
    out: List[Event] = []
    facts = _facts(mapped_events, call_id)
    linked = False
    if untrusted_tokens:
        if OVERFLOW in untrusted_tokens:
            linked = True
        else:
            itext = _input_text(tool_input)
            linked = any(tok in itext for tok in untrusted_tokens)
    if linked:
        out.append(Event("Classify", tid, call_id, "untrusted_data_link", "yes"))
    return out


def untrusted_result_tokens(content: str) -> Set[str]:
    """Tokens to remember from any untrusted tool result."""
    return distinctive_tokens(content)
