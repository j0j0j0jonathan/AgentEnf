"""Exact, opt-in semantic evidence capture at the actual predicate boundary.

Inputs may contain private data, just like the trace. Content-addressed blobs
avoid repeatedly copying long text into JSONL. No input is silently truncated.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time

_LOCK = threading.Lock()


def _blob(root, text):
    data = text.encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    directory = root / "blobs"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (digest + ".txt")
    if not target.exists():
        fd, name = tempfile.mkstemp(dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(name, target)
        finally:
            Path(name).unlink(missing_ok=True)
    return {"sha256": digest, "bytes": len(data), "file": str(target.relative_to(root))}


def capture(root, *, name, content, prompt, context, result, backend, threshold=0.5):
    root = Path(root) / "predicate_evidence"
    root.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": 1,
        "observed_at_ns": time.time_ns(),
        "pid": os.getpid(),
        "predicate": name,
        "context": context,
        "input": _blob(root, content),
        "definition": _blob(root, prompt),
        "backend": list(backend),
        "raw_score": result.raw_score,
        "threshold": threshold,
        "normalized_score": float(result.raw_score >= threshold),
        "reason": result.reason,
        "reasons": list(result.reasons),
        "origin": "exact_pre_evaluation"
        if result.replayed_pre_eval
        else "cache"
        if result.cache_hit
        else "evaluation",
        "failure": result.fail_mode or None,
        "cache_hit": result.cache_hit,
        "latency_ms": result.latency_ms,
        "raw_reply": result.raw_reply,
        "scope": "actual_predicate_input_not_a_tool_execution_claim",
    }
    # Separate processes never append to the same file; serialize local threads.
    with _LOCK:
        with (root / f"calls-{os.getpid()}.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
