"""Monitor-only predicate progress; hashes rather than private input text.

The monitor evaluates predicates serially. Dump Python stacks while a call is
still pending, before the process manager's timeout destroys the evidence.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import time

_current = ContextVar("predicate_progress", default=None)


def stage(name):
    current = _current.get()
    if current is None:
        return
    path, identity = current
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({**identity, "stage": name, "time_ns": time.time_ns()}) + "\n")


@contextmanager
def tracking(root, name, content):
    if os.environ.get("ENFGUARD_MONITOR_PREDICATE_DIAGNOSTICS") != "1":
        yield
        return
    directory = Path(root) / "predicate_evidence"
    directory.mkdir(parents=True, exist_ok=True)
    identity = {"pid": os.getpid(), "predicate": name,
                "input_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}
    token = _current.set((directory / f"progress-{os.getpid()}.jsonl", identity))
    with (directory / f"stacks-{os.getpid()}.log").open("a") as stacks:
        try:
            stage("entered")
            faulthandler.dump_traceback_later(10, repeat=True, file=stacks)
            yield
            stage("returned")
        finally:
            faulthandler.cancel_dump_traceback_later()
            _current.reset(token)
