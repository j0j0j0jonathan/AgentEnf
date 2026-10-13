"""Opt-in duration records containing no event content or credentials."""
import functools
import json
import os
import time
from threading import RLock

_lock = RLock()

def record(kind, start, **metadata):
    path = os.environ.get('ENFGUARD_LATENCY_FILE')
    if not path:
        return
    end = time.perf_counter_ns()
    row = dict(kind=kind, start_ns=start, end_ns=end, pid=os.getpid(), **metadata)
    try:
        with _lock, open(path, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(row) + '\n')
    except OSError:
        pass  # Measurement cannot change enforcement behaviour.


def timed(kind):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not os.environ.get('ENFGUARD_LATENCY_FILE'):
                return fn(*args, **kwargs)
            start = time.perf_counter_ns()
            try:
                return fn(*args, **kwargs)
            finally:
                record(kind, start)
        return wrapped
    return decorate
