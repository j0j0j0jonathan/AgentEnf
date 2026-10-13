"""Experimental outcome-aware revision ledger. NOT wired into production policies.

Paths are lexical in a declared runtime namespace, not host realpaths. A trusted
adapter must supply the actual working directory and completion outcome. A hash
is of submitted content, not filesystem attestation. Do not use it to authorize
execution or to claim a file is clean.
"""
from dataclasses import dataclass
from hashlib import sha256
import posixpath
import threading


def lexical_path(path: str, cwd: str | None = None) -> str | None:
    if not path or any(c in path for c in ('$', '~', '\\', '\x00')):
        return None
    if not path.startswith('/'):
        if not cwd or not cwd.startswith('/') or any(c in cwd for c in ('$', '~', '\\', '\x00')):
            return None
        path = posixpath.join(cwd, path)
    return posixpath.normpath(path)


@dataclass(frozen=True)
class Revision:
    namespace: str
    path: str
    sha256: str
    call_id: str
    evidence: str = 'runtime_reported_complete'


class ArtifactLedger:
    def __init__(self, limit=256):
        self.limit = limit
        self.pending = {}
        self.seen = set()
        self.revisions = {}
        self.lock = threading.Lock()

    def propose(self, sid, call_id, namespace, path, content, *, cwd=None):
        """Stage only a complete literal file replacement, not an edit fragment."""
        resolved = lexical_path(path, cwd)
        with self.lock:
            key = (sid, call_id)
            # A retired call id cannot be reused: a delayed old result could
            # otherwise commit the newer proposal. Capacity exhaustion is an
            # explicit refusal, not eviction of replay protection.
            if (not sid or not call_id or not namespace or resolved is None
                    or key in self.seen or len(self.seen) >= self.limit):
                for target in list(self.revisions):
                    if target[:2] == (sid, namespace):
                        self.revisions.pop(target)
                for item in self.pending.values():
                    if item['target'][:2] == (sid, namespace):
                        item['conflicted'] = True
                return False
            self.seen.add(key)
            target = (sid, namespace, resolved)
            conflicts = [item for item in self.pending.values() if item['target'] == target]
            for item in conflicts:
                item['conflicted'] = True
            self.pending[key] = dict(target=target, content_hash=sha256(content.encode()).hexdigest(),
                                     conflicted=bool(conflicts))
            # While a write is pending the old revision cannot authorize a use.
            self.revisions.pop(target, None)
            return True

    def finish(self, sid, call_id, outcome):
        with self.lock:
            pending = self.pending.get((sid,call_id))
            if pending is None:
                return None
            if outcome == 'running':
                return None
            self.pending.pop((sid,call_id))
            target = pending['target']
            # Failure may have partially modified the file. Unknown completion
            # or overlapping writers cannot establish a current revision.
            self.revisions.pop(target, None)
            if outcome != 'runtime_reported_complete' or pending['conflicted']:
                return None
            revision = Revision(target[1], target[2], pending['content_hash'], call_id)
            if len(self.revisions) >= self.limit:
                self.revisions.pop(next(iter(self.revisions)))
            self.revisions[target] = revision
            return revision

    def observe(self, sid, namespace, path, *, cwd=None):
        resolved = lexical_path(path,cwd)
        with self.lock:
            return self.revisions.get((sid,namespace,resolved))
