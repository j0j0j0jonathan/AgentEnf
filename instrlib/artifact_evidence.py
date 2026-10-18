"""Authenticated artifact observations, separate from proposed write intent.

Only full replacements with a matching runtime file snapshot establish a known
revision. Denials never clear prior state. Failed/partial/overlapping mutations
make state unknown. Clean is not an authorization or a claim about external edits.
"""

from dataclasses import dataclass
from hashlib import sha256
import json
import secrets
import threading
from instrlib.event import Event
from instrlib.persistence_paths import absolute_path, command_targets


def facts(events):
    return {(e.args[2], e.args[3]) for e in events if e.name == "Classify" and len(e.args) == 4}


def full_replacement(tool, args):
    return (
        tool == "file_write"
        and isinstance(args.get("content"), str)
        and args.get("operation", "replace") in ("replace", "write")
        and not any(
            k in args
            for k in (
                "oldText",
                "old_text",
                "newText",
                "new_text",
                "old_str",
                "new_str",
                "edits",
                "patch",
                "append",
                "replacements",
            )
        )
    )


def write_path(args):
    return next(
        (
            absolute_path(args.get(k))
            for k in ("path", "file_path", "filename", "file", "filepath")
            if absolute_path(args.get(k))
        ),
        None,
    )


def dangerous_properties(events):
    f = facts(events)
    # The legacy dangerous_authored_write_path also includes a mere secret
    # source, and authored_exfil includes ordinary upload helpers. Neither alone
    # establishes a harmful executable capability. Their existing review joins
    # remain; only the mapper's stronger current-content labels can hard-taint.
    return any(
        dim in {"untrusted_write_path", "loop_source_path"}
        or (
            dim == "impact_kind"
            and val
            in {
                "authored_destructive_script",
                "authored_sandbox_escape_script",
                "authored_unbounded_loop",
            }
        )
        for dim, val in f
    )


def use_targets(tool, args, events):
    targets = set()
    for dim, value in facts(events):
        if dim == "schedule_target_v2":
            try:
                _, path = json.loads(value)
                if absolute_path(path):
                    targets.add(path)
            except (ValueError, TypeError):
                pass
    f = facts(events)
    use = bool(targets) or any(d in {"exec_path", "chmod_exec_path"} for d, v in f)
    if tool == "bash" and use:
        command = args.get("command") or args.get("cmd") or ""
        if not isinstance(command, str):
            return targets, use
        found, _ = command_targets(
            command, _cwd=absolute_path(args.get("workdir") or args.get("cwd"))
        )
        targets.update(found)
        # chmod operands are file uses, not executable positions.
        import shlex

        try:
            words = shlex.split(command)
            if words and words[0].rsplit("/", 1)[-1] == "chmod":
                targets.update(p for p in map(absolute_path, words[1:]) if p)
        except ValueError:
            pass
    return targets, use


@dataclass
class Proposal:
    sid: str
    call: str
    namespace: str
    path: str | None
    digest: str | None
    size: int | None
    danger: bool
    token: str
    accepted: bool = False
    conflict: bool = False
    invalidates_namespace: bool = False


class ArtifactEvidence:
    def __init__(self, limit=10000):
        self.lock = threading.RLock()
        self.limit = limit
        self.pending = {}
        self.seen = set()
        self.states = {}
        self.intent = set()
        self.exhausted = set()

    def prepare(self, tid, sid, call, namespace, tool, args, events):
        """Called only at the authenticated dispatch boundary, before approval."""
        out = []

        def emit(d, v):
            out.append(Event("Classify", tid, call, d, v))

        ns = namespace if isinstance(namespace, str) and 0 < len(namespace) <= 256 else ""
        target = write_path(args) if tool == "file_write" else None
        targets, use = use_targets(tool, args, events)
        if not ns:
            if use:
                emit("artifact_state_unresolved", "missing_runtime_namespace")
            return out, None
        with self.lock:
            if ns in self.exhausted:
                if use or tool == "file_write":
                    emit("artifact_state_unresolved", "ledger_capacity_exceeded")
                return out, None
            if use and not targets:
                emit("artifact_state_unresolved", "unresolved_use_target")
            for path in sorted(targets):
                identity = json.dumps([ns, path], ensure_ascii=True, separators=(",", ":"))
                state = self.states.get((ns, path))
                if state and state["status"] == "dangerous":
                    emit("artifact_present_dangerous_path_v3", identity)
                    emit(
                        "artifact_revision_used_v3",
                        json.dumps(
                            [ns, path, state["sha256"]], ensure_ascii=True, separators=(",", ":")
                        ),
                    )
                elif state and state["status"] == "unknown":
                    emit("artifact_state_unresolved", "unverified_revision")
                if (sid, ns, path) in self.intent:
                    emit("artifact_attempted_dangerous_path_v3", identity)
            # Arbitrary shell/unknown tools may mutate any tracked file. Their
            # success message cannot prove the resulting bytes. Read-only file
            # tools have an explicit adapter contract; everything else needs a
            # new snapshot before a cached revision can again justify Block.
            if tool == "file_read":
                return out, None
            key = (sid, ns, call)
            if not sid or not call or key in self.seen or len(self.seen) >= self.limit:
                self.exhausted.add(ns)
                emit("artifact_state_unresolved", "reused_call_or_capacity")
                return out, None
            self.seen.add(key)
            if tool == "file_write" and not target:
                emit("artifact_state_unresolved", "unresolved_write_target")
            danger = dangerous_properties(events)
            if target and danger:
                self.intent.add((sid, ns, target))
            content = args.get("content")
            full = full_replacement(tool, args) and target is not None
            encoded = content.encode("utf-8") if full else None
            uncertain = any(
                d in {"judge_failed_open", "judge_fail_closed"}
                or (d == "authored_dataflow_status" and v == "unresolved")
                or (
                    d == "judge_status"
                    and v
                    in {"input_budget_exceeded", "failed_open", "failed_closed", "unavailable"}
                )
                for d, v in facts(events)
            )
            p = Proposal(
                sid,
                call,
                ns,
                target,
                sha256(encoded).hexdigest() if full and not uncertain else None,
                len(encoded) if encoded is not None else None,
                danger,
                secrets.token_urlsafe(24),
            )
            p.invalidates_namespace = tool != "file_write" or target is None
            self.pending[key] = p
            if p.digest:
                emit(
                    "artifact_write_proposal_v3",
                    json.dumps(
                        [ns, target, p.digest, p.size], ensure_ascii=True, separators=(",", ":")
                    ),
                )
            return out, (
                {"token": p.token, "path": target, "sha256": p.digest, "bytes": p.size}
                if p.digest
                else None
            )

    def decide(self, sid, call, namespace, allowed):
        if not isinstance(namespace, str):
            return
        with self.lock:
            key = (sid, namespace, call)
            p = self.pending.get(key)
            if not p:
                return
            if not allowed:
                self.pending.pop(key)
                return  # No state change for a denied proposal.
            p.accepted = True
            if p.invalidates_namespace:
                for ns, path in list(self.states):
                    if ns == namespace:
                        self.states[(ns, path)] = {"status": "unknown"}
                for q in self.pending.values():
                    if q.namespace == namespace and q.accepted:
                        q.conflict = True
            if p.path:
                conflicts = [
                    q
                    for k, q in self.pending.items()
                    if k != key
                    and q.accepted
                    and q.namespace == p.namespace
                    and (q.path == p.path or q.invalidates_namespace)
                ]
                p.conflict = p.conflict or bool(conflicts)
                for q in conflicts:
                    q.conflict = True
                self.states[(p.namespace, p.path)] = {"status": "unknown"}

    def finish(self, tid, sid, call, namespace, body, blocked=False):
        if not isinstance(namespace, str):
            return []
        with self.lock:
            p = self.pending.get((sid, namespace, call))
            if not p:
                return []
            if blocked or not p.accepted:
                self.pending.pop((sid, namespace, call), None)
                return []
            execution = body.get("tool_execution") or {}
            if not isinstance(execution, dict):
                execution = {}
            if execution.get("outcome") == "running":
                return []
            self.pending.pop((sid, namespace, call), None)
            a = body.get("artifact_attestation")
            valid = (
                not p.conflict
                and p.digest
                and isinstance(a, dict)
                and execution.get("outcome") in ("completed", "unknown")
                and body.get("exit_code", -1) in (-1, 0, None)
                and execution.get("effect_executed") is True
                and a.get("kind") == "verified_full_write"
                and a.get("token") == p.token
                and a.get("path") == p.path
                and a.get("sha256") == p.digest
                and type(a.get("bytes")) is int
                and a["bytes"] == p.size
            )
            status = ("dangerous" if p.danger else "clean") if valid else "unknown"
            if p.path:
                self.states[(p.namespace, p.path)] = {
                    "status": status,
                    "sha256": p.digest if valid else None,
                }
            result = [Event("Classify", tid, call, "artifact_completion", status)] if p.path else []
            if valid:
                result.append(
                    Event(
                        "Classify",
                        tid,
                        call,
                        "artifact_revision_v3",
                        json.dumps(
                            [p.namespace, p.path, p.digest, p.size, status],
                            ensure_ascii=True,
                            separators=(",", ":"),
                        ),
                    )
                )
            return result
