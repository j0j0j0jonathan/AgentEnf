"""Process-local state and approval records for the AgentEnf service.

Run one worker per state store. The monitor, approvals and call history are shared
within that worker and are not coordinated between independent processes.
"""

from __future__ import annotations
import asyncio
import threading
from dataclasses import dataclass, field
import httpx
from config import RuntimeConfig
from instrlib import Enforcer, Logger
from static_analysis import PredicateCall
from switch_state import SwitchState
from yaml_loader import HumanApprovalConfig, IngestJudgeConfig


@dataclass
class PendingApproval:
    """One in-flight ``Approve`` verdict awaiting a UI decision.

    The proxy registers a ``PendingApproval`` when a phase-1 verdict contains
    ``Approve`` and ``human_approval`` is enabled. The enforcement UI
    polls ``GET /pending_approvals`` to discover pending entries and replies
    via ``POST /feedback`` with ``kind`` set to ``approve`` or ``deny``. The
    awaiting coroutine wakes on the asyncio.Event and reads ``decision``.
    """

    tid: int
    sid: str
    label: str
    created_ts: float
    timeout_seconds: int
    on_timeout: str
    phase: str = "inbound"  # "inbound" | "outbound" — drives verdict mapping
    decision: str = ""  # "approve" | "deny" | "timeout" | ""
    payload: str = ""
    event: asyncio.Event = field(default_factory=asyncio.Event)


class ProxyState:
    """Mutable process state owned by the FastAPI lifespan."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self.tid = 0
        self.tid_lock = threading.Lock()
        self.sessions: set[str] = set()
        self.sessions_lock = threading.Lock()
        self.enforcer: Enforcer | None = None
        self.logger: Logger | None = None
        self.http: httpx.AsyncClient | None = None
        self.predicate_calls: dict[str, list[PredicateCall]] = {}
        self.predicate_policies: dict[str, frozenset[str]] = {}
        self.enforcement_lock = asyncio.Lock()
        self.reload_lock = asyncio.Lock()
        self.switches = SwitchState()
        self.human_approval = HumanApprovalConfig()
        self.pending_approvals: dict[int, "PendingApproval"] = {}
        self.pending_approvals_lock = threading.Lock()
        # Per-session map of (call_id -> tool_name) for tool proposals the
        # model emitted in past LLM calls. Used to look up the proposing
        # tool when a ToolCallResult arrives later, so the Untrusted event
        # respects ``backend.trusted_tool_names``.
        self.proposing_tools: dict[str, dict[str, str]] = {}
        self.proposing_tools_lock = threading.Lock()
        # Per-call result ORIGIN (external | local | unknown), recorded at tool
        # proposal/execution time. Source-based Untrusted tagging gates on this;
        # ``trusted_tool_names`` is only the fallback for ``unknown`` origins.
        self.tool_origins: dict[str, dict[str, str]] = {}
        self.tool_origins_lock = threading.Lock()
        # Call ids that EnfGuard has blocked (policy block or approval-deny). When
        # a tool call is blocked the tool never runs, but the runtime still
        # reports a "result" back — the echo of EnfGuard's own denial reason. That
        # text contains policy vocabulary (e.g. "installs a persistence foothold
        # (keys/sudoers/cron/service/import-hook)") and would otherwise be
        # re-ingested as untrusted external content and re-fire content_risk
        # classifiers (persistence_instruction, instruction_like, secret_material),
        # contaminating the same-session provenance window. Keyed globally because
        # the echoed result can arrive under a different/empty session id than the
        # block. Reset per run by _reset_run_scoped_state.
        self.blocked_call_ids: set[str] = set()
        self.blocked_call_ids_lock = threading.Lock()
        # Warnings recorded for WARNED-but-allowed tool calls (call_id -> message).
        # A WarnToolCall returns decision "allow", so the runtime runs the tool and
        # ignores the advisory `warning` field. To make the MODEL aware it is in a
        # flagged/monitored environment, the proxy prepends the warning to that
        # call's tool_result in the request it forwards upstream (added AFTER our
        # own event extraction, so it never re-arms our ingest classifiers). The
        # entry is popped on first injection, so the model sees it once — on the
        # turn immediately after the flagged action. Reset per run.
        self.tool_warnings: dict[str, str] = {}
        self.tool_warnings_lock = threading.Lock()
        # Frozen snapshot of ``backend.trusted_tool_names`` from YAML.
        # Tool results whose proposing tool name is in this set are not
        # paired with an ``Untrusted`` event. Reloaded on every YAML reload.
        self.trusted_tool_names: frozenset[str] = frozenset()
        # Backward-compatible master flag plus independent ingest-judge switches.
        self.unknown_tool_judge: bool = True
        self.ingest_judges = IngestJudgeConfig()
        # Wall-clock time this proxy run started (set by the lifespan after
        # _reset_run_scoped_state). ``tid`` restarts at 1 every run and the
        # per-tid trace files are reused across runs, so the trace list scopes
        # itself to files written at/after this time. 0.0 = unset (no scoping),
        # which keeps unit tests that never run the lifespan unaffected.
        self.run_started_at: float = 0.0

    def next_tid(self) -> int:
        with self.tid_lock:
            self.tid += 1
            return self.tid

    def include_session_start(self, sid: str) -> bool:
        if not sid:
            return False
        with self.sessions_lock:
            if sid in self.sessions:
                return False
            self.sessions.add(sid)
            return True

    def record_proposing_tools(self, sid: str, mapping: dict[str, str]) -> None:
        """Remember which tool name proposed each ``call_id`` in this session."""

        if not sid or not mapping:
            return
        with self.proposing_tools_lock:
            self.proposing_tools.setdefault(sid, {}).update(mapping)

    def snapshot_proposing_tools(self, sid: str) -> dict[str, str]:
        """Return a snapshot of the call_id -> tool_name map for ``sid``."""

        if not sid:
            return {}
        with self.proposing_tools_lock:
            return dict(self.proposing_tools.get(sid, {}))

    def record_tool_origins(self, sid: str, mapping: dict[str, str]) -> None:
        """Remember the result origin (external|local|unknown) per ``call_id``."""

        if not sid or not mapping:
            return
        with self.tool_origins_lock:
            self.tool_origins.setdefault(sid, {}).update(mapping)

    def snapshot_tool_origins(self, sid: str) -> dict[str, str]:
        """Return a snapshot of the call_id -> origin map for ``sid``."""

        if not sid:
            return {}
        with self.tool_origins_lock:
            return dict(self.tool_origins.get(sid, {}))

    def record_blocked_call(self, call_id: str) -> None:
        """Remember a call_id that EnfGuard blocked, so a later echo of our own
        denial reason is not re-ingested as untrusted external content."""

        if not call_id:
            return
        with self.blocked_call_ids_lock:
            self.blocked_call_ids.add(call_id)

    def is_blocked_call(self, call_id: str) -> bool:
        """True if ``call_id`` was blocked earlier this run (denial-echo guard)."""

        if not call_id:
            return False
        with self.blocked_call_ids_lock:
            return call_id in self.blocked_call_ids

    def blocked_call_ids_snapshot(self) -> frozenset[str]:
        """Snapshot of blocked call ids for the chat-request denial-echo guard."""

        with self.blocked_call_ids_lock:
            return frozenset(self.blocked_call_ids)

    def record_tool_warning(self, call_id: str, message: str) -> None:
        """Remember the advisory for a warned-but-allowed tool call so it can be
        surfaced to the model on the next turn."""

        if not call_id or not message:
            return
        with self.tool_warnings_lock:
            self.tool_warnings[call_id] = message

    def pop_tool_warning(self, call_id: str) -> str | None:
        """Return and clear the recorded advisory for ``call_id`` (once-only)."""

        if not call_id:
            return None
        with self.tool_warnings_lock:
            return self.tool_warnings.pop(call_id, None)

    def has_tool_warnings(self) -> bool:
        with self.tool_warnings_lock:
            return bool(self.tool_warnings)
