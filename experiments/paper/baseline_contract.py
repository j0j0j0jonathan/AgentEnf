"""Shared boundary contract for baseline ports; OFF is the only built-in arm.

No emulation is labelled AgentSpec/Invariant/AgentLTL. Those implementations must
be supplied and pinned before a comparative experiment is launchable.
"""

from dataclasses import dataclass
from typing import Protocol, Literal


@dataclass(frozen=True)
class Observation:
    namespace: str
    session: str
    call_id: str
    boundary: Literal["model_request", "model_reply", "tool_planned", "tool_result"]
    timestamp_ms: int
    payload: dict


@dataclass(frozen=True)
class Decision:
    action: Literal["allow", "block", "approve", "warn"]
    rule_ids: tuple[str, ...] = ()
    native_action: str | None = None
    halt: bool = False


class Adapter(Protocol):
    name: str
    implementation_revision: str

    def evaluate(self, current: Observation, history: tuple[Observation, ...]) -> Decision: ...


class Off:
    name = "OFF"
    implementation_revision = "off-contract-v1"

    def evaluate(self, current, history):
        return Decision("allow")


class BoundarySession:
    def __init__(self, adapter: Adapter):
        if not adapter.implementation_revision:
            raise ValueError("Pin the adapter implementation")
        self.adapter = adapter
        self.history = []
        self.identity = None

    def evaluate(self, observation):
        identity = (observation.namespace, observation.session)
        if self.identity is not None and self.identity != identity:
            raise ValueError("Separate baseline state per session")
        self.identity = identity
        verdict = self.adapter.evaluate(observation, tuple(self.history))
        if verdict.action not in {"allow", "block", "approve", "warn"}:
            raise ValueError("Invalid baseline decision")
        self.history.append(observation)
        return verdict
