"""Offline prototype for removing redundant OpenClaw startup instructions.

NOT a loader, authorization mechanism, or runtime integration. Receipts must
eventually come from the harness loader/prompt builder, never model/user fields.
The caller must obtain canonical paths and fresh versions from that loader.
This module validates a proposed contract; it cannot authenticate its caller or
prove that a filesystem read, absence check, or symlink check actually happened.
"""
from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
from pathlib import PurePosixPath
from typing import Literal, Mapping


ORIGINAL_STARTUP = """## Session Startup

Before doing anything else:

1. Read `SOUL.md` — this is who you are
2. Read `USER.md` — this is who you're helping
3. Read `memory/YYYY-MM-DD.md` (today + yesterday) for recent context
4. **If in MAIN SESSION** (direct chat with your human): Also read `MEMORY.md`

Don't ask permission. Just do it.
"""

Status = Literal["full", "truncated", "confirmed_absent", "unknown"]


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Scope:
    namespace: str
    session_id: str
    request_id: str
    workspace: str
    local_day: date


@dataclass(frozen=True)
class Observation:
    path: str
    status: Status
    # Opaque loader-owned file identity/version, NOT just its basename.
    version: str | None = None
    # Hash of the exact text supplied in Project Context, including truncation.
    supplied_sha256: str | None = None


@dataclass(frozen=True)
class LoaderReceipt:
    scope: Scope
    observations: tuple[Observation, ...]


@dataclass(frozen=True)
class Assembly:
    context_files: dict[str, str]
    statuses: dict[str, str]
    changed_path: str
    source_sha256: str
    assembled_sha256: str


def _canonical_spelling(path: str) -> bool:
    p = PurePosixPath(path)
    return (path.startswith("/") and not path.startswith("//")
            and ".." not in p.parts and str(p) == path
            and not any(ord(c) < 32 for c in path))


def assemble(scope: Scope, receipt: LoaderReceipt, context_files: Mapping[str, str]) -> Assembly:
    """Return a copy with only the known AGENTS startup paragraph rewritten.

    Stateless and scoped to one request. Full entries must match supplied bytes;
    missing entries remain unknown. Absence is only accepted as an explicit
    loader observation. No policy, hook, event, or runtime decision is changed.
    """
    if not all(isinstance(x, str) and x.strip() for x in
               (scope.namespace, scope.session_id, scope.request_id)):
        raise ValueError("Nonempty runtime namespace, session and request are required")
    if not _canonical_spelling(scope.workspace):
        raise ValueError("Workspace must have canonical absolute POSIX spelling")
    if receipt.scope != scope:
        raise ValueError("Stale or mismatched loader receipt")
    observations = {}
    for obs in receipt.observations:
        if not _canonical_spelling(obs.path) or not obs.path.startswith(scope.workspace + "/"):
            raise ValueError("Resource must be an exact path inside this workspace")
        if obs.path in observations:
            raise ValueError("Duplicate loader observation")
        if obs.status not in {"full", "truncated", "confirmed_absent", "unknown"}:
            raise ValueError("Unknown loader status")
        if obs.status in {"full", "truncated"}:
            if not obs.version or obs.path not in context_files:
                raise ValueError("Loaded resource requires version and supplied context")
            if obs.supplied_sha256 != sha256(context_files[obs.path]):
                raise ValueError("Loader receipt does not match supplied context")
        elif obs.version is not None or obs.supplied_sha256 is not None:
            raise ValueError("Unknown or absent resource must not claim a loaded version")
        if obs.status == "confirmed_absent" and obs.path in context_files:
            raise ValueError("Absent resource cannot have supplied content")
        observations[obs.path] = obs

    agents_path = scope.workspace + "/AGENTS.md"
    agents = observations.get(agents_path)
    if agents is None or agents.status != "full":
        raise ValueError("A full AGENTS.md snapshot is required for this experiment")
    original = context_files[agents_path]
    # Exact template recognition avoids rewriting an arbitrary or changed policy.
    if original.count(ORIGINAL_STARTUP) != 1:
        raise ValueError("Unsupported startup guidance; review the new template first")

    statuses = {}

    def instruction(relative_path: str) -> str:
        obs = observations.get(scope.workspace + "/" + relative_path)
        status = obs.status if obs else "unknown"
        statuses[relative_path] = status
        if status == "full":
            return f"Use `{relative_path}` from the current Project Context; do not reread solely for startup."
        if status == "confirmed_absent":
            return f"`{relative_path}` was confirmed absent by the loader for this request; do not probe it solely for startup."
        if status == "truncated":
            return f"Read `{relative_path}` for startup: its supplied context is incomplete."
        return f"Read `{relative_path}` for startup: its loading status is unknown."

    daily = ["memory/" + d.isoformat() + ".md"
             for d in (scope.local_day, scope.local_day - timedelta(days=1))]
    lines = [
        "## Session Startup", "", "Before doing anything else:", "",
        "1. " + instruction("SOUL.md"),
        "2. " + instruction("USER.md"),
        "3. For recent context: " + " ".join(instruction(p) for p in daily),
        "4. **If in MAIN SESSION** (direct chat with your human): " + instruction("MEMORY.md"),
        "", "These observations describe only the current request's snapshot. If the task needs fresh",
        "bytes or a resource may have changed, use a normal read through the existing tool checks.",
        "This guidance grants no permission for reads, writes, disclosure or outbound transfers.", "",
    ]
    files = dict(context_files)
    files[agents_path] = original.replace(ORIGINAL_STARTUP, "\n".join(lines), 1)
    return Assembly(files, statuses, agents_path, sha256(original), sha256(files[agents_path]))
