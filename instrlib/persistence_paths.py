"""Conservative literal schedule parsing. Paths identify proposals, not inodes.

Targets are over-approximated: every absolute path a scheduled command references
is a candidate, because the persistence join only Blocks when one of those paths
independently carried an *uncleared* dangerous write proposal. Over-matching a
launcher such as ``/usr/bin/python`` is therefore harmless. Dynamic or opaque
syntax stays explicit uncertainty (``schedule_target_unresolved``), never a
silent "no target".

Facts (value is JSON ``[namespace, abspath]``, ASCII-escaped, except the plain
string reason on ``schedule_target_unresolved``):
  dangerous_write_target_v2    a write whose body is a dangerous payload
  rewrite_or_delete_target_v2  a benign overwrite or a delete of a path; the
                               SINCE lifecycle join treats it as clearing an
                               earlier dangerous write on that path
  schedule_target_v2           a path referenced by a written/created schedule
  schedule_removed_target_v2   a schedule entry explicitly deleted (native tool)
  schedule_target_unresolved   the schedule could not be read literally
"""
import json
import posixpath
import re
from instrlib.command_risk import _unwrap_shell_c
from instrlib.event import Event

_ABS_PATH_RE = re.compile(r"(?<![\w:=@])/[A-Za-z0-9._+-][A-Za-z0-9._/+-]*")
_REL_PATH_RE = re.compile(r"(?<!\S)\.\.?/[A-Za-z0-9._/+-]+")
_DYNAMIC = ("$", "`", "\n", "\x00")
_PATH_KEYS = ("path", "file_path", "filename", "file", "filepath")
_REMOVE_ACTIONS = {"delete", "remove", "unschedule", "disable", "revoke", "unregister"}


def absolute_path(value):
    if not isinstance(value, str) or not value.startswith("/"):
        return None
    if any(c in value for c in ("$", "~", "\\", "\x00", "\n", "`", "*", "?", "[", "%")):
        return None
    return "/" + posixpath.normpath(value).lstrip("/")


def command_targets(command, _depth=0):
    """Return (targets, unknown). Over-approximate: every absolute path a command
    references is a candidate, which is safe because the join only Blocks a path
    that independently carried a dangerous write. ``unknown`` is True on dynamic
    or opaque syntax, on a relative script with no resolvable working directory,
    or when nothing literal was found, so the caller emits an explicit
    schedule_target_unresolved rather than a false negative.

    A ``sh -c "..."`` wrapper is unwrapped once so the real inner command is read
    instead of the shell binary. Only a leading ``cd /abs &&`` establishes a
    working directory for ``./rel`` resolution; a ``||`` or bare ``cd`` leaves the
    relative target unresolved (uncertain), never invented."""
    if not isinstance(command, str) or not command.strip():
        return set(), True
    if any(c in command for c in _DYNAMIC):
        return set(), True
    if _depth < 3:
        inner = _unwrap_shell_c(command)
        if inner != command:
            return command_targets(inner, _depth + 1)
    cwd = None
    m = re.match(r"\s*cd\s+(/[^\s;&|]+)\s*&&\s*(.*)", command, re.DOTALL)
    if m:
        cwd = absolute_path(m.group(1))
    targets = set()
    for raw in _ABS_PATH_RE.findall(command):
        resolved = absolute_path(raw)
        if resolved:
            targets.add(resolved)
    unknown = False
    for rel in _REL_PATH_RE.findall(command):
        resolved = absolute_path(posixpath.join(cwd, rel)) if cwd else None
        if resolved:
            targets.add(resolved)
        else:
            unknown = True  # a relative script we cannot pin to a directory
    return targets, unknown or not targets


def command_target(command):
    targets, _ = command_targets(command)
    return sorted(targets)[0] if len(targets) == 1 else None


def schedule_analysis(content, system_crontab=False):
    """Parse cron/systemd scheduler text. Returns (sorted targets, unknown)."""
    targets = set()
    unknown = False
    saw = False
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        m = re.match(
            r"Exec(?:Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)\s*=\s*(.*)",
            line,
        )
        if m:
            saw = True
            command = m.group(1)
            prefix = re.match(r"^[-+!@:]+", command)
            if prefix:
                command = command[prefix.end():]
        elif "=" in line.split()[0]:
            continue  # an unrelated ini/unit key, not a scheduled command
        else:
            fields = line.split()
            if fields and fields[0].startswith("@"):
                rest = fields[1:]
            elif len(fields) >= 6 and all(
                re.fullmatch(r"[0-9A-Za-z*,/\-]+", f) for f in fields[:5]
            ):
                rest = fields[5:]
            else:
                unknown = True
                continue
            saw = True
            # Only /etc/crontab and /etc/cron.d/* carry a leading user column.
            # A user crontab or systemd unit has none, so stripping there would
            # drop the real command's first token.
            if system_crontab and rest and re.fullmatch(r"[a-z_][a-z0-9_-]*", rest[0]):
                rest = rest[1:]
            command = " ".join(rest)
        found, miss = command_targets(command)
        targets |= found
        unknown |= miss
    return sorted(targets), unknown or not saw


def schedule_targets(content, system_crontab=False):
    return schedule_analysis(content, system_crontab)[0]


def _is_system_crontab(path):
    return bool(path) and (path == "/etc/crontab" or path.startswith("/etc/cron.d/"))


def _arg_path(args):
    return next(
        (args[k] for k in _PATH_KEYS if isinstance(args.get(k), str) and args[k]), ""
    )


def _dangerous(content):
    """Dangerous authored payload for the persistence join.

    Unlike the write-boundary ``_dangerous_written_content``, a scope-limited
    cleanup (``rm -rf`` confined to tmp/cache/build) is NOT dangerous here: a
    routine maintenance script scheduled by an admin assistant is exactly the
    case the candidate stopped over-blocking. Unscoped recursive deletes still
    classify as critical and match.
    """
    from instrlib.tool_mapper import (
        _dangerous_written_content, authored_exfil_dataflow, _AUTHORED_SEND_RE,
    )
    if _dangerous_written_content(content, scoped_delete_is_dangerous=False):
        return True
    if authored_exfil_dataflow(content):
        return True
    literal_credential_read = re.search(
        r"\bopen\s*\(\s*[\"'][^\"'\n]*(?:/\.env|/secrets\.env)[\"']\s*\)\.read\s*\(",
        content,
    )
    return bool(literal_credential_read and _AUTHORED_SEND_RE.search(content))


def persistence_path_events(tid, call_id, canonical_tool, args, namespace, mapped):
    def fact(dimension, value):
        return Event("Classify", tid, call_id, dimension, value)

    kinds = {
        e.args[3]
        for e in mapped
        if e.name == "Classify" and len(e.args) >= 4 and e.args[2] == "persistence_kind"
    }
    scheduling = bool(kinds & {"service", "scheduled_task", "scheduled_routine"})
    valid_ns = isinstance(namespace, str) and bool(namespace) and len(namespace) <= 256

    if scheduling and not valid_ns:
        return [fact("schedule_target_unresolved", "missing_runtime_namespace")]

    def pathfact(dimension, path):
        return fact(
            dimension,
            json.dumps([namespace, path], ensure_ascii=True, separators=(",", ":")),
        )

    events = []

    if canonical_tool == "file_write":
        path = absolute_path(_arg_path(args))
        content = args.get("content")
        if path and valid_ns and isinstance(content, str):
            # A write is EITHER a dangerous proposal OR a lifecycle clear, never
            # both: the file's latest write decides its state for the SINCE join,
            # so a benign overwrite of a formerly dangerous script clears it.
            if _dangerous(content):
                events.append(pathfact("dangerous_write_target_v2", path))
            else:
                events.append(pathfact("rewrite_or_delete_target_v2", path))
        if scheduling and valid_ns:
            targets, unknown = schedule_analysis(
                content if isinstance(content, str) else "", _is_system_crontab(path)
            )
            events.extend(pathfact("schedule_target_v2", target) for target in targets)
            if unknown:
                events.append(
                    fact("schedule_target_unresolved", "unsupported_or_partial_command")
                )

    elif canonical_tool == "file_delete":
        path = absolute_path(_arg_path(args))
        if path and valid_ns:
            # Deleting the script clears a prior dangerous write proposal on it.
            events.append(pathfact("rewrite_or_delete_target_v2", path))

    elif scheduling and valid_ns:
        # Native scheduling tools carry explicit command fields, never agent
        # prose, so only literal command strings are parsed. A delete/remove
        # action clears the matching schedule reference for the lifecycle join.
        commands = []
        removals = []

        def collect(obj, removing=False):
            if isinstance(obj, dict):
                action = str(
                    obj.get("action") or obj.get("operation") or obj.get("op") or ""
                ).strip().lower()
                removing = removing or action in _REMOVE_ACTIONS
                for key, value in obj.items():
                    if key in {"command", "cmd"} and isinstance(value, str):
                        (removals if removing else commands).append(value)
                    elif isinstance(value, (dict, list)):
                        collect(value, removing)
            elif isinstance(obj, list):
                for item in obj:
                    collect(item, removing)

        collect(args)
        unknown = not (commands or removals)
        for command in commands:
            targets, miss = command_targets(command)
            unknown |= miss
            events.extend(pathfact("schedule_target_v2", t) for t in sorted(targets))
        for command in removals:
            targets, _ = command_targets(command)
            events.extend(pathfact("schedule_removed_target_v2", t) for t in sorted(targets))
        if unknown:
            events.append(
                fact("schedule_target_unresolved", "native_payload_not_literal_command")
            )

    return events
