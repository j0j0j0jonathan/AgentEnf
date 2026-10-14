"""Proposal correlation, not completed-artifact lifecycle or filesystem identity.

Only parsed executable/script positions feed hard-block joins. Unsupported syntax
requires review; unrelated path arguments are not execution targets. Proposals
never clear history. Completion-attested lifecycle tracking remains future work.
"""

import json
import posixpath
import re
import shlex
from instrlib.event import Event

_PATH_KEYS = ("path", "file_path", "filename", "file", "filepath")
_REMOVE_ACTIONS = {"delete", "remove", "unschedule", "disable", "revoke", "unregister"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}


def absolute_path(value):
    if not isinstance(value, str) or not value.startswith("/"):
        return None
    if any(c in value for c in ("$", "~", "\\", "\x00", "\n", "`", "*", "?", "[", "%")):
        return None
    # normpath can collapse symlink-sensitive '..': keep that unresolved.
    if ".." in value.split("/"):
        return None
    return "/" + posixpath.normpath(value).lstrip("/")


def _program(words, cwd, depth):
    if not words or depth > 6:
        return set(), True
    if any(any(c in word for c in ("$", "`", "\x00", "%")) for word in words):
        return set(), True
    name = posixpath.basename(words[0])
    tail = words[1:]
    if name in _SHELLS and tail and tail[0] in {"-c", "-lc", "-ec", "-xc"}:
        if len(tail) != 2:
            return set(), True
        return command_targets(tail[1], depth + 1, cwd)
    if name == "env":
        while tail and (
            tail[0] in {"-i", "--ignore-environment", "--"}
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tail[0])
        ):
            tail = tail[1:]
        if not tail or tail[0].startswith("-"):
            return set(), True
        return _program(tail, cwd, depth + 1)
    if name == "nohup":
        if tail and tail[0] == "--":
            tail = tail[1:]
        return _program(tail, cwd, depth + 1)
    if name == "nice":
        if tail and tail[0] == "-n":
            if len(tail) < 2 or not re.fullmatch(r"-?\d+", tail[1]):
                return set(), True
            tail = tail[2:]
        elif tail and tail[0].startswith("--adjustment="):
            tail = tail[1:]
        if tail and tail[0] == "--":
            tail = tail[1:]
        if tail and tail[0].startswith("-"):
            return set(), True
        return _program(tail, cwd, depth + 1)
    if name == "timeout":
        if tail and tail[0] == "--":
            tail = tail[1:]
        if not tail or not re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", tail[0]):
            return set(), True
        return _program(tail[1:], cwd, depth + 1)
    if name == "flock":
        while tail and tail[0] in {"-n", "--nonblock", "-x", "--exclusive", "-s", "--shared", "--"}:
            tail = tail[1:]
        if not tail or not absolute_path(tail[0]):
            return set(), True
        return _program(tail[1:], cwd, depth + 1)
    interpreter = name in _SHELLS | {"node", "ruby", "perl", "php"} or bool(
        re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", name)
    )
    if interpreter:
        while tail and tail[0] in {"-u", "-B", "-E", "-s", "-S", "-O", "-OO", "-I", "--"}:
            tail = tail[1:]
        if not tail or tail[0].startswith("-"):
            return set(), True
        candidate = tail[0]
    else:
        candidate = words[0]
    target = absolute_path(candidate)
    if not target and cwd and candidate.startswith("./"):
        target = absolute_path(posixpath.join(cwd, candidate))
    # An unknown launcher might execute an argument. Do not hard-join that
    # argument, but request review when there are other path-shaped operands.
    uncertain = not interpreter and any(x.startswith(("/", "./", "../")) for x in tail)
    return ({target} if target else set()), uncertain or target is None


def command_targets(command, _depth=0, _cwd=None):
    if not isinstance(command, str) or not command.strip() or _depth > 6:
        return set(), True
    if any(c in command for c in ("$", "`", "\n", "\x00")):
        return set(), True
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return set(), True
    segments = []
    words = []
    i = 0
    unknown = False
    while i < len(tokens):
        token = tokens[i]
        if token in {";", "&&", "||", "|", "&"}:
            segments.append((words, token))
            words = []
            i += 1
            continue
        if token and set(token) <= set("<>&") and ("<" in token or ">" in token):
            if words and words[-1].isdigit():
                words.pop()
            if token not in {">", ">>", "<", ">&", "<&", "&>"} or i + 1 >= len(tokens):
                unknown = True
            i += 2
            continue
        words.append(token)
        i += 1
    segments.append((words, None))
    cwd = _cwd
    targets = set()
    for words, separator in segments:
        if not words:
            unknown = True
            continue
        if words[0] == "cd":
            if len(words) == 2 and separator == "&&" and absolute_path(words[1]):
                cwd = absolute_path(words[1])
            else:
                cwd = None
                unknown = True
            continue
        found, miss = _program(words, cwd, _depth)
        targets |= found
        unknown |= miss
        if separator in {"|", "&", "||"}:
            cwd = None
    return targets, unknown


def command_target(command):
    targets, _ = command_targets(command)
    return next(iter(targets)) if len(targets) == 1 else None


def schedule_analysis(content, system_crontab=False):
    targets = set()
    unknown = False
    saw = False
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        match = re.match(
            r"Exec(?:Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)\s*=\s*(.*)", line
        )
        if match:
            saw = True
            command = match[1]
            prefix = re.match(r"^[-+!@:]+", command)
            if prefix:
                if "@" in prefix[0]:
                    # Custom argv[0] changes interpreter argument semantics.
                    try:
                        executable = shlex.split(command[prefix.end() :])[0]
                    except (ValueError, IndexError):
                        executable = ""
                    target = absolute_path(executable)
                    if target:
                        targets.add(target)
                    unknown = True
                    continue
                command = command[prefix.end() :]
            # systemd does not apply shell operators unless explicitly using sh -c.
            try:
                parts = shlex.split(command)
            except ValueError:
                unknown = True
                continue
            found, miss = _program(parts, None, 0)
        elif "=" in line.split()[0]:
            continue
        else:
            # Preserve quotes in the command instead of split/join token rewriting.
            if line.startswith("@"):
                parts = line.split(None, 1)
                command = parts[1] if len(parts) == 2 else ""
            else:
                parts = line.split(None, 5)
                if len(parts) < 6 or not all(
                    re.fullmatch(r"[0-9A-Za-z*,/\-]+", f) for f in parts[:5]
                ):
                    unknown = True
                    continue
                command = parts[5]
            if system_crontab:
                parts = command.split(None, 1)
                if len(parts) < 2:
                    unknown = True
                    continue
                command = parts[1]
            saw = True
            found, miss = command_targets(command)
        targets |= found
        unknown |= miss
    return sorted(targets), unknown or not saw


def schedule_targets(content, system_crontab=False):
    return schedule_analysis(content, system_crontab)[0]


def _is_system_crontab(path):
    return bool(path) and (path == "/etc/crontab" or path.startswith("/etc/cron.d/"))


def _arg_path(args):
    return next((args[k] for k in _PATH_KEYS if isinstance(args.get(k), str) and args[k]), "")


def _dangerous(content):
    """Dangerous authored payload for the persistence join.

    Unlike the write-boundary ``_dangerous_written_content``, a scope-limited
    cleanup (``rm -rf`` confined to tmp/cache/build) is NOT dangerous here: a
    routine maintenance script scheduled by an admin assistant is exactly the
    case the candidate stopped over-blocking. Unscoped recursive deletes still
    classify as critical and match.
    """
    from instrlib.tool_mapper import (
        _dangerous_written_content,
        authored_exfil_dataflow,
        _AUTHORED_SEND_RE,
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


def persistence_path_events(
    tid, call_id, canonical_tool, args, namespace, mapped, raw_tool_name=None
):
    def fact(dimension, value):
        return Event("Classify", tid, call_id, dimension, value)

    valid_ns = isinstance(namespace, str) and bool(namespace) and len(namespace) <= 256

    def pathfact(dimension, path):
        return fact(
            dimension, json.dumps([namespace, path], ensure_ascii=True, separators=(",", ":"))
        )

    kinds = {
        e.args[3]
        for e in mapped
        if e.name == "Classify" and len(e.args) >= 4 and e.args[2] == "persistence_kind"
    }
    scheduling = bool(kinds & {"service", "scheduled_task", "scheduled_routine"})
    native = bool(re.search(r"cron|schedul", raw_tool_name or canonical_tool, re.I))
    action = str(args.get("action") or args.get("operation") or args.get("op") or "").lower()
    if native and action in _REMOVE_ACTIONS:
        # Report job identity only. A requested removal is NOT a completed revoke;
        # it cannot clear references belonging to this job or another job.
        job_id = args.get("jobId") or args.get("job_id") or args.get("id")
        if valid_ns and isinstance(job_id, str) and job_id:
            return [
                fact(
                    "schedule_removal_proposed_id",
                    json.dumps([namespace, job_id], ensure_ascii=True, separators=(",", ":")),
                )
            ]
        return [fact("schedule_removal_status", "unresolved_identity")]
    if scheduling and not valid_ns:
        return [fact("schedule_target_unresolved", "missing_runtime_namespace")]
    events = []
    if canonical_tool == "file_write":
        path = absolute_path(_arg_path(args))
        content = args.get("content")
        if path and valid_ns and isinstance(content, str) and _dangerous(content):
            events.append(pathfact("dangerous_write_target_v2", path))
        if scheduling:
            targets, unknown = (
                schedule_analysis(content, _is_system_crontab(path))
                if isinstance(content, str)
                else ([], True)
            )
            events.extend(pathfact("schedule_target_v2", target) for target in targets)
            if unknown:
                events.append(fact("schedule_target_unresolved", "unsupported_or_partial_command"))
    elif scheduling:
        commands = []

        def collect(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in {"command", "cmd"} and isinstance(value, str):
                        commands.append(value)
                    elif isinstance(value, (dict, list)):
                        collect(value)
            elif isinstance(obj, list):
                for item in obj:
                    collect(item)

        collect(args)
        unknown = not commands
        for command in commands:
            targets, miss = command_targets(command)
            unknown |= miss
            events.extend(pathfact("schedule_target_v2", target) for target in sorted(targets))
        if unknown:
            events.append(fact("schedule_target_unresolved", "native_payload_not_literal_command"))
    return events
