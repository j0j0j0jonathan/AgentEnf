"""Recognize literal chmod permission effects without running a shell.

This bounded recognizer accepts a single literal invocation. It does not resolve
variables, globs, aliases, symlinks, shell programs or reference-file modes. An
empty result means no supported positive fact, never proof that code is safe.
Facts describe requested permission bits, not successful execution or authority.
"""
import posixpath
import re
import shlex

MAX_COMMAND_BYTES = 16 * 1024
_PROGRAMS = {"chmod", "/bin/chmod", "/usr/bin/chmod"}
_SYSTEM_ROOTS = {"etc", "boot", "bin", "sbin", "lib", "lib64", "usr", "sys", "proc", "root"}
_SYMBOLIC = re.compile(r"([ugoa]*)([+\-=])([rwxXstugo]*)\Z")


def grants_other_write(mode):
    """Whether a literal mode explicitly leaves the others-write bit set.

    Omitted-who symbolic grants depend on umask; copy modes depend on current
    bits. Do not guess either. Later symbolic clauses override earlier ones.
    """
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return bool(int(mode, 8) & 0o002)
    state = None
    for part in mode.split(","):
        match = _SYMBOLIC.fullmatch(part)
        if not match:
            return False
        who, operation, permissions = match.groups()
        if not who:
            return False  # umask-sensitive; no structural positive claim
        if not ({"a", "o"} & set(who)):
            continue
        if any(char in "ugo" for char in permissions):
            state = None
        elif operation == "=":
            state = "w" in permissions
        elif "w" in permissions:
            state = operation == "+"
    return state is True


def chmod_system_worldwrite(command):
    """Return concrete literal target/mode facts for one supported command."""
    if not isinstance(command, str) or len(command.encode()) > MAX_COMMAND_BYTES:
        return []
    if any(char in command for char in ("\n", "\r", "\x00", "$", "`")):
        return []
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    # Also decline quoted shell metacharacters, rather than guessing whether a
    # parsed argument is a shell program. This is deliberately conservative.
    if any(any(char in token for char in ";&|<>()") for token in tokens):
        return []
    if tokens and tokens[0] in {"sudo", "/usr/bin/sudo"}:
        tokens = tokens[1:]
        if tokens and tokens[0] == "-n":
            tokens = tokens[1:]
    if not tokens or tokens.pop(0) not in _PROGRAMS:
        return []
    recursive, mode, paths, options = False, None, [], True
    for token in tokens:
        if mode is not None:
            if token.startswith("-"):
                return []  # Post-mode option semantics are outside this subset.
            paths.append(token)
        elif options and token == "--":
            options = False
        elif options and token in {"--help", "--version"}:
            return []
        elif options and token in {"--recursive", "--changes", "--silent", "--quiet", "--verbose"}:
            recursive |= token == "--recursive"
        elif options and re.fullmatch(r"-[RcvfHLP]+", token):
            recursive |= "R" in token
        elif token.startswith("--"):
            return []  # Includes --reference: effect cannot be derived locally.
        else:
            mode = token
    if not mode or not paths or not grants_other_write(mode):
        return []
    facts = []
    for path in paths:
        # No glob expansion, parent traversal or relative/CWD assumptions.
        if not path.startswith("/") or path.startswith("//") or any(c in path for c in "*?[]~") or ".." in path.split("/"):
            continue
        normalized = posixpath.normpath(path)
        first = normalized.lstrip("/").split("/", 1)[0]
        if first in _SYSTEM_ROOTS or (recursive and normalized == "/"):
            facts.append({"kind": "world_writable_system_path", "path": normalized,
                          "mode": mode, "recursive": recursive,
                          "basis": "literal chmod sets the others-write bit on a system path"})
    return facts
