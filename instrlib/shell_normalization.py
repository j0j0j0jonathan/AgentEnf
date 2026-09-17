"""Bounded textual shell normalization for classification.

These helpers inspect strings. They never execute shell commands and are not a
complete shell interpreter. Unresolved syntax remains available to the mapper.
"""

import base64
import posixpath
import re
from typing import Dict, List, Optional

_RECON_PREVIEW_HEAD_RE = re.compile(r"^\s*(?:echo|printf)\b", re.IGNORECASE)

_TOKEN_EMPTY_QUOTE_RE = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")

_LINE_CONTINUATION_RE = re.compile(r"\\\r?\n")

_BSLASH_LETTER_CLUSTER_RE = re.compile(r"(?:\\[A-Za-z]){2,}")

_HEX_ESCAPE_CLUSTER_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){3,}")

_OCTAL_ESCAPE_CLUSTER_RE = re.compile(r"(?:\\[0-7]{1,3}){3,}")

_DOT_SEGMENT_RE = re.compile(r"/(?:\./)+")

_UNQUOTED_BSLASH_LETTER_RE = re.compile(r"('[^']*'|\"[^\"]*\")|\\(?!x[0-9A-Fa-f]{2})([A-Za-z])")


def _strip_unquoted_bslash_letters(text: str) -> str:
    return _UNQUOTED_BSLASH_LETTER_RE.sub(
        lambda m: m.group(1) if m.group(1) is not None else m.group(2), text
    )


def _decode_hex_escape_cluster(blob: str) -> str:
    try:
        return "".join(chr(int(h, 16)) for h in re.findall(r"\\x([0-9A-Fa-f]{2})", blob))
    except Exception:
        return blob


def _decode_octal_escape_cluster(blob: str) -> str:
    try:
        return "".join(chr(int(o, 8) & 0xFF) for o in re.findall(r"\\([0-7]{1,3})", blob))
    except Exception:
        return blob


_BASE64_DECODE_FLAG_RE = re.compile(
    r"\bbase64\b[^|&;\n]*\s-(?:d\b|D\b|-decode\b)|\bbase64\s+--decode\b", re.IGNORECASE
)

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_base64_payloads(text: str) -> str:
    """Decoded text of base64 blobs in a command that runs a base64 decode.

    Returns '' when the command does not invoke a base64 decode, or no blob
    decodes to printable text. Matching-only and additive."""
    if not text or not _BASE64_DECODE_FLAG_RE.search(text):
        return ""
    out = []
    for tok in _BASE64_TOKEN_RE.findall(text):
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            txt = raw.decode("utf-8", "strict")
        except Exception:
            continue
        if txt and sum(ch.isprintable() or ch in "\t\n" for ch in txt) / len(txt) > 0.9:
            out.append(txt)
    return " ".join(out)


_BRACE_LIST_RE = re.compile(r"(?P<pre>[^\s{}]*)\{(?P<body>[^{}]*,[^{}]*)\}(?P<post>[^\s{}]*)")


def _expand_braces(text: str) -> str:
    def repl(m: "re.Match") -> str:
        pre, post = m.group("pre"), m.group("post")
        items = m.group("body").split(",")
        return " ".join(pre + it + post for it in items)

    prev = None
    s = text
    # Bounded passes so nested or adjacent braces expand without runaway.
    for _ in range(3):
        if "{" not in s or "," not in s:
            break
        s = _BRACE_LIST_RE.sub(repl, s)
        if s == prev:
            break
        prev = s
    return s


def _strip_obfuscation(text: str) -> str:
    """Collapse backslash-letter splitting and decode hex/octal escape clusters.

    Side-effect-free and matching-only. No ``$`` required (so it runs even when
    ``expand_shell_assembly`` short-circuits)."""
    s = text
    if "\\" in s:
        s = _BSLASH_LETTER_CLUSTER_RE.sub(lambda m: m.group(0).replace("\\", ""), s)
        s = _HEX_ESCAPE_CLUSTER_RE.sub(lambda m: _decode_hex_escape_cluster(m.group(0)), s)
        s = _OCTAL_ESCAPE_CLUSTER_RE.sub(lambda m: _decode_octal_escape_cluster(m.group(0)), s)
    if "{" in s:
        s = _expand_braces(s)
    if "/./" in s:
        s = _DOT_SEGMENT_RE.sub("/", s)
    if "\\" in s:
        s = _strip_unquoted_bslash_letters(s)
    return s


_SHEBANG_RE = re.compile(r"^\s*#![^\n]*\n")


def _deobfuscate(command: str) -> str:
    if not command:
        return command
    # Strip a leading interpreter shebang (`#!/bin/bash\n…`). RedCode and many
    # real scripts wrap their body in a `#!/bin/bash` header; left in place the
    # shebang's `bash` token was consumed by the bare-interpreter script_exec
    # branch (e.g. `bash\nfunction …`), producing a spurious resdev=script_exec.
    # The actual command body is what should be classified, so remove the shebang
    # line before any pattern matching. Only a true leading `#!` is removed.
    command = _SHEBANG_RE.sub("", command, count=1)
    s = _LINE_CONTINUATION_RE.sub("", command)
    if "''" in s or '""' in s:
        s = _TOKEN_EMPTY_QUOTE_RE.sub("", s)
    s = _strip_obfuscation(s)
    # base64 decode-to-execute: append the decoded payload so the persistence /
    # path / exec classifiers see the real command hidden in the blob. A decode
    # pipeline (`echo BLOB | base64 -d | bash`) is real execution, not a benign
    # echo preview, so when a payload is recovered we skip the preview
    # short-circuit below.
    decoded = _decode_base64_payloads(s)
    if decoded:
        return expand_shell_assembly(s) + " " + decoded
    # A command whose head is echo/printf only prints, do NOT expand its
    # arguments into a spurious "executed command" match. This keeps benign
    # echo/printf previews non-firing even when they contain a variable or a
    # `$(printf …)`. (Genuinely executed forms like `curl … | sh` still match on
    # the raw text, so detection is not lost.)
    if _RECON_PREVIEW_HEAD_RE.match(s):
        return s
    return expand_shell_assembly(s)


_PRINTF_CALL_RE = re.compile(r"\$\(\s*printf\s+(['\"])(.*?)\1((?:\s+[^()\s]+)*)\s*\)")

_ECHO_SUBST_RE = re.compile(
    r"\$\(\s*echo\s+(?:-[eEn]+\s+)?((?:'[^']*'|\"[^\"]*\"|[^()'\"|;&`$])*?)\s*\)"
    r"|`\s*echo\s+(?:-[eEn]+\s+)?((?:'[^']*'|\"[^\"]*\"|[^`|;&$])*?)\s*`"
)

_IFS_REF_RE = re.compile(r"\$\{IFS\}|\$IFS\b")

_ASSIGN_RE = re.compile(
    r"(?:^|[;&\n]\s*)"
    r"(?:export\s+|readonly\s+|local(?:\s+-[A-Za-z]+)?\s+)?"
    r"([A-Za-z_]\w*)\s*=\s*"
    r"('(?:[^']*)'|\"(?:[^\"`]*)\"|[^\s;|&`]+)",
    re.MULTILINE,
)

_VARREF_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")

_ABS_PATH_TOKEN_RE = re.compile(r"(?<![\w.-])(/[A-Za-z0-9_./~+-]+)")


def _strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]:
        return v[1:-1]
    return v


def _apply_printf(fmt: str, args_str: str) -> str:
    """Best-effort, execution-free `printf fmt args` (handles %s and %%)."""
    args = args_str.split()
    out: List[str] = []
    i = j = 0
    while i < len(fmt):
        if fmt[i] == "%" and i + 1 < len(fmt):
            spec = fmt[i + 1]
            if spec == "%":
                out.append("%")
            else:  # %s and other conversions: consume one positional arg
                out.append(args[j] if j < len(args) else "")
                j += 1
            i += 2
            continue
        out.append(fmt[i])
        i += 1
    return "".join(out)


def _literal_assignment_value(value: str) -> Optional[str]:
    """Return a safe analysis-only assignment value, or ``None`` if dynamic.

    Variable references to other known literals are allowed and resolved over
    bounded passes. Command/process substitutions, positional parameters, and
    shell special parameters are dynamic and must never be guessed.
    """

    value = _strip_quotes(value)
    if "$(" in value or "`" in value:
        return None
    if re.search(r"\$(?:\d+|[@*#?!$-])", value):
        return None
    return value


def _normalize_absolute_paths(text: str) -> str:
    """Lexically normalize absolute path tokens for matching only.

    This does not touch the executed command. It lets a path assembled as
    ``/usr/../etc/ssh/ssh_config`` carry the same semantic classification as
    ``/etc/ssh/ssh_config`` while preserving the original text for trace output.
    """

    def repl(match: re.Match[str]) -> str:
        token = match.group(1)
        if "/../" not in token and "/./" not in token:
            return token
        normalized = posixpath.normpath(token)
        return normalized if normalized.startswith("/") else token

    return _ABS_PATH_TOKEN_RE.sub(repl, text)


def expand_shell_assembly(text: str, max_passes: int = 3) -> str:
    """Expand `$(printf …)` substitutions and simple `VAR=…; … $VAR` assignments.

    Bounded and side-effect-free: it only rewrites the string for pattern
    matching, never runs a subprocess. Returns ``text`` unchanged when there is
    nothing to expand.
    """
    if not text or "$" not in text:
        return text
    s = text
    for _ in range(max(1, max_passes)):
        prev = s
        s = _PRINTF_CALL_RE.sub(lambda m: _apply_printf(m.group(2), m.group(3).strip()), s)
        s = _ECHO_SUBST_RE.sub(
            lambda m: _strip_quotes(m.group(1) if m.group(1) is not None else (m.group(2) or "")),
            s,
        )
        s = _IFS_REF_RE.sub(" ", s)
        varmap: Dict[str, str] = {}
        for m in _ASSIGN_RE.finditer(s):
            val = _literal_assignment_value(m.group(2))
            if val is not None:
                varmap[m.group(1)] = val
        if varmap:
            s = _VARREF_RE.sub(lambda m: varmap.get(m.group(1) or m.group(2), m.group(0)), s)
        s = _normalize_absolute_paths(s)
        if s == prev:
            break
    return s


_SHEBANG_RE = re.compile(r"^\s*#!.{0,40}\b(?:bash|sh|zsh|ksh)\b", re.IGNORECASE)
