"""Shell and inline-code risk rules with explicit benign-operation exceptions.

These rules inspect command text and limited Python syntax. They never execute
input. Their labels are evidence for policy and do not issue runtime verdicts.
"""

import ast
import posixpath
import re
import shlex
from typing import Optional
from instrlib.shell_normalization import _deobfuscate, _RECON_PREVIEW_HEAD_RE


# Classification rules

# Patterns that indicate critical bash commands.
# "Critical" = irreversible destructive or arbitrary code execution.
_CRITICAL_BASH_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"),  # rm -rf
    re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b"),  # rm -fr
    re.compile(r"\|\s*(ba)?sh\b"),  # curl|sh, wget|bash
    re.compile(r"\beval\s*[(\"`]"),  # eval(, eval`, eval"
    re.compile(r"\bdd\s+.*\bif="),  # dd if=/dev/...
    re.compile(r"\bmkfs\b"),  # mkfs (format disk)
    re.compile(r":\(\)\s*\{.*\|.*&"),  # fork bomb
    re.compile(r"\b(shred|wipe)\b"),  # secure-delete
    re.compile(r"\bbase64\s+-d\b.*\|\s*(ba)?sh"),  # base64 decode | sh
    # bare `python -c` / `perl -e` are not auto-critical anymore, a benign
    # `python3 -c "print(1)"` must not be critical. Inline interpreters are rated
    # by their PAYLOAD via classify_code (see classify_command below), only
    # eval/exec/subprocess/socket/etc. payloads come back critical.
    re.compile(r"\bnc\b.*-e\b"),  # netcat reverse shell
    # World-writable other bits (last octal digit 6 or 7), not owner-rw
    # modes such as ``chmod 600 /tmp/file`` (seed-0024).
    re.compile(r"\bchmod\s+(?:-R\s+)?(?:0*[0-7][0-7][67]|a\+r?wx?|o\+w)\s+/"),
    re.compile(r">\s*/dev/(sd|hd|nvme|vd)[a-z]"),  # write to raw disk device
]

# Patterns that indicate privilege escalation.
_ELEVATED_BASH_PATTERNS = [
    re.compile(r"\bsudo\b"),
    re.compile(r"\bsu\s+(-\s+)?root\b"),
    re.compile(r"\bsu\s*$"),  # bare "su"
    re.compile(r"\bchmod\s+[ug]\+s\b"),  # setuid/setgid
    re.compile(r"\bchown\s+root\b"),
    re.compile(r"\bnewgrp\b"),
    re.compile(r"\bpkexec\b"),
    re.compile(r"\bdoas\b"),
    re.compile(r"\brunlevel\b"),
    re.compile(r"\bsystemctl\s+(start|stop|enable|disable|mask)\b"),
    # Read-only scheduled-task inventory is Reconnaissance, not an elevated
    # persistence change. `command -v crontab` checks availability and
    # `crontab -l` lists jobs; a later `crontab newfile` / `crontab -` in the
    # same compound command remains an elevated persistence action.
    re.compile(r"(?<!command -v )\bcrontab\b(?!\s+-l(?:\s|$|[>|&;]))"),
]


def _has_crontab_install(command: str) -> bool:
    """Whether a shell command invokes ``crontab`` to change scheduling state."""
    try:
        tokens = shlex.split(command or "", posix=True)
    except ValueError:
        return False
    for index, token in enumerate(tokens):
        if token != "crontab":
            continue
        # Tool-availability checks do not schedule work.
        if index >= 2 and tokens[index - 2 : index] == ["command", "-v"]:
            continue
        if index >= 1 and tokens[index - 1] in {"which", "type"}:
            continue
        # Listing the current table is read-only even if stdout is redirected.
        if index + 1 < len(tokens) and tokens[index + 1] == "-l":
            continue
        return True
    return False


def _is_read_only_crontab_inventory(command: str) -> bool:
    """True for a command that discovers or lists cron but never installs a job."""
    command = command or ""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = []

    # `command -v crontab` is an availability probe. Shell wrappers and
    # output redirection are still read-only; without this explicit check the
    # generic `>` write-intent matcher below mistakes the redirect for a cron
    # configuration write.
    availability_probe = any(
        tokens[index : index + 3] == ["command", "-v", "crontab"]
        or tokens[index : index + 2] in (["which", "crontab"], ["type", "crontab"])
        for index in range(len(tokens))
    )
    listing_probe = bool(re.search(r"\bcrontab\s+-l(?:\s|$|[>|&;])", command, re.I))
    cron_dir_inventory = bool(
        re.search(r"\bfind\b[^\n]* /etc/cron", command, re.I)
        or re.search(r"\bsystemctl\s+list-timers\b", command, re.I)
    )
    return (availability_probe or listing_probe or cron_dir_inventory) and not _has_crontab_install(
        command
    )


# Sandbox / container escape via a symlink or bind-mount that bridges a sensitive
# system path into the agent's reach (A3S Sandbox Escape: `ln -s /root <ws>`,
# `ln -s /var/log <ws>`). The escape primitive (the link/mount) carries no
# destructive shape, so the per-call classifier saw command_risk=safe and missed
# it; only a later read THROUGH the link surfaced, and only at approve tier. We
# rate the link itself critical so the deterministic critical_command_backstop
# hard-blocks it. Keyed on a SENSITIVE source so a benign in-workspace symlink
# (`ln -s ./node_modules/.bin/x ./x`, `ln -s ../shared link`, `ln -s /tmp/proj/a b`)
# does not match (its source is relative or non-sensitive). /var/tmp and
# /var/folders are excluded so an ordinary staging symlink is not caught.
_SANDBOX_SYMLINK_ESCAPE_RE = re.compile(
    r"\bln\s+-[a-zA-Z]*s[a-zA-Z]*\s+(?:--\s+)?"
    # sensitive-content system roots only (config, secrets, logs, kernel, disks,
    # other users). /usr and /lib are deliberately excluded so a normal
    # `ln -s /usr/local/bin/tool ~/bin/tool` PATH symlink is not flagged.
    r"(?:/(?:root|etc|proc|sys|boot|dev)\b"
    r"|/var/(?:log|lib|spool|backups)\b"
    r"|/home/[^/\s]+"
    r"|~?/\.(?:ssh|aws|gnupg|kube|docker)\b)",
    re.IGNORECASE,
)

_BIND_MOUNT_ESCAPE_RE = re.compile(
    r"\bmount\b[^\n|;&]*(?:\s|^)(?:--r?bind|-o\s+r?bind)\b",
    re.IGNORECASE,
)

# Known container-breakout primitives beyond the symlink/bind-mount bridge above.
# These are containment escapes that are essentially never benign in an agent
# workspace, so matching on presence is a low-false-positive hard block. Path
# confinement (realpath escape) would also catch several of these, but only when
# it is enabled; routing them to command_risk=critical makes the block
# config-independent so they still hard-block in the no-path-confinement run.
_CONTAINER_ESCAPE_RE = re.compile(
    # namespace escapes: enter host namespaces or fork into fresh ones
    r"\bnsenter\b"
    r"|\bunshare\b[^\n|;&]*(?:--(?:mount|pid|user|net|uts|ipc|cgroup)\b|\s-[a-zA-Z]*[mpUnuiC])"
    r"|\bsetns\b"
    # mount a raw block device or a fresh proc/sysfs/cgroup to reach the host
    r"|\bmount\b[^\n|;&]*/dev/(?:sd|nvme|xvd|vd|hd|mapper|loop)\w*"
    r"|\bmount\b[^\n|;&]*-t\s+(?:proc|sysfs|cgroup2?|devtmpfs)\b"
    # privileged docker / raw docker-socket breakout
    r"|\bdocker\b[^\n]*\brun\b[^\n]*(?:--privileged\b|--pid[=\s]host\b|-v\s*/:(?:/|\s|$))"
    r"|--unix-socket\s+\S*docker\.sock|/var/run/docker\.sock"
    # kernel / cgroup release-agent breakout targets
    r"|/proc/sys/kernel/core_pattern"
    r"|\brelease_agent\b|\bnotify_on_release\b"
    # chroot into another process root or a host mount
    r"|\bchroot\b[^\n]*(?:/proc/\d+/root|/host\b|/mnt/host\b)",
    re.IGNORECASE,
)


def is_sandbox_escape(command: str) -> bool:
    """True if a command performs a containment escape.

    Covers three families: a symlink or bind-mount that bridges a sensitive
    system path into the agent's reach, and (via ``_CONTAINER_ESCAPE_RE``) the
    common container-breakout primitives, namespace escapes (nsenter / unshare /
    setns), mounting a raw block device or fresh proc/sysfs/cgroup, a privileged
    docker or raw docker-socket run, kernel/cgroup release-agent writes
    (core_pattern, release_agent), and chroot into a host or process root.
    """
    if not command:
        return False
    command = _deobfuscate(command)
    return bool(
        _SANDBOX_SYMLINK_ESCAPE_RE.search(command)
        or _BIND_MOUNT_ESCAPE_RE.search(command)
        or _CONTAINER_ESCAPE_RE.search(command)
    )


_TMP_SCRATCH_RM_RE = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+(?:--\s+)?(?:/tmp/|/var/tmp/|\$\{?(?:TMPDIR|TMP|TEMP|D|tmp_dir|tmpdir|dest|SRC)[\w]*\}?)",
    re.IGNORECASE,
)

_SYSTEM_RM_RE = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+(?:--\s+)?(?:/(?:etc|usr|var/log|home|root|boot|sys|proc)(?:/|\s|$)|/\s*$)",
    re.IGNORECASE,
)


def _is_tmp_scratch_rm_rf(command: str) -> bool:
    """True when every ``rm -rf`` is a /tmp or mktemp scratch dir, not a system root."""
    if _SYSTEM_RM_RE.search(command or ""):
        return False
    return bool(_TMP_SCRATCH_RM_RE.search(command or "") or _rm_of_mktemp_var(command or ""))


# Isolated micro-change (not the exfil join): ``find … -name __pycache__ -exec rm -rf``
# is regenerable bytecode cleanup. The F4 critical backstop treated it as
# ``rm -rf`` and blocked seed-0121 when the agent happened to clean caches.
# Keep this narrower than a generic ``find -exec rm`` exemption: the find must
# name ``__pycache__``. Mixed system wipes stay critical.
_PYCACHE_FIND_RM_RE = re.compile(
    r"\bfind\b[^\n]*-name\s+['\"]?__pycache__['\"]?[^\n]*"
    r"(?:-exec\s+rm\s+-[a-zA-Z]*r[a-zA-Z]*f\b|-delete\b)",
    re.IGNORECASE,
)


def _is_pycache_find_rm_rf(command: str) -> bool:
    """True for find-based ``__pycache__`` cleanup, not a generic tree wipe."""
    if _SYSTEM_RM_RE.search(command or ""):
        return False
    return bool(_PYCACHE_FIND_RM_RE.search(command or ""))


# A shell variable assigned from ``mktemp`` is a fresh, agent-created scratch dir,
# so ``rm -rf "$var"`` on it is cleanup, not a critical delete. Matches the common
# idiom ``tmp=$(mktemp -d) … rm -rf "$tmp"`` regardless of the var name (``shim``,
# ``tmpbin``) or quoting, which the name-allowlisted _TMP_SCRATCH_RM_RE missed
# (seed-0153, seed-0156: a python PATH-shim built in a mktemp dir then removed).
_MKTEMP_ASSIGN_RE = re.compile(r"(\w+)=\"?\$\(\s*mktemp\b[^)]*\)", re.IGNORECASE)

_RM_VAR_TARGET_RE = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+(?:--\s+)?\"?\$\{?(\w+)\}?\"?", re.IGNORECASE
)


def _rm_of_mktemp_var(command: str) -> bool:
    """True if every ``rm -rf $VAR`` targets a mktemp-assigned scratch variable."""
    scratch_vars = {m.group(1) for m in _MKTEMP_ASSIGN_RE.finditer(command or "")}
    if not scratch_vars:
        return False
    targets = _RM_VAR_TARGET_RE.findall(command or "")
    return bool(targets) and all(t in scratch_vars for t in targets)


_INLINE_INTERP_RE = re.compile(
    r"\b(?P<interp>python[23]?|perl|ruby|node|php)\s+-(?:c|e|r)\b\s*"
    r"(?P<q>['\"])(?P<code>.*?)(?P=q)",
    re.DOTALL,
)

_INLINE_INTERP_PRESENT_RE = re.compile(r"\b(?:python[23]?|perl|ruby|node|php)\s+-(?:c|e|r)\b")


def classify_command(cmd: str) -> str:
    """
    Classify a bash command string.
    Returns "critical" | "elevated" | "safe".

    critical, irreversible/destructive: rm -rf, eval, fork-bomb, pipe-to-sh.
    elevated, privilege-escalation: sudo, chown root, systemctl, crontab.
    safe, everything else.

    Inline interpreters (``python -c`` / ``perl -e`` / ``node -e`` / ``php -r``)
    are rated by their PAYLOAD via ``classify_code``, not by the mere presence of
    ``-c``: ``python3 -c "print(1)"`` is safe, while an ``eval``/``exec``/
    ``subprocess``/``socket`` payload is elevated/critical. This avoids
    false-criticalling benign one-liners (which previously armed the execution
    ``untrusted_authorization`` tier after any ordinary file read).

    The command is canonicalized first (line-joins, empty-quote / backslash
    splitting, hex/octal escapes, ``${IFS}`` word-splitting, ``$(printf …)`` /
    ``$(echo …)`` / ``VAR=`` assembly) so a variable- or escape-assembled
    dangerous command (e.g. ``R=rm; $R -rf /`` or ``rm${IFS}-rf${IFS}/``) is rated
    on its real shape rather than the obfuscated surface text. This keeps
    ``command_risk`` consistent with the action-class classifiers, all of which
    already deobfuscate.
    """
    cmd = _deobfuscate(cmd or "")
    if _is_recon_preview(cmd):
        return "safe"
    # An audit grep whose PATTERN mentions sudo/nc/rm is still a search, not an
    # elevated or critical command (seed-0457 lists skill files then greps for
    # `nc -e` / `sudo` / `/dev/tcp`). Unquoted mutations fail the search-shape
    # test and keep their real rating.
    if _is_pattern_search_command(cmd):
        return "safe"
    # A symlink / bind-mount that bridges a sensitive system path into the agent's
    # reach is a containment escape, rate it critical so the deterministic
    # critical_command_backstop hard-blocks it (A3S Sandbox Escape).
    if is_sandbox_escape(cmd):
        return "critical"
    # Quoted grep/audit literals (rm, kill, |sh) must not rate the command
    # critical. Scratch ``rm -rf /tmp/<review-dir>`` before a clone is also not
    # a system-destroying rm.
    pattern_view = _mask_quoted(cmd)
    for pattern in _CRITICAL_BASH_PATTERNS:
        if pattern.search(pattern_view):
            if _is_tmp_scratch_rm_rf(cmd) and pattern in _CRITICAL_BASH_PATTERNS[:2]:
                continue
            if _is_pycache_find_rm_rf(cmd) and pattern in _CRITICAL_BASH_PATTERNS[:2]:
                continue
            if _is_build_artifact_cleanup(cmd) and pattern in _CRITICAL_BASH_PATTERNS[:2]:
                continue
            return "critical"
    inlines = list(_INLINE_INTERP_RE.finditer(cmd))
    inline_elevated = False
    for inline in inlines:
        level = classify_code(inline.group("code"))
        if level == "critical":
            return "critical"
        inline_elevated |= level == "elevated"
        # classify_code recognizes Python danger tokens, only trust its "safe"
        # verdict for Python. A perl/ruby/node/php payload it can't read stays
        # elevated (e.g. `perl -e "system('id')"`), not downgraded to safe.
        if not inline.group("interp").startswith("python"):
            inline_elevated = True
        # benign Python payload (e.g. print) → fall through to elevated/safe checks
    if not inlines and _INLINE_INTERP_PRESENT_RE.search(cmd):
        # interpreter -c/-e with a payload we couldn't extract (unquoted, heredoc,
        # variable-built) → flag as elevated rather than blanket critical.
        return "elevated"
    elevated_view = cmd
    if _is_read_only_crontab_inventory(cmd):
        # Avoid treating the command token or an output filename such as
        # ``current-crontab`` as an elevated scheduler mutation.
        elevated_view = re.sub(r"\bcrontab\b", "cron_inventory", cmd, flags=re.IGNORECASE)
    for pattern in _ELEVATED_BASH_PATTERNS:
        if pattern.search(elevated_view):
            return "elevated"
    return "elevated" if inline_elevated else "safe"


# Code execution risk (dim: code_risk)

# Critical: dynamic execution primitives that can run arbitrary code or
# escape the sandbox, eval, exec, __import__, os.system, subprocess, ctypes.
_CRITICAL_CODE_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bos\.popen\s*\("),
    re.compile(r"\bsubprocess\.(run|call|Popen|check_output|check_call)\b"),
    re.compile(r"\bctypes\b"),
    re.compile(r"\bimportlib\.import_module\s*\("),
    re.compile(r"\bcompile\s*\(.*exec"),  # compile(..., 'exec')
    re.compile(r"\bpickle\.(loads|load)\s*\("),  # deserialisation RCE
    re.compile(r"\bmarshal\.loads?\s*\("),
]

_UNSAFE_YAML_LOAD_RE = re.compile(r"\byaml\.(?:unsafe_load|load)\s*\(")

_SAFE_YAML_LOAD_RE = re.compile(r"\b(?:CSafeLoader|SafeLoader)\b|\byaml\.safe_load\s*\(")

# Elevated: imports that give access to filesystem, network, or process state
# but don't themselves execute arbitrary code.
_ELEVATED_CODE_PATTERNS = [
    re.compile(r"\bimport\s+(os|sys|pathlib|shutil|glob)\b"),
    re.compile(r"\bimport\s+(socket|urllib|httpx|requests|aiohttp|httplib2)\b"),
    re.compile(r"\bimport\s+subprocess\b"),
    re.compile(r"\bimport\s+(pickle|marshal)\b"),
    re.compile(r"\bopen\s*\("),  # any file open
    re.compile(r"\bfrom\s+os\s+import\b"),
    re.compile(r"\bfrom\s+pathlib\s+import\b"),
]


def _bounded_python_operation(code: str) -> Optional[str]:
    """Recognize complete small encoding probes and stdlib pip bootstrap calls."""
    if len(code) > 8192:
        return None
    try:
        tree = ast.parse(code.strip())
    except (SyntaxError, ValueError, RecursionError):
        return None
    if sum(1 for _ in ast.walk(tree)) > 256:
        return None
    imports = set()
    expressions = []
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            if any(
                alias.asname or alias.name not in {"sys", "locale", "subprocess"}
                for alias in statement.names
            ):
                return None
            imports.update(alias.name for alias in statement.names)
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            expressions.append(statement.value)
        else:
            return None

    def name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return name(node.value) + "." + node.attr
        return ""

    if len(expressions) == 1:
        call = expressions[0]
        if (
            imports == {"sys", "subprocess"}
            and name(call.func) == "subprocess.check_call"
            and not call.keywords
            and len(call.args) == 1
            and isinstance(call.args[0], (ast.List, ast.Tuple))
        ):
            args = call.args[0].elts
            if (
                len(args) >= 3
                and name(args[0]) == "sys.executable"
                and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in args[1:])
                and [a.value for a in args[1:3]] == ["-m", "ensurepip"]
                and all(a.value in {"--upgrade", "--default-pip", "--altinstall"} for a in args[3:])
            ):
                return "package_bootstrap"

    def encoding_value(node):
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, bool, int, type(None)))
        if not isinstance(node, ast.Call) or node.keywords:
            return False
        if name(node.func) == "sys.getfilesystemencoding" and "sys" in imports:
            return not node.args
        if name(node.func) == "locale.getpreferredencoding" and "locale" in imports:
            return not node.args or (
                len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value is False
            )
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "environ"
        ):
            return False
        loader = node.func.value.value
        return (
            isinstance(loader, ast.Call)
            and name(loader.func) == "__import__"
            and not loader.keywords
            and len(loader.args) == 1
            and isinstance(loader.args[0], ast.Constant)
            and loader.args[0].value == "os"
            and 1 <= len(node.args) <= 2
            and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in node.args)
            and node.args[0].value in {"PYTHONIOENCODING", "PYTHONUTF8", "PYTHONCOERCECLOCALE"}
        )

    if (
        expressions
        and imports <= {"sys", "locale"}
        and any(isinstance(arg, ast.Call) for call in expressions for arg in call.args)
        and all(
            name(call.func) == "print"
            and not call.keywords
            and all(encoding_value(arg) for arg in call.args)
            for call in expressions
        )
    ):
        return "encoding_probe"
    return None


_READ_ONLY_SUBPROCESS_PROGRAMS = frozenset(
    {
        "cat",
        "du",
        "find",
        "head",
        "ls",
        "pwd",
        "stat",
        "tail",
        "wc",
    }
)

_SHELL_CONTROL_CHARS_RE = re.compile(r"[;&|><`\n\r$()]")


def _all_subprocess_calls_read_only(code: str) -> bool:
    """Recognize bounded subprocess calls that can only inspect local state.

    This is deliberately narrower than a shell parser. Dynamic arguments, shell
    operators, mutating ``find`` actions, alternate executables, environment
    replacement, and every subprocess API except ``run``/``check_output`` keep
    the critical rating.
    """
    if not code or len(code) > 8192:
        return False
    try:
        tree = ast.parse(code.strip())
    except (SyntaxError, ValueError, RecursionError):
        return False
    if sum(1 for _ in ast.walk(tree)) > 512:
        return False

    def dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = dotted_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and dotted_name(node.func).startswith("subprocess.")
    ]
    if not calls:
        return False

    allowed_keywords = {
        "capture_output",
        "check",
        "cwd",
        "encoding",
        "errors",
        "shell",
        "stderr",
        "stdout",
        "text",
        "timeout",
    }
    for call in calls:
        if dotted_name(call.func) not in {"subprocess.run", "subprocess.check_output"}:
            return False
        if not call.args or any(kw.arg not in allowed_keywords for kw in call.keywords):
            return False
        command = call.args[0]
        if isinstance(command, ast.Constant) and isinstance(command.value, str):
            if _SHELL_CONTROL_CHARS_RE.search(command.value):
                return False
            try:
                argv = shlex.split(command.value)
            except ValueError:
                return False
        elif isinstance(command, (ast.List, ast.Tuple)):
            if not all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in command.elts
            ):
                return False
            argv = [item.value for item in command.elts]
        else:
            return False
        if not argv or posixpath.basename(argv[0]) not in _READ_ONLY_SUBPROCESS_PROGRAMS:
            return False
        if posixpath.basename(argv[0]) == "find" and any(
            arg in {"-delete", "-exec", "-execdir", "-ok", "-okdir"} for arg in argv[1:]
        ):
            return False
    return True


def classify_code(code: str) -> str:
    """
    Classify code passed to a code-execution tool.
    Returns "critical" | "elevated" | "safe".

    critical, eval/exec/subprocess/ctypes, can escape the sandbox.
    elevated, filesystem or network imports, side effects outside the script.
    safe, pure computation, no dangerous imports detected.
    """
    if _bounded_python_operation(code):
        return "elevated"
    for match in _UNSAFE_YAML_LOAD_RE.finditer(code):
        call_window = code[match.start() : match.start() + 200]
        if not _SAFE_YAML_LOAD_RE.search(call_window):
            return "critical"
    readonly_subprocess = _all_subprocess_calls_read_only(code)
    for pattern in _CRITICAL_CODE_PATTERNS:
        if pattern is _CRITICAL_CODE_PATTERNS[5] and readonly_subprocess:
            continue
        if pattern.search(code):
            return "critical"
    for pattern in _ELEVATED_CODE_PATTERNS:
        if pattern.search(code):
            return "elevated"
    return "safe"


_RECON_COMMAND_PREVIEW_RE = re.compile(
    r"^\s*(?:echo|printf)\s+(?P<q>['\"])(?P<body>.*)(?P=q)\s*$",
    re.IGNORECASE | re.DOTALL,
)

_EXEC_OPERATOR_RE = re.compile(r"[|;&`]|\$\(|>|\n")


def _is_recon_preview(command: str) -> bool:
    if _RECON_COMMAND_PREVIEW_RE.match(command):
        return True
    return bool(_RECON_PREVIEW_HEAD_RE.match(command)) and not _EXEC_OPERATOR_RE.search(command)


# Protected target: a system dir, bare root, or parent-traversal (out of workspace).
_IMPACT_PROTECTED_PATH_RE = re.compile(
    r"(?:^|\s)/(?:etc|usr|bin|sbin|lib|lib64|boot|root|sys|proc|var|home|srv|opt)\b"
    # /dev is protected EXCEPT benign pseudo-devices (network sockets, null/zero,
    # std streams, fds, randomness): those are not destructive write targets, so
    # `> /dev/null`, `> /dev/tcp/...`, `2>/dev/null` must not read as Impact.
    r"|(?:^|\s)/dev/(?!(?:tcp|udp|null|zero|full|stdin|stdout|stderr|fd|random|urandom)\b)\S"
    r"|(?:^|\s)/(?:\s|$|\*)"  # bare /  or  /*
    r"|\.\./",  # parent traversal
    re.IGNORECASE,
)

# Regenerable build-artifact / cache directories whose recursive deletion is a
# routine developer cleanup, not a destructive impact. A recursive delete whose
# targets are ALL rooted at one of these (e.g. `rm -rf node_modules/.cache`,
# `rm -rf build dist`, `rm -rf __pycache__`) is allowed — neither impact nor a
# gated file delete. Matched on the FIRST path component, so `rm -rf src/build`
# (root `src`), any absolute / out-of-workspace target, a glob, a variable, or a
# parent traversal is NOT treated as cleanup and still gates. Reviewer call
# 2026-06-13: benign build/cache cleanup (EXEC-BENI-03, CROSS-BENI-02) must Allow.
_BUILD_ARTIFACT_DIRS = frozenset(
    {
        "node_modules",
        "bower_components",
        ".cache",
        "build",
        "dist",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".parcel-cache",
        ".turbo",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".gradle",
        "coverage",
        "htmlcov",
        ".nyc_output",
        ".sass-cache",
        ".eslintcache",
        # Regenerable virtualenvs. ``rm -rf .venv`` is ordinary Python cleanup
        # (unguarded seed-0121 / seed-0157), not a workspace wipe.
        ".venv",
        "venv",
        ".virtualenv",
        # Regenerable output directories a build or run recreates. Same basename-only,
        # system-path-excluded discipline as the rest of the set (seed-0154 clears
        # /tmp/project/output before rerunning the importer that regenerates it).
        "output",
        "outputs",
        "out",
        "generated",
        "gen",
        "artifacts",
    }
)

# A whole-command shell wrapper, ``bash -lc '<script>'``. The segment-based
# carve-outs below parse a command by shell segment; a wrapper the agent adds for
# its own reasons defeats every one of them, because the first segment then reads
# ``bash -lc 'rm …`` and never matches the ``rm`` anchor. seed-0435 ran its
# ``__pycache__`` cleanup exactly that way and lost the build-artifact carve-out.
# Detection regexes scan the raw string and are unaffected either way, so this can
# only restore a carve-out, never suppress a detection.
_SHELL_C_WRAPPER_RE = re.compile(
    r"^\s*(?:env\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|k|da)?sh\s+"
    r"-[a-zA-Z]*c[a-zA-Z]*\s+(?P<q>['\"])(?P<inner>.*)(?P=q)\s*$",
    re.DOTALL,
)


def _unwrap_shell_c(command: str) -> str:
    """Return the inner script of a whole-command ``bash -lc '<script>'`` wrapper.

    Only a command that is ENTIRELY one such invocation with a single quoted
    argument is unwrapped; anything that merely mentions ``sh -c`` is returned
    unchanged. A trailing segment outside the quotes survives the unwrap as an
    ordinary segment, so a mixed ``bash -lc 'rm -rf build' && rm -rf /etc`` is
    still parsed with both targets and still fails the carve-out.
    """
    m = _SHELL_C_WRAPPER_RE.match(command or "")
    if not m:
        return command
    inner = m.group("inner")
    if m.group("q") == "'":
        return inner
    return inner.replace('\\"', '"').replace("\\$", "$").replace("\\`", "`")


# ``/home/<user>/…`` and ``/Users/<user>/…`` STRICTLY BELOW the user directory.
# At least one segment must follow the user name, so ``/home``, ``/home/node``
# and ``/Users/jane`` are not matched and a wipe of a home directory itself keeps
# its protected-path treatment.
_USER_HOME_SUBPATH_RE = re.compile(r"^/(?:home|Users)/[^/]+/[^/]+", re.IGNORECASE)


def _is_user_home_subpath(path: str) -> bool:
    """Whether an absolute path sits strictly inside a user's home directory."""
    return bool(_USER_HOME_SUBPATH_RE.match(path or ""))


def _is_build_artifact_cleanup(command: str) -> bool:
    """Whether `command` is a recursive delete confined to regenerable build/cache
    dirs (see `_BUILD_ARTIFACT_DIRS`). The deleted directory must itself be a
    regenerable artifact — checked on its BASENAME, so this works for relative
    (`build`, `node_modules/.cache`) AND absolute in-workspace paths
    (`/workspace/proj/node_modules`). Conservative: a target under a protected
    SYSTEM path (`/etc`, `/var`, `/home`, …), a glob/variable/traversal target, a
    non-artifact basename, or `find -delete`/`shred` all return False."""
    if not command:
        return False
    cmd = _deobfuscate(command)
    if _is_command_preview(cmd):
        return False
    cmd = _unwrap_shell_c(cmd)
    saw_delete = False
    for seg in re.split(r"&&|\|\||[;|\n]", cmd):
        s = seg.strip()
        if not s:
            continue
        if re.search(r"\bfind\b[^\n]*(?:-delete\b|-exec\s+rm\b)|\bshred\b", s):
            return False
        m = re.match(r"(?:sudo\s+)?(?:rm|unlink)\b(.*)$", s, re.IGNORECASE)
        if not m:
            continue  # a non-delete segment (du, pytest, echo, …) is harmless
        saw_delete = True
        # Shell redirections are not deletion targets. Without this normalization,
        # ``rm -rf .venv 2>/dev/null`` treats /dev/null as a second target and
        # loses the otherwise narrow build-artifact carve-out.
        arg_text = re.sub(
            r"(?<!\S)(?:\d+)?(?:>>?|<<?|<>|>&|<&)\s*(?:&?\d+|[^\s]+)",
            " ",
            m.group(1),
        )
        try:
            args = shlex.split(arg_text)
        except ValueError:
            return False
        targets = [a for a in args if a != "--" and not a.startswith("-")]
        if not targets:
            return False
        for t in targets:
            p = t.strip().strip("'\"").rstrip("/")
            if p.startswith("./"):
                p = p[2:]
            if not p or p.startswith("~") or ".." in p or "*" in p or "$" in p or "`" in p:
                return False
            if p.startswith("/"):
                # absolute: allow only an in-workspace artifact dir (by basename),
                # never under a protected system root (/etc, /var, /usr, …).
                # A user HOME SUBTREE is the exception: /home/<u>/… and
                # /Users/<u>/… are where an agent's own workspace lives, so a
                # regenerable artifact dir under one is ordinary cleanup rather
                # than system damage. seed-0435 deleted
                # /home/node/.openclaw/workspace/skills/claude-code/__pycache__
                # and hard-Blocked as destructive_protected purely because the
                # path began with /home. The home root and its immediate children
                # are still protected, and the basename check below still has to
                # pass, so this excuses regenerable artefacts only.
                if _IMPACT_PROTECTED_PATH_RE.search(p) and not _is_user_home_subpath(p):
                    return False
                if p.split("/")[-1] not in _BUILD_ARTIFACT_DIRS:
                    return False
            else:
                # relative: the top-level dir being deleted must be an artifact
                # (keeps `src/build` gated while allowing `node_modules/.cache`)
                if p.split("/")[0] not in _BUILD_ARTIFACT_DIRS:
                    return False
    return saw_delete


_SEARCH_LEAD_TOOLS = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}

_SEARCH_SAFE_FILTERS = {
    "head",
    "tail",
    "sort",
    "uniq",
    "wc",
    "cat",
    "less",
    "more",
    "tr",
    "cut",
    "awk",
    "sed",
    "column",
    "nl",
    "tee",
    "xargs",
    "printf",
    "echo",
    "true",
    # read-only navigation/inspection that often wraps an audit grep (seed-0457
    # runs `cd ... && wc ... && find ... -print && grep -RniE '<danger tokens>'`).
    "cd",
    "find",
    "ls",
    "test",
    "stat",
    "file",
    "dirname",
    "basename",
    "realpath",
    "du",
    "pwd",
    "env",
}


def _is_pattern_search_command(command: str) -> bool:
    """True if the command is a pure search/filter pipeline (grep/rg for a
    pattern, piped only to benign filters), so dangerous tokens inside the search
    pattern are the query, not an executed command.

    Callers: impact, execution/reverse-shell, privilege, lateral movement,
    exfil, file-delete, and command_risk. A command that also runs ``nc``,
    ``curl``, ``rm``, or ``-exec`` in its own segment returns False.
    """
    if not command:
        return False
    # Double-quoted and unquoted shell substitutions can execute before grep.
    expansion_view = re.sub(r"'[^']*'", "''", command)
    if re.search(r"\$\(|`|[<>]\(", expansion_view):
        return False
    # Mask quoted strings first so the search PATTERN (which may literally contain
    # rm -rf, curl, sudo) is not mistaken for an executed command.
    c = _mask_quoted(_deobfuscate(command))
    # Diagnostic stderr redirection is not a write to an artifact.
    c = re.sub(r"(?<![\w>])2\s*>\s*(?:/dev/null(?=\s|[;&|]|$)|&1\b)", " ", c)
    # A real mutation or fetch outside a pattern disqualifies immediately.
    if re.search(r"-exec\b|-delete\b|>\s*\S|>>\s*\S|\bcurl\b|\bwget\b|\bnc\b", c, re.I):
        return False
    segments = [s.strip() for s in re.split(r"[|;&\n]+", c) if s.strip()]
    if not segments:
        return False
    has_search = False
    for seg in segments:
        lead = re.match(r"(?:sudo\s+)?([\w./-]+)", seg)
        name = lead.group(1).split("/")[-1] if lead else ""
        if name in _SEARCH_LEAD_TOOLS:
            has_search = True
            continue
        if name in _SEARCH_SAFE_FILTERS:
            continue
        return False
    return has_search


_QUOTED_STR_RE = re.compile(r"'[^']*'|\"[^\"]*\"")


def _mask_quoted(text: str) -> str:
    """Replace quoted substrings with a neutral placeholder so statement
    separators (`;`/`&&`) INSIDE a quoted payload do not split the command and
    so tokens inside the data are not read as executed shell syntax."""
    return _QUOTED_STR_RE.sub(" STR ", text)


_COMMAND_PREVIEW_RE = re.compile(
    r"^\s*(?:echo|printf)\s+(?P<q>['\"])(?P<body>[^'\"]{8,})(?P=q)\s*$",
    re.IGNORECASE | re.DOTALL,
)


def _is_command_preview(command: str) -> bool:
    """True for shell commands that only print another command string."""

    match = _COMMAND_PREVIEW_RE.match(command or "")
    if not match:
        return False
    body = match.group("body")
    return bool(
        re.search(
            r"\b(?:scp|rsync|sftp|curl|wget|nc|ncat|mail|dig|nslookup|host"
            r"|ssh|chisel|ngrok|smbclient|mount|psexec|winexe|wmic|masscan|zmap"
            r"|tar|zip|7z|rar|gzip|pax|cpio|cp|mv|mysqldump|pg_dump|mongodump"
            r"|sqlite3?|redis-cli|journalctl|scrot|screencapture|gnome-screenshot"
            r"|spectacle|maim|xwd|pbpaste|wl-paste|xclip|xsel|find|grep"
            r"|rm|unlink|shred|chmod|chown|dd|mkfs|wipefs|fallocate)\b",
            body,
            re.IGNORECASE,
        )
    )
