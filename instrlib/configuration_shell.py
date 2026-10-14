"""Bounded shell configuration observations; never execute shell to resolve bytes.

Only a standalone cat + quoted heredoc has exact recovered bytes. Other visible
configuration mutations carry uncertainty. This is not a general shell parser.
"""
import re
import shlex

_CONFIG = re.compile(r'\.(?:ya?ml|json|toml|ini|cfg|conf)$', re.I)
_PATH = r'''(?:"[^"\n]+"|'[^'\n]+'|[^\s<>;&|]+)'''
_LITERAL = re.compile(
    rf'''\A[ \t\n]*cat[ \t]+(?P<op>>>?)[ \t]*(?P<path>{_PATH})[ \t]+<<[ \t]*(?P<q>['"])(?P<delimiter>[A-Za-z_][A-Za-z_0-9]*)(?P=q)[ \t]*\n(?P<content>[\s\S]*?)\n(?P=delimiter)[ \t]*(?=\n|$)'''
)

def is_config(path):
    return isinstance(path, str) and bool(_CONFIG.search(path))


def shell_configuration_writes(command):
    """Return observations with exact content or explicit unresolved status.

    Whole-command single-quoted shell -c wrappers are unwrapped. Double-quoted
    wrappers may expand in the outer shell and are never treated as literal.
    """
    from instrlib.command_risk import _unwrap_shell_c
    if not isinstance(command, str):
        return []
    original = command
    unwrapped = _unwrap_shell_c(command)
    expanded_wrapper = unwrapped != command
    if unwrapped != command and re.match(r"^\s*(?:/\S+/)?(?:bash|sh|zsh)\s+-[a-z]*c\s+'", command):
        expanded_wrapper = False
    command = unwrapped
    out = []
    def recover(match):
        path = shlex.split(match['path'])[0]
        if not is_config(path):
            # Remove all heredoc bodies so data isn't misread as shell effects.
            return '\n'
        dynamic_path = any(c in match['path'] for c in '$`*?[')
        if expanded_wrapper or dynamic_path or match['op'] != '>':
            out.append({'path': path, 'shell_write_status': 'unresolved', 'reason': 'dynamic target or append'})
        else:
            out.append({'path': path, 'content': match['content']+'\n', 'shell_write_status': 'literal_heredoc'})
        return '\n'
    remainder = command
    while _LITERAL.match(remainder):
        remainder = _LITERAL.sub(recover, remainder, count=1)
    # A mutation outside the recovered literal blocks must never be hidden by a
    # benign classification of one block. Preserve the full command for audit.
    try:
        lexer = shlex.shlex(remainder, posix=True, punctuation_chars=';&|<>')
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = []
        if re.search(r'\.(?:ya?ml|json|toml|ini|cfg|conf)\b', remainder, re.I):
            out.append({'shell_write_status': 'unresolved', 'reason': 'unparseable shell containing configuration path'})
    for i, token in enumerate(tokens):
        if token in {'>', '>>', '>|'} and i+1 < len(tokens) and is_config(tokens[i+1]):
            out.append({'path': tokens[i+1], 'shell_write_status': 'unresolved', 'reason': 'nonliteral redirection'})
    # Mutation commands with visible configuration paths. Read-only cat/grep/
    # sed without -i do not meet this gate. Interpreter source is not evaluated.
    if any(is_config(t) for t in tokens) and (
        re.search(r'(?:^|[\n;&|])\s*(?:sudo\s+)?(?:cp|mv|install|tee|truncate)\b', remainder)
        or re.search(r'\bsed\s+[^\n]*?(?:-i\b|--in-place\b)', remainder)
    ):
        out.append({'shell_write_status': 'unresolved', 'reason': 'configuration mutation command'})
    if re.search(r'\.(?:ya?ml|json|toml|ini|cfg|conf)\b', remainder, re.I) and re.search(
        r'\.(?:write_text|write_bytes|write)\s*\(|\bopen\([^\n]*[,=]\s*[\'"][wax]', remainder
    ):
        out.append({'shell_write_status': 'unresolved', 'reason': 'interpreter configuration mutation'})
    if out:
        # Include original command in the evidence budget; do not silently drop
        # surrounding context or assume recovered bytes describe the whole call.
        return {'shell_command': original, 'writes': out}
    return None
