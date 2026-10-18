"""Bounded shell destination observations, never shell execution or expansion.

Recognizes visible copy/move/install/clone destinations. Does not infer payload
content, successful installation, or filesystem identity from a proposal.
"""
import posixpath
import re
import shlex

SKILL = re.compile(r'(?:^|/)(?:skills?|plugins?)(?:/|$)|(?:^|/)(?:SKILL\.md|skill\.(?:md|json|ya?ml))$', re.I)
SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh'}
SEPARATORS = {';', '&&', '||', '|', '&', '\n', '(', ')'}
RELATED = re.compile(r'(?:\b|_)(?:skills?|plugins?)(?:\b|_)|SKILL\.md', re.I)


def destinations(command, depth=0, cwd=None):
    """Return (visible destinations, unresolved skill-related mutation).

    Quoted command text passed to echo/printf is data, as are heredoc bodies.
    Unsupported syntax with skill references stays unresolved, never certified safe.
    """
    if not isinstance(command, str):
        return [], False
    related = bool(RELATED.search(command))
    if depth > 4 or len(command) > 65536:
        return [], related
    # A standalone quoted cat heredoc only displays literal text. Do not turn
    # documentation examples into approval requests. Unquoted bodies can expand.
    literal = re.match(r"\s*cat\s+<<\s*(['\"])([A-Za-z_]\w*)\1[^\S\n]*\n", command)
    if literal:
        lines = command[literal.end():].splitlines()
        for i, line in enumerate(lines):
            if line == literal[2]:
                if not any(x.strip() for x in lines[i + 1:]):
                    return [], False
                break
    try:
        punctuation = ';&|\n()<>'
        lex = shlex.shlex(command, posix=True, punctuation_chars=punctuation)
        lex.whitespace = ' \t\r'
        lex.whitespace_split = True
        tokens = [p for t in lex for p in (re.split(r'(\n)', t) if all(c in punctuation for c in t) else [t]) if p]
    except ValueError:
        return [], related
    if any(t.startswith('<<') for t in tokens):
        return [], related  # Do not parse a document body as executed commands.
    segments, current = [], []
    for token in tokens + [';']:
        if token in SEPARATORS:
            if current:
                segments.append(current)
            current = []
            if token in {'(', ')'}:
                segments.append([token])
        else:
            current.append(token)
    found, uncertain, directories = [], False, []
    for segment in segments:
        if segment == ['(']:
            directories.append(cwd)
            continue
        if segment == [')']:
            cwd = directories.pop() if directories else None
            continue
        while segment and (segment[0] in {'then', 'do', 'else', 'command', 'exec', 'sudo'}
                           or re.fullmatch(r'[A-Za-z_]\w*=.*', segment[0], re.S)):
            segment = segment[1:]
        if not segment:
            continue
        name = posixpath.basename(segment[0])
        args = segment[1:]
        segment_related = bool(RELATED.search(' '.join(args))) or bool(cwd and SKILL.search(cwd))
        if name == 'cd':
            target = args[-1] if args else ''
            cwd = (posixpath.normpath(posixpath.join(cwd or '', target))
                   if target and not any(c in target for c in '$`*?[]') else None)
            continue
        if name in SHELLS:
            for i, value in enumerate(args):
                if re.fullmatch(r'-[a-z]*c[a-z]*', value) and i + 1 < len(args):
                    paths, unresolved = destinations(args[i + 1], depth + 1, cwd=cwd)
                    found.extend(paths)
                    uncertain |= unresolved
                    break
            continue
        if name == 'git' and args[:1] == ['clone']:
            args = args[1:]
            options_with_value = {'--depth', '--filter', '--branch', '-b', '--origin', '-o', '--template', '--reference', '--reference-if-able', '--separate-git-dir', '--config', '-c', '--jobs', '-j', '--shallow-since', '--shallow-exclude', '--upload-pack', '-u'}
        elif name in {'cp', 'mv', 'install'}:
            if '--help' in args or '--version' in args:
                continue
            if name == 'install' and ('-d' in args or '--directory' in args):
                continue
            options_with_value = {'-m', '--mode', '-o', '--owner', '-g', '--group', '-S', '--suffix'} if name == 'install' else {'-S', '--suffix'}
        else:
            continue
        operands, target, i, options = [], None, 0, True
        while i < len(args):
            arg = args[i]
            if arg in {'>', '>>', '<', '>&', '<&'}:
                break
            if options and arg == '--':
                options = False
            elif options and (arg in {'-t', '--target-directory'}):
                if i + 1 >= len(args):
                    uncertain |= segment_related
                    break
                i += 1
                target = args[i]
            elif options and arg.startswith('--target-directory='):
                target = arg.split('=', 1)[1]
            elif options and arg.startswith('-t') and len(arg) > 2:
                target = arg[2:]
            elif options and arg in options_with_value:
                i += 1
            elif options and arg.startswith('-'):
                pass
            else:
                operands.append(arg)
            i += 1
        if target is None and len(operands) >= 2:
            target = operands[-1]
        if target is None:
            # Clone without an explicit destination is not proven a skill install.
            uncertain |= segment_related and any('$' in x or '`' in x for x in operands)
            continue
        if any(c in target for c in '$`*?[]\n'):
            uncertain |= segment_related
            continue
        path = posixpath.normpath(posixpath.join(cwd or '', target))
        if SKILL.search(path):
            # Preserve a directory suffix for the existing mapper's path matcher.
            found.append(path + '/' if path.rsplit('/', 1)[-1].lower() in {'skill', 'skills', 'plugin', 'plugins'} else path)
    return list(dict.fromkeys(found)), uncertain
