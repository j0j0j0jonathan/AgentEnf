"""Shadow-only read contract. No policy facts or decisions are emitted.

Lexical parsing measures opportunity only. It never proves filesystem safety.
A ResourcePolicy is trusted deployer configuration, not a model/tool argument.
Historical calls lack such a policy and lack a constrained runtime implementation.
"""
from dataclasses import dataclass
import posixpath
import re
import shlex
from typing import Mapping

PRIVATE = {'agents.md','soul.md','user.md','memory.md','bootstrap.md','identity.md','skill.md',
           '.git','.ssh','.aws','.codex','.openclaw','secrets','credentials','id_rsa','id_ed25519'}
READ_TOOLS = {'read','read_file','file_read'}
LIST_TOOLS = {'list_directory','list_dir'}
SHELL_TOOLS = {'bash','exec','shell','run_command'}


@dataclass(frozen=True)
class ResourcePolicy:
    runtime_namespace: str
    workspace: str
    # Exact file revisions the deployer designates ordinary; no filename inference.
    files: Mapping[str, str]
    # List only authorized names, not an unrestricted enumeration of workspace contents.
    directories: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class Assessment:
    structural_candidate: bool
    operation: str = ''
    path: str = ''
    transport: str = ''
    reason: str = ''
    # Always false: this module has no trusted constrained-runtime receipt.
    eligible: bool = False


def protected_path(path):
    return any(part.lower() in PRIVATE or part.lower().startswith('.env')
               or re.search(r'(secret|credential|password|token)', part, re.I)
               or part.lower().endswith(('.pem','.key','.p12','.pfx'))
               for part in path.split('/'))


def static_path(path):
    if not isinstance(path, str) or not path or '\x00' in path:
        return False
    if any(ch in path for ch in ('$', '`', '*', '?', '[', ']', '\\', '~', '\n', '\r')):
        return False
    return not any(p in {'.','..'} for p in path.split('/')) and '//' not in path


def inspect_call(tool, args, workspace=None, cwd=None):
    """Recognize only narrow read/list shapes. Even a match is not an exemption."""
    if not isinstance(args, dict):
        return Assessment(False, reason='invalid_arguments')
    tool = str(tool).lower()
    operation = path = transport = ''
    if tool in READ_TOOLS | LIST_TOOLS:
        transport = 'native'
        keys = [k for k in ('path','file_path') if k in args]
        allowed = {'path','file_path','offset','limit'} if tool in READ_TOOLS else {'path','file_path'}
        if len(keys) != 1 or set(args)-allowed:
            return Assessment(False, reason='unsupported_arguments')
        if any(type(args[k]) is not int or args[k] < 0 for k in ('offset','limit') if k in args):
            return Assessment(False, reason='unsupported_arguments')
        operation, path = ('read' if tool in READ_TOOLS else 'list'), args[keys[0]]
    elif tool in SHELL_TOOLS:
        transport = 'shell_requires_replacement'
        keys = [k for k in ('command','cmd') if k in args]
        if len(keys) != 1:
            return Assessment(False, reason='unsupported_arguments')
        # No shell execution. Reject operators even inside quotes: intentionally conservative.
        command = args[keys[0]]
        if not isinstance(command, str) or any(ch in command for ch in '\n\r;&|<>$`*?[]\\'):
            return Assessment(False, reason='shell_not_single_literal_read')
        try:
            words = shlex.split(command)
        except ValueError:
            return Assessment(False, reason='invalid_shell_syntax')
        if len(words) == 2 and words[0] in {'cat','/bin/cat','/usr/bin/cat'}:
            operation,path = 'read',words[1]
        elif len(words) in {2,3} and words[0] in {'ls','/bin/ls','/usr/bin/ls'} and (len(words)==2 or words[1] in {'-l','-a','-la','-al'}):
            operation,path = 'list',words[-1]
        else:
            return Assessment(False, reason='shell_not_single_literal_read')
    else:
        return Assessment(False, reason='unsupported_tool')
    if not static_path(path) or path.startswith('-') or '://' in path:
        return Assessment(False, reason='ambiguous_path')
    if not path.startswith('/'):
        if not cwd or not static_path(cwd) or not cwd.startswith('/'):
            return Assessment(False, reason='missing_working_directory')
        path = posixpath.join(cwd, path)
    if protected_path(path):
        return Assessment(False, operation,path,transport,'protected_resource')
    if workspace:
        if not static_path(workspace) or not workspace.startswith('/') or workspace=='/':
            return Assessment(False, reason='invalid_workspace')
        if path != workspace and not path.startswith(workspace.rstrip('/')+'/'):
            return Assessment(False, operation,path,transport,'outside_workspace')
    return Assessment(True, operation,path,transport,
                      'requires_explicit_resource_grant_and_runtime_proof' if workspace else 'workspace_and_runtime_proof_unknown')
