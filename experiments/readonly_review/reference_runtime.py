"""Local contract fixture, NOT an OpenClaw adapter or production exemption.

Only returns explicitly granted content revisions. No shell, interpreters, network
or recursive directory traversal. All filesystem access is relative to an opened
workspace descriptor; symlinks and hardlinks are rejected. Returned bytes must
match the deployer's hash, so a concurrent rewrite cannot substitute other bytes.
OS metadata (e.g. access time) may change; "read-only" refers to application data.
"""
import hashlib
import os
import stat
from pathlib import PurePosixPath
from .capability import ResourcePolicy, protected_path, static_path

MAX_BYTES = 65536


def read_granted(policy: ResourcePolicy, namespace: str, relative_path: str) -> str:
    if not namespace or namespace != policy.runtime_namespace:
        raise PermissionError('runtime_namespace_mismatch')
    if not static_path(relative_path) or relative_path.startswith('/') or protected_path(relative_path):
        raise PermissionError('invalid_or_protected_path')
    expected = policy.files.get(relative_path)
    if not expected or len(expected) != 64:
        raise PermissionError('no_explicit_revision_grant')
    if not static_path(policy.workspace) or not policy.workspace.startswith('/') or policy.workspace == '/':
        raise PermissionError('invalid_workspace')
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fds = []
    try:
        # Walk from /: reject symlink components even in the workspace root itself.
        parent = os.open('/', directory_flags)
        fds.append(parent)
        for part in PurePosixPath(policy.workspace).parts[1:]:
            parent = os.open(part, directory_flags, dir_fd=parent)
            fds.append(parent)
        parts = relative_path.split('/')
        for part in parts[:-1]:
            parent = os.open(part, directory_flags, dir_fd=parent)
            fds.append(parent)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fds.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
            raise PermissionError('unsupported_file_or_size')
        data = bytearray()
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, min(8192, MAX_BYTES+1-len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != expected:
            raise PermissionError('revision_mismatch_or_size')
        return bytes(data).decode('utf-8', errors='strict')
    finally:
        for fd in reversed(fds):
            os.close(fd)


def list_granted(policy: ResourcePolicy, namespace: str, relative_dir: str) -> list[str]:
    """List configured ordinary names only; never expose arbitrary directory names."""
    if not namespace or namespace != policy.runtime_namespace:
        raise PermissionError('runtime_namespace_mismatch')
    if relative_dir != '' and (not static_path(relative_dir) or relative_dir.startswith('/') or protected_path(relative_dir)):
        raise PermissionError('invalid_or_protected_path')
    if relative_dir not in policy.directories:
        raise PermissionError('no_explicit_directory_grant')
    names = policy.directories[relative_dir]
    if any(not static_path(n) or '/' in n or protected_path(n) for n in names):
        raise PermissionError('invalid_listing_grant')
    return sorted(names)
