"""Read-only fixture snapshots inside disposable benchmark containers.

Never follows symlinks or executes captured content. Explicit budgets produce
coverage gaps, never a silent claim of a complete snapshot.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat


def capture(roots, *, max_files=256, max_bytes=2_000_000, max_file_bytes=200_000):
    records, gaps = [], []
    total = 0
    directories = 0
    def no_symlinks(path):
        for p in [*path.parents, path]:
            if p.is_symlink():
                raise ValueError('symlink component')
    for root in roots:
        root = Path(root)
        if not root.is_absolute() or '..' in root.parts:
            raise ValueError('Absolute fixture root required')
        try:
            no_symlinks(root)
            root.lstat()
        except FileNotFoundError:
            records.append({'path': str(root), 'status': 'absent'})
            continue
        except (OSError, ValueError) as exc:
            gaps.append({'path': str(root), 'reason': type(exc).__name__})
            continue
        paths = []
        if root.is_file():
            paths = [root]
        else:
            def walk_error(exc):
                gaps.append({'path': str(exc.filename), 'reason': type(exc).__name__})
            for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
                directories += 1
                if directories > max_files:
                    gaps.append({'path': str(root), 'reason': 'directory_count_budget'})
                    break
                dirs.sort(); files.sort()
                for name in dirs[:]:
                    p = Path(directory) / name
                    if p.is_symlink():
                        gaps.append({'path': str(p), 'reason': 'symlink_directory'})
                        dirs.remove(name)
                paths.extend(Path(directory) / name for name in files)
                if len(paths) > max_files:
                    gaps.append({'path': str(root), 'reason': 'file_count_budget'})
                    break
        for p in sorted(paths):
            if len(records) >= max_files:
                gaps.append({'path': str(root), 'reason': 'file_count_budget'})
                break
            try:
                no_symlinks(p)
                with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
                    before = os.fstat(f.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError('not a regular file')
                    if before.st_size > max_file_bytes or total + before.st_size > max_bytes:
                        gaps.append({'path': str(p), 'reason': 'byte_budget', 'size': before.st_size})
                        continue
                    data = f.read(max_file_bytes + 1)
                    after = os.fstat(f.fileno())
                named = p.lstat()
                signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                if signature(before) != signature(after) or signature(after) != signature(named) or len(data) != after.st_size:
                    raise ValueError('file changed during snapshot')
                total += len(data)
                record = {'path': str(p), 'status': 'observed', 'bytes': len(data),
                          'sha256': hashlib.sha256(data).hexdigest()}
                try:
                    record['text'] = data.decode('utf-8')
                except UnicodeDecodeError:
                    record['base64'] = base64.b64encode(data).decode('ascii')
                records.append(record)
            except (OSError, ValueError) as exc:
                gaps.append({'path': str(p), 'reason': type(exc).__name__})
    return {'records': records, 'gaps': gaps, 'captured_bytes': total,
            'complete_within_declared_roots': not gaps,
            'limits': 'Point-in-time fixture snapshot, not an atomic filesystem or network audit.'}


if __name__ == '__main__':
    import sys
    print(json.dumps(capture(json.loads(sys.argv[1])), ensure_ascii=False))
