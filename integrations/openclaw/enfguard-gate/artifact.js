import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

// Metadata is produced by the authenticated runtime, never extracted from the
// tool's prose. Only an exact complete replacement can establish a revision.
export function attestFullWrite(ticket, event, execution) {
  if (!ticket || execution?.effect_executed !== true ||
      ['failed','running','not_executed'].includes(execution?.outcome) ||
      event?.error || event?.result?.isError === true) return null;
  const p=ticket.path;
  if (typeof p !== 'string' || !path.isAbsolute(p) || p.split(path.sep).includes('..') ||
      !/^[a-f0-9]{64}$/.test(ticket.sha256 || '') ||
      !Number.isSafeInteger(ticket.bytes) || ticket.bytes < 0 || ticket.bytes > 200000) return null;
  let fd;
  try {
    // Refuse symlink components, including a symlinked parent directory.
    let current=path.parse(p).root;
    for (const component of p.slice(current.length).split(path.sep).filter(Boolean)) {
      current=path.join(current,component);
      if (fs.lstatSync(current).isSymbolicLink()) return null;
    }
    fd=fs.openSync(p,fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before=fs.fstatSync(fd);
    if (!before.isFile() || before.size !== ticket.bytes) return null;
    // A file can grow after fstat. Never allocate/read beyond the ticket budget.
    const bytes=Buffer.alloc(ticket.bytes);let read=0;
    while(read<bytes.length) {
      const n=fs.readSync(fd,bytes,read,bytes.length-read,read);
      if(n===0)return null;
      read+=n;
    }
    const extra=Buffer.alloc(1);
    if(fs.readSync(fd,extra,0,1,read)!==0)return null;
    const after=fs.fstatSync(fd);const named=fs.lstatSync(p);
    if (before.ino!==after.ino || before.size!==after.size || before.mtimeMs!==after.mtimeMs ||
        before.ctimeMs!==after.ctimeMs || named.ino!==after.ino || named.dev!==after.dev || named.isSymbolicLink()) return null;
    const digest=createHash('sha256').update(bytes).digest('hex');
    if (digest!==ticket.sha256) return null;
    return {kind:'verified_full_write',token:ticket.token,path:p,sha256:digest,bytes:bytes.length};
  } catch { return null; }
  finally { if (fd!==undefined) fs.closeSync(fd); }
}
